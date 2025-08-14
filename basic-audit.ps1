$ReportPath = Read-Host "Please enter the full path where the report will be saved"

Write-Host "Starting 'Basic Audit (Full Report)'..." -ForegroundColor Cyan

    $RequiredGraphScopes = @(
        "Application.Read.All",
        "Directory.Read.All",
        "DelegatedPermissionGrant.Read.All",
        "AuditLog.Read.All"
    )

    # --- 1. Microsoft Graph Module Check, Profile Selection, and Connection ---
    Write-Host "Ensuring Microsoft Graph PowerShell SDK is installed and connected..."
    try {
        # Check for module and install if not found
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
            Write-Warning "Microsoft.Graph PowerShell module not found. Attempting to install for CurrentUser. You may need to restart PowerShell if prompted."
            Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -ErrorAction Stop
        }

        # Explicitly select the v1.0 profile
        Write-Host "Selecting Microsoft.Graph v1.0 profile..."


        # Check if already connected with required scopes
        $currentContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($null -eq $currentContext -or -not ($RequiredGraphScopes | ForEach-Object { $currentContext.Scopes -contains $_ } | Select-Object -First 1)) {
            Write-Host "Connecting to Microsoft Graph with required scopes ($($RequiredGraphScopes -join ', '))..." -ForegroundColor Green
            Connect-MgGraph -Scopes $RequiredGraphScopes
            Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
        } else {
            Write-Host "Already connected to Microsoft Graph with required scopes." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to initialize Microsoft Graph connection or modules: $($_.Exception.Message)"
        Write-Error "Please ensure you have network connectivity and sufficient permissions."
        return # Exit function on critical error
    }

    # --- 2 & 3. Data Collection & Caching (Service Principals & Users) ---
    Write-Host "Caching all Service Principals (Enterprise Applications) and Users for faster lookup..."
    $ServicePrincipalCache = @{} # Hashtable for quick Service Principal lookup
    $UserCache = @{}             # Hashtable for quick User lookup

    try {
        # Get all Service Principals (Enterprise Applications) and cache them
        Write-Host "Getting all service principals..." -ForegroundColor yellow
        $spCount = 0
        Get-MgServicePrincipal -All | ForEach-Object {
            $ServicePrincipalCache[$_.Id] = $_ # Cache the entire object, keyed by its Id
            $spCount++
        }
        Write-Host "Cached $($spCount) Service Principals."

        # Get all Users and cache them
        Write-Host "Getting all users..." -ForegroundColor yellow
        $userCount = 0
        Get-MgUser -All | ForEach-Object {
            $UserCache[$_.Id] = $_ # Cache the entire object, keyed by its Id
            $userCount++
        }
        Write-Host "Cached $($userCount) Users."
    }
    catch {
        Write-Warning "Failed to retrieve and cache Service Principals or Users: $($_.Exception.Message)"
        Write-Warning "Report may contain 'Unknown App' or 'Unknown User' entries."
    }

    # --- 4. Retrieve Raw User Consents ---
    Write-Host "Retrieving all delegated permission grants (user consents)..." -ForegroundColor Yellow
    $UserConsents = @()
    try {
        # Get all grants and filter for those where a PrincipalId (user) is present
        $UserConsents = Get-MgOauth2PermissionGrant -All | Where-Object { $_.PrincipalId -ne $null }
        Write-Host "Found $($UserConsents.Count) individual user consent grants." -ForegroundColor Green
    }
    catch {
        Write-Error "Could not retrieve user consent grants: $($_.Exception.Message)."
        Write-Error "Ensure your connected account has the 'DelegatedPermissionGrant.Read.All' permission."
        Disconnect-MgGraph 
        return
    }

    # --- 5. Process and Enrich Consents (Grouping Logic) ---
    Write-Host "Processing consents and building report entries..." -ForegroundColor Cyan
    $ReportEntries = @{} # This hashtable will hold our final report entries, grouped by the ServicePrincipal's ObjectId

    $totalConsents = $UserConsents.Count
    $progressCounter = 0

    foreach ($consent in $UserConsents) {
        $progressCounter++
        Write-Progress -Activity "Processing User Consents" -Status "Consent $progressCounter of $totalConsents" -PercentComplete (($progressCounter / $totalConsents) * 100)

        $appObjectId = $consent.ClientId # The ClientId in grant is the ObjectId of the Service Principal
        $userId = $consent.PrincipalId
        $scopeString = $consent.Scope

        $sp = $ServicePrincipalCache[$appObjectId]
        $user = $UserCache[$userId]

        # Handle cases where the Service Principal might not be found (e.g., deleted app)
        if (-not $sp) {
            Write-Verbose "Service Principal with ID '$appObjectId' not found in cache. Creating placeholder for report."
            $sp = [PSCustomObject]@{
                DisplayName = "Unknown Application (ID: $appObjectId)"
                AppId       = $appObjectId # Use ObjectId as AppId for unknown
                Id          = $appObjectId
            }
        }

        # If this is the first consent for this app, initialize the report entry
        if (-not $ReportEntries.ContainsKey($appObjectId)) {
            $ReportEntries[$appObjectId] = [PSCustomObject]@{
                DisplayName         = $sp.DisplayName
                AppId               = $sp.AppId
                ObjectId            = $sp.Id
                UserConsentsCount   = 0
                ConsentingUsers     = [System.Collections.Generic.List[string]]::new() # List to collect unique users
                DelegatedPermissions= [System.Collections.Generic.List[string]]::new() # List to collect unique permissions
                UnverifiedPublisher = $false
                HasRiskyConsents = $false
                CountryOfOrigin = [System.Collections.Generic.List[string]]::new() # List to collect countries of origin
                LastSignIn = [System.Collections.Generic.List[string]]::new()
                FullAccessAsApp = $false
                IsOrphaned = $false

            }
        }

        $appEntry = $ReportEntries[$appObjectId]

        # Increment consent count (every unique consent grant for this SP)
        $appEntry.UserConsentsCount++

        # Add Consenting User (ensure uniqueness)
        if ($user) {
            if (-not ($appEntry.ConsentingUsers -contains $user.UserPrincipalName)) {
                $appEntry.ConsentingUsers.Add($user.UserPrincipalName)
            }
        } else {
            $unknownUserIdentifier = "Unknown User (ID: $userId)"
            if (-not ($appEntry.ConsentingUsers -contains $unknownUserIdentifier)) {
                $appEntry.ConsentingUsers.Add($unknownUserIdentifier)
            }
        }

        # Add Delegated Permissions (ensure uniqueness of raw scopes)
        if ($scopeString) {
            $scopes = $scopeString.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
            foreach ($scope in $scopes) {
                if (-not ($appEntry.DelegatedPermissions -contains $scope)) {
                    $appEntry.DelegatedPermissions.Add($scope)
                }
            }
        }

        $RiskyPermissions = @(
            "Application.ReadWrite.All", "Directory.ReadWrite.All", "Group.ReadWrite.All",
            "User.ReadWrite.All", "Mail.ReadWrite", "Mail.ReadWrite.All",
            "Sites.ReadWrite.All", "TeamsActivity.ReadWrite.All", "TeamSettings.ReadWrite.All",
            "Policy.ReadWrite.ConditionalAccess", "AuditLog.Read.All",
            "Files.ReadWrite.All", "Calendars.ReadWrite.All",
            "offline_access" # Often a risk indicator when combined with other scopes
        )

        #Check if app has risky consents and set variable to true if valid
        foreach ($app in $appEntry) {
            if ($app.DelegatedPermissions | Where-Object { $RiskyPermissions -contains $_ }) {
                $app.HasRiskyConsents = $true
            }
        }

        #Check if app is from verified publisher, or set UnverifiedPublisher to true
        if($appEntry.VerifiedPublisher -eq $null){
            $appEntry.UnverifiedPublisher = $true
        }

        #Get last sign-in for each enterprise application
        foreach ($app in $appEntry) {
            $displayName = $app.DisplayName

            $signIns = Get-MgAuditLogSignIn -Filter "appDisplayName eq '$displayName'" -Top 1

            if ($signIns.Count -gt 0) {
                $lastSignInTime = ($signIns | Select-Object -First 1).CreatedDateTime

                if (-not $app.PSObject.Properties.Match('LastSignIn')) {
                    $app | Add-Member -MemberType NoteProperty -Name LastSignIn -Value $lastSignInTime
                } else {
                    $app.LastSignIn = $lastSignInTime
                }
            } else {

                if (-not $app.PSObject.Properties.Match('LastSignIn')) {
                    $app | Add-Member -MemberType NoteProperty -Name LastSignIn -Value $null
                } else {
                    $app.LastSignIn = $null
                }
            }
        }

        #Determine if app has "full_access_as_app" permissions
        foreach($app in $appEntry){
            $app.RequiredResourceAccess | ForEach-Object {
            $_.ResourceAccess | Where-Object { $_.Id -eq "dc50a0fb-09a3-484d-be87-e023b12c6440" }
            $app.FullAccessAsApp = $true
            }
        }

        #Get orphaned applications
        foreach ($app in $appEntry) {
            try {
                # Use the correct object ID for service principal
                $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $app.Id

                # Check if owners exist
                $isOrphaned = -not $owners

                # Add or update the IsOrphaned property
                if ($app.PSObject.Properties.Match("IsOrphaned")) {
                    $app.IsOrphaned = $isOrphaned
                } else {
                    $app | Add-Member -NotePropertyName IsOrphaned -NotePropertyValue $isOrphaned
                }
            } catch {
                # Handle 404 or other errors gracefully
                Write-Warning "Could not retrieve owners for app $($app.DisplayName): $($_.Exception.Message)"
                if ($app.PSObject.Properties.Match("IsOrphaned")) {
                    $app.IsOrphaned = $true
                } else {
                    $app | Add-Member -NotePropertyName IsOrphaned -NotePropertyValue $true
                }
            }
        }


        

    }
    # Ensure the progress bar completes
    Write-Progress -Activity "Processing User Consents" -Status "Complete." -PercentComplete 100 -Completed

    # --- 6. Finalize and Format Output for CSV ---
    Write-Host "Finalizing report data..."
    $FinalReport = @()
    foreach ($entry in $ReportEntries.Values) {
        # Convert List objects to semicolon-separated strings for CSV
        $entry.ConsentingUsers = ($entry.ConsentingUsers | Sort-Object | Select-Object -Unique) -join '; '
        $entry.DelegatedPermissions = ($entry.DelegatedPermissions | Sort-Object | Select-Object -Unique) -join '; '
        $entry.UnverifiedPublisher = ($entry.UnverifiedPublisher)
        $FinalReport += $entry
    }

    # --- 7. Generate and Export Report ---
    Write-Host "Exporting basic audit report to '$ReportPath'..." -ForegroundColor Yellow
    try {
        $FinalReport | Export-Csv $ReportPath -NoTypeInformation -Force
        Write-Host "Basic audit completed successfully. Report saved to '$ReportPath'" -ForegroundColor Green
        Read-Host "Press Enter to return to menu"
    }
    catch {
        Write-Error "Failed to export report to '$ReportPath': $($_.Exception.Message)"
        Write-Warning "The report might not have been created."
        Read-Host "Press Enter to return to menu"
    }
    finally {
        # --- 8. Disconnect from Microsoft Graph ---
        Write-Host "Disconnecting from Microsoft Graph." -ForegroundColor DarkGray
        Disconnect-MgGraph 
    }
