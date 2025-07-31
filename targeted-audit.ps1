Write-Host "`n--- Targeted Risk Audit ---" -ForegroundColor Yellow
            $reportFileName = Read-Host "Enter the full path and filename for the risk report (e.g., C:\Reports\ShadowIT_RiskAudit.csv)"

            if (-not [string]::IsNullOrEmpty($reportFileName)) {
                Write-Host "Configuring audit parameters:" -ForegroundColor Cyan

                # --- User Prompts for Audit Parameters ---
                # These variables will directly hold the boolean (Y/N) or integer values
                $FlagUnverifiedPublisher = (Read-Host "Flag apps from unverified publishers? (Y/N)" -eq 'Y')
                $minUsersInput = Read-Host "Minimum users to flag an app as 'high user count' (e.g., 50, Enter for default 50)"
                $FlagFullAccessAsApp = (Read-Host "Flag apps with 'full_access_as_app' permission? (Y/N)" -eq 'Y')
                $FlagDisabledApp = (Read-Host "Flag apps that are Disabled in Azure AD? (Y/N)" -eq 'Y')
                $FlagExternalTenantApp = (Read-Host "Flag apps from an External Azure AD Tenant? (Y/N)" -eq 'Y')

                # Handle MinConsentingUsers default
                $MinConsentingUsers = 50 # Default value for MinConsentingUsers
                $_intResult = 0
                if ([int]::TryParse($minUsersInput, [ref]$_intResult)) {
                    $MinConsentingUsers = $_intResult
                } else {
                    Write-Host "Using default minimum consenting users: $MinConsentingUsers" -ForegroundColor DarkGray
                }

                # Define the default list of risky permissions directly as a variable
                $RiskyPermissions = @(
                    "Application.ReadWrite.All", "Directory.ReadWrite.All", "Group.ReadWrite.All",
                    "User.ReadWrite.All", "Mail.ReadWrite", "Mail.ReadWrite.All",
                    "Sites.ReadWrite.All", "TeamsActivity.ReadWrite.All", "TeamSettings.ReadWrite.All",
                    "Policy.ReadWrite.ConditionalAccess", "AuditLog.Read.All",
                    "Files.ReadWrite.All", "Calendars.ReadWrite.All",
                    "offline_access" # Often a risk indicator when combined with other scopes
                )

                # --- BEGIN TARGETED RISK AUDIT LOGIC ---

                Write-Host "Starting 'Targeted Risk Audit'..." -ForegroundColor Cyan

                $RequiredGraphScopes = @(
                    "Application.Read.All",
                    "Directory.Read.All",
                    "DelegatedPermissionGrant.Read.All"
                )

                # --- 1. Microsoft Graph Module Check, Profile Selection, and Connection ---
                Write-Host "Ensuring Microsoft Graph PowerShell SDK is installed and connected..."
                try {
                    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
                        Write-Warning "Microsoft.Graph PowerShell module not found. Please install it and restart PowerShell."
                        exit # Exit the script if critical module is missing
                    }

                    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop


                    $currentContext = Get-MgContext -ErrorAction SilentlyContinue
                    if ($null -eq $currentContext -or -not ($RequiredGraphScopes | ForEach-Object { $currentContext.Scopes -contains $_ } | Select-Object -First 1)) {
                        Write-Host "Connecting to Microsoft Graph with required scopes ($($RequiredGraphScopes -join ', '))..." -ForegroundColor Green
                        Connect-MgGraph 
                        Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
                    } else {
                        Write-Host "Already connected to Microsoft Graph with required scopes." -ForegroundColor Green
                    }
                }
                catch {
                    Write-Error "Failed to initialize Microsoft Graph connection or modules: $($_.Exception.Message)"
                    Write-Error "Please ensure you have network connectivity and sufficient permissions."
                    exit # Exit script on critical error
                }

                # --- 2 & 3. Data Collection & Caching (Service Principals & Users) ---
                Write-Host "Caching all Service Principals (Enterprise Applications) and Users for faster lookup..."
                $ServicePrincipalCache = @{}
                $UserCache = @{}

                # Get the current tenant ID once for 'IsExternalTenantApp' check
                $myTenantId = (Get-MgContext).TenantId

                try {
                    Write-Host "Getting all service principals..." -ForegroundColor Yellow
                    $spCount = 0
                    Get-MgServicePrincipal -All | ForEach-Object {
                        $ServicePrincipalCache[$_.Id] = $_
                        $spCount++
                    }
                    Write-Host "Cached $($spCount) Service Principals."

                    Write-Host "Getting all users..." -ForegroundColor Yellow
                    $userCount = 0
                    Get-MgUser -All | ForEach-Object {
                        $UserCache[$_.Id] = $_
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
                    $UserConsents = Get-MgOauth2PermissionGrant -All | Where-Object { $_.PrincipalId -ne $null }
                    Write-Host "Found $($UserConsents.Count) individual user consent grants." -ForegroundColor Green
                }
                catch {
                    Write-Error "Could not retrieve user consent grants: $($_.Exception.Message)."
                    Write-Error "Ensure your connected account has the 'DelegatedPermissionGrant.Read.All' permission."
                    Disconnect-MgGraph 
                    exit # Exit script on critical error
                }

                # --- 5. Process and Enrich Consents (Grouping & Risk Logic) ---
                Write-Host "Processing consents and applying risk criteria..." -ForegroundColor Cyan
                $ReportEntries = @{}

                $totalConsents = $UserConsents.Count
                $progressCounter = 0

                foreach ($consent in $UserConsents) {
                    $progressCounter++
                    Write-Progress -Activity "Processing User Consents for Risk Audit" -Status "Consent $progressCounter of $totalConsents" -PercentComplete (($progressCounter / $totalConsents) * 100)

                    $appObjectId = $consent.ClientId
                    $userId = $consent.PrincipalId
                    $scopeString = $consent.Scope

                    $sp = $ServicePrincipalCache[$appObjectId]
                    $user = $UserCache[$userId]

                    # Handle cases where the Service Principal might not be found
                    if (-not $sp) {
                        Write-Verbose "Service Principal with ID '$appObjectId' not found in cache. Creating placeholder for report."
                        $sp = [PSCustomObject]@{
                            DisplayName = "Unknown Application (ID: $appObjectId)"
                            AppId       = $appObjectId
                            Id          = $appObjectId
                            VerifiedPublisher = $null
                            AccountEnabled = $false
                            AppRoleAssignmentRequired = $false
                            AppOwnerOrganizationId = $null
                        }
                    }

                    # If this is the first consent for this app, initialize the report entry
                    if (-not $ReportEntries.ContainsKey($appObjectId)) {
                        $ReportEntries[$appObjectId] = [PSCustomObject]@{
                            DisplayName         = $sp.DisplayName
                            AppId               = $sp.AppId
                            ObjectId            = $sp.Id
                            UserConsentsCount   = 0
                            ConsentingUsers     = [System.Collections.Generic.List[string]]::new()
                            DelegatedPermissions= [System.Collections.Generic.List[string]]::new()
                            IsRiskyApp          = $false
                            RiskReasons         = [System.Collections.Generic.List[string]]::new()
                            RiskyPermissionsFound = [System.Collections.Generic.List[string]]::new()
                            UnverifiedPublisher = $false
                            HasFullAccessAsApp  = $false
                            IsDisabledApp       = $false
                            OldestConsentDate   = [DateTime]::MaxValue
                            IsExternalTenantApp = $false
                            RequiresUserAssignment = $false
                        }

                        # Set initial flags based on SP properties when the app entry is first created
                        $appEntry = $ReportEntries[$appObjectId]

                        if ($sp) {
                            if ($FlagDisabledApp -and (-not $sp.AccountEnabled -and $sp.AppId -ne $null)) {
                                $appEntry.IsDisabledApp = $true
                                $appEntry.IsRiskyApp = $true
                            }
                            if ($FlagExternalTenantApp -and $sp.AppOwnerOrganizationId -ne $myTenantId) {
                                $appEntry.IsExternalTenantApp = $true
                                $appEntry.IsRiskyApp = $true
                            }
                            if ($sp.AppRoleAssignmentRequired -eq $true) {
                                $appEntry.RequiresUserAssignment = $true
                            }
                        }
                    } else {
                        $appEntry = $ReportEntries[$appObjectId]
                    }

                    $appEntry.UserConsentsCount++

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

                    if ($consent.CreationDateTime -lt $appEntry.OldestConsentDate) {
                        $appEntry.OldestConsentDate = $consent.CreationDateTime
                    }

                    if ($scopeString) {
                        $scopes = $scopeString.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
                        foreach ($scope in $scopes) {
                            if (-not ($appEntry.DelegatedPermissions -contains $scope)) {
                                $appEntry.DelegatedPermissions.Add($scope)
                            }
                            if ($RiskyPermissions -contains $scope) {
                                if (-not ($appEntry.RiskyPermissionsFound -contains $scope)) {
                                    $appEntry.RiskyPermissionsFound.Add($scope)
                                    $appEntry.IsRiskyApp = $true
                                }
                            }
                            if ($FlagFullAccessAsApp -and $scope -eq "full_access_as_app") {
                                $appEntry.HasFullAccessAsApp = $true
                                $appEntry.IsRiskyApp = $true
                            }
                        }
                    }
                }
                Write-Progress -Activity "Processing User Consents for Risk Audit" -Status "Complete." -PercentComplete 100 -Completed

                # --- Final Risk Assessment Pass (after all consents are aggregated) ---
                Write-Host "Performing final risk assessment pass..." -ForegroundColor Cyan
                $FinalReport = @()
                foreach ($entry in $ReportEntries.Values) {
                    if ($FlagUnverifiedPublisher) {
                        $sp = $ServicePrincipalCache[$entry.ObjectId]
                        if ($sp -and ($null -eq $sp.VerifiedPublisher -or [string]::IsNullOrWhiteSpace($sp.VerifiedPublisher.DisplayName))) {
                            $entry.UnverifiedPublisher = $true
                            $entry.IsRiskyApp = $true
                        }
                    }

                    if ($entry.UserConsentsCount -ge $MinConsentingUsers) {
                        $sp = $ServicePrincipalCache[$entry.ObjectId]
                        if ($sp -and $sp.AppId -notmatch "^00000002-0000-0000-c000-000000000000" -and $sp.AppId -notmatch "^de8bc8b5-d9f9-48cd-aee3-f923a2959846") {
                            $entry.IsRiskyApp = $true
                            if (-not ($entry.RiskReasons -contains "High User Count")) {
                                $entry.RiskReasons.Add("High User Count")
                            }
                        }
                    }
                    
                    if ($entry.RiskyPermissionsFound.Count -gt 0) {
                        $entry.RiskReasons.Add("Risky Permissions: $($($entry.RiskyPermissionsFound | Sort-Object | Select-Object -Unique) -join ', ')")
                    }
                    if ($entry.UnverifiedPublisher) {
                        $entry.RiskReasons.Add("Unverified Publisher")
                    }
                    if ($entry.HasFullAccessAsApp) {
                        $entry.RiskReasons.Add("Has 'full_access_as_app' permission (High Privilege)")
                    }
                    if ($entry.IsDisabledApp) {
                        $entry.RiskReasons.Add("App is Disabled in Azure AD")
                    }
                    if ($entry.IsExternalTenantApp) {
                        $entry.RiskReasons.Add("App is from an External Tenant")
                    }

                    if ($entry.RiskReasons.Count -gt 0) {
                        $entry.IsRiskyApp = $true
                    } else {
                        $entry.IsRiskyApp = $false
                    }

                    $entry.ConsentingUsers = ($entry.ConsentingUsers | Sort-Object | Select-Object -Unique) -join '; '
                    $entry.DelegatedPermissions = ($entry.DelegatedPermissions | Sort-Object | Select-Object -Unique) -join '; '
                    $entry.RiskyPermissionsFound = ($entry.RiskyPermissionsFound | Sort-Object | Select-Object -Unique) -join '; '
                    $entry.RiskReasons = ($entry.RiskReasons | Sort-Object | Select-Object -Unique) -join '; '
                    
                     <#if ($entry.OldestConsentDate -eq [DateTime]::MaxValue) {
                        $entry.OldestConsentDate = "N/A"
                    } else {
                        $entry.OldestConsentDate = $entry.OldestConsentDate.ToString("yyyy-MM-dd HH:mm:ss")
                    }#>

                    $FinalReport += $entry
                }

                # --- 6. Generate and Export Report ---
                Write-Host "Exporting targeted risk audit report to '$ReportPath'..." -ForegroundColor Yellow
                try {
                    $FinalReport | Sort-Object -Property IsRiskyApp -Descending | Export-Csv $ReportPath -NoTypeInformation -Force
                    Write-Host "Targeted risk audit completed successfully. Report saved to '$ReportPath'" -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed to export report to '$ReportPath': $($_.Exception.Message)"
                    Write-Warning "The report might not have been created."
                }
                finally {
                    # --- 7. Disconnect from Microsoft Graph ---
                    Write-Host "Disconnecting from Microsoft Graph." -ForegroundColor DarkGray
                    Disconnect-MgGraph 
                }
                # --- END TARGETED RISK AUDIT LOGIC ---

            } else {
                Write-Warning "Report path cannot be empty. Returning to menu."
            }
            Read-Host "Targeted audit finished. Press Enter to return to menu."
            Clear-Host