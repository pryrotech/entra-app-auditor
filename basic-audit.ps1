$ReportPath = Read-Host "Enter full path to save the report"

Write-Host "Starting Basic Audit..." -ForegroundColor Cyan

$RequiredGraphScopes = @(
    "Application.Read.All",
    "Directory.Read.All",
    "DelegatedPermissionGrant.Read.All",
    "AuditLog.Read.All",
    "User.Read.All"
)

# Connect to Microsoft Graph
try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Warning "Installing Microsoft.Graph module..."
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
    }

    $context = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -eq $context -or -not ($RequiredGraphScopes | Where-Object { $context.Scopes -contains $_ })) {
        Connect-MgGraph -Scopes $RequiredGraphScopes
    }
} catch {
    Write-Error "Graph connection failed: $($_.Exception.Message)"
    return
}

# Cache Service Principals and Users
$ServicePrincipalCache = @{}
$UserCache = @{}

Get-MgServicePrincipal -All | ForEach-Object { $ServicePrincipalCache[$_.Id] = $_ }
Get-MgUser -All | ForEach-Object { $UserCache[$_.Id] = $_ }

# Get user consents
$UserConsents = Get-MgOauth2PermissionGrant -All | Where-Object { $_.PrincipalId -ne $null }

# Initialize report
$ReportEntries = @{}

foreach ($consent in $UserConsents) {
    $appId = $consent.ClientId
    $userId = $consent.PrincipalId
    $scopeString = $consent.Scope
    $sp = $ServicePrincipalCache[$appId]
    $user = $UserCache[$userId]

    if (-not $sp) {
        $sp = [PSCustomObject]@{
            DisplayName = "Unknown App ($appId)"
            AppId = $appId
            Id = $appId
        }
    }

    if (-not $ReportEntries.ContainsKey($appId)) {
        $ReportEntries[$appId] = [PSCustomObject]@{
            DisplayName               = $sp.DisplayName
            AppId                     = $sp.AppId
            ObjectId                  = $sp.Id
            UserConsentsCount         = 0
            ConsentingUsers           = [System.Collections.Generic.List[string]]::new()
            DelegatedPermissions      = [System.Collections.Generic.List[string]]::new()
            UnverifiedPublisher       = $false
            HasRiskyConsents          = $false
            CountryOfOrigin           = [System.Collections.Generic.List[string]]::new()
            LastSignInUTC             = [System.Collections.Generic.List[string]]::new()
            FullAccessAsApp           = $false
            HasFullAccessAsApp        = $false
            IsOrphaned                = $false
            HighValueUser             = $false
            HasBroadMailboxAccess     = $false
            IsRiskyApp                = $false
            RiskReasons               = [System.Collections.Generic.List[string]]::new()
            RiskyPermissionsFound     = [System.Collections.Generic.List[string]]::new()
            IsDisabledApp             = $false
            OldestConsentDate         = [DateTime]::MaxValue
            IsExternalTenantApp       = $false
            RequiresUserAssignment    = $false
            UsageStatus               = ""
        }
    }

    $entry = $ReportEntries[$appId]
    $entry.UserConsentsCount++

    # Add user
    $upn = if ($user) { $user.UserPrincipalName } else { "Unknown User ($userId)" }
    if (-not $entry.ConsentingUsers.Contains($upn)) { $entry.ConsentingUsers.Add($upn) }

    # Add permissions
    $scopes = $scopeString -split ' '
    foreach ($scope in $scopes) {
        if (-not $entry.DelegatedPermissions.Contains($scope)) {
            $entry.DelegatedPermissions.Add($scope)
        }
    }

    # Risky permissions
    $RiskyPermissions = @(
        "Application.ReadWrite.All", "Directory.ReadWrite.All", "Group.ReadWrite.All",
        "User.ReadWrite.All", "Mail.ReadWrite", "Mail.ReadWrite.All", "Sites.ReadWrite.All",
        "TeamsActivity.ReadWrite.All", "TeamSettings.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess",
        "AuditLog.Read.All", "Files.ReadWrite.All", "Calendars.ReadWrite.All", "offline_access"
    )

    foreach ($scope in $scopes) {
        if ($RiskyPermissions -contains $scope) {
            $entry.HasRiskyConsents = $true
            if (-not $entry.RiskyPermissionsFound.Contains($scope)) {
                $entry.RiskyPermissionsFound.Add($scope)
                $entry.IsRiskyApp = $true
                $entry.RiskReasons.Add("Risky permission: $scope")
            }
        }
    }

    # Unverified publisher
    if (-not $sp.VerifiedPublisher) { $entry.UnverifiedPublisher = $true }

    # Last sign-in
    $signIn = Get-MgAuditLogSignIn -Filter "appDisplayName eq '$($sp.DisplayName)'" -Top 1
    if ($signIn) {
        $entry.LastSignInUTC.Add($signIn[0].CreatedDateTime)
    }

    # Full access as app
    if ($sp.RequiredResourceAccess.ResourceAccess.Id -contains "dc50a0fb-09a3-484d-be87-e023b12c6440") {
        $entry.FullAccessAsApp = $true
        $entry.HasFullAccessAsApp = $true
        $entry.IsRiskyApp = $true
        $entry.RiskReasons.Add("Has full_access_as_app")
    }

    # Orphaned app
    try {
        $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id
        $entry.IsOrphaned = ($owners.Count -eq 0)
    } catch {
        $entry.IsOrphaned = $true
    }

    # Disabled app
    $entry.IsDisabledApp = ($sp.AccountEnabled -eq $false)

    # External tenant
    $tenantId = (Get-MgOrganization).Id
    $entry.IsExternalTenantApp = ($sp.AppOwnerOrganizationId -ne $tenantId)

    # Requires user assignment
    $entry.RequiresUserAssignment = $sp.AppRoleAssignmentRequired

    # Oldest consent date
    if ($consent.ConsentTypeDateTime -lt $entry.OldestConsentDate) {
        $entry.OldestConsentDate = $consent.ConsentTypeDateTime
    }

    # High-value user
    $highRiskRoles = @(
        "Global Administrator", "Privileged Role Administrator", "Application Administrator",
        "Cloud Application Administrator", "Security Administrator", "User Administrator",
        "Exchange Administrator", "SharePoint Administrator", "Teams Administrator"
    )

    $roles = Get-MgDirectoryRole | Where-Object { $_.DisplayName -in $highRiskRoles }
    foreach ($role in $roles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
        if ($members.Id -contains $userId) {
            $entry.HighValueUser = $true
        }
    }

    # Broad mailbox access
    $broadPerms = @("Mail.ReadWrite", "Mail.ReadWrite.Shared", "Calendars.ReadWrite", "Calendars.ReadWrite.Shared")
    foreach ($perm in $broadPerms) {
        if ($scopeString -match "\b$perm\b") {
            $entry.HasBroadMailboxAccess = $true
        }
    }
}

# Finalize report
$FinalReport = @()
foreach ($entry in $ReportEntries.Values) {
    $entry.ConsentingUsers        = ($entry.ConsentingUsers | Sort-Object -Unique) -join '; '
    $entry.DelegatedPermissions   = ($entry.DelegatedPermissions | Sort-Object -Unique) -join '; '
    $entry.CountryOfOrigin        = ($entry.CountryOfOrigin | Sort-Object -Unique) -join '; '
    $entry.LastSignInUTC          = ($entry.LastSignInUTC | Sort-Object -Unique) -join '; '
    $entry.RiskReasons            = ($entry.RiskReasons | Sort-Object -Unique) -join '; '
    $entry.RiskyPermissionsFound = ($entry.RiskyPermissionsFound | Sort-Object -Unique) -join '; '
    $FinalReport += $entry
}

# Export
$FinalReport | Export-Csv -Path $ReportPath -NoTypeInformation -Force
Write-Host "Report saved to $ReportPath" -ForegroundColor Green
Disconnect-MgGraph
