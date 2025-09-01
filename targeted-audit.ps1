param (
    [string]$ReportPath = "$PWD\bulk-app-audit.csv"
)

Write-Host "Starting Bulk Audit..." -ForegroundColor Cyan

# Define available flags
$AvailableFlags = @(
    "UnverifiedPublisher",
    "RiskyPermissions",
    "Orphaned",
    "BroadMailboxAccess",
    "ExternalTenant",
    "DisabledApp",
    "HighValueUser",
    "FullAccessAsApp",
    "CountryOfOrigin",
    "UsageStatus",
    "OldestConsentDate"
)

# Prompt user for flags
Write-Host "Available flags: $($AvailableFlags -join ', ')" -ForegroundColor Yellow
Write-Host "Enter flags to check (comma-separated), or press Enter to check all:" -ForegroundColor Cyan
$flagInput = Read-Host "Flags"

if ([string]::IsNullOrWhiteSpace($flagInput)) {
    $SelectedFlags = $AvailableFlags
} else {
    $SelectedFlags = $flagInput.Split(',') | ForEach-Object { $_.Trim() }
}

function IsFlagEnabled($flagName) {
    return $SelectedFlags -contains $flagName
}

# Connect to Microsoft Graph
Connect-MgGraph -Scopes @(
    "Application.Read.All",
    "Directory.Read.All",
    "DelegatedPermissionGrant.Read.All",
    "AuditLog.Read.All",
    "User.Read.All"
)

# Cache users and roles
$UserCache = @{}
Get-MgUser -All | ForEach-Object { $UserCache[$_.Id] = $_ }

$highRiskRoles = @(
    "Global Administrator", "Privileged Role Administrator", "Application Administrator",
    "Cloud Application Administrator", "Security Administrator", "User Administrator",
    "Exchange Administrator", "SharePoint Administrator", "Teams Administrator"
)

$RoleMembers = @{}
$roles = Get-MgDirectoryRole | Where-Object { $_.DisplayName -in $highRiskRoles }
foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
    foreach ($member in $members) {
        $RoleMembers[$member.Id] = $true
    }
}

# Get all service principals and consents
$ServicePrincipals = Get-MgServicePrincipal -All
$UserConsents = Get-MgOauth2PermissionGrant -All | Where-Object { $_.PrincipalId -ne $null }

$FinalReport = @()

foreach ($sp in $ServicePrincipals) {
    $entry = [PSCustomObject]@{
        DisplayName               = $sp.DisplayName
        AppId                     = $sp.AppId
        ObjectId                  = $sp.Id
        UserConsentsCount         = 0
        ConsentingUsers           = [System.Collections.Generic.List[string]]::new()
        DelegatedPermissions      = [System.Collections.Generic.List[string]]::new()
        UnverifiedPublisher       = $false
        HasRiskyConsents          = $false
        RiskReasons               = [System.Collections.Generic.List[string]]::new()
        RiskyPermissionsFound     = [System.Collections.Generic.List[string]]::new()
        IsOrphaned                = $false
        HighValueUser             = $false
        HasBroadMailboxAccess     = $false
        IsDisabledApp             = $false
        IsExternalTenantApp       = $false
        HasFullAccessAsApp        = $false
        LastSignInUTC             = [System.Collections.Generic.List[string]]::new()
        CountryOfOrigin           = [System.Collections.Generic.List[string]]::new()
        UsageStatus               = ""
        OldestConsentDate         = [DateTime]::MaxValue
    }

    $consents = $UserConsents | Where-Object { $_.ClientId -eq $sp.Id }

    foreach ($consent in $consents) {
        $entry.UserConsentsCount++

        $userId = $consent.PrincipalId
        $user = $UserCache[$userId]
        $upn = if ($user) { $user.UserPrincipalName } else { "Unknown User ($userId)" }
        if (-not $entry.ConsentingUsers.Contains($upn)) { $entry.ConsentingUsers.Add($upn) }

        $scopes = $consent.Scope -split ' '
        foreach ($scope in $scopes) {
            if (-not $entry.DelegatedPermissions.Contains($scope)) {
                $entry.DelegatedPermissions.Add($scope)
            }
        }

        if (IsFlagEnabled "RiskyPermissions") {
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
                        $entry.RiskReasons.Add("Risky permission: $scope")
                    }
                }
            }
        }

        if (IsFlagEnabled "HighValueUser" -and $RoleMembers.ContainsKey($userId)) {
            $entry.HighValueUser = $true
        }

        if (IsFlagEnabled "BroadMailboxAccess") {
            $broadPerms = @("Mail.ReadWrite", "Mail.ReadWrite.Shared", "Calendars.ReadWrite", "Calendars.ReadWrite.Shared")
            foreach ($perm in $broadPerms) {
                if ($entry.DelegatedPermissions -contains $perm) {
                    $entry.HasBroadMailboxAccess = $true
                }
            }
        }

        if (IsFlagEnabled "OldestConsentDate" -and $consent.ConsentTypeDateTime -lt $entry.OldestConsentDate) {
            $entry.OldestConsentDate = $consent.ConsentTypeDateTime
        }
    }

    if (IsFlagEnabled "UnverifiedPublisher" -and -not $sp.VerifiedPublisher) {
        $entry.UnverifiedPublisher = $true
    }

    if (IsFlagEnabled "FullAccessAsApp") {
        if ($sp.RequiredResourceAccess.ResourceAccess.Id -contains "dc50a0fb-09a3-484d-be87-e023b12c6440") {
            $entry.HasFullAccessAsApp = $true
            $entry.RiskReasons.Add("Has full_access_as_app")
        }
    }

    if (IsFlagEnabled "Orphaned") {
        try {
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id
            $entry.IsOrphaned = ($owners.Count -eq 0)
        } catch {
            $entry.IsOrphaned = $true
        }
    }

    if (IsFlagEnabled "DisabledApp") {
        $entry.IsDisabledApp = ($sp.AccountEnabled -eq $false)
    }

    if (IsFlagEnabled "ExternalTenant") {
        $tenantId = (Get-MgOrganization).Id
        $entry.IsExternalTenantApp = ($sp.AppOwnerOrganizationId -ne $tenantId)
    }

    $signIn = Get-MgAuditLogSignIn -Filter "appDisplayName eq '$($sp.DisplayName)'" -Top 1
    if ($signIn) {
        $entry.LastSignInUTC.Add($signIn[0].CreatedDateTime)
    }

    if (IsFlagEnabled "UsageStatus") {
        if ($entry.LastSignInUTC.Count -eq 0) {
            $entry.UsageStatus = "Unused"
        } else {
            $entry.UsageStatus = "Active"
        }
    }

    if (IsFlagEnabled "CountryOfOrigin") {
        if ($sp.VerifiedPublisher -and $sp.VerifiedPublisher.VerifiedPublisherId) {
            $entry.CountryOfOrigin.Add("VerifiedPublisherId: $($sp.VerifiedPublisher.VerifiedPublisherId)")
        } else {
            $entry.CountryOfOrigin.Add("Unknown")
        }
    }

    # Finalize entry
    $entry.ConsentingUsers        = ($entry.ConsentingUsers | Sort-Object -Unique) -join '; '
    $entry.DelegatedPermissions   = ($entry.DelegatedPermissions | Sort-Object -Unique) -join '; '
    $entry.RiskReasons            = ($entry.RiskReasons | Sort-Object -Unique) -join '; '
    $entry.RiskyPermissionsFound  = ($entry.RiskyPermissionsFound | Sort-Object -Unique) -join '; '
    $entry.LastSignInUTC          = ($entry.LastSignInUTC | Sort-Object -Unique) -join '; '
    $entry.CountryOfOrigin        = ($entry.CountryOfOrigin | Sort-Object -Unique) -join '; '
    if (-not $entry.UsageStatus) { $entry.UsageStatus = "Unknown" }

    $FinalReport += $entry
}

# Export
$FinalReport | Export-Csv -Path $ReportPath -NoTypeInformation -Force
Write-Host "Bulk audit complete. Report saved to $ReportPath" -ForegroundColor Green
Disconnect-MgGraph
