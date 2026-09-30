param (
    [string]$ReportPath
)

if ($global:IsGuiMode) {
    if ([string]::IsNullOrWhiteSpace($ReportPath)) {
        $ReportPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "ShadowmanBasicAudit_$(Get-Date -f 'yyyyMMdd-HHmmss').csv")
    }
} elseif ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Read-Host "Enter full path to save the report"
}

$modulePath = Join-Path (Split-Path $PSCommandPath) "security-signals-detection.psm1"
Import-Module $modulePath -Force -Global

Write-Host "Starting Basic Audit..." -ForegroundColor Cyan
Write-Host "Initializing audit environment..." -ForegroundColor Gray

$RequiredGraphScopes = @(
    "Application.Read.All",
    "Directory.Read.All",
    "DelegatedPermissionGrant.Read.All",
    "AuditLog.Read.All",
    "User.Read.All"
)

# Connect to Microsoft Graph
try {
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        Write-Host "Checking for Microsoft Graph module..." -ForegroundColor Gray
        try {
            if (Get-Module -ListAvailable -Name Microsoft.Graph) {
                Import-Module Microsoft.Graph -ErrorAction Stop
            }
            else {
                Write-Warning "Installing Microsoft.Graph module..."
                Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -Confirm:$false -ErrorAction Stop
                Import-Module Microsoft.Graph -ErrorAction Stop
            }
        }
        catch {
            Write-Error "Microsoft.Graph load failed: $($_.Exception.Message)"
            return
        }
    }

    Write-Host "Microsoft Graph module ready." -ForegroundColor Green

    $context = Get-MgContext -ErrorAction SilentlyContinue
    $missingScopes = @($RequiredGraphScopes | Where-Object { $context.Scopes -notcontains $_ })
    if ($null -eq $context -or $missingScopes.Count -gt 0) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes $RequiredGraphScopes -ErrorAction Stop
        Write-Host "Connected successfully!" -ForegroundColor Green
    }
} catch {
    Write-Error "Graph connection failed: $($_.Exception.Message)"
    return
}

# Cache Service Principals and Users
Write-Host "Caching service principals (gallery apps only)..." -ForegroundColor Gray
$ServicePrincipalCache = @{}
$UserCache = @{}

Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')" | ForEach-Object { $ServicePrincipalCache[$_.Id] = $_ }
Write-Host "Caching users..." -ForegroundColor Gray
Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName' |
    ForEach-Object { $UserCache[$_.id] = $_ }

# Get user consents
Write-Host "Retrieving user consents..." -ForegroundColor Gray
$UserConsents = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' |
    Where-Object { $_.principalId -ne $null }

# Initialize report
$ReportEntries = @{}

Write-Host "Analyzing $($UserConsents.Count) consents..." -ForegroundColor Yellow
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
    $signIn = Get-GraphSignIns -Filter "appId eq '$($sp.AppId)'" -Top 1 -Days 0 | Select-Object -First 1
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
    $tenantId = (Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/organization' | Select-Object -First 1).id
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

    $roles = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/directoryRoles' |
        Where-Object { $_.displayName -in $highRiskRoles }
    foreach ($role in $roles) {
        $members = Get-GraphCollection -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members"
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

Write-Host "Analysis complete. Generating report..." -ForegroundColor Green

# Export
Write-Host "Saving report to $ReportPath" -ForegroundColor Cyan
$FinalReport | Export-Csv -Path $ReportPath -NoTypeInformation -Force

try {
    & (Join-Path (Split-Path $PSCommandPath) "generate-html-report.ps1") -CsvPath $ReportPath
} catch {
    Write-Warning "HTML report generation failed: $($_.Exception.Message)"
}

Write-Host "Report saved to $ReportPath" -ForegroundColor Green
# Return results for GUI mode
if ($global:IsGuiMode) {
    return $FinalReport
}
