# OAuth & Consent Signals Audit
# Detects risky consent patterns, mass consent events, and high-privilege user consents

param (
    [string]$ReportPath = "$PWD\oauth-consent-audit-report.csv"
)

Write-Host "Starting OAuth & Consent Signals Audit..." -ForegroundColor Cyan

# Import security signals module
$modulePath = Join-Path (Split-Path $PSCommandPath) "security-signals-detection.psm1"
Import-Module $modulePath -Force

# Ensure Microsoft Graph connection
$context = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $context) {
    Connect-MgGraph -Scopes @(
        "Application.Read.All",
        "Directory.Read.All",
        "DelegatedPermissionGrant.Read.All"
    ) -NoWelcome
}

# Cache high-privilege users
Write-Host "Caching high-privilege users..." -ForegroundColor Yellow
$HighPrivilegeUsers = @{}

$highRiskRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Security Administrator",
    "User Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Teams Administrator"
)

$roles = Get-MgDirectoryRole -All | Where-Object { $_.DisplayName -in $highRiskRoles }
foreach ($role in $roles) {
    try {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
        foreach ($member in $members) {
            $HighPrivilegeUsers[$member.Id] = $role.DisplayName
        }
    }
    catch {
        # Continue processing
    }
}

# Get all consent grants
Write-Host "Fetching consent grants..." -ForegroundColor Yellow
$Consents = Get-MgOauth2PermissionGrant -All | Where-Object { $_.PrincipalId -ne $null }

$report = @()

# Check for risky consent patterns
Write-Host "Analyzing risky consent patterns..." -ForegroundColor Yellow
$riskPatterns = Get-RiskyConsentPatterns -ConsentGrants $Consents
foreach ($pattern in $riskPatterns) {
    $report += [PSCustomObject]@{
        SignalType = $pattern.RiskType
        ClientId = $pattern.ClientId
        Details = $pattern.Details
        Severity = "HIGH"
        AffectedCount = $pattern.ConsentCount
        TimeframeDays = $pattern.TimeframeDays
        Recommendation = "Review app permissions and user consent"
    }
}

# Check for high-privilege user consents
Write-Host "Identifying high-privilege user consents..." -ForegroundColor Yellow
$privConsentUsers = Get-HighPrivilegeConsentUsers -ConsentGrants $Consents -HighPrivilegeUsers $HighPrivilegeUsers
foreach ($priv in $privConsentUsers) {
    $report += [PSCustomObject]@{
        SignalType = "High-Privilege User Consent"
        ClientId = $priv.ClientId
        Details = "Admin user consented to app: $($priv.Permissions)"
        Severity = "CRITICAL"
        AffectedCount = 1
        TimeframeDays = 0
        Recommendation = "Audit app legitimacy and permissions for admin consent"
    }
}

# Check for risky permission combinations
$riskPerms = @("offline_access", "Mail.ReadWrite.All"), @("offline_access", "Files.ReadWrite.All")
$consentsByApp = $Consents | Group-Object -Property ClientId

foreach ($appGroup in $consentsByApp) {
    $allPerms = ($appGroup.Group.Scope -split ' ' | Sort-Object -Unique)
    
    foreach ($combo in $riskPerms) {
        if ($combo.Count -eq ($combo | Where-Object { $allPerms -contains $_ }).Count) {
            $report += [PSCustomObject]@{
                SignalType = "High-Risk Permission Combo"
                ClientId = $appGroup.Name
                Details = "Dangerous permissions: $($combo -join ' + ')"
                Severity = "CRITICAL"
                AffectedCount = $appGroup.Count
                TimeframeDays = 0
                Recommendation = "Revoke consent or restrict permission scope"
            }
        }
    }
}

if ($report.Count -eq 0) {
    Write-Host "`nNo risky OAuth/consent signals detected." -ForegroundColor Green
} else {
    $report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "`nReport saved to $ReportPath" -ForegroundColor Green
    Write-Host "Total signals detected: $($report.Count)" -ForegroundColor Yellow
}

Disconnect-MgGraph -ErrorAction SilentlyContinue
