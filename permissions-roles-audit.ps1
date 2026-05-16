# Permissions & Role Signals Audit
# Detects privileged role assignments, risky delegated permissions, and sensitive API access

param (
    [string]$ReportPath = "$PWD\permissions-roles-audit-report.csv"
)

Write-Host "Starting Permissions & Role Signals Audit..." -ForegroundColor Cyan

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

$report = @()

# Get privileged role assignments
Write-Host "Detecting privileged role assignments..." -ForegroundColor Yellow
$privRoleAssignments = Get-PrivilegedRoleAssignments
foreach ($assignment in $privRoleAssignments) {
    $report += [PSCustomObject]@{
        SignalType = "Privileged Role Assignment"
        AppDisplayName = $assignment.ServicePrincipalName
        AppId = $assignment.AppId
        RoleOrPermission = $assignment.PrivilegedRole
        Details = "App assigned to: $($assignment.PrivilegedRole)"
        Severity = $assignment.Severity
        Recommendation = "Review and remove unnecessary privilege elevation"
    }
}

# Get risky delegated permissions
Write-Host "Analyzing risky delegated permissions..." -ForegroundColor Yellow
$consents = Get-MgOauth2PermissionGrant -All | Where-Object { $_.PrincipalId -ne $null }
$riskPerms = Get-RiskyDelegatedPermissions -ConsentGrants $consents
foreach ($perm in $riskPerms) {
    $report += [PSCustomObject]@{
        SignalType = "Risky Delegated Permission"
        AppDisplayName = ""
        AppId = $perm.ClientId
        RoleOrPermission = $perm.Permissions
        Details = "High-risk permissions: $($perm.Permissions)"
        Severity = $perm.Severity
        Recommendation = "Restrict scope or revoke consent"
    }
}

# Get sensitive Graph API access
Write-Host "Identifying sensitive Graph API access..." -ForegroundColor Yellow
$sensitiveAccess = Get-SensitiveGraphApiUsage -ConsentGrants $consents
foreach ($access in $sensitiveAccess) {
    $report += [PSCustomObject]@{
        SignalType = "Sensitive API Access"
        AppDisplayName = ""
        AppId = $access.ClientId
        RoleOrPermission = $access.SensitiveEndpoints
        Details = "Access to sensitive endpoints: $($access.SensitiveEndpoints)"
        Severity = $access.Severity
        Recommendation = "Verify app legitimacy and limit scope"
    }
}

if ($report.Count -eq 0) {
    Write-Host "`nNo permission/role signals detected." -ForegroundColor Green
} else {
    $report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "`nReport saved to $ReportPath" -ForegroundColor Green
    Write-Host "Total signals detected: $($report.Count)" -ForegroundColor Yellow
}

Disconnect-MgGraph -ErrorAction SilentlyContinue
