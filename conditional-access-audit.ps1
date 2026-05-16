# Conditional Access Signals Audit
# Detects CA bypass patterns, non-compliant device access, and weak CA posture

param (
    [string]$ReportPath = "$PWD\conditional-access-audit-report.csv"
)

Write-Host "Starting Conditional Access Signals Audit..." -ForegroundColor Cyan

# Import security signals module
$modulePath = Join-Path (Split-Path $PSCommandPath) "security-signals-detection.psm1"
Import-Module $modulePath -Force

# Ensure Microsoft Graph connection
$context = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $context) {
    Connect-MgGraph -Scopes @(
        "Application.Read.All",
        "AuditLog.Read.All",
        "Policy.Read.All"
    ) -NoWelcome
}

$report = @()

# Get all applications
$apps = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')" | Where-Object { $_.DisplayName -notlike "Microsoft*" }

Write-Host "Analyzing $($apps.Count) apps for Conditional Access signals..." -ForegroundColor Yellow

foreach ($app in $apps) {
    Write-Host "Processing: $($app.DisplayName)" -ForegroundColor Gray
    
    # Check for CA bypass patterns
    $caBypass = Get-ConditionalAccessBypassIndicators -AppDisplayName $app.DisplayName
    foreach ($bypass in $caBypass) {
        $report += [PSCustomObject]@{
            SignalType = $bypass.SignalType
            AppDisplayName = $bypass.AppDisplayName
            Finding = $bypass.AuthProtocol
            BypassPercentage = $bypass.BypassPercentage
            Details = $bypass.Details
            Severity = $bypass.Severity
            Recommendation = "Review CA policies for legacy auth and misconfigurations"
        }
    }
    
    # Check for non-compliant device access
    $nonCompliancePatterns = Get-NonCompliantDeviceAccessPatterns -AppDisplayName $app.DisplayName
    foreach ($pattern in $nonCompliancePatterns) {
        $report += [PSCustomObject]@{
            SignalType = $pattern.PatternType
            AppDisplayName = $pattern.AppDisplayName
            Finding = "Device: $($pattern.DeviceId)"
            BypassPercentage = ""
            Details = $pattern.Details
            Severity = $pattern.Severity
            Recommendation = "Enforce device compliance policies"
        }
    }
}

# Analyze weak CA posture
Write-Host "Analyzing Conditional Access posture..." -ForegroundColor Yellow
$weakPosture = Get-WeakConditionalAccessPosture
foreach ($finding in $weakPosture) {
    $report += [PSCustomObject]@{
        SignalType = "Weak CA Posture"
        AppDisplayName = ""
        Finding = $finding.Finding
        BypassPercentage = ""
        Details = $finding.Description
        Severity = $finding.Severity
        Recommendation = $finding.Recommendation
    }
}

if ($report.Count -eq 0) {
    Write-Host "`nNo Conditional Access signals detected." -ForegroundColor Green
} else {
    $report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "`nReport saved to $ReportPath" -ForegroundColor Green
    Write-Host "Total signals detected: $($report.Count)" -ForegroundColor Yellow
}

Disconnect-MgGraph -ErrorAction SilentlyContinue
