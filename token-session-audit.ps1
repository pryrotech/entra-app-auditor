# Token & Session Security Audit
# Detects suspicious token usage, unusual refresh patterns, and long-lived sessions

param (
    [string]$ReportPath = "$PWD\token-session-audit-report.csv"
)

Write-Host "Starting Token & Session Security Audit..." -ForegroundColor Cyan

# Import security signals module
$modulePath = Join-Path (Split-Path $PSCommandPath) "security-signals-detection.psm1"
Import-Module $modulePath -Force

# Ensure Microsoft Graph connection
$context = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $context) {
    Connect-MgGraph -Scopes @(
        "Application.Read.All",
        "AuditLog.Read.All"
    ) -NoWelcome
}

$report = @()

# Get all applications
$apps = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')" | Where-Object { $_.DisplayName -notlike "Microsoft*" }

Write-Host "Analyzing $($apps.Count) apps for token/session signals..." -ForegroundColor Yellow

foreach ($app in $apps) {
    Write-Host "Processing: $($app.DisplayName)" -ForegroundColor Gray
    
    # Check for suspicious token usage
    $tokenAnomalies = Get-SuspiciousTokenUsage -AppDisplayName $app.DisplayName
    foreach ($anomaly in $tokenAnomalies) {
        $report += [PSCustomObject]@{
            SignalType = $anomaly.AnomalyType
            AppDisplayName = $anomaly.AppDisplayName
            AppId = ""
            UserAgent = $anomaly.UserAgent
            UsageCount = $anomaly.UsageCount
            Details = $anomaly.Details
            Timestamp = ""
            Severity = "MEDIUM"
            Recommendation = "Investigate non-standard user agents"
        }
    }
    
    # Check for unusual token refresh patterns
    $refreshPatterns = Get-UnusualTokenRefreshPatterns -AppId $app.AppId
    foreach ($pattern in $refreshPatterns) {
        $report += [PSCustomObject]@{
            SignalType = "Unusual Token Refresh"
            AppDisplayName = $app.DisplayName
            AppId = $pattern.AppId
            UserAgent = ""
            UsageCount = ""
            Details = $pattern.Details
            Timestamp = ""
            Severity = "MEDIUM"
            Recommendation = "Monitor for token replay or session hijacking"
        }
    }
}

if ($report.Count -eq 0) {
    Write-Host "`nNo token/session signals detected." -ForegroundColor Green
} else {
    $report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "`nReport saved to $ReportPath" -ForegroundColor Green
    Write-Host "Total signals detected: $($report.Count)" -ForegroundColor Yellow
}

Disconnect-MgGraph -ErrorAction SilentlyContinue
