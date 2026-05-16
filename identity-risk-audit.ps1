# Advanced Identity & Sign-In Risk Audit
# Detects risky sign-in patterns, impossible travel, and anomalous authentication

param (
    [string]$ReportPath = "$PWD\identity-risk-audit-report.csv",
    [ValidateSet("Summary", "Detailed")]$ReportFormat = "Detailed"
)

Write-Host "Starting Advanced Identity & Sign-In Risk Audit..." -ForegroundColor Cyan

# Import security signals module
$modulePath = Join-Path (Split-Path $PSCommandPath) "security-signals-detection.psm1"
Import-Module $modulePath -Force

# Ensure Microsoft Graph connection
$context = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $context) {
    Connect-MgGraph -Scopes @(
        "Application.Read.All",
        "Directory.Read.All",
        "AuditLog.Read.All"
    ) -NoWelcome
}

# get all apps
$apps = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')" | Where-Object { $_.DisplayName -notlike "Microsoft*" }

$allRiskySignIns = @()
$allUnfamiliarLocations = @()

Write-Host "`nAnalyzing $($apps.Count) applications for sign-in risk signals..." -ForegroundColor Yellow

foreach ($app in $apps) {
    Write-Host "Processing: $($app.DisplayName)" -ForegroundColor Gray
    
    # Get risky sign-ins
    $riskySignIns = Get-RiskySignInSignals -AppDisplayName $app.DisplayName
    if ($riskySignIns.Count -gt 0) {
        $allRiskySignIns += $riskySignIns
    }
    
    # Get unfamiliar location sign-ins
    $unfamiliarLocs = Get-UnfamiliarLocationSignIns -AppDisplayName $app.DisplayName
    if ($unfamiliarLocs.Count -gt 0) {
        $allUnfamiliarLocations += $unfamiliarLocs
    }
}

# Create report
$report = @()

if ($allRiskySignIns.Count -gt 0) {
    $allRiskySignIns | ForEach-Object {
        $report += [PSCustomObject]@{
            SignalType = "Risky Sign-In"
            AppDisplayName = $_.AppDisplayName
            UserId = $_.UserId
            UserPrincipalName = $_.UserPrincipalName
            IpAddress = $_.IpAddress
            Location = $_.Location
            RiskLevel = $_.RiskLevel
            RiskDetails = $_.RiskDetails -join '; '
            Timestamp = $_.Timestamp
            Severity = $_.RiskLevel -replace "^high$", "CRITICAL" -replace "^medium$", "HIGH" -replace "^low$", "MEDIUM"
        }
    }
}

if ($allUnfamiliarLocations.Count -gt 0) {
    $allUnfamiliarLocations | ForEach-Object {
        $report += [PSCustomObject]@{
            SignalType = "Unfamiliar Location Sign-In"
            AppDisplayName = ""
            UserId = ""
            UserPrincipalName = ""
            IpAddress = ""
            Location = $_.Location
            RiskLevel = "medium"
            RiskDetails = "First-time or infrequent location"
            Timestamp = $_.LastSignIn
            Severity = "MEDIUM"
        }
    }
}

if ($report.Count -eq 0) {
    Write-Host "`nNo risky sign-in signals detected." -ForegroundColor Green
} else {
    $report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "`nReport saved to $ReportPath" -ForegroundColor Green
    Write-Host "Total signals detected: $($report.Count)" -ForegroundColor Yellow
}

Disconnect-MgGraph -ErrorAction SilentlyContinue
