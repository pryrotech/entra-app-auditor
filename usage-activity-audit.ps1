# Usage & Activity Signals Audit
# Detects inactive high-privilege apps, usage spikes, and unusual activity patterns

param (
    [string]$ReportPath = "$PWD\usage-activity-audit-report.csv"
)

Write-Host "Starting Usage & Activity Signals Audit..." -ForegroundColor Cyan

# Import security signals module
$modulePath = Join-Path (Split-Path $PSCommandPath) "security-signals-detection.psm1"
Import-Module $modulePath -Force -Global

# Ensure Microsoft Graph connection
$context = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $context) {
    Connect-MgGraph -Scopes @(
        "Application.Read.All",
        "AuditLog.Read.All",
        "DelegatedPermissionGrant.Read.All"
    ) -NoWelcome -ErrorAction Stop
}

$report = @()

# Get inactive high-privilege apps
Write-Host "Detecting inactive high-privilege apps..." -ForegroundColor Yellow
$inactiveHighPriv = Get-InactiveHighPrivilegeApps -InactivityDays 30
foreach ($app in $inactiveHighPriv) {
    $report += [PSCustomObject]@{
        SignalType = "Inactive High-Privilege App"
        AppDisplayName = $app.DisplayName
        AppId = $app.AppId
        LastSignIn = $app.LastSignIn
        InactiveDays = $app.InactiveDays
        UsagePattern = "Inactive"
        Details = "App requires user assignment but has been inactive"
        Severity = "HIGH"
        Recommendation = "Review and disable if no longer needed"
    }
}

# Get all applications for activity analysis
$apps = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')" | Where-Object { $_.DisplayName -notlike "Microsoft*" }

Write-Host "Analyzing $($apps.Count) apps for usage patterns..." -ForegroundColor Yellow

foreach ($app in $apps) {
    Write-Host "Processing: $($app.DisplayName)" -ForegroundColor Gray
    
    # Check for usage spikes
    $spikes = Get-UnusualUsageSpikes -AppDisplayName $app.DisplayName -AppId $app.AppId
    foreach ($spike in $spikes) {
        $report += [PSCustomObject]@{
            SignalType = "Unusual Usage Spike"
            AppDisplayName = $spike.AppDisplayName
            AppId = ""
            LastSignIn = $spike.Date
            InactiveDays = ""
            UsagePattern = "Spike"
            Details = "$($spike.SpikePercentage)% increase - possible compromise"
            Severity = $spike.Severity
            Recommendation = "Investigate for potential compromise or abuse"
        }
    }
}

# Analyze high-consent, low-usage apps
Write-Host "Identifying high-consent, low-usage apps..." -ForegroundColor Yellow
$consents = Get-GraphCollection -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' |
    Where-Object { $_.principalId -ne $null }
$consentsByApp = $consents | Group-Object -Property ClientId

foreach ($clientId in $consentsByApp.Name) {
    $app = $apps | Where-Object { $_.Id -eq $clientId }
    
    if ($app) {
        $consentCount = ($consentsByApp | Where-Object { $_.Name -eq $clientId }).Count
        
        try {
            $signIns = Get-GraphSignIns -Filter "appId eq '$($app.AppId)'" -Top 1 -Days 0 | Select-Object -First 1
            
            if ($null -eq $signIns -or $consentCount -gt 10) {
                $report += [PSCustomObject]@{
                    SignalType = "High-Consent, Low-Usage App"
                    AppDisplayName = $app.DisplayName
                    AppId = $app.AppId
                    LastSignIn = if ($signIns) { $signIns.CreatedDateTime } else { "Never" }
                    InactiveDays = if ($signIns) { ((Get-Date) - $signIns.CreatedDateTime).Days } else { "N/A" }
                    UsagePattern = "Suspicious"
                    Details = "$consentCount users consented but minimal usage"
                    Severity = "MEDIUM"
                    Recommendation = "Verify app legitimacy and usage patterns"
                }
            }
        }
        catch {
            # Continue processing
        }
    }
}

if ($report.Count -eq 0) {
    Write-Host "`nNo usage/activity signals detected." -ForegroundColor Green
} else {
    Write-Host "Total signals detected: $($report.Count)" -ForegroundColor Yellow
}

$report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
try {
    & (Join-Path (Split-Path $PSCommandPath) "generate-html-report.ps1") -CsvPath $ReportPath
} catch {
    Write-Warning "HTML report generation failed: $($_.Exception.Message)"
}
Write-Host "`nReport saved to $ReportPath" -ForegroundColor Green

