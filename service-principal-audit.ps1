# Service Principal Activity & Credentials Audit
# Detects unused SPs, credential anomalies, and suspicious service principal activity

param (
    [string]$ReportPath = "$PWD\service-principal-audit-report.csv",
    [int]$InactivityDays = 90
)

Write-Host "Starting Service Principal Activity & Credentials Audit..." -ForegroundColor Cyan

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

$report = @()

# Get unused service principals
Write-Host "Detecting unused/stale service principals..." -ForegroundColor Yellow
$unusedSPs = Get-UnusedServicePrincipals -InactivityDays $InactivityDays
foreach ($sp in $unusedSPs) {
    $report += [PSCustomObject]@{
        SignalType = "Unused Service Principal"
        ServPrincipalName = $sp.DisplayName
        AppId = $sp.AppId
        LastSignIn = $sp.LastSignIn
        InactiveDays = $sp.InactiveDays
        Status = $sp.Status
        HasPrivileges = $sp.HasPrivileges
        Severity = if ($sp.HasPrivileges) { "HIGH" } else { "MEDIUM" }
        Recommendation = "Review and disable if not needed"
    }
}

# Check credential status
Write-Host "Analyzing credential status..." -ForegroundColor Yellow
$servicePrincipals = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
$credStatus = Get-ServicePrincipalCredentialStatus -ServicePrincipals $servicePrincipals
foreach ($cred in $credStatus) {
    $report += [PSCustomObject]@{
        SignalType = "Multiple Active Credentials"
        ServPrincipalName = $cred.ServicePrincipalName
        AppId = ""
        LastSignIn = $cred.LastModifiedDateTime
        InactiveDays = ""
        Status = ""
        HasPrivileges = $cred.HasMultipleCredentials
        Severity = "HIGH"
        Recommendation = "Review and remove unused credentials"
    }
}

# Get credential expiration warnings
Write-Host "Checking credential expiration status..." -ForegroundColor Yellow
$expiringCreds = Get-CredentialExpirationStatus -ExpirationWarningDays 30
foreach ($cred in $expiringCreds) {
    $report += [PSCustomObject]@{
        SignalType = "Credential Expiration"
        ServPrincipalName = $cred.ServicePrincipalName
        AppId = $cred.AppId
        LastSignIn = $cred.ExpirationDate
        InactiveDays = $cred.DaysUntilExpiration
        Status = $cred.Status
        HasPrivileges = ""
        Severity = if ($cred.Status -eq "EXPIRED") { "CRITICAL" } else { "MEDIUM" }
        Recommendation = "Rotate or renew credentials"
    }
}

# Check for sudden credential replacement
Write-Host "Detecting credential replacement anomalies..." -ForegroundColor Yellow
$credAnomalies = Get-CredentialReplacementAnomalies -TimeframeHours 24
foreach ($anomaly in $credAnomalies) {
    $report += [PSCustomObject]@{
        SignalType = "Credential Replacement Anomaly"
        ServPrincipalName = $anomaly.ServicePrincipalName
        AppId = $anomaly.AppId
        LastSignIn = ""
        InactiveDays = ""
        Status = ""
        HasPrivileges = ""
        Severity = $anomaly.Severity
        Recommendation = "Investigate potential compromise"
    }
}

# Check for anomalous service principal activity
Write-Host "Detecting anomalous service principal activity..." -ForegroundColor Yellow
foreach ($sp in $servicePrincipals | Where-Object { $_.AccountEnabled -eq $true } | Select-Object -First 50) {
    $spAnomalies = Get-AnomalousServicePrincipalActivity -AppId $sp.AppId
    foreach ($anomaly in $spAnomalies) {
        $report += [PSCustomObject]@{
            SignalType = $anomaly.AnomalyType
            ServPrincipalName = ""
            AppId = $anomaly.AppId
            LastSignIn = ""
            InactiveDays = ""
            Status = ""
            HasPrivileges = ""
            Severity = "MEDIUM"
            Recommendation = $anomaly.Details
        }
    }
}

if ($report.Count -eq 0) {
    Write-Host "`nNo service principal activity signals detected." -ForegroundColor Green
} else {
    $report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "`nReport saved to $ReportPath" -ForegroundColor Green
    Write-Host "Total signals detected: $($report.Count)" -ForegroundColor Yellow
}

Disconnect-MgGraph -ErrorAction SilentlyContinue
