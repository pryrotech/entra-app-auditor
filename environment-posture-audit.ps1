# Environment & Posture Signals Audit
# Detects weak Identity Secure Score, risky user activity, and CA posture issues

param (
    [string]$ReportPath = "$PWD\environment-posture-audit-report.csv"
)

Write-Host "Starting Environment & Posture Signals Audit..." -ForegroundColor Cyan

# Import security signals module
$modulePath = Join-Path (Split-Path $PSCommandPath) "security-signals-detection.psm1"
Import-Module $modulePath -Force

# Ensure Microsoft Graph connection
$context = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $context) {
    Connect-MgGraph -Scopes @(
        "Application.Read.All",
        "Directory.Read.All",
        "AuditLog.Read.All",
        "Policy.Read.All"
    ) -NoWelcome
}

$report = @()

# Get Identity Secure Score indicators
Write-Host "Analyzing Identity Secure Score indicators..." -ForegroundColor Yellow
$secureScoreIndicators = Get-IdentitySecureScoreIndicators
foreach ($indicator in $secureScoreIndicators) {
    if ($indicator.Status -eq "Vulnerable" -or $indicator.Status -eq "Not Enforced") {
        $report += [PSCustomObject]@{
            SignalType = "Identity Posture Finding"
            Metric = $indicator.MetricType
            Value = $indicator.Value
            Description = $indicator.Description
            Status = $indicator.Status
            Details = ""
            Severity = "HIGH"
            Recommendation = "Implement security controls to address gaps"
        }
    }
}

# Get tenant-wide risky user activity
Write-Host "Detecting tenant-wide risky user activity..." -ForegroundColor Yellow
$riskyUsers = Get-TenantRiskyUserActivity -Days 30
foreach ($user in $riskyUsers) {
    $report += [PSCustomObject]@{
        SignalType = "Risky User Activity"
        Metric = "User Risk"
        Value = $user.UserId
        Description = "$($user.RiskySignInCount) risky sign-ins in 30 days"
        Status = "Active Risk"
        Details = "Last risky sign-in: $($user.LastRiskySignIn)"
        Severity = "HIGH"
        Recommendation = "Reset credentials and enable MFA"
    }
}

# Analyze weak Conditional Access posture
Write-Host "Analyzing Conditional Access posture..." -ForegroundColor Yellow
$weakPosture = Get-WeakConditionalAccessPosture
foreach ($finding in $weakPosture) {
    $report += [PSCustomObject]@{
        SignalType = "Weak CA Posture"
        Metric = $finding.Finding
        Value = ""
        Description = $finding.Description
        Status = "Vulnerable"
        Details = $finding.Impact
        Severity = $finding.Severity
        Recommendation = $finding.Recommendation
    }
}

# Environment health checks
Write-Host "Running environment health checks..." -ForegroundColor Yellow

try {
    # Check for disabled MFA policies
    $mfaPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
                   Where-Object { $_.GrantControls.BuiltInControls -contains "mfa" }
    
    if ($mfaPolicies.Count -eq 0) {
        $report += [PSCustomObject]@{
            SignalType = "Environment Posture"
            Metric = "MFA Enforcement"
            Value = "0 policies"
            Description = "No CA policies enforcing MFA"
            Status = "Vulnerable"
            Details = "Accounts at risk from credential compromise"
            Severity = "CRITICAL"
            Recommendation = "Create Conditional Access policy requiring MFA"
        }
    }
    
    # Check for legacy auth blocking
    $legacyAuthBlock = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
                       Where-Object { $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" }
    
    if ($legacyAuthBlock.Count -eq 0) {
        $report += [PSCustomObject]@{
            SignalType = "Environment Posture"
            Metric = "Legacy Auth Blocking"
            Value = "0 policies"
            Description = "No policies blocking legacy authentication"
            Status = "Vulnerable"
            Details = "Legacy protocols can bypass modern security"
            Severity = "CRITICAL"
            Recommendation = "Block legacy authentication via Conditional Access"
        }
    }
}
catch {
    Write-Warning "Error running environment health checks: $_"
}

if ($report.Count -eq 0) {
    Write-Host "`nNo environment/posture signals detected." -ForegroundColor Green
} else {
    $report | Export-Csv -Path $ReportPath -NoTypeInformation -Force
    Write-Host "`nReport saved to $ReportPath" -ForegroundColor Green
    Write-Host "Total signals detected: $($report.Count)" -ForegroundColor Yellow
}

Disconnect-MgGraph -ErrorAction SilentlyContinue
