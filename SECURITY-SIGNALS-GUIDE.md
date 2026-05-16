# Shadowman v2.0 - Advanced Security Signals Documentation

## Overview

Shadowman v2.0 is an enhanced Entra ID security audit tool that provides comprehensive detection and reporting of security risks across your tenant. The new "Advanced Security Signals Audit" feature enables detection of sophisticated attack indicators and risky patterns across nine critical security domains.

## New Features - Security Signals Categories

### 1. Identity & Sign-In Risk Signals
**File:** `identity-risk-audit.ps1`

Detects risky authentication patterns and anomalies:
- **Risky Sign-Ins**: Identifies sign-ins from anonymous IPs, atypical travel locations, and known malware-linked IPs
- **Impossible Travel Detection**: Flags impossible travel patterns (e.g., user in two geographic locations within an impossible timeframe)
- **Token Theft Indicators**: Detects anomalies suggesting token compromise (from Entra ID Protection)
- **Unfamiliar Location Sign-Ins**: Identifies sign-ins from new or infrequent locations

**Risk Levels:** HIGH, MEDIUM, LOW

**Remediation:**
- Enable MFA for all users
- Implement Conditional Access policies for risky sign-ins
- Educate users about phishing and credential theft

---

### 2. OAuth & Consent Signals
**File:** `oauth-consent-audit.ps1`

Analyzes OAuth consent patterns and identifies suspicious approval trends:
- **Risky Consent Patterns**: Detects mass consent events (multiple users consenting to same app within 7 days)
- **High-Privilege User Consents**: Identifies when admins consent to apps
- **Dangerous Permission Combos**: Alerts on combinations like `offline_access` + `Mail.ReadWrite.All`
- **Delegated Permission Risks**: Finds high-risk permissions that could enable data exfiltration

**Red Flags:**
- Single app getting 10+ consents in 7 days
- Admin granting permissions to unknown apps
- Apps with Mail + Calendar + Files permissions

**Remediation:**
- Require admin consent for all apps
- Implement app approval workflows
- Use CA to restrict app access

---

### 3. Service Principal Activity Signals
**File:** `service-principal-audit.ps1`

Monitors service principal (app identity) behavior and health:
- **Unused Service Principals**: Finds SPs with high privileges but no activity (90+ days)
- **Credential Management Issues**: Detects multiple active credentials (possible misuse indicator)
- **Unused Credentials**: Identifies credentials that were created but never used
- **Anomalous Geographic/IP Activity**: Detects SPs accessed from unexpected locations or IPs

**Critical Findings:**
- High-privilege SP with no sign-ins in 90 days
- 5+ active credentials for single app
- Sudden access from new geographic region

**Remediation:**
- Remove unnecessary privileges
- Rotate unused credentials
- Disable unused service principals
- Implement IP allowlisting for known workloads

---

### 4. Token & Session Security
**File:** `token-session-audit.ps1`

Detects suspicious token and session patterns:
- **Suspicious Token Usage**: Identifies non-standard user agents and bot-like behavior
- **Unusual Token Refresh Patterns**: Detects potential token replay or session hijacking
- **Long-Lived Sessions**: Identifies sessions from non-compliant devices lasting 24+ hours
- **Anomalous User Agents**: Flags requests from unknown or suspicious user agents

**Warning Signs:**
- Tokens used by bot/crawler user agents
- Frequent token refresh with long gaps
- Sessions from unmanaged devices
- Non-standard authentication protocols

**Remediation:**
- Enforce device compliance requirements
- Limit token lifetime
- Block non-standard authentication
- Enable continuous access evaluation (CAE)

---

### 5. Conditional Access Signals
**File:** `conditional-access-audit.ps1`

Analyzes Conditional Access effectiveness and bypasses:
- **CA Bypass Patterns**: Apps repeatedly bypassing CA policies (50%+ bypass rate on specific protocols)
- **Non-Compliant Device Access**: Tracks access from unmanaged/non-compliant devices
- **Legacy Auth Bypass**: Detects apps using legacy protocols to bypass CA
- **Weak CA Posture**: Identifies gaps in overall CA policy coverage

**Critical Issues:**
- No MFA enforcement policies
- Legacy auth not blocked
- No device compliance checks
- Insufficient policy coverage

**Remediation:**
- Create MFA enforcement policies
- Block legacy authentication
- Require compliant devices
- Implement grant controls for sensitive operations

---

### 6. Permissions & Role Signals
**File:** `permissions-roles-audit.ps1`

Examines dangerous permission assignments and scope creep:
- **Privileged Role Assignments**: Apps with Global Admin, Security Admin, or other critical roles
- **Risky Delegated Permissions**: High-risk combos and excessive permission scope
- **Sensitive API Access**: Apps able to access sensitive Graph endpoints
- **App Role Overprovisioning**: Apps with permissions they don't use

**High-Risk Permissions:**
- Application.ReadWrite.All
- Directory.ReadWrite.All
- User.ReadWrite.All
- Mail.ReadWrite.All
- Files.ReadWrite.All
- Policy.ReadWrite.ConditionalAccess

**Remediation:**
- Apply least privilege principle
- Use app permissions instead of delegated when possible
- Regularly audit and revoke unused permissions
- Implement permission monitoring

---

### 7. Usage & Activity Signals
**File:** `usage-activity-audit.ps1`

Detects unusual activity and usage anomalies:
- **Inactive High-Privilege Apps**: High-privilege apps not used for 30+ days
- **High-Consent, Low-Usage Apps**: Apps many users consented to but see little actual usage
- **Usage Spikes**: Sudden 3x+ increase in daily sign-ins (compromise indicator)
- **Sensitive API Endpoints**: Apps accessing sensitive Graph APIs

**Anomaly Indicators:**
- 50 users consented but no sign-ins
- 300% usage increase in single day
- Apps accessing Mail/Calendar/Files without expected usage

**Remediation:**
- Investigate usage anomalies for potential compromise
- Disable apps with high consent but no usage
- Implement usage baseline monitoring
- Flag for incident response if needed

---

### 8. Environment & Posture Signals
**File:** `environment-posture-audit.ps1`

Assesses overall tenant security posture:
- **Identity Secure Score Indicators**: MFA adoption, legacy auth protection, weak policies
- **Tenant-Wide Risky User Activity**: Users with multiple risky sign-ins (indicator of compromise)
- **Weak CA Posture**: Insufficient policies protecting critical resources
- **Missing Security Controls**: MFA not enforced, legacy auth not blocked

**Posture Findings:**
- Identity Secure Score below baseline
- 10%+ of users with risky sign-in activity
- Fewer than 3 active CA policies
- No legacy auth blocking

**Remediation:**
- Create comprehensive CA policy baseline
- Enforce MFA across organization
- Block legacy authentication
- Implement continuous monitoring

---

### 9. Comprehensive Multi-Signal Audit
**Menu Option:** "Run All Security Signals Audits"

Runs all 8 security signal audits sequentially, generating complete security report:
- Executes all audit types
- Generates 8 individual CSV reports
- Provides comprehensive security posture assessment
- Takes 10-30 minutes depending on tenant size

**Output Files:**
- `identity-risk-audit-report.csv`
- `oauth-consent-audit-report.csv`
- `service-principal-audit-report.csv`
- `token-session-audit-report.csv`
- `conditional-access-audit-report.csv`
- `permissions-roles-audit-report.csv`
- `usage-activity-audit-report.csv`
- `environment-posture-audit-report.csv`

---

## Severity Levels

All findings are categorized with severity levels:

| Level | Description | Action |
|-------|-------------|--------|
| **CRITICAL** | Immediate risk to security posture | Address immediately |
| **HIGH** | Significant risk requiring attention | Address within 1 week |
| **MEDIUM** | Notable risk for investigation | Address within 2 weeks |
| **LOW** | Minor issue for monitoring | Address as resources permit |

---

## Required Graph API Scopes

The enhanced tool requires the following Microsoft Graph scopes:

```powershell
@(
    "Application.Read.All",               # Read app registrations
    "Directory.Read.All",                 # Read directory objects
    "DelegatedPermissionGrant.Read.All",  # Read OAuth consent grants
    "AuditLog.Read.All",                  # Read audit logs for sign-ins
    "User.Read.All",                      # Read user directory
    "Policy.Read.All"                     # Read policies including CA
)
```

---

## Usage Examples

### Run Individual Audit

```powershell
# Identity & Sign-In Risk
.\identity-risk-audit.ps1

# OAuth & Consent Patterns
.\oauth-consent-audit.ps1

# Service Principal Credentials
.\service-principal-audit.ps1 -InactivityDays 60 -ReportPath "C:\reports\sp-audit.csv"
```

### Run from Main Menu

1. Launch: `.\entra-app-auditor-main.ps1`
2. Select option `3) Advanced Security Signals Audit`
3. Choose specific audit or option `9) Run All`

### Generate Compressed Report

```powershell
# Run all audits and compress reports
$reportPath = "C:\reports\security-signals-$(Get-Date -f 'yyyyMMdd')"
mkdir $reportPath -Force
$reports = Get-ChildItem *.csv
Compress-Archive -Path $reports -DestinationPath "$reportPath\shadowman-report.zip"
```

---

## Interpretation Guide

### High-Risk Findings to Prioritize

1. **Apps with privileged roles** - Can modify tenant-wide settings
2. **Unusual usage spikes** - Potential compromise or abuse
3. **High-privilege user consents** - Admin approval of risky apps
4. **Credential replacement anomalies** - Possible account compromise
5. **Weak CA posture** - Inadequate baseline security

### Investigation Process

1. **Identify** - Run relevant security signal audit
2. **Categorize** - Note severity and affected users/apps
3. **Investigate** - Check app legitimacy, consent context, usage patterns
4. **Remediate** - Revoke consent, remove privileges, or disable app
5. **Monitor** - Track changes and re-run audits periodically

---

## Troubleshooting

### Module Not Found
If you get "security-signals-detection.psm1 not found" error:
- Ensure all `.ps1` and `.psm1` files are in same directory
- Run scripts from that directory
- Check file permissions

### Graph Connection Issues
```powershell
# Disconnect and reconnect
Disconnect-MgGraph
Connect-MgGraph -Scopes @(
    "Application.Read.All",
    "Directory.Read.All",
    "DelegatedPermissionGrant.Read.All",
    "AuditLog.Read.All",
    "User.Read.All",
    "Policy.Read.All"
) -UseDeviceAuthentication
```

### Insufficient Permissions
Ensure your account has:
- Global Reader
- Security Reader
- Or Administrator role

---

## Performance Notes

- Initial run may take 10-30 minutes for large tenants (5000+ apps)
- Subsequent runs leveraging cache are faster
- Audit logs have 30-day retention - older activities unavailable
- Results depend on Azure AD audit log retention settings

---

## Version History

- **v2.0** - Added comprehensive security signals detection
  - 8 new audit categories
  - 21 detection functions
  - Advanced anomaly analysis
  
- **v1.0** - Initial release
  - Basic OAuth consent audits
  - Targeted risk assessment

---

## Support & Feedback

For issues or feature requests, please document:
1. PowerShell version: `$PSVersionTable.PSVersion`
2. Error message and stack trace
3. Tenant context (size, geography)
4. Which audit(s) affected

---

## Security Disclaimer

- This tool reads audit logs and performs analysis
- No modifications are made unless explicitly confirmed
- Review all high-severity findings before taking action
- Test in non-production environment first
- Ensure proper audit logging for compliance

---

## Best Practices

1. **Schedule Regular Audits**
   - Weekly for high-security environments
   - Monthly for standard environments
   - Archive reports for compliance

2. **Create Response Procedures**
   - Document remediation steps
   - Define escalation paths
   - Train team on findings

3. **Implement Detective Controls**
   - Set up alerts for risky sign-ins
   - Monitor CA bypasses
   - Track credential usage

4. **Enable Preventive Measures**
   - Require admin consent
   - Enforce device compliance
   - Restrict legacy auth

---

**Last Updated:** 2024
**Shadowman v2.0 - Advanced Entra ID Security Audit Tool**
