# Shadowman v2.0 - Security Signals Quick Reference

## Menu Navigation

```
Main Menu (6 options)
    │
    ├─ 1: Basic Audit
    │   └─ Historical OAuth consent audit with risky APP detection
    │
    ├─ 2: Targeted Risk Audit
    │   └─ Flag-based audit with selective signal checking
    │
    ├─ 3: Advanced Security Signals Audit
    │   │
    │   ├─ 1: Identity & Sign-In Risk Signals
    │   │   ├─ Risky sign-ins (anonymous IP, malware-linked IP)
    │   │   ├─ Impossible travel detection
    │   │   └─ Unfamiliar location sign-ins
    │   │
    │   ├─ 2: OAuth & Consent Signals
    │   │   ├─ Mass consent patterns (10+ users in 7 days)
    │   │   ├─ High-privilege user consents
    │   │   ├─ Dangerous permission combos
    │   │   └─ Risky delegated permissions
    │   │
    │   ├─ 3: Service Principal Activity
    │   │   ├─ Unused/stale SPs (90+ days)
    │   │   ├─ Multiple active credentials
    │   │   ├─ Credential expiration warnings
    │   │   └─ Anomalous activity by location/IP
    │   │
    │   ├─ 4: Token & Session Security
    │   │   ├─ Suspicious user agents
    │   │   ├─ Unusual token refresh patterns
    │   │   ├─ Long-lived sessions
    │   │   └─ Non-standard auth protocols
    │   │
    │   ├─ 5: Conditional Access Signals
    │   │   ├─ CA bypass patterns (50%+ bypass rate)
    │   │   ├─ Non-compliant device access
    │   │   ├─ Legacy auth bypass
    │   │   └─ Weak CA posture
    │   │
    │   ├─ 6: Permissions & Role Signals
    │   │   ├─ Apps with privileged roles (Global Admin, etc.)
    │   │   ├─ High-risk permissions (Mail.ReadWrite.All, etc.)
    │   │   ├─ Sensitive API access
    │   │   └─ Over-privileged apps
    │   │
    │   ├─ 7: Usage & Activity Signals
    │   │   ├─ Inactive high-privilege apps
    │   │   ├─ High-consent, low-usage apps
    │   │   ├─ Usage spikes (3x+ increase)
    │   │   └─ Sensitive endpoint access
    │   │
    │   ├─ 8: Environment & Posture Signals
    │   │   ├─ Identity Secure Score gaps
    │   │   ├─ Tenant-wide risky user activity
    │   │   ├─ Weak CA posture summary
    │   │   └─ Missing security controls
    │   │
    │   └─ 9: Run All Audits
    │       └─ Execute all 8 audits sequentially
    │
    ├─ 4: Setup Active Defense (Coming Soon)
    │
    ├─ 5: About & Help
    │
    └─ 6: Exit
```

---

## Critical Findings Checklist

### 🔴 CRITICAL - Address Immediately

- [ ] Apps with Global Administrator role
- [ ] Credentials expired (past expiration date)
- [ ] Sudden credential replacement (multiple in 24h)
- [ ] No MFA enforcement CA policy
- [ ] Legacy authentication not blocked
- [ ] 50%+ CA bypass rate on any protocol

### 🟠 HIGH - Address Within 1 Week

- [ ] Admin/executive user consented to unknown app
- [ ] App with 10+ users consenting in 7 days
- [ ] Permissions: Mail.ReadWrite.All + offline_access
- [ ] High-privilege SP unused for 90+ days
- [ ] 5+ active credentials on single app
- [ ] Usage spike of 300%+

### 🟡 MEDIUM - Address Within 2 Weeks

- [ ] Unfamiliar location sign-ins
- [ ] Non-compliant device frequent access
- [ ] High-consent, low-usage app
- [ ] Credentials expiring in 30 days
- [ ] Anomalous geographic spread of SP activity
- [ ] Insufficient CA policies (<3 active)

---

## Top 10 Risky Signals

| Rank | Signal | Detection Audit | Severity | Action |
|------|--------|-----------------|----------|--------|
| 1 | App with Global Admin role | Permissions & Role | CRITICAL | Remove role immediately |
| 2 | Expired credential | Service Principal | CRITICAL | Rotate immediately |
| 3 | Multiple credentials added (24h) | Service Principal | CRITICAL | Investigate compromise |
| 4 | No MFA enforcement policy | Environment & Posture | CRITICAL | Create CA policy |
| 5 | Legacy auth not blocked | Environment & Posture | CRITICAL | Create blocking policy |
| 6 | Admin consented to unknown app | OAuth & Consent | HIGH | Revoke consent |
| 7 | Mass consent (10+ users/7 days) | OAuth & Consent | HIGH | Review app legitimacy |
| 8 | Mail + offline_access combo | Permissions & Role | HIGH | Revoke or restrict |
| 9 | Usage spike (3x+ increase) | Usage & Activity | HIGH | Investigate for abuse |
| 10 | 50%+ CA bypass rate | Conditional Access | HIGH | Review CA policies |

---

## Remediation Quick Links

### For Each Signal Type

**Identity & Sign-In Risks**
- 👉 Enable MFA for flagged users
- 👉 Review MA properties
- 👉 Check for credential compromise

**OAuth & Consent**
- 👉 Revoke risky consents
- 👉 Require admin consent for new apps
- 👉 Review app legitimacy via AppSource/developer

**Service Principal Activity**
- 👉 Disable unused SPs
- 👉 Rotate credentials
- 👉 Set expiration dates on credentials
- 👉 Restrict by security group

**Token & Session**
- 👉 Enforce token lifetime limits
- 👉 Require device compliance
- 👉 Block legacy auth protocols

**Conditional Access**
- 👉 Add CA policies for unprotected apps
- 👉 Enforce MFA on sensitive operations
- 👉 Require compliant devices
- 👉 Block external tenant apps

**Permissions & Roles**
- 👉 Apply least privilege principle
- 👉 Remove unnecessary roles
- 👉 Use app permissions instead of delegated
- 👉 Regular scope audits

**Usage & Activity**
- 👉 Investigate usage anomalies
- 👉 Disable high-consent, low-use apps
- 👉 Monitor for trends
- 👉 Escalate suspicious patterns

**Environment & Posture**
- 👉 Create policy baseline
- 👉 Enable MFA globally
- 👉 Block legacy auth
- 👉 Implement device compliance

---

## Output Files Reference

| Command | Output File | Contains |
|---------|------------|----------|
| Identity Risk Audit | `identity-risk-audit-report.csv` | Risky sign-ins, impossible travel, unfamiliar locations |
| OAuth Consent | `oauth-consent-audit-report.csv` | Mass consent, admin consents, permission combos |
| Service Principal | `service-principal-audit-report.csv` | Unused SPs, credential status, expiration warnings |
| Token & Session | `token-session-audit-report.csv` | Suspicious tokens, refresh anomalies, long sessions |
| Conditional Access | `conditional-access-audit-report.csv` | CA bypasses, non-compliant devices, weak posture |
| Permissions & Role | `permissions-roles-audit-report.csv` | Privileged roles, risky perms, API access |
| Usage & Activity | `usage-activity-audit-report.csv` | Inactive apps, usage spikes, high-consent patterns |
| Environment Posture | `environment-posture-audit-report.csv` | Secure Score gaps, user risk, CA weaknesses |

---

## Common Remediation Workflows

### Scenario 1: Admin Consent to Risky App

1. Run: `oauth-consent-audit.ps1`
2. Find finding: "High-Privilege User Consent"
3. In Azure AD:
   - Go to: Enterprise Applications > App name
   - Click: Permissions (left menu)
   - Select: Admin consents
   - Click: Revoke admin consent
4. Request app re-review or removal

### Scenario 2: Credential Expiration Warning

1. Run: `service-principal-audit.ps1`
2. Find finding: "Credential Expiration - Warning"
3. In Azure AD:
   - Go to: App registrations > App name
   - Click: Certificates & secrets
   - Add new secret/certificate before expiration
   - Delete expired credential
4. Update systems using the credential

### Scenario 3: Usage Spike Detected

1. Run: `usage-activity-audit.ps1`
2. Find finding: "Unusual Usage Spike"
3. In Azure AD:
   - Go to: Sign-in logs
   - Filter: App name + Last 24 hours
   - Review users and IPs
   - Check for patterns (same user vs. multiple users)
4. If compromise suspected:
   - Reset affected user passwords
   - Revoke user sessions in Entra ID Protection
   - Check for data exfiltration

### Scenario 4: Weak CA Posture

1. Run: `environment-posture-audit.ps1`
2. Review findings under "Weak CA Posture"
3. Create CA policies:
   - Require MFA for all users
   - Block legacy authentication
   - Require compliant devices
   - Restrict external app access
4. Re-run audit to verify remediation

---

## Tips for Success

✅ **Do's**
- Run all audits quarterly minimum
- Archive reports for compliance
- Document all remediation actions
- Create playbooks for common findings
- Test CA policies in report-only mode first
- Train SOC/SecOps teams on signals

❌ **Don'ts**
- Don't rush to disable apps without investigation
- Don't ignore CRITICAL findings
- Don't rely solely on automated scans
- Don't skip manual investigation of anomalies
- Don't forget to test CA policy exceptions
- Don't ignore false positives - tune your CA

---

## Performance Guide

| Tenant Size | Estimated Runtime | Output Size |
|-------------|------------------|------------|
| <1000 apps | 10-15 minutes | <5 MB |
| 1000-5000 apps | 15-30 minutes | 5-20 MB |
| 5000+ apps | 30-60+ minutes | 20+ MB |

**Tip:** Run all audits during off-hours to avoid sign-in delay impact.

---

## Report Analysis Template

### For Each Report:
1. **Count Findings**: Total signals detected
2. **Severity Distribution**: Count CRITICAL/HIGH/MEDIUM/LOW
3. **Top Issues**: Sort by severity, note top 5
4. **Affected Users/Apps**: Identify at-risk accounts
5. **Patterns**: Look for correlations (same app, same user, etc.)
6. **Action Items**: Create remediation ticket for each CRITICAL

### Sample Analysis:
```
Report: identity-risk-audit-report.csv
├─ Total Findings: 12
├─ CRITICAL: 0
├─ HIGH: 3
├─ MEDIUM: 6
├─ LOW: 3
├─ Top Issue: User X from Angola (impossible travel)
├─ Affected Users: 8 unique users
└─ Action: 1 ticket for impossible travel investigation
```

---

**Version:** 2.0
**Last Updated:** 2024
**For Help:** See SECURITY-SIGNALS-GUIDE.md for detailed documentation
