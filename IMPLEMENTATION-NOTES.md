# Security Signals Detection Module - Implementation Notes

## Module Architecture

The `security-signals-detection.psm1` module provides a comprehensive library of detection functions for various security signals in Entra ID. Each function is designed to:

1. Query specific data from Microsoft Graph
2. Apply detection logic and analysis
3. Return structured findings
4. Handle errors gracefully

### Function Organization

Functions are organized into 9 signal categories:

```
security-signals-detection.psm1
├── Identity & Sign-In Risk (2 functions)
├── OAuth & Consent (2 functions)
├── Service Principal Activity (3 functions)
├── Credential & Secret (2 functions)
├── Token & Session (2 functions)
├── Conditional Access (2 functions)
├── Permission & Role (2 functions)
├── Usage & Activity (3 functions)
└── Environment & Posture (3 functions)
```

Total: 21 detection functions

---

## Function Reference

### IDENTITY & SIGN-IN RISK SIGNALS

#### `Get-RiskySignInSignals`

**Purpose:** Detects risky sign-ins based on Entra ID Protection risk classification

**Parameters:**
- `AppDisplayName` (string): Name of app to analyze

**Returns:** PSCustomObject array with properties:
- `Timestamp`: When sign-in occurred
- `UserId`: ID of user
- `UserPrincipalName`: UPN of user
- `IpAddress`: Source IP address
- `Location`: City/Country of sign-in
- `RiskLevel`: Risk level (high/medium/low)
- `RiskDetails`: Array of specific risk indicators

**Detection Logic:**
1. Query audit log sign-ins for app
2. Filter for RiskLevelAggregated = high or medium
3. Extract risk details from RiskDetail enum
4. Check for impossibleTravel, anonymousIP, maliciousIPAddress

**Graph API Used:**
```powershell
Get-MgAuditLogSignIn -Filter "appDisplayName eq '$AppDisplayName'"
```

**Example:**
```powershell
$risks = Get-RiskySignInSignals -AppDisplayName "MyApp"
$risks | Where-Object { $_.RiskLevel -eq "high" } | Export-Csv risks.csv
```

---

#### `Get-UnfamiliarLocationSignIns`

**Purpose:** Identifies sign-ins from infrequent or new locations

**Parameters:**
- `AppDisplayName` (string): Name of app
- `Days` (int): Lookback period (default: 30)

**Returns:** PSCustomObject array with properties:
- `Location`: City, Country
- `SignInCount`: Number of sign-ins from location
- `LastSignIn`: Most recent sign-in timestamp
- `Users`: Comma-separated users

**Detection Logic:**
1. Get sign-ins for last N days
2. Group by location (City, Country)
3. Filter for groups with < 3 sign-ins (infrequent)
4. Return locations sorted by frequency

**Assumption:** Locations with only 1-2 sign-ins are "unfamiliar"

**Performance Note:** Sorts all sign-ins, could be slow for high-volume apps
- Consider adding pagination for very large datasets
- May need to increase -PageSize for high-volume scenarios

---

### OAUTH & CONSENT SIGNALS

#### `Get-RiskyConsentPatterns`

**Purpose:** Detects unusual consent approval patterns and dangerous permission combinations

**Parameters:**
- `ConsentGrants` (PSCustomObject[]): Array of consent grant objects from `Get-MgOauth2PermissionGrant`

**Returns:** PSCustomObject array with properties:
- `RiskType`: Type of risk detected
- `ClientId`: App ID
- `ConsentCount`: Number of consents
- `TimeframeDays`: Detection timeframe
- `Details`: Description of finding

**Detection Logic:**

**Pattern 1: Mass Consent**
1. Filter consents from last 7 days
2. Group by ClientId
3. Flag apps with 5+ consents in 7 days
4. Return with RiskType="Mass Consent Pattern"

**Pattern 2: Risky Permission Combinations**
1. Define risky combos: [offline_access + Mail.ReadWrite.All], [offline_access + Files.ReadWrite.All]
2. For each combo, filter consents containing all permissions
3. Return matches with RiskType="High-Risk Permission Combo"

**Risk Level:** Both patterns are HIGH severity

---

#### `Get-HighPrivilegeConsentUsers`

**Purpose:** Identifies when high-privilege users grant app permissions

**Parameters:**
- `ConsentGrants` (PSCustomObject[]): Array of consent grants
- `HighPrivilegeUsers` (hashtable): Map of user IDs to roles

**Returns:** PSCustomObject array with properties:
- `PrincipalId`: User ID
- `ClientId`: App ID
- `Permissions`: Scope string
- `ConsentDate`: When consent was given
- `PrivilegeLevel`: "High" for all results
- `Details`: Description

**Detection Logic:**
1. Iterate through all consent grants
2. Check if PrincipalId exists in HighPrivilegeUsers hashtable
3. Return matches with key information

**Performance:** O(n) - single pass through consents

**Example Usage:**
```powershell
$admins = @{}
Get-MgDirectoryRole | Where-Object { $_.DisplayName -like "*Admin" } | ForEach-Object {
    Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id | ForEach-Object {
        $admins[$_.Id] = $true
    }
}
$privConsents = Get-HighPrivilegeConsentUsers -ConsentGrants $allConsents -HighPrivilegeUsers $admins
```

---

### SERVICE PRINCIPAL ACTIVITY SIGNALS

#### `Get-UnusedServicePrincipals`

**Purpose:** Finds service principals with high privileges but minimal activity

**Parameters:**
- `InactivityDays` (int): Threshold for "unused" (default: 90)

**Returns:** PSCustomObject array with properties:
- `DisplayName`: App name
- `AppId`: Application ID
- `ObjectId`: Service principal object ID
- `LastSignIn`: Last detected sign-in
- `InactiveDays`: Days since last activity
- `HasPrivileges`: Whether app requires user assignment
- `Status`: Enabled/Disabled
- `Severity`: HIGH or MEDIUM

**Detection Logic:**
1. Get all service principals with AppRoleAssignmentRequired=true OR AccountEnabled=false
2. For each SP, query latest sign-in event
3. Calculate inactivity (now - LastSignIn)
4. Flag if LastSignIn is null or > InactivityDays threshold

**Performance Notes:**
- Queries all SPs then performs sign-in check for each
- Sign-in queries use -Top 1 for efficiency
- Consider pagination for very large tenants

---

#### `Get-ServicePrincipalCredentialStatus`

**Purpose:** Detects multiple active credentials indicating potential misuse

**Parameters:**
- `ServicePrincipals` (PSCustomObject[]): Array of SP objects

**Returns:** PSCustomObject array with properties:
- `ServicePrincipalName`: App name
- `ObjectId`: SP object ID
- `PasswordCredentialCount`: Number of active passwords
- `KeyCredentialCount`: Number of certificates
- `LastModifiedDateTime`: When credentials were modified
- `HasMultipleCredentials`: Boolean flag
- `Details`: Description

**Detection Logic:**
1. Iterate through service principals
2. Count $sp.PasswordCredentials and $sp.KeyCredentials
3. Flag if total > 1 (multiple credentials)
4. Single credential is normal; multiples indicate risk

**Risk Interpretation:**
- 1 credential: Normal
- 2-3 credentials: Watch for unused ones
- 4+ credentials: Likely misconfiguration or compromise

---

#### `Get-AnomalousServicePrincipalActivity`

**Purpose:** Detects service principal access from unusual locations or IP patterns

**Parameters:**
- `AppId` (string): Application ID (not name)

**Returns:** PSCustomObject array with properties:
- `AppId`: Application ID
- `AnomalyType`: Type of anomaly detected
- `SignInLocations`: List of detected locations
- `Details`: Description
- `Severity`: MEDIUM

**Detection Logic:**

**Anomaly Type 1: Geographic Spread**
1. Get all sign-ins for app
2. Group by country
3. Count unique countries
4. Flag if > 5 countries (unusual spread)

**Anomaly Type 2: One-Off IPs**
1. Get all sign-ins
2. Group by IP address
3. Count occurrences per IP
4. Flag IPs with only 1-2 uses (rare)

**Assumptions:**
- SPs should have consistent geographic footprint
- Multiple countries from same SP is suspicious
- Single-use IPs are indicators of anomalous activity

---

### CREDENTIAL & SECRET SIGNALS

#### `Get-CredentialExpirationStatus`

**Purpose:** Detects credentials and certificates nearing or past expiration

**Parameters:**
- `ExpirationWarningDays` (int): Days to warn before expiration (default: 30)

**Returns:** PSCustomObject array with properties:
- `ServicePrincipalName`: App name
- `AppId`: Application ID
- `CredentialType`: "Password" or "Certificate"
- `KeyId`: Credential ID
- `ExpirationDate`: When credential expires
- `DaysUntilExpiration`: Days remaining
- `Status`: "Warning" or "EXPIRED"

**Detection Logic:**
1. Get all service principals
2. For each SP, check PasswordCredentials and KeyCredentials
3. For each credential:
   - If EndDateTime in future but < warning date: Status="Warning"
   - If EndDateTime in past: Status="EXPIRED"
4. Return all warn-level and expired credentials

**Example Output:**
```
AppId                                  Status    DaysUntilExpiration
-----                                  ------    -------------------
a1b2c3d4-...                          Warning   15
a1b2c3d4-...                          EXPIRED   -3
```

---

#### `Get-CredentialReplacementAnomalies`

**Purpose:** Detects sudden credential additions (possible compromise indicator)

**Parameters:**
- `TimeframeHours` (int): Detection window (default: 24)

**Returns:** PSCustomObject array with properties:
- `ServicePrincipalName`: App name
- `AppId`: Application ID
- `NewCredentialsInLast24h`: Count of new credentials
- `Details`: Description
- `Severity`: "HIGH"

**Detection Logic:**
1. Get all service principals
2. For each SP, check PasswordCredentials + KeyCredentials
3. Filter for credentials where StartDateTime > (now - TimeframeHours)
4. Flag if count > 1 (multiple added recently)

**Theory:** Multiple new credentials in 24h indicates:
- Quick response to suspected compromise
- Attacker adding backdoor credentials
- System automation issue

**Action If Found:** Immediate investigation required

---

### TOKEN & SESSION SIGNALS

#### `Get-SuspiciousTokenUsage`

**Purpose:** Identifies non-standard user agents and suspicious token patterns

**Parameters:**
- `AppDisplayName` (string): App name

**Returns:** PSCustomObject array with properties:
- `AppId`: Application ID
- `AnomalyType`: "Suspicious User Agent"
- `UserAgent`: The user agent string
- `UsageCount`: Number of uses
- `Details`: Description

**Detection Logic:**
1. Get sign-ins filtered for MFA requirement
2. Group by UserAgent
3. Detect patterns:
   - Contains "bot" or "crawler": Flag as suspicious
   - Non-standard format: Flag as suspicious
   - Known malicious patterns: Flag

**Limitations:**
- Only captures MFA-protected sign-ins
- User agent spoofing possible
- Some legitimate tools may use bot-like agents

**Example Suspicious Agents:**
- "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
- Custom bot frameworks
- Unusual combinations

---

#### `Get-UnusualTokenRefreshPatterns`

**Purpose:** Detects abnormal token refresh behavior and extended sessions

**Parameters:**
- `AppId` (string): Application ID

**Returns:** PSCustomObject array with properties:
- `UserId`: User ID
- `AppId`: Application ID
- `SessionDurationHours`: Duration between first and last activity
- `SessionCount`: Number of sign-ins in session
- `Details`: Description

**Detection Logic:**
1. Get all sign-ins for app
2. Group by UserId
3. For each user session:
   - Sort chronologically
   - Calculate time gaps between consecutive sign-ins
   - Flag if gap is 24-48 hours (unusual refresh pattern)
   - Break after first unusual pattern found per user

**Theory:** Normal refresh cycles are every few hours; 24h+ gaps indicate:
- Token replay
- Session persistence
- Compromise of refresh token

---

### CONDITIONAL ACCESS SIGNALS

#### `Get-ConditionalAccessBypassIndicators`

**Purpose:** Detects apps successfully bypassing Conditional Access policies

**Parameters:**
- `AppDisplayName` (string): App name

**Returns:** PSCustomObject array with properties:
- `AppDisplayName`: App name
- `SignalType`: "CA Bypass Pattern"
- `AuthProtocol`: Authentication protocol used
- `BypassPercentage`: Percentage of bypasses
- `Details`: Description
- `Severity`: "HIGH"

**Detection Logic:**
1. Get sign-ins for app where ConditionalAccessStatus != "Applied"
2. Group by AuthenticationProtocol
3. Calculate bypass rate: (bypassed / total) * 100
4. Flag if bypass rate > 50%

**Protocols to Monitor:**
- "legacy" - Inherent CA weakness
- "exchangeActiveSync" - Often misconfigured
- "other" - Unknown and risky

---

#### `Get-NonCompliantDeviceAccessPatterns`

**Purpose:** Identifies non-compliant or unmanaged devices accessing apps

**Parameters:**
- `AppDisplayName` (string): App name

**Returns:** PSCustomObject array with properties:
- `AppDisplayName`: App name
- `PatternType`: "Non-Compliant Device Access"
- `DeviceId`: Device object ID
- `AccessCount`: Number of access attempts
- `LastAccess`: Most recent access
- `Details`: Description
- `Severity`: "MEDIUM"

**Detection Logic:**
1. Get sign-ins where IsCompliant=false OR IsManaged=false
2. Group by DeviceId
3. Flag if AccessCount > 5 (frequent)
4. Include last access time for trend analysis

**Note:** Requires device detail data in sign-in logs

---

### PERMISSION & ROLE SIGNALS

#### `Get-PrivilegedRoleAssignments`

**Purpose:** Finds service principals with critical directory roles

**Parameters:** (None)

**Returns:** PSCustomObject array with properties:
- `ServicePrincipalName`: App name
- `AppId`: Application ID
- `ObjectId`: SP object ID
- `PrivilegedRole`: Role name
- `RoleId`: Role object ID
- `Severity`: "CRITICAL"
- `Details`: Description

**Detection Logic:**
1. Define privileged roles list
2. Get all directory roles matching list
3. For each role, get members
4. Filter for service principals only
5. Return each SP-role combination

**Privileged Roles Checked:**
- Global Administrator
- Privileged Role Administrator
- Application Administrator
- Cloud Application Administrator
- Security Administrator
- User Administrator

**Risk:** Any SP with these roles can modify entire tenant

---

#### `Get-RiskyDelegatedPermissions`

**Purpose:** Identifies delegated permissions with high-risk exposure

**Parameters:**
- `ConsentGrants` (PSCustomObject[]): Array of consent grants

**Returns:** PSCustomObject array with properties:
- `ClientId`: App ID
- `PrincipalId`: User ID
- `Permissions`: Scope string
- `ConsentDate`: When granted
- `Details`: Description
- `Severity`: "HIGH" or "MEDIUM"

**Detection Logic:**
1. Define high-risk permissions list
2. For each consent, extract scopes
3. Check if any scope is in risk list
4. Assign severity based on count (>2 = HIGH)

**High-Risk Permissions:**
- `offline_access` - Long-lived tokens
- `Mail.ReadWrite.*` - All email access
- `Calendar.ReadWrite.*` - Calendar manipulation
- `Files.ReadWrite.All` - All files
- `Directory.ReadWrite.All` - AD manipulation
- `User.ReadWrite.All` - User account manipulation
- `Group.ReadWrite.All` - Group manipulation
- `Application.ReadWrite.All` - App registration manipulation
- `Policy.ReadWrite.ConditionalAccess` - CA manipulation

---

### USAGE & ACTIVITY SIGNALS

#### `Get-InactiveHighPrivilegeApps`

**Purpose:** Finds high-privilege apps with no recent activity

**Parameters:**
- `InactivityDays` (int): Inactivity threshold (default: 30)

**Returns:** PSCustomObject array with properties:
- `DisplayName`: App name
- `AppId`: Application ID
- `ObjectId`: SP object ID
- `LastSignIn`: Last sign-in time
- `InactiveDays`: Days of inactivity
- `HasHighPrivileges`: Boolean
- `RiskLevel`: "HIGH"
- `Details`: Description

**Detection Logic:**
1. Get SPs with AppRoleAssignmentRequired=true
2. Query last sign-in for each
3. Calculate inactivity period
4. Flag if > InactivityDays or never signed in

**Risk:** High-privilege app that never runs has no use

---

#### `Get-UnusualUsageSpikes`

**Purpose:** Identifies sudden increases in app usage (possible compromise)

**Parameters:**
- `AppDisplayName` (string): App name

**Returns:** PSCustomObject array with properties:
- `AppDisplayName`: App name
- `Date`: Date of spike
- `SignInCount`: Number of sign-ins that day
- `AverageDailyCount`: Average before spike
- `SpikePercentage`: Percentage increase
- `Details`: Description
- `Severity`: "MEDIUM"

**Detection Logic:**
1. Get all sign-ins for app
2. Group by date (daily)
3. Calculate average daily sign-ins
4. Set threshold: average * 3
5. Flag days exceeding threshold
6. Calculate percentage increase

**Example:**
- Average: 10 sign-ins/day
- Threshold: 30 sign-ins/day
- Spike day: 85 sign-ins
- Percentage: (85/10)*100 - 100 = 750%

---

#### `Get-SensitiveGraphApiUsage`

**Purpose:** Flags apps with access to sensitive Microsoft Graph APIs

**Parameters:**
- `ConsentGrants` (PSCustomObject[]): Array of consent grants

**Returns:** PSCustomObject array with properties:
- `ClientId`: App ID
- `PrincipalId`: User ID
- `SensitiveEndpoints`: Endpoint list
- `ConsentDate`: When granted
- `Details`: Description
- `Severity`: "HIGH"

**Detection Logic:**
1. Define sensitive endpoints
2. For each consent, parse scopes
3. Check for sensitive endpoint matches
4. Return matches with endpoint list

**Sensitive Endpoints:**
- Mail.ReadWrite.All - All email
- Calendar.ReadWrite.All - All calendar events
- Contacts.ReadWrite.All - All contacts
- User.ReadWrite.All - All user properties
- Directory.ReadWrite.All - Full AD access
- Group.ReadWrite.All - Group management
- Application.ReadWrite.All - App management
- AuditLog.Read.All - Audit log access
- Policy.ReadWrite.ConditionalAccess - CA policy

---

### ENVIRONMENT & POSTURE SIGNALS

#### `Get-IdentitySecureScoreIndicators`

**Purpose:** Retrieves organization security posture indicators

**Parameters:** (None)

**Returns:** PSCustomObject array with properties:
- `MetricType`: Type of metric
- `Value`: Current value
- `Description`: Description
- `Status`: Status indicator

**Metrics Returned:**
1. Organization name
2. Legacy auth control (# of CA policies)
3. MFA enforcement (# of MFA policies)

**Detection Logic:**
1. Get organization details
2. Query CA policies for legacy auth blocking
3. Query CA policies for MFA enforcement
4. Return summary

---

#### `Get-TenantRiskyUserActivity`

**Purpose:** Detects users with multiple risky sign-in events

**Parameters:**
- `Days` (int): Lookback period (default: 30)

**Returns:** PSCustomObject array with properties:
- `UserId`: User ID
- `RiskySignInCount`: Number of risky sign-ins
- `LastRiskySignIn`: Most recent risky sign-in
- `TimeframeDays`: Analysis period
- `Status`: "Active Risk"
- `Details`: Description

**Detection Logic:**
1. Get sign-ins where riskLevelAggregated != "none"
2. Filter by date range
3. Group by UserId
4. Flag if count > 3 (multiple risky events)
5. Sort by count descending

---

#### `Get-WeakConditionalAccessPosture`

**Purpose:** Identifies gaps in Conditional Access policy coverage

**Parameters:** (None)

**Returns:** PSCustomObject array with properties:
- `Finding`: Name of gap
- `Description`: Description
- `Impact`: Business impact
- `Recommendation`: Remediation action
- `Severity`: CRITICAL or HIGH

**Findings Checked:**

1. **Insufficient Policies**
   - Severity: MEDIUM
   - Condition: < 3 enabled policies
   - Impact: Low baseline protection

2. **No MFA Enforcement**
   - Severity: HIGH
   - Condition: 0 policies with MFA grant control
   - Impact: Accounts vulnerable to credential compromise

3. **No Device Compliance**
   - Severity: HIGH
   - Condition: 0 policies with device compliance
   - Impact: Non-compliant devices can access

4. **Legacy Auth Not Blocked**
   - Severity: CRITICAL
   - Condition: 0 policies blocking legacy auth
   - Impact: Basic auth can bypass modern security

---

## Error Handling Patterns

All functions follow consistent error handling:

```powershell
try {
    # Main logic
    $result = Get-MgAuditLogSignIn -Filter "..."
    # Process result
    return $result
}
catch {
    Write-Warning "Error in function: $_"
    return @()  # Return empty array on error
}
```

**Pattern Benefits:**
- Permits continue processing on errors
- Non-blocking failures
- Clear error messages
- Graceful degradation

---

## Performance Optimization Tips

1. **Batch Operations**
   - Use pagination carefully
   - PageSize 999 for medium datasets
   - Reduce for very large tenants

2. **Caching**
   - Cache service principals
   - Reuse consent grant queries
   - Pre-compute user role lists

3. **Filtering**
   - Apply -Filter in Graph query when possible
   - Don't retrieve all, then filter
   - Use -Top when only sample needed

4. **Parallel Execution**
   - Individual audit scripts can run in parallel
   - Main menu runs sequentially (expected)
   - Background jobs possible with careful scoping

---

## Extension Points

To add new detection functions:

1. **Create Function**
   ```powershell
   function Get-MySignal {
       param([string]$Parameter)
       try {
           # Logic here
           return $results
       }
       catch {
           Write-Warning "Error: $_"
           return @()
       }
   }
   ```

2. **Add to Export List**
   ```powershell
   Export-ModuleMember -Function @(
       'Get-MySignal'
   )
   ```

3. **Create Audit Script**
   ```powershell
   $modulePath = Join-Path (Split-Path $PSCommandPath) "security-signals-detection.psm1"
   Import-Module $modulePath
   
   $signals = Get-MySignal -Parameter "value"
   $signals | Export-Csv $ReportPath
   ```

4. **Add to Main Menu**
   Update `entra-app-auditor-main.ps1` menu

---

## Testing Recommendations

1. **In Development Tenant**
   - Test with known risky apps
   - Verify detection accuracy
   - Check performance impact

2. **Manual Verification**
   - Compare results to Graph explorer
   - Spot-check high-priority findings
   - Validate thresholds

3. **False Positive Testing**
   - Test legitimate scenarios
   - Ensure low false positive rate
   - Document exceptions

---

**Version:** 2.0
**Last Updated:** 2024
