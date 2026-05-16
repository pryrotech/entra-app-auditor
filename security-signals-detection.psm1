# Security Signals Detection Module
# Comprehensive detection functions for Entra ID security signals

<#
    This module provides functions for detecting various security signals in Entra ID:
    - Identity & Sign-in Risk Signals
    - OAuth & Consent Signals
    - Service Principal Activity Signals
    - Credential & Secret Signals
    - Token & Session Signals
    - Conditional Access Signals
    - Permission & Role Signals
    - Usage & Activity Signals
    - Environment & Posture Signals
#>

# ========== IDENTITY & SIGN-IN RISK SIGNALS ==========

function Get-RiskySignInSignals {
    <#
    .SYNOPSIS
        Detects risky sign-in patterns and anomalies
    .OUTPUTS
        PSCustomObject with risky sign-in details
    #>
    param(
        [string]$AppDisplayName
    )
    
    $riskSignals = @()
    
    try {
        # Get sign-in logs for the app
        $signIns = Get-MgAuditLogSignIn -Filter "appDisplayName eq '$AppDisplayName'" -All -PageSize 999 -ErrorAction SilentlyContinue
        
        foreach ($signIn in $signIns) {
            $riskDetails = @{
                Timestamp = $signIn.CreatedDateTime
                UserId = $signIn.UserId
                UserPrincipalName = $signIn.UserPrincipalName
                IpAddress = $signIn.IpAddress
                Location = $signIn.Location.City + ", " + $signIn.Location.CountryOrRegion
                RiskLevel = $signIn.RiskLevelAggregated
                RiskDetails = @()
            }
            
            # Check for risk indicators
            if ($signIn.RiskLevelAggregated -in @("high", "medium")) {
                $riskDetails.RiskDetails += "Risk Level: $($signIn.RiskLevelAggregated)"
            }
            
            # Check for impossible travel
            if ($signIn.RiskDetail -contains "impossibleTravel") {
                $riskDetails.RiskDetails += "Impossible travel detected"
            }
            
            # Anonymous IP detection
            if ($signIn.RiskDetail -contains "anonymousIP") {
                $riskDetails.RiskDetails += "Anonymous IP used"
            }
            
            # Malware-linked IP
            if ($signIn.RiskDetail -contains "maliciousIPAddress") {
                $riskDetails.RiskDetails += "Malware-linked IP detected"
            }
            
            if ($riskDetails.RiskDetails.Count -gt 0) {
                $riskSignals += [PSCustomObject]$riskDetails
            }
        }
    }
    catch {
        Write-Warning "Error fetching sign-in logs for $AppDisplayName : $_"
    }
    
    return $riskSignals
}

function Get-UnfamiliarLocationSignIns {
    <#
    .SYNOPSIS
        Detects sign-ins from unfamiliar locations
    #>
    param(
        [string]$AppDisplayName,
        [int]$Days = 30
    )
    
    $unfamiliarSignIns = @()
    $startDate = (Get-Date).AddDays(-$Days)
    
    try {
        $signIns = Get-MgAuditLogSignIn -Filter "appDisplayName eq '$AppDisplayName' and CreatedDateTime gt $startDate" -All -PageSize 999 -ErrorAction SilentlyContinue | 
                   Sort-Object CreatedDateTime -Descending
        
        $uniqueLocations = $signIns | Group-Object -Property { "$($_.Location.City), $($_.Location.CountryOrRegion)" } | 
                          Where-Object { $_.Count -lt 3 } # Locations with fewer than 3 sign-ins
        
        foreach ($location in $uniqueLocations) {
            $unfamiliarSignIns += [PSCustomObject]@{
                Location = $location.Name
                SignInCount = $location.Count
                LastSignIn = ($location.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
                Users = ($location.Group.UserPrincipalName | Sort-Object -Unique) -join '; '
            }
        }
    }
    catch {
        Write-Warning "Error detecting unfamiliar locations: $_"
    }
    
    return $unfamiliarSignIns
}

# ========== OAUTH & CONSENT SIGNALS ==========

function Get-RiskyConsentPatterns {
    <#
    .SYNOPSIS
        Detects risky or unusual consent patterns
    #>
    param(
        [PSCustomObject[]]$ConsentGrants
    )
    
    $riskPatterns = @()
    
    # Mass consent to new app (multiple users consenting to same app in short timeframe)
    $recentConsents = $ConsentGrants | Where-Object { $_.ConsentTypeDateTime -gt (Get-Date).AddDays(-7) }
    $massConsentApps = $recentConsents | Group-Object -Property ClientId | Where-Object { $_.Count -gt 5 }
    
    foreach ($app in $massConsentApps) {
        $riskPatterns += [PSCustomObject]@{
            RiskType = "Mass Consent Pattern"
            ClientId = $app.Name
            ConsentCount = $app.Count
            TimeframeDays = 7
            Details = "Multiple users consenting to this app in a 7-day window"
        }
    }
    
    # High-risk permission combinations
    $riskPermCombos = @(
        @("offline_access", "Mail.ReadWrite.All"),
        @("offline_access", "Files.ReadWrite.All"),
        @("offline_access", "Directory.Read.All", "Mail.ReadWrite.All")
    )
    
    foreach ($combo in $riskPermCombos) {
        $matching = $ConsentGrants | Where-Object {
            $scopes = $_.Scope -split ' '
            ($combo | Where-Object { $scopes -contains $_ }).Count -eq $combo.Count
        }
        
        foreach ($grant in $matching) {
            $riskPatterns += [PSCustomObject]@{
                RiskType = "High-Risk Permission Combo"
                ClientId = $grant.ClientId
                Permissions = ($grant.Scope -split ' ') -join '; '
                Details = "Dangerous permission combination detected: $($combo -join ' + ')"
            }
        }
    }
    
    return $riskPatterns
}

function Get-HighPrivilegeConsentUsers {
    <#
    .SYNOPSIS
        Identifies consent from high-privilege users (admins, executives)
    #>
    param(
        [PSCustomObject[]]$ConsentGrants,
        [hashtable]$HighPrivilegeUsers
    )
    
    $results = @()
    
    foreach ($grant in $ConsentGrants) {
        if ($HighPrivilegeUsers.ContainsKey($grant.PrincipalId)) {
            $results += [PSCustomObject]@{
                PrincipalId = $grant.PrincipalId
                ClientId = $grant.ClientId
                Permissions = $grant.Scope
                ConsentDate = $grant.ConsentTypeDateTime
                PrivilegeLevel = "High"
                Details = "High-privilege user granted sensitive permissions"
            }
        }
    }
    
    return $results
}

# ========== SERVICE PRINCIPAL ACTIVITY SIGNALS ==========

function Get-UnusedServicePrincipals {
    <#
    .SYNOPSIS
        Detects unused or stale service principals with high privileges
    #>
    param(
        [int]$InactivityDays = 90
    )
    
    $unused = @()
    $inactivityThreshold = (Get-Date).AddDays(-$InactivityDays)
    
    try {
        $servicePrincipals = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')" | Where-Object { 
            $_.AppRoleAssignmentRequired -eq $true -or 
            $_.AccountEnabled -eq $false 
        }
        
        foreach ($sp in $servicePrincipals) {
            try {
                $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$($sp.AppId)'" -Top 1 -ErrorAction SilentlyContinue
                
                if ($null -eq $signIns -or $signIns.CreatedDateTime -lt $inactivityThreshold) {
                    $unused += [PSCustomObject]@{
                        DisplayName = $sp.DisplayName
                        AppId = $sp.AppId
                        ObjectId = $sp.Id
                        LastSignIn = if ($signIns) { $signIns.CreatedDateTime } else { "Never" }
                        InactiveDays = if ($signIns) { ((Get-Date) - $signIns.CreatedDateTime).Days } else { "N/A" }
                        HasPrivileges = $sp.AppRoleAssignmentRequired
                        Status = if ($sp.AccountEnabled) { "Enabled" } else { "Disabled" }
                    }
                }
            }
            catch {
                # Continue processing other SPs
            }
        }
    }
    catch {
        Write-Warning "Error detecting unused service principals: $_"
    }
    
    return $unused
}

function Get-ServicePrincipalCredentialStatus {
    <#
    .SYNOPSIS
        Detects apps with credentials that have never been used or are unused
    #>
    param(
        [PSCustomObject[]]$ServicePrincipals
    )
    
    $credentialStatus = @()
    
    foreach ($sp in $ServicePrincipals) {
        if ($sp.PasswordCredentials.Count -gt 0 -or $sp.KeyCredentials.Count -gt 0) {
            $credentialStatus += [PSCustomObject]@{
                ServicePrincipalName = $sp.DisplayName
                ObjectId = $sp.Id
                PasswordCredentialCount = $sp.PasswordCredentials.Count
                KeyCredentialCount = $sp.KeyCredentials.Count
                LastModifiedDateTime = $sp.PasswordCredentials.CustomKeyIdentifier | Select-Object -First 1
                HasMultipleCredentials = (($sp.PasswordCredentials.Count + $sp.KeyCredentials.Count) -gt 1)
                Details = "Multiple active credentials detected - possible misuse"
            }
        }
    }
    
    return $credentialStatus
}

function Get-AnomalousServicePrincipalActivity {
    <#
    .SYNOPSIS
        Detects service principal activity from unexpected IPs or geographies
    #>
    param(
        [string]$AppId
    )
    
    $anomalies = @()
    
    try {
        $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$AppId'" -All -PageSize 999 -ErrorAction SilentlyContinue
        
        $locationGroups = $signIns | Group-Object -Property { "$($_.Location.City), $($_.Location.CountryOrRegion)" }
        
        $geographySpread = $signIns | Group-Object -Property { $_.Location.CountryOrRegion } | Measure-Object | Select-Object -ExpandProperty Count
        
        if ($geographySpread -gt 5) {
            $anomalies += [PSCustomObject]@{
                AppId = $AppId
                AnomalyType = "Unusual Geographic Spread"
                SignInLocations = ($locationGroups | Select-Object -ExpandProperty Name) -join '; '
                Details = "Service principal accessed from $geographySpread different countries"
            }
        }
        
        # Detect unusual IPs
        $ipCounts = $signIns | Group-Object -Property IpAddress | Sort-Object Count
        $rareIps = $ipCounts | Where-Object { $_.Count -lt 2 }
        
        if ($rareIps.Count -gt 0) {
            $anomalies += [PSCustomObject]@{
                AppId = $AppId
                AnomalyType = "One-off IP Usage"
                RareIpCount = $rareIps.Count
                Details = "$($rareIps.Count) IP addresses used only once"
            }
        }
    }
    catch {
        Write-Warning "Error detecting anomalous SP activity: $_"
    }
    
    return $anomalies
}

# ========== CREDENTIAL & SECRET SIGNALS ==========

function Get-CredentialExpirationStatus {
    <#
    .SYNOPSIS
        Detects credentials and certificates nearing expiration
    #>
    param(
        [int]$ExpirationWarningDays = 30
    )
    
    $expiringCredentials = @()
    $warningDate = (Get-Date).AddDays($ExpirationWarningDays)
    
    try {
        $servicePrincipals = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
        
        foreach ($sp in $servicePrincipals) {
            # Check password credentials
            foreach ($cred in $sp.PasswordCredentials) {
                if ($cred.EndDateTime -lt $warningDate -and $cred.EndDateTime -gt (Get-Date)) {
                    $expiringCredentials += [PSCustomObject]@{
                        ServicePrincipalName = $sp.DisplayName
                        AppId = $sp.AppId
                        CredentialType = "Password"
                        KeyId = $cred.KeyId
                        ExpirationDate = $cred.EndDateTime
                        DaysUntilExpiration = [Math]::Ceiling(($cred.EndDateTime - (Get-Date)).TotalDays)
                        Status = "Warning"
                    }
                }
                elseif ($cred.EndDateTime -lt (Get-Date)) {
                    $expiringCredentials += [PSCustomObject]@{
                        ServicePrincipalName = $sp.DisplayName
                        AppId = $sp.AppId
                        CredentialType = "Password"
                        KeyId = $cred.KeyId
                        ExpirationDate = $cred.EndDateTime
                        DaysUntilExpiration = 0
                        Status = "EXPIRED"
                    }
                }
            }
            
            # Check key credentials (certificates)
            foreach ($cert in $sp.KeyCredentials) {
                if ($cert.EndDateTime -lt $warningDate -and $cert.EndDateTime -gt (Get-Date)) {
                    $expiringCredentials += [PSCustomObject]@{
                        ServicePrincipalName = $sp.DisplayName
                        AppId = $sp.AppId
                        CredentialType = "Certificate"
                        KeyId = $cert.KeyId
                        ExpirationDate = $cert.EndDateTime
                        DaysUntilExpiration = [Math]::Ceiling(($cert.EndDateTime - (Get-Date)).TotalDays)
                        Status = "Warning"
                    }
                }
                elseif ($cert.EndDateTime -lt (Get-Date)) {
                    $expiringCredentials += [PSCustomObject]@{
                        ServicePrincipalName = $sp.DisplayName
                        AppId = $sp.AppId
                        CredentialType = "Certificate"
                        KeyId = $cert.KeyId
                        ExpirationDate = $cert.EndDateTime
                        DaysUntilExpiration = 0
                        Status = "EXPIRED"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error checking credential expiration: $_"
    }
    
    return $expiringCredentials
}

function Get-CredentialReplacementAnomalies {
    <#
    .SYNOPSIS
        Detects sudden credential replacement (possible compromise)
    #>
    param(
        [int]$TimeframeHours = 24
    )
    
    $anomalies = @()
    $timeframeStart = (Get-Date).AddHours(-$TimeframeHours)
    
    try {
        $servicePrincipals = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
        
        foreach ($sp in $servicePrincipals) {
            $recentCredentials = @()
            
            foreach ($cred in $sp.PasswordCredentials) {
                if ($cred.StartDateTime -gt $timeframeStart) {
                    $recentCredentials += $cred
                }
            }
            
            foreach ($cert in $sp.KeyCredentials) {
                if ($cert.StartDateTime -gt $timeframeStart) {
                    $recentCredentials += $cert
                }
            }
            
            if ($recentCredentials.Count -gt 1) {
                $anomalies += [PSCustomObject]@{
                    ServicePrincipalName = $sp.DisplayName
                    AppId = $sp.AppId
                    NewCredentialsInLast24h = $recentCredentials.Count
                    Details = "Multiple credentials added recently - possible compromise investigation needed"
                    Severity = "HIGH"
                }
            }
        }
    }
    catch {
        Write-Warning "Error detecting credential replacement anomalies: $_"
    }
    
    return $anomalies
}

# ========== TOKEN & SESSION SIGNALS ==========

function Get-SuspiciousTokenUsage {
    <#
    .SYNOPSIS
        Detects suspicious token usage patterns
    #>
    param(
        [string]$AppDisplayName
    )
    
    $anomalies = @()
    
    try {
        $signIns = Get-MgAuditLogSignIn -Filter "appDisplayName eq '$AppDisplayName'" -All -PageSize 999 -ErrorAction SilentlyContinue | 
                   Where-Object { $_.AuthenticationRequirement -eq "multiFactorAuthentication" }
        
        # Check for unusual user agents
        $userAgents = $signIns | Group-Object -Property UserAgent | Where-Object { $_.Count -gt 1 }
        
        foreach ($agent in $userAgents) {
            if ($agent.Name -like "*bot*" -or $agent.Name -like "*crawler*" -or $agent.Name -match "suspicious") {
                $anomalies += [PSCustomObject]@{
                    AppDisplayName = $AppDisplayName
                    AnomalyType = "Suspicious User Agent"
                    UserAgent = $agent.Name
                    UsageCount = $agent.Count
                    Details = "Non-standard user agent detected"
                }
            }
        }
    }
    catch {
        Write-Warning "Error detecting suspicious token usage: $_"
    }
    
    return $anomalies
}

function Get-UnusualTokenRefreshPatterns {
    <#
    .SYNOPSIS
        Detects unusual token refresh patterns and long-lived sessions
    #>
    param(
        [string]$AppId
    )
    
    $patterns = @()
    
    try {
        $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$AppId'" -All -PageSize 999 -ErrorAction SilentlyContinue |
                   Sort-Object CreatedDateTime
        
        # Identify sessions with multiple sign-ins from same user in short timeframe
        $signInsByUser = $signIns | Group-Object -Property UserId
        
        foreach ($userSessions in $signInsByUser) {
            $sessions = $userSessions.Group | Sort-Object CreatedDateTime
            for ($i = 0; $i -lt $sessions.Count - 1; $i++) {
                $timeDiff = ($sessions[$i + 1].CreatedDateTime - $sessions[$i].CreatedDateTime).TotalHours
                
                if ($timeDiff -gt 24 -and $timeDiff -lt 48) {
                    $patterns += [PSCustomObject]@{
                        UserId = $userSessions.Name
                        AppId = $AppId
                        SessionDurationHours = $timeDiff
                        SessionCount = $sessions.Count
                        Details = "Long-lived session or unusual refresh pattern detected"
                    }
                    break
                }
            }
        }
    }
    catch {
        Write-Warning "Error detecting unusual token refresh patterns: $_"
    }
    
    return $patterns
}

# ========== CONDITIONAL ACCESS SIGNALS ==========

function Get-ConditionalAccessBypassIndicators {
    <#
    .SYNOPSIS
        Detects apps bypassing Conditional Access due to legacy auth or misconfigurations
    #>
    param(
        [string]$AppDisplayName
    )
    
    $indicators = @()
    
    try {
        $signIns = Get-MgAuditLogSignIn -Filter "appDisplayName eq '$AppDisplayName'" -All -PageSize 999 -ErrorAction SilentlyContinue |
                   Where-Object { $_.ConditionalAccessStatus -ne "Applied" }
        
        $conversionRates = $signIns | Group-Object -Property AuthenticationProtocol | ForEach-Object {
            [PSCustomObject]@{
                Protocol = $_.Name
                Count = $_.Count
                BypassRate = (($_ | Where-Object { $_.ConditionalAccessStatus -ne "Applied" }).Count / $_.Count * 100)
            }
        }
        
        foreach ($protocol in $conversionRates) {
            if ($protocol.BypassRate -gt 50) {
                $indicators += [PSCustomObject]@{
                    AppDisplayName = $AppDisplayName
                    SignalType = "CA Bypass Pattern"
                    AuthProtocol = $protocol.Protocol
                    BypassPercentage = [Math]::Round($protocol.BypassRate, 2)
                    Details = "App frequently bypasses Conditional Access - possible legacy auth or misconfiguration"
                    Severity = "HIGH"
                }
            }
        }
    }
    catch {
        Write-Warning "Error detecting CA bypass indicators: $_"
    }
    
    return $indicators
}

function Get-NonCompliantDeviceAccessPatterns {
    <#
    .SYNOPSIS
        Detects apps attempting access from non-compliant or unmanaged devices
    #>
    param(
        [string]$AppDisplayName
    )
    
    $patterns = @()
    
    try {
        $signIns = Get-MgAuditLogSignIn -Filter "appDisplayName eq '$AppDisplayName'" -All -PageSize 999 -ErrorAction SilentlyContinue |
                   Where-Object { $_.DeviceDetail.IsCompliant -eq $false -or $_.DeviceDetail.IsManaged -eq $false }
        
        $deviceNonCompliance = $signIns | Group-Object -Property { $_.DeviceDetail.DeviceId } | ForEach-Object {
            [PSCustomObject]@{
                DeviceId = $_.Name
                NonCompliantAccessCount = $_.Count
                LastAccess = ($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
                Devices = ($_.Group | Select-Object -ExpandProperty DeviceDetail).DisplayName | Sort-Object -Unique
            }
        }
        
        foreach ($device in $deviceNonCompliance) {
            if ($device.NonCompliantAccessCount -gt 5) {
                $patterns += [PSCustomObject]@{
                    AppDisplayName = $AppDisplayName
                    PatternType = "Non-Compliant Device Access"
                    DeviceId = $device.DeviceId
                    AccessCount = $device.NonCompliantAccessCount
                    LastAccess = $device.LastAccess
                    Details = "Non-compliant device accessing this app frequently"
                    Severity = "MEDIUM"
                }
            }
        }
    }
    catch {
        Write-Warning "Error detecting non-compliant device patterns: $_"
    }
    
    return $patterns
}

# ========== PERMISSION & ROLE SIGNALS ==========

function Get-PrivilegedRoleAssignments {
    <#
    .SYNOPSIS
        Identifies apps assigned to privileged directory roles
    #>
    
    $assignments = @()
    
    try {
        $privilegedRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "Application Administrator",
            "Cloud Application Administrator",
            "Security Administrator",
            "User Administrator"
        )
        
        $roles = Get-MgDirectoryRole -All | Where-Object { $_.DisplayName -in $privilegedRoles }
        
        foreach ($role in $roles) {
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                
                foreach ($member in $members) {
                    if ($member.AdditionalProperties["@odata.type"] -like "*servicePrincipal*") {
                        $sp = Get-MgServicePrincipal -ServicePrincipalId $member.Id -ErrorAction SilentlyContinue
                        
                        if ($sp) {
                            $assignments += [PSCustomObject]@{
                                ServicePrincipalName = $sp.DisplayName
                                AppId = $sp.AppId
                                ObjectId = $sp.Id
                                PrivilegedRole = $role.DisplayName
                                RoleId = $role.Id
                                Severity = "CRITICAL"
                                Details = "App assigned to highly privileged role"
                            }
                        }
                    }
                }
            }
            catch {
                # Continue processing other roles
            }
        }
    }
    catch {
        Write-Warning "Error detecting privileged role assignments: $_"
    }
    
    return $assignments
}

function Get-RiskyDelegatedPermissions {
    <#
    .SYNOPSIS
        Identifies delegated permissions with high risk (e.g., offline_access + Mail.ReadWrite)
    #>
    param(
        [PSCustomObject[]]$ConsentGrants
    )
    
    $riskPermissions = @()
    
    $highRiskPermissions = @(
        "offline_access",
        "Mail.ReadWrite",
        "Mail.ReadWrite.All",
        "Calendar.ReadWrite",
        "Calendar.ReadWrite.All",
        "Files.ReadWrite.All",
        "Directory.ReadWrite.All",
        "Directory.Read.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Application.ReadWrite.All"
    )
    
    foreach ($grant in $ConsentGrants) {
        $grantScopes = $grant.Scope -split ' '
        $foundRiskPermissions = @()
        
        foreach ($perm in $grantScopes) {
            if ($perm -in $highRiskPermissions) {
                $foundRiskPermissions += $perm
            }
        }
        
        if ($foundRiskPermissions.Count -gt 0) {
            $riskPermissions += [PSCustomObject]@{
                ClientId = $grant.ClientId
                PrincipalId = $grant.PrincipalId
                Permissions = ($foundRiskPermissions) -join '; '
                ConsentDate = $grant.ConsentTypeDateTime
                Details = "High-risk delegated permissions detected"
                Severity = if ($foundRiskPermissions.Count -gt 2) { "HIGH" } else { "MEDIUM" }
            }
        }
    }
    
    return $riskPermissions
}

# ========== USAGE & ACTIVITY SIGNALS ==========

function Get-InactiveHighPrivilegeApps {
    <#
    .SYNOPSIS
        Identifies apps with no sign-ins in 30/60/90 days but high privileges
    #>
    param(
        [int]$InactivityDays = 30
    )
    
    $apps = @()
    $inactivityThreshold = (Get-Date).AddDays(-$InactivityDays)
    
    try {
        $servicePrincipals = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')" | Where-Object { 
            $_.AppRoleAssignmentRequired -eq $true 
        }
        
        foreach ($sp in $servicePrincipals) {
            try {
                $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$($sp.AppId)'" -Top 1 -ErrorAction SilentlyContinue
                
                if ($null -eq $signIns -or $signIns.CreatedDateTime -lt $inactivityThreshold) {
                    $apps += [PSCustomObject]@{
                        DisplayName = $sp.DisplayName
                        AppId = $sp.AppId
                        ObjectId = $sp.Id
                        LastSignIn = if ($signIns) { $signIns.CreatedDateTime } else { "Never" }
                        InactiveDays = if ($signIns) { ((Get-Date) - $signIns.CreatedDateTime).Days } else { "N/A" }
                        HasHighPrivileges = $true
                        RiskLevel = "HIGH"
                        Details = "App requires user assignment but has been inactive"
                    }
                }
            }
            catch {
                # Continue processing other apps
            }
        }
    }
    catch {
        Write-Warning "Error detecting inactive high-privilege apps: $_"
    }
    
    return $apps
}

function Get-UnusualUsageSpikes {
    <#
    .SYNOPSIS
        Identifies apps with sudden spikes in usage indicating potential compromise
    #>
    param(
        [string]$AppDisplayName
    )
    
    $spikes = @()
    
    try {
        $signIns = Get-MgAuditLogSignIn -Filter "appDisplayName eq '$AppDisplayName'" -All -PageSize 999 -ErrorAction SilentlyContinue |
                   Sort-Object CreatedDateTime
        
        if ($signIns.Count -gt 10) {
            # Group by day
            $dailySignIns = $signIns | Group-Object -Property { $_.CreatedDateTime.Date } | ForEach-Object {
                [PSCustomObject]@{
                    Date = $_.Name
                    SignInCount = $_.Count
                }
            } | Sort-Object Date
            
            # Calculate average
            $avgPerDay = ($dailySignIns | Measure-Object -Property SignInCount -Average).Average
            $threshold = $avgPerDay * 3
            
            foreach ($day in $dailySignIns) {
                if ($day.SignInCount -gt $threshold) {
                    $spikes += [PSCustomObject]@{
                        AppDisplayName = $AppDisplayName
                        Date = $day.Date
                        SignInCount = $day.SignInCount
                        AverageDailyCount = [Math]::Round($avgPerDay, 2)
                        SpikePercentage = [Math]::Round(($day.SignInCount / $avgPerDay * 100) - 100, 2)
                        Details = "Unusual spike in app usage - possible compromise"
                        Severity = "MEDIUM"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error detecting usage spikes: $_"
    }
    
    return $spikes
}

function Get-SensitiveGraphApiUsage {
    <#
    .SYNOPSIS
        Identifies apps accessing sensitive Graph endpoints
    #>
    param(
        [PSCustomObject[]]$ConsentGrants
    )
    
    $sensitiveUsage = @()
    
    $sensitiveEndpoints = @(
        "Mail.ReadWrite.All",
        "Calendar.ReadWrite.All",
        "Contacts.ReadWrite.All",
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",
        "Group.ReadWrite.All",
        "Application.ReadWrite.All",
        "AuditLog.Read.All",
        "Policy.ReadWrite.ConditionalAccess"
    )
    
    foreach ($grant in $ConsentGrants) {
        $grantScopes = $grant.Scope -split ' '
        $accessedSensitive = @()
        
        foreach ($scope in $grantScopes) {
            if ($scope -in $sensitiveEndpoints) {
                $accessedSensitive += $scope
            }
        }
        
        if ($accessedSensitive.Count -gt 0) {
            $sensitiveUsage += [PSCustomObject]@{
                ClientId = $grant.ClientId
                PrincipalId = $grant.PrincipalId
                SensitiveEndpoints = ($accessedSensitive) -join '; '
                ConsentDate = $grant.ConsentTypeDateTime
                Details = "App has access to sensitive Graph APIs"
                Severity = "HIGH"
            }
        }
    }
    
    return $sensitiveUsage
}

# ========== ENVIRONMENT & POSTURE SIGNALS ==========

function Get-IdentitySecureScoreIndicators {
    <#
    .SYNOPSIS
        Retrieves Identity Secure Score indicators (MFA, legacy auth, weak policies)
    #>
    
    $indicators = @()
    
    try {
        $org = Get-MgOrganization -All | Select-Object -First 1
        
        $indicators += [PSCustomObject]@{
            MetricType = "Organization Details"
            Value = $org.DisplayName
            Description = "Tenant Name"
        }
        
        # Check for legacy authentication policies
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" }
        
        $indicators += [PSCustomObject]@{
            MetricType = "Legacy Auth Control"
            Value = $policies.Count
            Description = "Conditional Access policies blocking legacy auth"
            Status = if ($policies.Count -gt 0) { "Protected" } else { "Vulnerable" }
        }
        
        # MFA indicators
        $mfaPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
                       Where-Object { $_.GrantControls.BuiltInControls -contains "mfa" }
        
        $indicators += [PSCustomObject]@{
            MetricType = "MFA Enforcement"
            Value = $mfaPolicies.Count
            Description = "Conditional Access policies requiring MFA"
            Status = if ($mfaPolicies.Count -gt 0) { "Enforced" } else { "Not Enforced" }
        }
    }
    catch {
        Write-Warning "Error retrieving Identity Secure Score indicators: $_"
    }
    
    return $indicators
}

function Get-TenantRiskyUserActivity {
    <#
    .SYNOPSIS
        Detects tenant-wide risky user activity that correlates with app usage
    #>
    param(
        [int]$Days = 30
    )
    
    $riskyActivity = @()
    $startDate = (Get-Date).AddDays(-$Days)
    
    try {
        # Check for risky sign-in events
        $riskySignIns = Get-MgAuditLogSignIn -Filter "CreatedDateTime gt $startDate and riskLevelAggregated ne 'none'" -All -PageSize 999 -ErrorAction SilentlyContinue
        
        $riskyByUser = $riskySignIns | Group-Object -Property UserId | ForEach-Object {
            [PSCustomObject]@{
                UserId = $_.Name
                RiskySignInCount = $_.Count
                LastRiskySignIn = ($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
            }
        }
        
        foreach ($user in $riskyByUser) {
            if ($user.RiskySignInCount -gt 3) {
                $riskyActivity += [PSCustomObject]@{
                    UserId = $user.UserId
                    RiskySignInCount = $user.RiskySignInCount
                    LastRiskySignIn = $user.LastRiskySignIn
                    TimeframeDays = $Days
                    Status = "Active Risk"
                    Details = "User has multiple risky sign-ins"
                }
            }
        }
    }
    catch {
        Write-Warning "Error detecting risky user activity: $_"
    }
    
    return $riskyActivity
}

function Get-WeakConditionalAccessPosture {
    <#
    .SYNOPSIS
        Identifies weak Conditional Access posture enabling risky app behavior
    #>
    
    $weakPosture = @()
    
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All
        
        $policyAnalysis = [PSCustomObject]@{
            TotalPolicies = $policies.Count
            EnabledPolicies = ($policies | Where-Object { $_.State -eq "enabled" }).Count
            DisabledPolicies = ($policies | Where-Object { $_.State -eq "disabled" }).Count
            MfaRequired = ($policies | Where-Object { $_.GrantControls.BuiltInControls -contains "mfa" }).Count
            DeviceComplianceRequired = ($policies | Where-Object { $_.GrantControls.BuiltInControls -contains "deviceCompliancePolicy" }).Count
            LegacyAuthBlocked = ($policies | Where-Object { $_.Conditions.ClientAppTypes -contains "other" }).Count
        }
        
        # Identify gaps
        if ($policyAnalysis.EnabledPolicies -lt 3) {
            $weakPosture += [PSCustomObject]@{
                Finding = "Insufficient Policies"
                Description = "Less than 3 active CA policies detected"
                Impact = "Low baseline protection"
                Recommendation = "Create more granular Conditional Access policies"
                Severity = "MEDIUM"
            }
        }
        
        if ($policyAnalysis.MfaRequired -eq 0) {
            $weakPosture += [PSCustomObject]@{
                Finding = "No MFA Enforcement"
                Description = "No policies enforcing MFA"
                Impact = "Accounts vulnerable to credential compromise"
                Recommendation = "Create CA policy requiring MFA for sensitive operations"
                Severity = "HIGH"
            }
        }
        
        if ($policyAnalysis.DeviceComplianceRequired -eq 0) {
            $weakPosture += [PSCustomObject]@{
                Finding = "No Device Compliance Check"
                Description = "No policies checking device compliance"
                Impact = "Non-compliant devices can access resources"
                Recommendation = "Create CA policy requiring compliant devices"
                Severity = "HIGH"
            }
        }
        
        if ($policyAnalysis.LegacyAuthBlocked -eq 0) {
            $weakPosture += [PSCustomObject]@{
                Finding = "Legacy Auth Not Blocked"
                Description = "No policy blocking legacy authentication"
                Impact = "Apps using basic auth can bypass modern security"
                Recommendation = "Create CA policy blocking legacy authentication"
                Severity = "CRITICAL"
            }
        }
    }
    catch {
        Write-Warning "Error analyzing weak CA posture: $_"
    }
    
    return $weakPosture
}

# Export public functions
Export-ModuleMember -Function @(
    'Get-RiskySignInSignals',
    'Get-UnfamiliarLocationSignIns',
    'Get-RiskyConsentPatterns',
    'Get-HighPrivilegeConsentUsers',
    'Get-UnusedServicePrincipals',
    'Get-ServicePrincipalCredentialStatus',
    'Get-AnomalousServicePrincipalActivity',
    'Get-CredentialExpirationStatus',
    'Get-CredentialReplacementAnomalies',
    'Get-SuspiciousTokenUsage',
    'Get-UnusualTokenRefreshPatterns',
    'Get-ConditionalAccessBypassIndicators',
    'Get-NonCompliantDeviceAccessPatterns',
    'Get-PrivilegedRoleAssignments',
    'Get-RiskyDelegatedPermissions',
    'Get-InactiveHighPrivilegeApps',
    'Get-UnusualUsageSpikes',
    'Get-SensitiveGraphApiUsage',
    'Get-IdentitySecureScoreIndicators',
    'Get-TenantRiskyUserActivity',
    'Get-WeakConditionalAccessPosture'
)
