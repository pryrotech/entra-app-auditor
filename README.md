# Shadowman (entra-app-auditor)

A PowerShell tool to identify and audit user-consented applications in Microsoft Entra ID (Azure AD), with a focus on uncovering "Shadow IT" and security risks.

## 🌟 Overview

**Shadowman** is a powerful and targeted PowerShell script designed for IT administrators and security professionals. It goes beyond a standard application inventory by focusing specifically on applications where individual users have granted permissions (user consent). By combining consent data with usage analysis and a configurable risk scoring model, this tool provides a clear, actionable report to help you:

  * **Discover** user-consented applications that bypass formal IT approval processes.
  * **Prioritize** security reviews by flagging apps with high-risk permissions.
  * **Manage** your application security posture by identifying dormant but privileged apps that should be revoked.
  * **Demonstrate** compliance by providing a clear audit trail of user consents.

## 🚀 Key Features

  * **Targeted User Consent Auditing:** Pinpoints applications consented to by individual users, which are a primary source of "Shadow IT."
  * **Risk-Based Prioritization:** Flags applications with highly privileged permissions (e.g., `Mail.ReadWrite`, `Files.ReadWrite.All`) using a configurable risk model.
  * **Usage Analysis:** Correlates consent data with sign-in logs to differentiate between active and dormant threats.
  * **Accountability Report:** Identifies which users have consented to which applications and how many total consents exist per app.
  * **Flexible Reporting:** Exports a single, comprehensive report to a CSV file for easy filtering and analysis.
  * **Dependency Management:** Automatically checks for and installs the necessary Microsoft Graph PowerShell SDK modules.

## 🛠️ Prerequisites

  * **PowerShell 5.1 or later** (PowerShell 7.x recommended for cross-platform support).
  * **Microsoft Entra ID/M365 administrator account** with the following Microsoft Graph API permissions:
      * `Application.Read.All`
      * `Directory.Read.All`
      * `AuditLog.Read.All`
      * `DelegatedPermissionGrant.Read.All`
      * `User.Read.All`

The script will automatically prompt you to connect to Microsoft Graph and consent to these permissions on the first run.

## 📖 Getting Started

### 1\. Download the Script

Clone the repository to start using the script.

```bash
git clone https://github.com/pryrotech/entra-app-auditor.git
```

### 2\. Run the Audit

Open a PowerShell console and navigate to the directory where you saved the script. Execute the script with your desired parameters.

```powershell
# Set execution policy if you encounter script errors
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Run a basic audit and save the report
.\Invoke-EntraAppAuditor.ps1 -ReportPath "C:\temp\Shadowman_Report.csv"

# Run a more detailed audit, focusing only on high-risk apps and looking back 180 days
.\Invoke-EntraAppAuditor.ps1 -ReportPath "C:\temp\HighRisk_Shadowman_Report.csv" -IncludeHighRiskOnly -DaysBackForUsage 180 -Verbose
```

On the first run, a browser window will open for you to authenticate with your M365 account and consent to the required API permissions.

### 3\. Review the Report

Open the generated CSV file in Excel or your preferred spreadsheet application. The report will include columns for:

  * `DisplayName`
  * `AppId`
  * `UserConsentsCount`
  * `ConsentingUsers`
  * `HasHighRiskPermissions`
  * `DelegatedPermissions`
  * `LastSignInUTC`
  * `UsageStatus`
  * ...and more\!

## ⚙️ Parameters

| Parameter                   | Type      | Description                                                                                             | Default   |
| --------------------------- | --------- | ------------------------------------------------------------------------------------------------------- | --------- |
| `-ReportPath`               | `string`  | **(Mandatory)** The full path to save the generated CSV report.                                         |           |


## 🤝 Contributing

Contributions are welcome\! If you have suggestions for new features, bug fixes, or improvements to the documentation, please open an issue or submit a pull request.

## ⚖️ License

This project is licensed under the MIT License. See the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

-----

*Disclaimer: This tool is provided as-is for auditing purposes. The author is not responsible for any actions taken based on its output. Always follow your organization's security and change management policies.*
