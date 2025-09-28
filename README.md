![PowerShell](https://img.shields.io/badge/PowerShell-Tool-blue)
![License](https://img.shields.io/github/license/pryrotech/port-diagnostics-tool)
![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen)
[![GitHub all releases](https://img.shields.io/github/downloads/pryrotech/entra-app-auditor/total.svg?cacheSeconds=3600)](https://github.com/pryrotech/entra-app-auditor/releases)
![NuGet Package Workflow](https://github.com/pryrotech/entra-app-auditor/actions/workflows/main.yml/badge.svg)

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
### Install via PowerShell

```powershell
Install-Package EntraAppAuditor -Version 1.0.1
```
### Install via .NET CLI

```bash
dotnet add package EntraAppAuditor --version 1.0.1
```


### 2\. Run the Audit

Open the program and select from the menu the audit you wish to execute. You may also run each individually instead of using the main program if desired.


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
