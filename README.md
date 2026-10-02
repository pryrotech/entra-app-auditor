<div align="center">
  <img src="https://github.com/user-attachments/assets/33aedceb-c3c5-4d22-ba24-c8d41e3df68b" alt="Shadowman Logo" width="230" height="200" /><br><br>
</div>

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
  * **Flexible Reporting:** Writes CSV results with a matching HTML dashboard and CSS stylesheet.
  * **Desktop GUI:** Windows interface for running one audit or all audits, monitoring output, and opening reports.

## 🛠️ Prerequisites

  * **PowerShell 7.x on Windows** for the desktop GUI. Console audit scripts can also run in PowerShell 5.1 where their dependencies are available.
  * Microsoft Graph PowerShell Authentication and Applications modules installed and available to the selected PowerShell host. The GUI does not install modules.
  * **Microsoft Entra ID/M365 administrator account** with the following Microsoft Graph API permissions:
      * `Application.Read.All`
      * `Directory.Read.All`
      * `AuditLog.Read.All`
      * `DelegatedPermissionGrant.Read.All`
      * `User.Read.All`
      * `Policy.Read.All`

The tool prompts you to connect to Microsoft Graph when needed. The GUI runs audits in a child PowerShell process and uses interactive Microsoft Graph authentication; follow any sign-in prompt shown by the Graph SDK. Grant only the permissions required by the audits you plan to run.

## 📖 Getting Started

### 1\. Download the Script

Clone the repository to start using the script.

```bash
git clone https://github.com/pryrotech/entra-app-auditor.git
```
### Install via PowerShell

```powershell
Install-Package pryrotech.Shadowman -Version 2.0.0
```
### Install via .NET CLI

```bash
dotnet add package pryrotech.Shadowman --version 2.0.0
```


### 2. Run the Audit

From the project folder, start the console menu:

```powershell
.\entra-app-auditor-main.ps1
```

Choose **1** for Basic, **2** for Targeted, or **3** to open Security Signals. In that submenu, choose **9** to run all eight signal audits. You can also launch the Windows GUI:

```powershell
pwsh -NoProfile -STA -File .\entra-app-auditor-gui.ps1
```

The GUI has individual audit buttons and **Run All Audits**, displays process output, and lets you open generated HTML reports. Authentication still requires an interactive Microsoft Graph sign-in; the GUI does not use device-code flow.

### 3\. Review the Report

Each audit writes a CSV file, a matching HTML dashboard, and a CSS stylesheet alongside the script (or at the specified `-ReportPath`). Reports are generated when the audit exports results, including successful runs with zero findings. To recreate an HTML report from a CSV file, run:

```powershell
pwsh -File .\generate-html-report.ps1 -CsvPath .\conditional-access-audit-report.csv
```

Open the generated HTML file in a browser, or the CSV file in a spreadsheet application. The columns depend on the audit; the Basic Audit includes fields such as:

  * `DisplayName`
  * `AppId`
  * `UserConsentsCount`
  * `ConsentingUsers`
  * `HasHighRiskPermissions`
  * `DelegatedPermissions`
  * `LastSignInUTC`
  * `UsageStatus`
  * ...and more\!

Audit sign-in analysis is limited to recent data (the shared sign-in query defaults to the latest 100 results from the last 7 days). Last-sign-in fields use a latest-event lookup. Treat results as investigation leads and confirm them in Entra ID.

Reports can contain user identifiers and security findings. Store and share them according to your organization’s data-handling requirements. Generated report files are local output and can be removed after review.

## ⚙️ Parameters

| Parameter                   | Type      | Description                                                                                             | Default   |
| --------------------------- | --------- | ------------------------------------------------------------------------------------------------------- | --------- |
| `-ReportPath`               | `string`  | Output CSV path; the matching HTML and CSS use the same base filename. | Audit-specific |


## 🤝 Contributing

Contributions are welcome\! If you have suggestions for new features, bug fixes, or improvements to the documentation, please open an issue or submit a pull request.

## 🤖 AI Transparency

Portions of this project were developed with assistance from Generative AI tools (Microsoft Copilot and related models).

All code and documentation were reviewed, tested, and validated manually before inclusion.

AI outputs were treated as suggestions, not authoritative sources — every implementation was verified against official Microsoft Graph and Entra documentation.

The repository maintains full human accountability for all commits and releases.

## ⚖️ License

This project is licensed under the MIT License. See the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

-----

*Disclaimer: This tool is provided as-is for auditing purposes. The author is not responsible for any actions taken based on its output. Always follow your organization's security and change management policies.*
