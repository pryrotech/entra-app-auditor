# Shadowman v2.0.0

Shadowman v2.0.0 expands the original consent audit into a multi-audit Entra ID security review tool.

## Highlights

- Eight focused security-signal audits, with a console menu and a Windows desktop GUI.
- CSV output with matching HTML dashboards and CSS stylesheets.
- Shared Microsoft Graph REST helpers for endpoints whose SDK submodules may not be installed.
- Sign-in signal queries are bounded to the latest 100 events from the previous 7 days by default. Last-sign-in lookups query the latest event separately.
- The GUI uses interactive Microsoft Graph sign-in and does not install PowerShell modules.

## Requirements

- PowerShell 7 on Windows for the GUI; console scripts support PowerShell 5.1 where dependencies are available.
- Microsoft Graph PowerShell Authentication and Applications modules available to the PowerShell host.
- Appropriate delegated Microsoft Graph permissions for the selected audits, including application, directory, consent, audit-log, user, and policy read access.

## Notes

- Reports may contain user identifiers, IP addresses, and security findings. Handle them according to your organization's data policies.
- A report with no findings is meaningful only if the audit completed without Graph authentication, permission, or API errors.
