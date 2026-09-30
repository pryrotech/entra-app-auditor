[CmdletBinding()]
param(
    [ValidateSet(
        "Basic",
        "Targeted",
        "IdentityRisk",
        "OAuthConsent",
        "ServicePrincipal",
        "TokenSession",
        "ConditionalAccess",
        "PermissionsRoles",
        "UsageActivity",
        "EnvironmentPosture",
        "All"
    )]
    [string]$RunAudit,
    [switch]$SelfTest
)

$script:AuditCatalog = @(
    [PSCustomObject]@{ Key = "Basic"; Label = "Basic Consent Audit"; Script = "basic-audit.ps1"; Csv = "basic-audit-report.csv" },
    [PSCustomObject]@{ Key = "Targeted"; Label = "Targeted Risk Audit"; Script = "targeted-audit.ps1"; Csv = "bulk-app-audit.csv" },
    [PSCustomObject]@{ Key = "IdentityRisk"; Label = "Identity & Sign-In Risk"; Script = "identity-risk-audit.ps1"; Csv = "identity-risk-audit-report.csv" },
    [PSCustomObject]@{ Key = "OAuthConsent"; Label = "OAuth & Consent"; Script = "oauth-consent-audit.ps1"; Csv = "oauth-consent-audit-report.csv" },
    [PSCustomObject]@{ Key = "ServicePrincipal"; Label = "Service Principal Activity"; Script = "service-principal-audit.ps1"; Csv = "service-principal-audit-report.csv" },
    [PSCustomObject]@{ Key = "TokenSession"; Label = "Token & Session Security"; Script = "token-session-audit.ps1"; Csv = "token-session-audit-report.csv" },
    [PSCustomObject]@{ Key = "ConditionalAccess"; Label = "Conditional Access"; Script = "conditional-access-audit.ps1"; Csv = "conditional-access-audit-report.csv" },
    [PSCustomObject]@{ Key = "PermissionsRoles"; Label = "Permissions & Roles"; Script = "permissions-roles-audit.ps1"; Csv = "permissions-roles-audit-report.csv" },
    [PSCustomObject]@{ Key = "UsageActivity"; Label = "Usage & Activity"; Script = "usage-activity-audit.ps1"; Csv = "usage-activity-audit-report.csv" },
    [PSCustomObject]@{ Key = "EnvironmentPosture"; Label = "Environment & Posture"; Script = "environment-posture-audit.ps1"; Csv = "environment-posture-audit-report.csv" }
)

if ($RunAudit) {
    Set-Location -Path $PSScriptRoot
    $global:IsGuiMode = $true
    $ErrorActionPreference = "Continue"
    $requiredScopes = @(
        "Application.Read.All",
        "Directory.Read.All",
        "DelegatedPermissionGrant.Read.All",
        "AuditLog.Read.All",
        "User.Read.All",
        "Policy.Read.All"
    )
    $failed = $false

    try {
        if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
            throw "Microsoft Graph Authentication is unavailable. Install/configure the required Graph modules before running audits."
        }

        $context = Get-MgContext -ErrorAction SilentlyContinue
        $missingScopes = @($requiredScopes | Where-Object { $context.Scopes -notcontains $_ })
        if ($null -eq $context -or $missingScopes.Count -gt 0) {
            Write-Host "Connecting to Microsoft Graph..."
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
        }

        if ($RunAudit -eq "All") {
            $auditsToRun = $script:AuditCatalog
        } else {
            $auditsToRun = @($script:AuditCatalog | Where-Object { $_.Key -eq $RunAudit })
        }

        foreach ($audit in $auditsToRun) {
            $scriptPath = Join-Path $PSScriptRoot $audit.Script
            $reportPath = Join-Path $PSScriptRoot $audit.Csv
            if (-not (Test-Path -LiteralPath $scriptPath)) {
                Write-Error "Audit script not found: $scriptPath"
                $failed = $true
                continue
            }

            Write-Host ""
            Write-Host "Starting $($audit.Label)..."
            & $scriptPath -ReportPath $reportPath
            if (-not $?) {
                $failed = $true
            }
        }

        if ($failed) {
            Write-Error "One or more audits reported errors. Review the run log and generated reports."
            exit 1
        }

        Write-Host ""
        Write-Host "Audit run finished."
    }
    catch {
        Write-Error $_.Exception.Message
        exit 1
    }
    finally {
        if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
    }

    exit 0
}

if ($env:OS -ne "Windows_NT") {
    throw "The Shadowman desktop GUI is available on Windows only."
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

if (-not ('Shadowman.Gui.ProcessOutputLine' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace Shadowman.Gui {
    public sealed class ProcessOutputLine {
        public string Text { get; private set; }
        public bool IsError { get; private set; }

        public ProcessOutputLine(string text, bool isError) {
            Text = text;
            IsError = isError;
        }
    }

    public sealed class ProcessOutputBuffer {
        public ConcurrentQueue<ProcessOutputLine> Lines { get; private set; }
        public DataReceivedEventHandler StandardOutputHandler { get; private set; }
        public DataReceivedEventHandler StandardErrorHandler { get; private set; }

        public ProcessOutputBuffer() {
            Lines = new ConcurrentQueue<ProcessOutputLine>();
            StandardOutputHandler = OnStandardOutput;
            StandardErrorHandler = OnStandardError;
        }

        private void OnStandardOutput(object sender, DataReceivedEventArgs args) {
            if (args.Data != null) {
                Lines.Enqueue(new ProcessOutputLine(args.Data, false));
            }
        }

        private void OnStandardError(object sender, DataReceivedEventArgs args) {
            if (args.Data != null) {
                Lines.Enqueue(new ProcessOutputLine(args.Data, true));
            }
        }
    }
}
"@
}

$script:OutputBuffer = $null
$script:ChildProcess = $null
$script:AuditButtons = @()
$screenArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$minimumWidth = [Math]::Min(960, [Math]::Max(700, $screenArea.Width - 24))
$minimumHeight = [Math]::Min(660, [Math]::Max(400, $screenArea.Height - 24))
$formWidth = [Math]::Min(1160, [Math]::Max($minimumWidth, [int]($screenArea.Width * 0.94)))
$formHeight = [Math]::Min(800, [Math]::Max($minimumHeight, [int]($screenArea.Height * 0.94)))
$sidebarWidth = [Math]::Min(306, [int]($formWidth * 0.31))
$script:SidebarButtonWidth = $sidebarWidth - 42

function New-ActionButton {
    param(
        [string]$Text,
        [string]$BackColor = "#FFFFFF",
        [string]$ForeColor = "#20313B"
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Height = 38
    $button.Width = 264
    $button.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 7)
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button.FlatAppearance.BorderColor = [System.Drawing.ColorTranslator]::FromHtml("#CAD2D0")
    $button.FlatAppearance.BorderSize = 1
    $button.BackColor = [System.Drawing.ColorTranslator]::FromHtml($BackColor)
    $button.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($ForeColor)
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Regular)
    $button.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $button.Padding = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
    return $button
}

function Update-ReportList {
    $reportList.BeginUpdate()
    $reportList.Items.Clear()
    Get-ChildItem -Path $PSScriptRoot -Filter *.html -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        ForEach-Object { [void]$reportList.Items.Add($_.Name) }
    $reportList.EndUpdate()
}

function Set-AuditControlsEnabled {
    param([bool]$Enabled)

    foreach ($button in $script:AuditButtons) {
        $button.Enabled = $Enabled
    }
    $stopButton.Enabled = -not $Enabled
    $openButton.Enabled = $Enabled -and $reportList.Items.Count -gt 0
}

function Add-RunLogLine {
    param([string]$Text)

    $logBox.AppendText($Text + [Environment]::NewLine)
    if ($logBox.TextLength -gt 100000) {
        $logBox.Text = $logBox.Text.Substring($logBox.TextLength - 80000)
    }
    $logBox.SelectionStart = $logBox.TextLength
    $logBox.ScrollToCaret()
}

function Start-Audit {
    param([string]$Key)

    if ($script:ChildProcess -and -not $script:ChildProcess.HasExited) {
        return
    }

    $hostExe = if ($PSVersionTable.PSEdition -eq "Core") {
        Join-Path $PSHOME "pwsh.exe"
    } else {
        Join-Path $PSHOME "powershell.exe"
    }
    $quotedScript = '"' + $PSCommandPath.Replace('"', '\"') + '"'
    $arguments = "-NoProfile -NoLogo -STA -ExecutionPolicy Bypass -File $quotedScript -RunAudit $Key"

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName = $hostExe
    $process.StartInfo.Arguments = $arguments
    $process.StartInfo.WorkingDirectory = $PSScriptRoot
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true

    $script:OutputBuffer = [Shadowman.Gui.ProcessOutputBuffer]::new()
    $process.add_OutputDataReceived($script:OutputBuffer.StandardOutputHandler)
    $process.add_ErrorDataReceived($script:OutputBuffer.StandardErrorHandler)

    try {
        [void]$process.Start()
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        $script:ChildProcess = $process
        $script:CurrentAuditKey = $Key
        $script:AuditStartTime = Get-Date
        Add-RunLogLine "Started $Key at $($script:AuditStartTime.ToString('HH:mm:ss'))."
        $statusLabel.Text = "Running: $Key"
        Set-AuditControlsEnabled -Enabled $false
        $runTimer.Start()
    }
    catch {
        $statusLabel.Text = "Could not start audit"
        Add-RunLogLine "ERROR: $($_.Exception.Message)"
        Set-AuditControlsEnabled -Enabled $true
        $process.Dispose()
    }
}

function Stop-Audit {
    if ($script:ChildProcess -and -not $script:ChildProcess.HasExited) {
        $script:ChildProcess.Kill()
        $statusLabel.Text = "Stopping audit..."
    }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Shadowman | Entra App Auditor"
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.MinimumSize = New-Object System.Drawing.Size($minimumWidth, $minimumHeight)
$form.Size = New-Object System.Drawing.Size($formWidth, $formHeight)
$form.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#F1F3F0")
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$root = New-Object System.Windows.Forms.TableLayoutPanel
$root.Dock = [System.Windows.Forms.DockStyle]::Fill
$root.ColumnCount = 1
$root.RowCount = 3
[void]$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 82)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
$form.Controls.Add($root)

$header = New-Object System.Windows.Forms.Panel
$header.Dock = [System.Windows.Forms.DockStyle]::Fill
$header.Height = 82
$header.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#182831")
$root.Controls.Add($header, 0, 0)

$brand = New-Object System.Windows.Forms.Label
$brand.Text = "SHADOWMAN"
$brand.AutoSize = $true
$brand.Location = New-Object System.Drawing.Point(24, 14)
$brand.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#9BE3CF")
$brand.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 11)
$header.Controls.Add($brand)

$title = New-Object System.Windows.Forms.Label
$title.Text = "Entra ID Audit Workspace"
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(24, 38)
$title.ForeColor = [System.Drawing.Color]::White
$title.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 16)
$header.Controls.Add($title)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.AutoSize = $true
$statusLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$statusLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#D5E0E1")
$statusLabel.Location = New-Object System.Drawing.Point(($formWidth - 140), 32)
$header.Controls.Add($statusLabel)

$body = New-Object System.Windows.Forms.TableLayoutPanel
$body.Dock = [System.Windows.Forms.DockStyle]::Fill
$body.ColumnCount = 2
$body.RowCount = 1
[void]$body.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, $sidebarWidth)))
[void]$body.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$body.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$root.Controls.Add($body, 0, 1)

$sidebar = New-Object System.Windows.Forms.Panel
$sidebar.Dock = [System.Windows.Forms.DockStyle]::Fill
$sidebar.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#E5EAE6")
$sidebar.Padding = New-Object System.Windows.Forms.Padding(18, 16, 18, 12)
$body.Controls.Add($sidebar, 0, 0)

$auditHeading = New-Object System.Windows.Forms.Label
$auditHeading.Text = "AUDITS"
$auditHeading.Dock = [System.Windows.Forms.DockStyle]::Fill
$auditHeading.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#52646A")
$auditHeading.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9)
$sidebarLayout = New-Object System.Windows.Forms.TableLayoutPanel
$sidebarLayout.Dock = [System.Windows.Forms.DockStyle]::Fill
$sidebarLayout.ColumnCount = 1
$sidebarLayout.RowCount = 2
[void]$sidebarLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$sidebarLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
[void]$sidebarLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$sidebar.Controls.Add($sidebarLayout)
[void]$sidebarLayout.Controls.Add($auditHeading, 0, 0)

$auditFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$auditFlow.Dock = [System.Windows.Forms.DockStyle]::Fill
$auditFlow.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
$auditFlow.WrapContents = $false
$auditFlow.AutoScroll = $true
$auditFlow.Padding = New-Object System.Windows.Forms.Padding(0, 4, 4, 0)
$sidebarLayout.Controls.Add($auditFlow, 0, 1)

$runAllButton = New-ActionButton -Text "Run All Audits" -BackColor "#176B5B" -ForeColor "#FFFFFF"
$runAllButton.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 10)
$runAllButton.Tag = "All"
$runAllButton.Add_Click({ param($sender, $eventArgs) Start-Audit -Key ([string]$sender.Tag) })
[void]$auditFlow.Controls.Add($runAllButton)
$script:AuditButtons += $runAllButton

$separator = New-Object System.Windows.Forms.Label
$separator.Text = "FOCUSED AUDITS"
$separator.Width = 255
$separator.Height = 28
$separator.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$separator.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#64767A")
$separator.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 8.5)
[void]$auditFlow.Controls.Add($separator)

foreach ($audit in $script:AuditCatalog) {
    $button = New-ActionButton -Text $audit.Label
    $button.Tag = $audit.Key
    $button.Add_Click({ param($sender, $eventArgs) Start-Audit -Key ([string]$sender.Tag) })
    [void]$auditFlow.Controls.Add($button)
    $script:AuditButtons += $button
}

$workspace = New-Object System.Windows.Forms.TableLayoutPanel
$workspace.Dock = [System.Windows.Forms.DockStyle]::Fill
$workspace.Padding = New-Object System.Windows.Forms.Padding(20, 17, 20, 16)
$workspace.ColumnCount = 1
$workspace.RowCount = 3
[void]$workspace.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
[void]$workspace.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$workspace.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 148)))
$body.Controls.Add($workspace, 1, 0)

$logHeading = New-Object System.Windows.Forms.Label
$logHeading.Text = "RUN OUTPUT"
$logHeading.Dock = [System.Windows.Forms.DockStyle]::Fill
$logHeading.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$logHeading.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#43565D")
$logHeading.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9)
$workspace.Controls.Add($logHeading, 0, 0)

$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Multiline = $true
$logBox.ReadOnly = $true
$logBox.WordWrap = $true
$logBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$logBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$logBox.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#172329")
$logBox.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#D8E4E0")
$logBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$logBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$workspace.Controls.Add($logBox, 0, 1)

$reportsPanel = New-Object System.Windows.Forms.TableLayoutPanel
$reportsPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$reportsPanel.ColumnCount = 2
$reportsPanel.RowCount = 2
[void]$reportsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$reportsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 142)))
[void]$reportsPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
[void]$reportsPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$reportsPanel.Margin = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)
$workspace.Controls.Add($reportsPanel, 0, 2)

$reportsHeading = New-Object System.Windows.Forms.Label
$reportsHeading.Text = "HTML REPORTS"
$reportsHeading.Dock = [System.Windows.Forms.DockStyle]::Fill
$reportsHeading.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$reportsHeading.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#43565D")
$reportsHeading.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9)
$reportsPanel.Controls.Add($reportsHeading, 0, 0)

$reportList = New-Object System.Windows.Forms.ListBox
$reportList.Dock = [System.Windows.Forms.DockStyle]::Fill
$reportList.IntegralHeight = $false
$reportList.BackColor = [System.Drawing.Color]::White
$reportList.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$reportList.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$reportList.Add_DoubleClick({
    if ($reportList.SelectedItem) {
        $reportPath = Join-Path $PSScriptRoot ([string]$reportList.SelectedItem)
        if (Test-Path -LiteralPath $reportPath) { Start-Process -FilePath $reportPath }
    }
})
$reportsPanel.Controls.Add($reportList, 0, 1)

$reportActions = New-Object System.Windows.Forms.FlowLayoutPanel
$reportActions.Dock = [System.Windows.Forms.DockStyle]::Fill
$reportActions.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
$reportActions.WrapContents = $false
$reportActions.Padding = New-Object System.Windows.Forms.Padding(8, 1, 0, 0)
$reportsPanel.Controls.Add($reportActions, 1, 1)

$openButton = New-ActionButton -Text "Open Selected" -BackColor "#FFFFFF"
$openButton.Width = 126
$openButton.Height = 32
$openButton.Enabled = $false
$openButton.Add_Click({
    if ($reportList.SelectedItem) {
        $reportPath = Join-Path $PSScriptRoot ([string]$reportList.SelectedItem)
        if (Test-Path -LiteralPath $reportPath) { Start-Process -FilePath $reportPath }
    }
})
$reportList.Add_SelectedIndexChanged({
    $openButton.Enabled = $reportList.SelectedIndex -ge 0 -and
        (-not $script:ChildProcess -or $script:ChildProcess.HasExited)
})
[void]$reportActions.Controls.Add($openButton)

$folderButton = New-ActionButton -Text "Open Folder" -BackColor "#FFFFFF"
$folderButton.Width = 126
$folderButton.Height = 32
$folderButton.Add_Click({ Start-Process -FilePath $PSScriptRoot })
[void]$reportActions.Controls.Add($folderButton)

$stopButton = New-ActionButton -Text "Stop Audit" -BackColor "#F8E7E3" -ForeColor "#8B3728"
$stopButton.Width = 126
$stopButton.Height = 32
$stopButton.Enabled = $false
$stopButton.Add_Click({ Stop-Audit })
[void]$reportActions.Controls.Add($stopButton)

$bottomBar = New-Object System.Windows.Forms.Panel
$bottomBar.Dock = [System.Windows.Forms.DockStyle]::Fill
$bottomBar.Height = 34
$bottomBar.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#DCE3DF")
$root.Controls.Add($bottomBar, 0, 2)

$footerLabel = New-Object System.Windows.Forms.Label
$footerLabel.Text = "Microsoft Graph authentication is requested only when needed. No modules are installed by this GUI."
$footerLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
$footerLabel.Padding = New-Object System.Windows.Forms.Padding(16, 0, 0, 0)
$footerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$footerLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#53656A")
$footerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
$bottomBar.Controls.Add($footerLabel)

$runTimer = New-Object System.Windows.Forms.Timer
$runTimer.Interval = 150
$runTimer.Add_Tick({
    $entry = $null
    while ($script:OutputBuffer -and $script:OutputBuffer.Lines.TryDequeue([ref]$entry)) {
        if ($entry.IsError) {
            Add-RunLogLine "ERROR: $($entry.Text)"
        } else {
            Add-RunLogLine $entry.Text
        }
    }

    if ($script:ChildProcess -and $script:ChildProcess.HasExited) {
        $script:ChildProcess.WaitForExit()
        $entry = $null
        while ($script:OutputBuffer.Lines.TryDequeue([ref]$entry)) {
            if ($entry.IsError) { Add-RunLogLine "ERROR: $($entry.Text)" } else { Add-RunLogLine $entry.Text }
        }
        $exitCode = $script:ChildProcess.ExitCode
        $script:ChildProcess.Dispose()
        $script:ChildProcess = $null
        $runTimer.Stop()
        Set-AuditControlsEnabled -Enabled $true
        if ($exitCode -eq 0) {
            $statusLabel.Text = "Finished: $($script:CurrentAuditKey)"
        } else {
            $statusLabel.Text = "Finished with errors: $($script:CurrentAuditKey)"
        }
        Update-ReportList
    }
})

$form.Add_FormClosing({
    if ($script:ChildProcess -and -not $script:ChildProcess.HasExited) {
        $script:ChildProcess.Kill()
        $script:ChildProcess.Dispose()
        $script:ChildProcess = $null
    }
})

Update-ReportList
if ($SelfTest) {
    $workerStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $workerStartInfo.CreateNoWindow = $false
    if ($workerStartInfo.CreateNoWindow) {
        throw "The audit worker must remain attached to a console for interactive WAM authentication."
    }

    $testBuffer = [Shadowman.Gui.ProcessOutputBuffer]::new()
    $testProcess = New-Object System.Diagnostics.Process
    $testProcess.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $testProcess.StartInfo.FileName = Join-Path $PSHOME "pwsh.exe"
    $testProcess.StartInfo.Arguments = '-NoProfile -Command "Write-Output stdout-ok; [Console]::Error.WriteLine(''stderr-ok'')"'
    $testProcess.StartInfo.UseShellExecute = $false
    $testProcess.StartInfo.CreateNoWindow = $true
    $testProcess.StartInfo.RedirectStandardOutput = $true
    $testProcess.StartInfo.RedirectStandardError = $true
    $testProcess.add_OutputDataReceived($testBuffer.StandardOutputHandler)
    $testProcess.add_ErrorDataReceived($testBuffer.StandardErrorHandler)
    [void]$testProcess.Start()
    $testProcess.BeginOutputReadLine()
    $testProcess.BeginErrorReadLine()
    $testProcess.WaitForExit()
    $capturedLines = @()
    $entry = $null
    while ($testBuffer.Lines.TryDequeue([ref]$entry)) {
        $capturedLines += $entry
        $entry = $null
    }
    $testExitCode = $testProcess.ExitCode
    $testProcess.Dispose()
    if ($testExitCode -ne 0 -or @($capturedLines | Where-Object Text -eq "stdout-ok").Count -ne 1 -or @($capturedLines | Where-Object Text -eq "stderr-ok").Count -ne 1) {
        throw "Child-process output test failed with exit code $testExitCode."
    }

    $form.PerformLayout()
    $root.PerformLayout()
    $sidebarLayout.PerformLayout()
    if ($form.Width -gt $screenArea.Width -or $form.Height -gt $screenArea.Height) {
        throw "GUI size $($form.Width)x$($form.Height) exceeds screen work area $($screenArea.Width)x$($screenArea.Height)."
    }
    if ($header.Bounds.Bottom -gt $body.Bounds.Top -or $body.Bounds.Bottom -gt $bottomBar.Bounds.Top) {
        throw "Top-level GUI sections overlap: header=$($header.Bounds), body=$($body.Bounds), footer=$($bottomBar.Bounds)."
    }
    if ($auditHeading.Bounds.Bottom -gt $auditFlow.Bounds.Top) {
        throw "Audit heading overlaps audit buttons: heading=$($auditHeading.Bounds), buttons=$($auditFlow.Bounds)."
    }
    $reportListScreenBottom = $reportList.PointToScreen((New-Object System.Drawing.Point(0, $reportList.Height)))
    $reportListBottom = $form.PointToClient($reportListScreenBottom).Y
    if ($reportListBottom -gt $bottomBar.Bounds.Top) {
        throw "Report list overlaps footer: report bottom=$reportListBottom, footer top=$($bottomBar.Bounds.Top)."
    }
    Write-Host "GUI controls initialized at $($form.Width)x$($form.Height). Audits configured: $($script:AuditCatalog.Count). Child stdout/stderr capture passed."
    $runTimer.Dispose()
    $form.Dispose()
    exit 0
}

[void]$form.ShowDialog()
$runTimer.Dispose()
$form.Dispose()