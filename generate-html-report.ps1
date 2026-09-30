[CmdletBinding()]
param(
    [string]$CsvPath,
    [string]$HtmlPath,
    [string]$CssPath,
    [string]$Title = "Shadowman Entra Audit Results"
)

function ConvertTo-HtmlSafe {
    param([object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    $text = [string]$Value
    $text = $text.Replace("&", "&amp;")
    $text = $text.Replace("<", "&lt;")
    $text = $text.Replace(">", "&gt;")
    $text = $text.Replace('"', "&quot;")
    $text = $text.Replace("'", "&#39;")

    return $text
}

function Get-SeverityClass {
    param([string]$Severity)

    if ([string]::IsNullOrWhiteSpace($Severity)) {
        return "default"
    }

    switch ($Severity.Trim().ToLowerInvariant()) {
        "critical" { return "critical" }
        "high" { return "high" }
        "medium" { return "medium" }
        "low" { return "low" }
        default { return "default" }
    }
}

if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    $CsvPath = Get-ChildItem -Path (Get-Location) -Filter *.csv -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 |
        ForEach-Object { $_.FullName }
}

if ([string]::IsNullOrWhiteSpace($CsvPath) -or -not (Test-Path -Path $CsvPath)) {
    throw "CSV file not found. Provide -CsvPath or run this script in a folder containing a .csv report."
}

$csvFile = Get-Item -Path $CsvPath
if ([string]::IsNullOrWhiteSpace($HtmlPath)) {
    $HtmlPath = [System.IO.Path]::ChangeExtension($csvFile.FullName, ".html")
}
if ([string]::IsNullOrWhiteSpace($CssPath)) {
    $CssPath = [System.IO.Path]::ChangeExtension($csvFile.FullName, ".css")
}

$rows = @(Import-Csv -Path $csvFile.FullName)
$allColumns = @()
foreach ($row in $rows) {
    foreach ($prop in $row.PSObject.Properties.Name) {
        if (-not ($allColumns -contains $prop)) {
            $allColumns += $prop
        }
    }
}

if ($allColumns.Count -eq 0) {
    $allColumns = @("SignalType", "Severity", "Finding", "Details")
}

$totalFindings = $rows.Count
$severitySummary = [ordered]@{
    Critical = 0
    High = 0
    Medium = 0
    Low = 0
    Other = 0
}

foreach ($row in $rows) {
    $severityValue = $null
    if ($row.PSObject.Properties.Name -contains "Severity") {
        $severityValue = [string]$row.Severity
    }

    if (-not [string]::IsNullOrWhiteSpace($severityValue)) {
        switch ($severityValue.Trim().ToLowerInvariant()) {
            "critical" { $severitySummary.Critical++; break }
            "high" { $severitySummary.High++; break }
            "medium" { $severitySummary.Medium++; break }
            "low" { $severitySummary.Low++; break }
            default { $severitySummary.Other++; break }
        }
    }
    else {
        $severitySummary.Other++
    }
}

$summaryCards = @(
    @{ Label = "Total Findings"; Value = $totalFindings; Class = "card-total" },
    @{ Label = "Critical"; Value = $severitySummary.Critical; Class = "card-critical" },
    @{ Label = "High"; Value = $severitySummary.High; Class = "card-high" },
    @{ Label = "Medium"; Value = $severitySummary.Medium; Class = "card-medium" },
    @{ Label = "Low"; Value = $severitySummary.Low; Class = "card-low" }
)

$cardHtml = foreach ($card in $summaryCards) {
    @"
    <div class="summary-card $($card.Class)">
        <div class="summary-label">$($card.Label)</div>
        <div class="summary-value">$($card.Value)</div>
    </div>
"@
}

$tableRows = @()
foreach ($row in $rows) {
    $cells = foreach ($column in $allColumns) {
        $rawValue = if ($row.PSObject.Properties.Name -contains $column) { $row.$column } else { $null }
        $safeValue = ConvertTo-HtmlSafe -Value $rawValue

        if ($column -eq "Severity" -and -not [string]::IsNullOrWhiteSpace($safeValue)) {
            $className = Get-SeverityClass -Severity $safeValue
            $cellMarkup = "<span class='severity-badge severity-$className'>$safeValue</span>"
        }
        else {
            $cellMarkup = $safeValue
        }

        "<td>$cellMarkup</td>"
    }

    $tableRows += "<tr>$($cells -join '')</tr>"
}

$headerCells = foreach ($column in $allColumns) {
    "<th>$(ConvertTo-HtmlSafe -Value $column)</th>"
}

$cssContent = @'
:root {
    --bg: #0b1220;
    --panel: #141d2d;
    --panel-alt: #1d2a3f;
    --header: #0f172a;
    --text: #e5edf9;
    --muted: #afbdd1;
    --border: #2d3a52;
    --critical: #f87171;
    --high: #fb923c;
    --medium: #facc15;
    --low: #34d399;
    --default: #7dd3fc;
    --accent: #60a5fa;
    --shadow: rgba(15, 23, 42, 0.35);
}

* { box-sizing: border-box; }

body {
    margin: 0;
    font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #0b1220, #111827 42%, #0f172a);
    color: var(--text);
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 32px 20px 48px;
}

.page-header {
    background: rgba(15, 23, 42, 0.9);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px 28px;
    box-shadow: 0 14px 28px var(--shadow);
    margin-bottom: 24px;
}

.title {
    margin: 0;
    font-size: clamp(1.8rem, 3vw, 2.6rem);
    font-weight: 700;
    letter-spacing: 0.02em;
}

.subtitle {
    margin: 8px 0 0;
    color: var(--muted);
    font-size: 0.98rem;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px;
    margin: 24px 0;
}

.summary-card {
    background: linear-gradient(180deg, rgba(29,42,63,0.95), rgba(20,29,45,0.95));
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 16px;
    box-shadow: 0 8px 22px rgba(15, 23, 42, 0.25);
}

.summary-label {
    color: var(--muted);
    font-size: 0.8rem;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    margin-bottom: 8px;
}

.summary-value {
    font-size: clamp(1.6rem, 2vw, 2.3rem);
    font-weight: 700;
}

.card-total { border-left: 4px solid var(--accent); }
.card-critical { border-left: 4px solid var(--critical); }
.card-high { border-left: 4px solid var(--high); }
.card-medium { border-left: 4px solid var(--medium); }
.card-low { border-left: 4px solid var(--low); }

.table-wrap {
    background: rgba(20,29,45,0.92);
    border: 1px solid var(--border);
    border-radius: 16px;
    box-shadow: 0 14px 28px var(--shadow);
    overflow: auto;
}

.table-wrap table {
    width: 100%;
    border-collapse: collapse;
    min-width: 900px;
}

th, td {
    text-align: left;
    padding: 14px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}

th {
    background: rgba(15, 23, 42, 0.9);
    color: var(--text);
    font-weight: 700;
    position: sticky;
    top: 0;
}

tr:nth-child(even) td {
    background: rgba(15, 23, 42, 0.18);
}

tr:hover td {
    background: rgba(96, 165, 250, 0.08);
}

.severity-badge {
    display: inline-block;
    padding: 5px 10px;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    border: 1px solid transparent;
}

.severity-critical {
    background: rgba(248, 113, 113, 0.15);
    border-color: rgba(248, 113, 113, 0.7);
    color: #fecaca;
}

.severity-high {
    background: rgba(251, 146, 60, 0.15);
    border-color: rgba(251, 146, 60, 0.7);
    color: #fed7aa;
}

.severity-medium {
    background: rgba(250, 204, 21, 0.14);
    border-color: rgba(250, 204, 21, 0.7);
    color: #fef3c7;
}

.severity-low {
    background: rgba(52, 211, 153, 0.14);
    border-color: rgba(52, 211, 153, 0.7);
    color: #bbf7d0;
}

.severity-default {
    background: rgba(125, 211, 252, 0.14);
    border-color: rgba(125, 211, 252, 0.7);
    color: #dbeafe;
}

.empty-state {
    padding: 28px;
    color: var(--muted);
    font-size: 1.05rem;
}

@media (max-width: 768px) {
    .container {
        padding: 18px 12px 28px;
    }

    .page-header {
        padding: 18px 16px;
    }
}
'@

Set-Content -Path $CssPath -Value $cssContent -Encoding UTF8

if ($rows.Count -eq 0) {
    $tableMarkup = @"
    <div class="empty-state">No findings were detected for this audit. The generated report is empty.</div>
"@
}
else {
    $tableMarkup = @"
    <table>
        <thead>
            <tr>
                $($headerCells -join "")
            </tr>
        </thead>
        <tbody>
            $($tableRows -join "")
        </tbody>
    </table>
"@
}

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>$(ConvertTo-HtmlSafe -Value $Title)</title>
    <link rel="stylesheet" href="$(Split-Path -Leaf $CssPath)" />
</head>
<body>
    <div class="container">
        <header class="page-header">
            <h1 class="title">$(ConvertTo-HtmlSafe -Value $Title)</h1>
            <p class="subtitle">Source: $(ConvertTo-HtmlSafe -Value $csvFile.Name) | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </header>

        <section class="summary-grid">
            $($cardHtml -join "")
        </section>

        <section class="table-wrap">
            $tableMarkup
        </section>
    </div>
</body>
</html>
"@

Set-Content -Path $HtmlPath -Value $htmlContent -Encoding UTF8

Write-Host "Generated HTML report: $HtmlPath" -ForegroundColor Green
Write-Host "Generated CSS stylesheet: $CssPath" -ForegroundColor Cyan
