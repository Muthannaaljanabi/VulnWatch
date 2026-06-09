#Requires -Version 5.1
<#
.SYNOPSIS
    Fleet Dashboard Generator v2.0 - Enhanced with Dark/Light Mode

.DESCRIPTION
    Generates an interactive HTML dashboard from vulnerability scan results stored in SharePoint.
    Features dark/light mode toggle, trend analysis, Planner task integration, and modern design.

.PARAMETER SharePointSiteUrl
    SharePoint site URL where scan results are stored

.PARAMETER DocumentLibrary
    SharePoint document library name (default: VulnerabilityScans)

.PARAMETER OutputPath
    Path to save the generated HTML dashboard

.PARAMETER IncludeTrends
    Include historical trend analysis (compares with previous scans)

.PARAMETER MaxDevices
    Maximum number of devices to include (default: all)

.EXAMPLE
    .\Generate-FleetDashboard-v2.ps1 -SharePointSiteUrl "https://contoso.sharepoint.com/sites/VulnMgmt"

.EXAMPLE
    .\Generate-FleetDashboard-v2.ps1 -SharePointSiteUrl "https://contoso.sharepoint.com/sites/VulnMgmt" -IncludeTrends

.NOTES
    Version: 2.0
    Author: Enterprise IT Security
    Requires: PowerShell 5.1+, outbound HTTPS to graph.microsoft.com and login.microsoftonline.com
    License: MIT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SharePointSiteUrl = "https://<YOUR-TENANT>.sharepoint.com/sites/<YOUR-SITE>",

    [Parameter(Mandatory = $false)]
    [string]$DocumentLibrary = "VulnerabilityScans",

    [Parameter(Mandatory = $false)]
    [string]$SourceFolder = "Enriched",

    [Parameter(Mandatory = $false)]
    [string]$DriveId = "<YOUR_SHAREPOINT_DRIVE_ID>",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\FleetDashboard_v2_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeTrends,

    [Parameter(Mandatory = $false)]
    [int]$MaxDevices = 0
)

# -- Credential fallbacks ----------------------------------------------------
# Supply via environment variables; never commit real values.
# See CONFIGURATION_GUIDE.md for where to obtain each value.
if (-not $env:PLANNER_TENANT_ID)     { $env:PLANNER_TENANT_ID     = "<YOUR_ENTRA_TENANT_ID>" }
if (-not $env:PLANNER_CLIENT_ID)     { $env:PLANNER_CLIENT_ID     = "<YOUR_APP_CLIENT_ID>" }
if (-not $env:PLANNER_CLIENT_SECRET) { $env:PLANNER_CLIENT_SECRET = "<YOUR_CLIENT_SECRET>" }

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Fleet Dashboard Generator v2.0" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "SharePoint: $SharePointSiteUrl" -ForegroundColor White
Write-Host "Library: $DocumentLibrary" -ForegroundColor White
Write-Host "Output: $OutputPath" -ForegroundColor White
Write-Host ""

# -- Acquire Graph API access token (client_credentials, no interactive login) --
# Same auth pattern used by Invoke-DeviceCollector.ps1 and Invoke-VulnerabilityScan-v2.ps1
# Graph permission required: Sites.ReadWrite.All (Application, admin-consented)
Write-Host "Connecting to SharePoint..." -ForegroundColor Cyan
try {
    $tokenBody = @{
        client_id     = $env:PLANNER_CLIENT_ID
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $env:PLANNER_CLIENT_SECRET
        grant_type    = "client_credentials"
    }
    $tokenResponse = Invoke-RestMethod `
        -Uri         "https://login.microsoftonline.com/$($env:PLANNER_TENANT_ID)/oauth2/v2.0/token" `
        -Method      Post `
        -Body        $tokenBody `
        -ContentType "application/x-www-form-urlencoded" `
        -UseBasicParsing `
        -ErrorAction Stop

    $script:GraphToken = $tokenResponse.access_token

    if (-not $script:GraphToken) {
        throw "Access token was empty. Check Client ID and Secret."
    }

    $script:GraphHeaders = @{
        "Authorization" = "Bearer $script:GraphToken"
        "Content-Type"  = "application/json"
    }

    Write-Host "Connected to SharePoint" -ForegroundColor Green

} catch {
    Write-Host "Failed to connect to SharePoint: $_" -ForegroundColor Red
    Write-Host "Check PLANNER_TENANT_ID, PLANNER_CLIENT_ID, PLANNER_CLIENT_SECRET are set correctly." -ForegroundColor Yellow
    exit 1
}

# Retrieve enriched results from SharePoint via Graph API
# Lists all files in the /Enriched/ folder (written by Invoke-VulnerabilityEnrichment.ps1)
Write-Host "`nRetrieving scan results from SharePoint/$SourceFolder..." -ForegroundColor Cyan
try {
    $listUrl = "https://graph.microsoft.com/v1.0/drives/$DriveId/root:/$($SourceFolder):/children"
    $listResponse = Invoke-RestMethod `
        -Uri     $listUrl `
        -Method  Get `
        -Headers $script:GraphHeaders `
        -UseBasicParsing `
        -ErrorAction Stop

    $scanFiles = $listResponse.value | Where-Object { $_.name -like "*.json" }
    Write-Host "Found $($scanFiles.Count) result files" -ForegroundColor Green
} catch {
    Write-Host "Failed to retrieve files: $_" -ForegroundColor Red
    Write-Host "Check that the $SourceFolder folder exists in SharePoint/$DocumentLibrary" -ForegroundColor Yellow
    exit 1
}

if ($scanFiles.Count -eq 0) {
    Write-Host "No result files found in SharePoint/$DocumentLibrary/$SourceFolder" -ForegroundColor Yellow
    Write-Host "Run Invoke-DeviceCollector.ps1 on devices, then Invoke-VulnerabilityEnrichment.ps1 to populate $SourceFolder." -ForegroundColor Gray
    exit 0
}

# Download and parse scan results
Write-Host "`nProcessing scan results..." -ForegroundColor Cyan
$allVulnerabilities = @()
$deviceStats = @{}
$processedDevices = 0

foreach ($file in $scanFiles) {
    if ($MaxDevices -gt 0 -and $processedDevices -ge $MaxDevices) {
        break
    }
    
    if ($file.name -like "*.json") {
        try {
            Write-Host "  Processing: $($file.name)..." -ForegroundColor Gray
            
            # Download file content via Graph API pre-authenticated download URL
            $downloadUrl = $file."@microsoft.graph.downloadUrl"
            if (-not $downloadUrl) {
                # Fallback: build download URL from drive path
                $downloadUrl = "https://graph.microsoft.com/v1.0/drives/$DriveId/root:/$SourceFolder/$($file.name):/content"
                $fileContent = (Invoke-RestMethod -Uri $downloadUrl -Method Get -Headers $script:GraphHeaders -UseBasicParsing -ErrorAction Stop) | ConvertTo-Json -Depth 10
                $scanData = $fileContent | ConvertFrom-Json
            } else {
                # Pre-authenticated URL — no auth header needed, faster
                $fileContent = Invoke-RestMethod -Uri $downloadUrl -Method Get -UseBasicParsing -ErrorAction Stop
                $scanData = $fileContent
            }
            
            # ------------------------------------------------------------------
            # Schema detection — three formats can appear in CurrentScan:
            #
            #   A) Collector format  (device-HOSTNAME_date.json)
            #      Written by Invoke-DeviceCollector.ps1
            #      Top-level keys: SchemaVersion, Device{}, InstalledKBs[], InstalledApps[]
            #      No Vulnerabilities array — raw inventory only
            #
            #   B) Flat array format  (HOSTNAME_date.json)
            #      Written by Invoke-VulnerabilityScan-v2.ps1 ($allVulnerabilities | ConvertTo-Json)
            #      $scanData is a PSCustomObject[] array of vuln objects, not a wrapper object
            #
            #   C) Wrapped format  (original expected schema)
            #      Top-level keys: SystemInfo{}, Vulnerabilities[], ScanDate
            # ------------------------------------------------------------------

            # Detect format A — collector JSON (has Device property, no Vulnerabilities)
            $isCollectorFormat = ($null -ne $scanData.Device -and $null -eq $scanData.Vulnerabilities -and $scanData -isnot [System.Array])

            # Detect format B — flat array written by v2 scan script
            $isFlatArray = ($scanData -is [System.Array]) -or ($scanData -is [System.Object[]])

            # Resolve device name across all three schemas
            $deviceName = if ($scanData.SystemInfo.ComputerName)  { $scanData.SystemInfo.ComputerName }
                          elseif ($scanData.Device.ComputerName)  { $scanData.Device.ComputerName }
                          else { $file.name -replace '^device-', '' -replace '_\d{8}_\d{6}\.json$', '' -replace '\.json$', '' }

            # Resolve scan timestamp across all three schemas
            $scanDate = if ($scanData.ScanDate)       { $scanData.ScanDate }
                        elseif ($scanData.ScanTimestamp) { $scanData.ScanTimestamp }
                        else { (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss") }

            # Resolve OS version across all three schemas
            $osVersion = if ($scanData.SystemInfo.OSVersion) { $scanData.SystemInfo.OSVersion }
                         elseif ($scanData.Device.OSVersion)  { $scanData.Device.OSVersion }
                         else { "Unknown" }

            # Build the vulnerability list for this file
            $fileVulns = @()

            if ($isFlatArray) {
                # Format B: $scanData is already the array of vuln objects
                $fileVulns = $scanData
            } elseif (-not $isCollectorFormat -and $scanData.Vulnerabilities) {
                # Format C: wrapped object with Vulnerabilities array
                $fileVulns = $scanData.Vulnerabilities
            }
            # Format A (collector-only): $fileVulns stays empty — device appears in
            # the device table as "Pending enrichment" with 0 vulns until
            # Invoke-VulnerabilityScan-v2.ps1 runs and uploads enriched data.

            # Stamp each vulnerability with its device name and scan date
            foreach ($vuln in $fileVulns) {
                if ($null -ne $vuln) {
                    $vuln | Add-Member -NotePropertyName "DeviceName" -NotePropertyValue $deviceName -Force
                    $vuln | Add-Member -NotePropertyName "ScanDate"   -NotePropertyValue $scanDate   -Force
                    $allVulnerabilities += $vuln
                }
            }

            # Track device statistics
            $deviceStats[$deviceName] = @{
                TotalVulns = $fileVulns.Count
                Critical   = ($fileVulns | Where-Object { $_.Severity -eq "Critical"  -or $_.CVSSScore -ge 9.0 }).Count
                High       = ($fileVulns | Where-Object { ($_.Severity -in @("Important","High")) -or ($_.CVSSScore -ge 7.0 -and $_.CVSSScore -lt 9.0) }).Count
                Medium     = ($fileVulns | Where-Object { ($_.Severity -in @("Moderate","Medium")) -or ($_.CVSSScore -ge 4.0 -and $_.CVSSScore -lt 7.0) }).Count
                Low        = ($fileVulns | Where-Object { $_.Severity -eq "Low" -or ($_.CVSSScore -gt 0 -and $_.CVSSScore -lt 4.0) }).Count
                Unpatched  = ($fileVulns | Where-Object { -not $_.IsPatched }).Count
                OSVersion  = $osVersion
                LastScan   = $scanDate
                Schema     = if ($isCollectorFormat) { "CollectorOnly" } elseif ($isFlatArray) { "EnrichedFlat" } else { "EnrichedWrapped" }
            }
            
            $processedDevices++
            
        } catch {
            Write-Warning "Failed to process $($file.name): $_"
        }
    }
}

Write-Host "Processed $processedDevices devices with $($allVulnerabilities.Count) total vulnerabilities" -ForegroundColor Green

# Calculate fleet statistics
$fleetStats = @{
    TotalDevices = $processedDevices
    TotalVulnerabilities = $allVulnerabilities.Count
    Critical = ($allVulnerabilities | Where-Object { $_.Severity -eq "Critical" -or $_.CVSSScore -ge 9.0 }).Count
    High = ($allVulnerabilities | Where-Object { ($_.Severity -in @("Important", "High")) -or ($_.CVSSScore -ge 7.0 -and $_.CVSSScore -lt 9.0) }).Count
    Medium = ($allVulnerabilities | Where-Object { ($_.Severity -in @("Moderate", "Medium")) -or ($_.CVSSScore -ge 4.0 -and $_.CVSSScore -lt 7.0) }).Count
    Low = ($allVulnerabilities | Where-Object { $_.Severity -eq "Low" -or ($_.CVSSScore -gt 0 -and $_.CVSSScore -lt 4.0) }).Count
    MSRCCount = ($allVulnerabilities | Where-Object { $_.Source -eq "MSRC" }).Count
    ThirdPartyCount = ($allVulnerabilities | Where-Object { $_.Source -eq "Third-Party" }).Count
    UnpatchedCount = ($allVulnerabilities | Where-Object { -not $_.IsPatched }).Count
    PatchedCount = ($allVulnerabilities | Where-Object { $_.IsPatched }).Count
}

# Find top vulnerable devices
$topVulnerableDevices = $deviceStats.GetEnumerator() | 
    Sort-Object { $_.Value.Critical + $_.Value.High } -Descending | 
    Select-Object -First 10

# Group vulnerabilities by CVE for deduplication
$uniqueVulns = $allVulnerabilities | 
    Group-Object CVE | 
    ForEach-Object {
        $cve = $_.Group[0]
        $cve | Add-Member -NotePropertyName "AffectedDevices" -NotePropertyValue $_.Count -Force
        $cve | Add-Member -NotePropertyName "DeviceList" -NotePropertyValue ($_.Group.DeviceName -join ', ') -Force
        $cve
    }

Write-Host "`nGenerating HTML dashboard..." -ForegroundColor Cyan

# Generate vulnerability table rows
$tableRows = ""
foreach ($vuln in ($uniqueVulns | Sort-Object { 
    switch ($_.Severity) {
        "Critical" { 0 }
        "Important" { 1 }
        "High" { 1 }
        "Moderate" { 2 }
        "Medium" { 2 }
        "Low" { 3 }
        default { 4 }
    }
}, CVE)) {
    
    $severityClass = switch ($vuln.Severity) {
        "Critical" { "critical" }
        "Important" { "high" }
        "High" { "high" }
        "Moderate" { "medium" }
        "Medium" { "medium" }
        "Low" { "low" }
        default { "unknown" }
    }
    
    $sourceClass = if ($vuln.Source -eq "MSRC") { "msrc" } else { "thirdparty" }
    $patchedClass = if ($vuln.IsPatched) { "patched" } else { "unpatched" }
    
    $cveLink = if ($vuln.Source -eq "MSRC") {
        "https://msrc.microsoft.com/update-guide/vulnerability/$($vuln.CVE)"
    } else {
        "https://nvd.nist.gov/vuln/detail/$($vuln.CVE)"
    }
    
    $kbArticles = if ($vuln.KBArticles) { $vuln.KBArticles } else { "N/A" }
    $updateMonth = if ($vuln.Update) { $vuln.Update } else { "N/A" }
    
    $tableRows += @"
        <tr data-severity="$severityClass" data-source="$sourceClass" data-patched="$patchedClass" data-kbs="$kbArticles" data-update="$updateMonth">
            <td><a href="$cveLink" target="_blank" class="cve-link">$($vuln.CVE)</a></td>
            <td><span class="severity-badge $severityClass">$($vuln.Severity)</span></td>
            <td>$([Math]::Round($vuln.CVSSScore, 1))</td>
            <td class="product-cell">$($vuln.Product)</td>
            <td class="title-cell">$($vuln.Title)</td>
            <td>$($vuln.AffectedDevices)</td>
            <td>$kbArticles</td>
            <td>$updateMonth</td>
            <td>$(if ($vuln.IsPatched) { '<span class="status-badge patched">✓ Patched</span>' } else { '<span class="status-badge unpatched">✗ Unpatched</span>' })</td>
        </tr>
"@
}

# Generate device table rows
$deviceTableRows = ""
foreach ($device in ($topVulnerableDevices | Select-Object -First 20)) {
    $stats = $device.Value
    $riskScore = ($stats.Critical * 10) + ($stats.High * 5) + ($stats.Medium * 2) + $stats.Low
    
    $deviceTableRows += @"
        <tr>
            <td><strong>$($device.Key)</strong></td>
            <td>$($stats.TotalVulns)</td>
            <td class="severity-critical">$($stats.Critical)</td>
            <td class="severity-high">$($stats.High)</td>
            <td class="severity-medium">$($stats.Medium)</td>
            <td class="severity-low">$($stats.Low)</td>
            <td>$($stats.Unpatched)</td>
            <td>$riskScore</td>
        </tr>
"@
}

# HTML Dashboard Template with Dark/Light Mode
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnWatch Enterprise &mdash; Fleet Vulnerability Dashboard</title>
    <style>
        /* ===== CSS VARIABLES FOR THEMING ===== */
        :root {
            /* Light Mode (Default) */
            --bg-primary: #f5f7fa;
            --bg-secondary: #ffffff;
            --bg-card: #ffffff;
            --text-primary: #2c3e50;
            --text-secondary: #7f8c8d;
            --border-color: #e1e8ed;
            --shadow: 0 2px 8px rgba(0,0,0,0.08);
            --shadow-hover: 0 4px 16px rgba(0,0,0,0.12);
            
            /* Severity Colors */
            --critical-bg: linear-gradient(135deg, #c0392b 0%, #8e44ad 100%);
            --high-bg: linear-gradient(135deg, #e67e22 0%, #d35400 100%);
            --medium-bg: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
            --low-bg: linear-gradient(135deg, #27ae60 0%, #229954 100%);
            
            /* Status Colors */
            --patched-color: #27ae60;
            --unpatched-color: #e74c3c;
        }
        
        /* Dark Mode */
        [data-theme="dark"] {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-card: #2d2d2d;
            --text-primary: #e0e0e0;
            --text-secondary: #b0b0b0;
            --border-color: #404040;
            --shadow: 0 2px 8px rgba(0,0,0,0.3);
            --shadow-hover: 0 4px 16px rgba(0,0,0,0.4);
        }
        
        /* ===== BASE STYLES ===== */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background 0.3s ease, color 0.3s ease;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* ===== HEADER ===== */
        .header {
            position: relative;
            background: #0d1117;
            color: white;
            padding: 22px 0 26px;
            margin-bottom: 30px;
            border-radius: 12px;
            border: 1px solid #1e2a44;
            box-shadow: var(--shadow-hover);
        }

        .header-top {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 18px;
        }

        .header-logo {
            width: 64px;
            height: 64px;
            border-radius: 12px;
            box-shadow: 0 0 18px rgba(59,130,246,0.45);
            flex: 0 0 auto;
        }

        .header h1 {
            font-size: 2.1em;
            margin: 0;
            text-align: center;
            font-weight: 800;
            background: linear-gradient(90deg, #5bc4ff 0%, #8b7cf6 55%, #a855f7 100%);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header p {
            text-align: center;
            color: #a0aec0;
            opacity: 0.95;
            font-size: 1.0em;
            margin: 12px 0 0;
        }

        .header-credit {
            position: absolute;
            top: 16px;
            left: 22px;
            text-align: left;
            line-height: 1.5;
        }

        .header-credit .credit-label {
            font-size: 0.72em;
            color: #a0aec0;
        }

        .header-credit .credit-label::before {
            content: "\2764";
            color: #e05c8a;
            font-size: 0.9em;
            margin-right: 4px;
        }

        .header-credit .credit-name {
            font-size: 0.98em;
            font-weight: 700;
            color: #5bc4ff;
            display: block;
        }

        .header-credit .credit-role {
            font-size: 0.78em;
            color: #a0aec0;
            display: block;
        }

        .header-brand {
            position: absolute;
            top: 16px;
            right: 22px;
            text-align: right;
            font-size: 0.95em;
            font-weight: 700;
            color: #5bc4ff;
            line-height: 1.5;
        }

        .header-brand span {
            display: block;
            color: #a0aec0;
            font-size: 0.82em;
            font-weight: 400;
        }
        
        /* ===== THEME TOGGLE ===== */
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            border-radius: 50%;
            width: 60px;
            height: 60px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            transition: all 0.3s ease;
            box-shadow: var(--shadow);
        }
        
        .theme-toggle:hover {
            transform: scale(1.1) rotate(15deg);
            box-shadow: var(--shadow-hover);
        }
        
        /* ===== STATS GRID ===== */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            padding: 25px;
            border-radius: 12px;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
            border: 1px solid var(--border-color);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-hover);
        }
        
        .stat-card.critical {
            background: var(--critical-bg);
            color: white;
            border: none;
        }
        
        .stat-card.high {
            background: var(--high-bg);
            color: white;
            border: none;
        }
        
        .stat-card.medium {
            background: var(--medium-bg);
            color: white;
            border: none;
        }
        
        .stat-card.low {
            background: var(--low-bg);
            color: white;
            border: none;
        }
        
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 1.1em;
            opacity: 0.95;
        }
        
        .stat-sublabel {
            font-size: 0.9em;
            opacity: 0.8;
            margin-top: 5px;
        }
        
        /* ===== SECTION ===== */
        .section {
            background: var(--bg-card);
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 12px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }
        
        .section h2 {
            margin-bottom: 20px;
            color: var(--text-primary);
            font-size: 1.8em;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
        }
        
        /* ===== CONTROLS ===== */
        .controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .search-box, select {
            padding: 12px 20px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            font-size: 16px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            transition: all 0.3s ease;
        }
        
        .search-box {
            flex: 1;
            min-width: 300px;
        }
        
        .search-box:focus, select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        /* ===== TABLE ===== */
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }
        
        th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        th:hover {
            background: linear-gradient(135deg, #5568d3 0%, #653a8b 100%);
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
        }
        
        tr:hover {
            background: var(--bg-primary);
        }
        
        .product-cell, .title-cell {
            max-width: 300px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        /* ===== BADGES ===== */
        .severity-badge {
            padding: 6px 12px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
            display: inline-block;
        }
        
        .severity-badge.critical {
            background: #c0392b;
            color: white;
        }
        
        .severity-badge.high {
            background: #e67e22;
            color: white;
        }
        
        .severity-badge.medium {
            background: #f39c12;
            color: white;
        }
        
        .severity-badge.low {
            background: #27ae60;
            color: white;
        }
        
        .status-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .status-badge.patched {
            background: #d5f4e6;
            color: #27ae60;
        }
        
        .status-badge.unpatched {
            background: #fadbd8;
            color: #e74c3c;
        }
        
        [data-theme="dark"] .status-badge.patched {
            background: #1e4d2b;
            color: #52c77e;
        }
        
        [data-theme="dark"] .status-badge.unpatched {
            background: #5d2a2a;
            color: #ff6b6b;
        }
        
        /* ===== LINKS ===== */
        .cve-link {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        
        .cve-link:hover {
            color: #764ba2;
            text-decoration: underline;
        }
        
        /* ===== SEVERITY COLORS IN DEVICE TABLE ===== */
        .severity-critical {
            color: #c0392b;
            font-weight: bold;
        }
        
        .severity-high {
            color: #e67e22;
            font-weight: bold;
        }
        
        .severity-medium {
            color: #f39c12;
            font-weight: bold;
        }
        
        .severity-low {
            color: #27ae60;
            font-weight: bold;
        }
        
        /* ===== FOOTER ===== */
        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9em;
        }
        
        /* ===== RESPONSIVE ===== */
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .controls {
                flex-direction: column;
            }
            
            .search-box {
                min-width: 100%;
            }
        }
    </style>
</head>
<body>
    <!-- Theme Toggle Button -->
    <button class="theme-toggle" onclick="toggleTheme()" id="themeToggle" title="Toggle Dark/Light Mode">
        🌙
    </button>

    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-credit">
                <span class="credit-label">Created by</span>
                <span class="credit-name">Matt Aljanabi</span>
                <span class="credit-role">Enterprise Security</span>
            </div>
            <div class="header-brand">
                VulnWatch Enterprise<span>Fleet Dashboard v2.0</span>
            </div>
            <div class="header-top">
                <img class="header-logo" src="data:image/png;base64,/9j/4AAQSkZJRgABAgAAAQABAAD/wAARCAO4BOwDACIAAREBAhEB/9sAQwAIBgYHBgUIBwcHCQkICgwUDQwLCwwZEhMPFB0aHx4dGhwcICQuJyAiLCMcHCg3KSwwMTQ0NB8nOT04MjwuMzQy/9sAQwEJCQkMCwwYDQ0YMiEcITIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMAAAERAhEAPwD5/ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf8Akoeof9gqT/0bFXj9ewfs4/8AJQ9Q/wCwVJ/6NioA+n6KKKAPgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK9g/Zx/5KHqH/YKk/wDRsVeP17B+zj/yUPUP+wVJ/wCjYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf8Akoeof9gqT/0bFXj9ewfs4/8AJQ9Q/wCwVJ/6NioA+n6KKKAPgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK9g/Zx/5KHqH/YKk/wDRsVeP17B+zj/yUPUP+wVJ/wCjYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf8Akoeof9gqT/0bFXj9ewfs4/8AJQ9Q/wCwVJ/6NioA+n6KKKAPgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAorU0PQNU8R362WlWUt1OeoQcKPVj0A9zXvHgv4FadpojvPEsi390MEWqHEKn3PVv0FNK4Hj/hH4ea/wCMpgbC18qzBw93MCsa/Q/xH2H6V9A+FPhD4a8NWx+0266peOm2Sa5QFeeu1egH613sMMVvCkMEaRRINqoigKo9AB0p9Wok3PEvGnwHgufMvfCsqwyfeNlM3yN/uN2+h4+leGappN/ot7JZalZzWtzGcNHKuD+HqPevuCsjxB4Y0bxTYm01ixjuE52uRh4z6q3UUnEEz4por1vxp8D9V0bzb3QWbUrIZJhx++jH0/i/DmvJ5EaNyjqyOpIZWGCD71NihlFFFIAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/2CpP8A0bFXj9ewfs4/8lD1D/sFSf8Ao2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAopcGu/8F/CTxB4sKXMqHTtNPJuJ1OXH+wvU/Xge9AHCW9vNdTpBbxPLK5wqIpZmPsK9i8F/Am+v/LvfE8jWVucEWkZHmv8A7x6KPzNev+E/AGgeDYANNtA90R893NhpW/Ht9BgV09Wo9xXM/R9D0zw/YLY6TZxWtuv8MY5b3J6k+5rQooqiQooqJ7hEO3lm9FGcUAS0U1JEkXcjZFOoAK47xj8M/D/jJGluYfsuoYwt5AAH/wCBDow+vPvXY0UbgfJHjH4YeIfBzNLPB9rsAflu7cErj/aHVfxrij1r7rZVdCjqGVhgqwyD9a8r8afBHSNd8y80Jk0y/bJ8sD9zIfcD7v1H5VDj2KTPmeitnxF4V1nwtfG11exkt2/gcjKSD1VhwaxsVIwooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK9g/Zx/5KHqH/YKk/wDRsVeP17B+zj/yUPUP+wVJ/wCjYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAoxQBmrumaTf6zfR2Wm2st1cv0jiXJ+p9B7mgCnjNdB4W8Fa74vvPJ0qyZ4wcSXD/LFH9W/oMn2r13wX8BoYfLvfFcolfgixgb5R/vt3+gr2izs7bT7SO1s7eK3t4xhIolCqo+gqlG4rnnvgz4NaF4a8u71BV1PUV53Sr+6jP+ynf6mvSfTHGOBRRV2EFFFGaBBTXkSNdzsAKj81pTtt13Hu5+6KlitVRt8hMknqe30pgRKs1wOMxRnufvH/AAqzFBHCuEXHqe5qSii4FeW1Vm3xny5PUdD9ai85o2CXC7Sejj7p/wAKu0jKHUqwBB6ii4EOQRnNFRtbSQndbnK942/pSRzq528q46o3WgCWiiikBU1LS7DWLF7LUrSK6tn+9HKuR9R6H3rw/wAZ/AaSLzL3wpKZVHJsZm+YeyN3+h/Ove6KTQz4ZvLK60+7ktby3lt7iM4eOVSrKfoahIxX2b4n8F6F4vtfJ1ayV5AMR3CfLLH9G/oeK+fvGnwZ13w55l3pobVNOHO6Jf3qD/aTv9RUuNh3PMqKUqRSVIwooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/2CpP8A0bFXj9ewfs4/8lD1D/sFSf8Ao2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiilxxQAlPSJ3cIiszMcKqjJJ9K7Hwd8MvEHjJ1ltoPsun5+a8uAQn/AR1Y/Tj3FfQ3g74ZeH/ByLLBB9r1DHzXk4BbP+yOij6c00rhc8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pi6kn+KtmsnxF/yDY/8Ar5i/9CqofEhS2ZquiucHP4HFIqKmduefUk089TSVIxjIWOQ7L9KcoKjBYsfU4paKYDD5uTtCEfXBp46cjFFFIBgmjJxuwfcYp9BAPUZpCMgjJHuKYC0UxFdW5fcvuOaV3VMFjgHvSAgktAWMkJ8t/bofqKjExRtk67G7HsfoauAhhkEEeopHRXUq6gj0NVcCKiojBLBzCd6f3GPT6GljmSTgZDDqp4IoAkooopAGARgjj0rzPxp8F9E8SeZd6WE0vUm5zGv7mQ/7Sjp9R+Rr0yii1xnxl4m8Ga54RvPI1ayeNSfknX5o3+jdPw61z9fct7Y2upWklpfW8VxbyDDRyruU/hXivjT4DJIZL7wpKEbkmwmbg+yMen0P5iocR3PBKKuajpl7pN5JZ6haS2tzGcNHKpUiqdSMKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK9g/Zx/5KHqH/YKk/wDRsVeP17B+zj/yUPUP+wVJ/wCjYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAoooxQAUUUUAFFFFABRRRQAUUUUAFFFSQwS3EywwxvJK5wqIuWY+gA60AR9K0tH0PU9fv1stKspbq4b+GNc7R6k9APc16h4L+Beo6n5d74kkawtDgi2TBmce/Zf517xofh/SvDlgLLSLGK1hGM7B8zn1ZupP1qlG4mzy7wZ8CbKx8u98TyLeXA5FpET5Sn/aPVv0FewQW8Nrbpb28KQwxjakcagKo9ABUlFWlYVwooooEFFIzqi7mIA9TUQM1x/qwY0/vt1P0pgOkmWPjkseijkmkW3lmwZztT/nmp5/E1PDbxw8qPmPVj1p6yKzFVOcdSOlFwBEWNcKoUD0pQwYZUgj1FNeNZCC2SPTsacAB0GPakAzY5PzPgdgvFSUUUgCiiigAooooAKKKKACiiigArJ8Rf8AINj/AOvmL/0IVrVk+Iv+QbH/ANfMX/oQqofEhS2ZrnqaSlPU0lSMKKKKACiiigAooooAKKKKAEVQudoAz6Cms0inIUMvoDyKfRTAByOhFRTW6TcsMN2YdRUpGRio1V1bBbcvv1FAFZjLb/60b4/769fxqVWV13KwI9RViq0lpht8DeWx7djTuA6iohPtbZMvlv2z0P0qWiwBRRRSAxfEfhTRfFdl9m1iyScAfJIOJI/91uorwPxp8EtY0ISXmiFtTsRkmNV/fRj/AHR978Pyr6WopNXHc+FHUoxVgQwOCD1BptfW/jL4X+H/ABirzyw/Y9RI4vIFALH/AGx0b+fvXz14x+GviDwc7SXVv9osc/LeQDKfj3X8ahxsUcbRRiikAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFewfs4/wDJQ9Q/7BUn/o2KvH69g/Zx/wCSh6h/2CpP/RsVAH0/RRRQB8AUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAtFA6V0Gj+HvtUa3F0SsR5VR1YetbUaE60uSCuyZzjBXkc/wA0V6Ami6ai4FnGfdhk0v8AZGnf8+UP/fNep/YeI7r8f8jl+u0+zPPaK9C/sjTv+fKH/vmj+yNO/wCfKH/vmj+w8R3X4/5B9dp9n/XzPPaXFeg/2Rp3/PlD/wB80yXQ9OlXb9lRPdODSeR4hLdfj/kCxtPszgcUYNdbaeAtU1jWYtP0hFnMuTudgoQDqWPp9Pyr3LwZ8F9E8O+Xd6rt1TUVwfnX9zGf9le/1P6V5lWhOlLkmrM6ozjJXieOeDfhRr/i4pcGL7Bpve6uFI3D/YXq38vevoXwh8O9A8GQg2Nt5t5jD3k/zSH6f3R7D9a6oAAAAAAcAAcAUtSkkFw+tFFFMQUUVHJMkXBOWPRR1NMCSoTOWbZAvmP+g+tKsEs/Mx8tP7i9T9atIixqFRQoHYUbAQR2g3B5j5j/AKD6Cp3kVMAnk9FHU0LIrkheQO/alCgMSByeppNgDAOpBHBHSgAKMAAD2paKQBRRRQAUUUUAFFFFMAooooAKKKKQBRSFlXqQPqaie8to/v3ES/VgKYE1ZPiL/kGx/wDXzF/6EKt/2nZdrmM/7pzWZrt9bzafGqSbj9oiPAPQMKqCfMiZPRm+eppKqnU7PJzMB9QRQNSsicC7hz7uBU2ZVy1RUazwv9yVG+jVJnPSgAooopAFFFFMAooooAKKKKQBRRRQA10V8ZyCOhHUUIGC4Y7j64xTqKBjXRJV2uAyntVVoJYOYsyR/wBxuo+lWPL2vuQ7QT8y9jUlO4irHMkv3Tgjqp4Ip9LNbxzcnhx0detQF5bf/XDcnaRR/MU9wJqKRWDAFSCD3FLSAKR0SWNo5FDowwysMgj3FLRQM8l8Z/A7StYMl54fZdNvCcmA8wSH2/uH6ce1eB+IPDOr+Gb82erWMltIPusRlXHqrdCPpX2tVLVdI07W7F7LU7OG6t26pKuce49D9KTiFz4gxRivbPG/wKns1l1DwxN50Cgs1nO2HUD+6x4I9j+ZridJ8HxLGsuo5eQ8+UDgD6mtaGFq15ctNXLjFy2OIxRivUhoWlAY+wQH6rR/Yelf9A+3/wC+K9H+wsR3X4/5GvsJHluKK9S/sPSv+gfb/wDfFH9h6V/0D7f/AL4o/sLEd1+P+QewkeXUV6j/AGHpX/QPg/75qtdeF9LuUISDyG7NHxj8KUsjxKV7p/f/AJB7CR5vikrR1bSZ9JuvKlwVblHHRhWea8qpTlTk4zVmjJqzsxKKKKzEFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABXsH7OP/JQ9Q/7BUn/o2KvH69g/Zx/5KHqH/YKk/wDRsVAH0/RRRQB8AUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQBb06AXV/BCejuAfpXoYAUYAAA4Arg9C/5DVr/v8A9DXe19LkUFyTl1uedjm7pBRRUttbz3dwkFtC80zH5URck/hXv36nARUV6f4b+F25Fudec8ji1jb/ANCYf0qh4m+GV3Y77rRy11bjkwn/AFij2/vfzriWYYf2ns+Y29hPl5rHn9FKysjlGUqynBBGCKSu3dGJb0vUJdK1W2voWKvDIGyO47j8q+kUYPGrjowB/OvmJvun6V9NW3/HpD/1zX+VeBnkV7kuup34JvVEtFFFfPncFIzKi7mIAHc1E0+WKQr5j+3QfjUkdplg87b37L/CPwp2AjUy3BxECif32HX6Cp4bdIeQMserHk1N7CilcBCwVSWOAOpoIDrg8g0hQM4cknHQdhTqAAAAADp6UUUUgCiiigAooopgFFFIzqilnYKo6knAFIBaKqfbTKSLSJpf9s/Kn5nr+FILaebm4uCFP/LOH5R+J6n9KqwXJprqC3IEsqqT0XPJ+g6movtkkn+otJW/2n+Qfrz+lSw2sFv/AKqJVJ6nHJ+p6mpqWgiptvpOs0UI/wBhSx/M0fYS3+tubh/bftH6VboouOxVGnWY6wK3++S386mSCGP7kMa/7qAVJRRdhZBWV4hz/Zsf/XzF0/3hWrQRmhOzTE0Kc5ppAYYKg/UUtFIdiB7O1k+/bQk+uwZqM6dbA5RXjPqkhH9cVbop3YWRU+yzp/q72X6SANRvv4z80UMw/wBhip/XIq3RRfuFip/aES8TpLAf+mi8fmOKso6yIGRgynoVOQadVV9Pt2cuimGQ9XhO0n644P45o0FqWqKqYvIOhS5T0Pyvj+R/SnRXsMj+W26KT+5IME/T1osO5ZooopAFFFFMAooopAFNdA4xkg9iOop1FADU3bcOQW9R3p3t+dFRqHVtp+ZT0Pp7GmBC9ptJeBtjdx/CaYs2G2SqY39+h+hq7TJI0lXa6hh707gR0VEYZYOYyZY/7p6inRypKPlPPcHqKLAPooopAcn8Q7+Sy8MmKNtrXUgiJHXHU/yryCvUvij/AMgSx/6+f/ZDXltfUZNFLDuXW520F7oYoHOMVd0iCO61qwt5RmOW4jRh6gsAa9e8Ua+nhTTbZobKOXzHMaR52qoAz6V2YvGOhOMIx5nLzsXKXK7HilFegf8AC07j/oDQf9/j/hV3SPiPJqOr2tlLpUcazyrHvSUkgk4BxisnisSld0f/ACZBzS7HmVFei/FGzgiOn3SRqs0jOjsBjcAARn8686rpwmJWIpKolYcZcyuY3im0W60OZyPnhw6n+debmvUdc/5AV9/1xavLjXz+ewSqxkuqMK+4lFFFeEYBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAV7B+zj/AMlD1D/sFSf+jYq8fr2D9nH/AJKHqH/YKk/9GxUAfT9FFFAHwBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFAGloX/Ibtf8Af/oa72uC0L/kN2v+/wD0Nd7X0+Q/wp+p5uO+JCHgGvoDwnoGnaRo9rLa26iaeBJJJW5ZiVB6+nPSvn8/dNfSejf8gLTv+vWL/wBAFa51OUaUUnuyMGk5O5dooor5k9LU4X4k6Dp0nh661b7OqXsJTEqcFgXVTu9eDXjVe7/ET/kRdR/7Zf8Aoxa8Ir6fJpylRld7P9Eebi0lNWQjfdb6V9NW3/HpD/1zX+VfMrfcb6V9KWzyz2sIhG1digu307Csc8+GHz/QrBbyJ5Jki+8eT0UdTSCGWfmQmOP+4Op+pqaG2jhycFn7s3Wpq+euegNSNI1CooUDsKdRTXYIueT7AUgHVGiHdvc5bt6AU5A20l8ZPOB2p1IAooooAKKKKACiiimAUjMFUliAB1J7VXmu1jfyo1Ms/wDcXt7k9hTVs2mIe8cSEciMfcX8O/1NFuoX7Cfa5LjizjDL/wA9X4T8PX/PNKtihYPcuZ5ByC/3QfZeg/n71b7Y7UUX7AGAKKKKQwooooEFFFFABRRRQAUVFLcRxHaSS56KvJNNEd1PyW8hewHLH60wJ6KrmWa34nTcv/PRBx+IqZHWRdyMGHtQA6iiikAUUUUAFFFFABTJYY502Sxq6+jDNPopgU/s9xb820nmIP8AllMxP5N1H45p8N4kj+U6tFN/zzfgn6ev4VZqOaCK4TZKgYe/b8e1F+4ElFUsXNnyN1xB6H76/Q/xfTrVmGeO4j3xOGX19PrRYLklFFFABRRRSAKKKKYDHcowJHydz6U/ryORRTWZUHPTOKAHVDNbJMd33XHRl61NRRcCkXlgOJxuXtIo4/GpQQwBUgg9xVjg8HkGqr2hRi9u2xv7p+6ad7gcT8Uf+QJY/wDX1/7Ia8tr074myFtGskdCji55HY/I3evMa+qyZf7M/V/odtD4DR0D/kY9L/6+4v8A0MV3/wAVP+QXpv8A13b/ANBrgNA/5GPS/wDr7i/9DFd98VP+QXp3/Xdv/QaWO/3uj6/5Dn8aPMK1PDX/ACNGlf8AX3H/AOhCsutTw1/yNGlf9fcf/oQr06nwM1Z3HxV/49NL/wCukn8hXmdemfFX/j00v/rpJ/IV5nXn5R/uq9WZ0vhRn65/yAr7/ri1eXGvUdc/5AV9/wBcWry415mffxIejMq+6EooorwDAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/2CpP/AEbFXj9ewfs4/wDJQ9Q/7BUn/o2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA0tC/5Ddr/AL/9DXe1wOhkDWbU9Pn/AKV31fT5D/Cn6nm474kIeQa+ifC10t54V0yZDkeQqn6qMf0r53r0v4YeJo4d2hXcgQOxe2Zjxk9V/rXTm9GVShddGZ4WajOz6nqlFFISACSQAOpNfKnpnHfE66WDwdJCT81xKiKPod3/ALLXiXeux+IfiWPXdYW2tX3WdplVYdHc9W+nAFcdX1mVUZUsPeXXU8rFTUp6CN9xvpX1Da/8ekH/AFzX+Qr5eILAqOp4FfTdteWotYQbmDiNR/rB6fWuTPfhh8/0NsFvIt0VD9stP+fqD/v4KT7ba/8APzB/38FfOHeTMwVSTQDuUHBGexqu11Zuyk3UJwenmCrAOeR3pgLRRRQAUUUUgCiimSzJBGZJGCoOpNMBxIUEk4A5JPpVPzpb3i3Jjg7zEct/uj09zQIpL477lSkA+7Cf4vdv8Pzq6OBxxQLcjhgjt02RrtHU+pPqT3qSiihj2CiiikAUUUUAFFFFABRUcs0cK5dgPQdzUYFzcfdHkx+rfeP4UwJJZ44fvNyeijkmowlzcdf3EZ/Fj/hViG1ihO5Rlz1duSampXHYihtooB8i8nqTyT+NS0UUhhVWSyQsXhYxP6r0P1FWqKNgKJmkgOLlMD/nonIqdWDqCpBB7ipyMiqr2QBLW7mJvQfdP4U7isSUVX+0PEdtymz0ccqf8KnBDDIII9RTELRRRQAUUUUgCiiigAqtNabpDNA3lT/3gOG9mHerNFMHqVoLrfJ5MyeXOB93OQw9VPcVZqKe3juE2SL0OQQcFT6g9jUEc8ls6w3bZUnCTdA3sfQ/zo3FexcooooGFFFFIAoIyMEcUUUwGouxcZJA6U6mSyRIn72RY1PGWbH61BHe2+Cr3MGR38wc0AWqKh+2Wn/P1B/38FH2y0/5+oP+/gpAcR8Vf+QHYf8AX1/7Ia8qr1P4oTRT6JZeVNG+25yQrA4G0+leWV9Xkv8Auz9X+h20PgL+iSJFr+nSSMFRLqJmJ7DcK9z1DS7HVoFhvrdLiIHcA3r6givn2r8euatFGsceqXqIowFW4cAD860zDBVMRKMqcrNFTg5ao9h/4Qnw4f8AmEQn/gTf41NaeFdCsbpLm202KOaM5VgSSD68mub8I+N7CDQRDqmoSLdRMxZpmZjICSRg/TjHtXEal4n1O51O6nttSvooJJWaOMXDjaueB1ryYYfHVKsqXO9OrbszNRm21c674qSIYdMjDDeGkYr3xgc15tUtxcz3cpluZ5JpDwXkcsfzNRV7uCw7w9FU5O7NoLlVjP1z/kBX3/XFq8uNeo66QNBvcnGYiK8uNeJn38SHozCvuhKKKK8AwCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAr2D9nH/koeof9gqT/ANGxV4/XsH7OP/JQ9Q/7BUn/AKNioA+n6KKKAPgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAJIZWhlSVOGQhhXoVjfRX9qs0R6/eXuprzqvbfgNo9hrWmeJLfULdJk322M9V4l5B7V6WXY54Wbvqmc+Io+0j5owKUMVYMpIYHII6g16/L8JtGkkLR3t7Ev90FTj8SKZ/wqPSf+glffkn+FfQrNcI18X4M894Wr2Mvwx8T2t4ktNdV5VXhbpBlh/vDv9RWd4r+Il1rUb2WnK9rZNwxP+skHvjoPaul/wCFR6V/0Er78k/wrK1LwL4Z0awjudQ1e/RpCQkaKhZsHsMVwxeWurzq/pZ2v6WNn9YUbPb5Hm9Fd3Y+EvDutlYNI1DUpLpjzHMqLsXuxwOn0NdbZfCbQ4HV7m4urnHJVmCqfyGa9CpmWHp/E2n2s/1OeNCctkef+BvDEviDW4nkjP2C3YPM5HBx0X3zXt39i6X/ANA+2/79ip7OxtdOtUtbOBIYUGFRBgCrFfPY7HSxM7rRLY9CjQVONnuUf7F0v/oH23/fsVG+i6azBV0+3A6kiMflWg7hAOMknAHrTq4ueXc25V2M86JpZBH9n23PpGKqLJNoTiOZml04nCyHlofY+o9626a6K6lXUMpGCD3o539oOXsKrq6hlIKkZBHelrEZJtCcyQq02nE5ePq0PuPatiGaOeFZYnDxsMqw6Gk421WwJ9B9FFRzTJbxNJIcKtSMJ50t4zJIcDoO5J7Ae9QQwPNKLi5XDD/VxZ4j/wDsveiCF5ZRc3Aww/1cf9wf4mrdPYW4UUUUhhRRRQAUUUUAFFNeRI13OwUe9QiSa4/1C7E/56OP5CmBLJKkK7nYL9aiDXFx/ql8pP77jn8BU0VnHG29sySf3m5qxSuOxBDaRwndgs/d25NT0UUhhRRRQAUUUUAFFFFABRRRQAhAYYIBB7EVVay8slrZzGT1U/dNW6KAsURcmNgtwnlt2P8ACfxqwCCMg5FSsqupVgCD2Iqo1m0R3Wz7f9huVNO6YrE1FQLchWCToYn9+h+hqemIKKKKQBRRRQAU2SNZUZHUMpGCDTqKAKSO1i4imJa3JxHIeq/7Lf0NXaa6LIhRwGUjBB7iqkbtZSrBKS0DHETnnaf7p/pT3EXaKKKRQVUv7+GwhDyZZ2OEjXlnb0ApmoaitkFjRDLcycRwr1P19BUdjprLKby9cS3jDr/DGPRapLS72Jb7EMGlteSfatWRJHIwlueUiH9T71Z/sXS+2nW3/fsVfop876ByrqZyaRpTrkadbD1Hljg0/wDsXS/+gfbf9+xVwKA7MOp606jnl3DlXY57X/CtjqejXFtbWsENwRujdUAww/x6V4nc201pcyW9xG0cyMQysOQa+jax9Z8M6VroBvbcGQDAlQ7XH416WX5i8M3GesWb0qihozwWivTNR+GNpBD51rdXUgU5eM7cle+DjrXNtY+C1uVhOq6qQesgiQqv14z+Qr34ZjQqawbfyZtLE0o7uxy9FemR/DbSZnQw6ldvE8QkVxsIIP4dKl/4Vdpn/QQvf/HP8Kh5rhf5vwf+RXt4PW55dRXqX/CrtM/6CF7+Sf4VdsPh5ollKJZBLdMpyBM3H5DAqZZvhUrp3+TD20T508Yasi2/9nRNl2IMuP4QO1cUa6Hx4qp4/wDEKIAqrqU4AHQDea52vmMdi3iqvO9F0Oec+Z3CiiiuMgKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf8Akoeof9gqT/0bFXj9ewfs4/8AJQ9Q/wCwVJ/6NioA+n6KKKAPgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAFzXvX7OP/Hv4k/37b+UteCV73+zj/x7+JP9+2/lLTW4nse5UUUVqSFeX/ELTLyT7FqEcbyWqxtG20E7DuJyfrnr7V6h3ptiM2SA4Iyf51vhq3sKiqpXsZ1aftI8p5T8N9MvJfEUd+qOlrCjbnIwHJGAo9fX8K9fpAAvAAFLVYzFfWanPa2liaFH2UeUKKKjlydqLkbuCR2FchuOKAuGOcgYFOoooEFFFFABjIxWNLaz6TM11YIZLZjma1HUf7Se/tWzQentVKVhNXILa9t7q2FzFKDERkt6Y65qGFWvJVuZFIhU/uU9f9o/0Hasu8spDfTT6cmUUj7RDuwszDnA9x3rXsb6G/g8yHgjhkIwyH0IpuNldCv0ZaoooqCgooooAKKKKAEZlRSzEADuagE005xbx4X/AJ6OMD8BSX3Nt7b1/nV/pRsMrR2SKweUmWT+83b6CrNFFIYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFADXRJFKuoZT61Va1kh5tn+X/AJ5v0/A9quUUA0UkuRv8uVTFJ6N0P0NT1DqI/cJ/10XB/Gpu9VuIKKKKQgooooAKZLEk0TRyKGRhgin0UwKlvI8M32WdiWxmKQ/xr/iP/r1Df6kYZBaWiefeuPlTsg/vMewqDU7o3UosLFQ90pDGQfdg9yfX2qbR7aO3hkUgm73fv2Y5Zm9c+h7VdlbmZN+iH6fpotC00z+ddyf6yU/yHoKv0UVDd9SkrBRRRSAKjiBXMZ5A6H2qSkJwCaAFopFYOoYdDzS0AVdSgkutMu7eJ9kksLorehIIBr5+m069t702ctrKtyDt8rYcn6etfRdJtGc4GfXFd+Bx31Ry0vc58Rh/bW12Oc8MWNxpukWVrdf69LfLAn7uWJx+AOK3ajf/AJCB/wCuQ/nUlctWftJub6ts2hHlikFFFFZlHxp49/5KF4j/AOwlcf8Aow1ztdF4+/5KF4j/AOwlcf8Aow1ztZssKKKKQBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAV7B+zj/yUPUP+wVJ/6Nirx+vYP2cf+Sh6h/2CpP8A0bFQB9P0UUUAfAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFe9/s4/wDHv4k/37b+UteCV73+zj/x7+JP9+2/lLTjuJnuVFFFakh3pth/x5p9T/Ond6bYf8eafU/zo6AWaKKKkAJwMnpSKwZQw6HmmyIXTbnAPX6U+gAooooAKKKKACq13M6hYYT++lOFP90d2/Cp3dY1LMdqqCST2qtZo0m67kGHl+6D/CnYf1pruDJ4YUt4Vij+6o49/c0iW0Mc8kyRqskgAZgOTipaKLhYKKKKQBRRRQAUUUUAVr3/AI9v+Br/ADFX6oXv/Ht/wNf5ir9DGgooopDCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAKmof6hP8Arqv86l71FqH+oT/rqv8AOpe9NbCe4UUUUCCiiigAooooAiht4bcMIY1TcxZsDqT3qG7Ro2F3ECXTh1H8ad/xHUVbop31uwsNR1kRXQhlYZBHcU6qcP8Aol2bf/llJl4vY91/r/8Aqq5Q0CCiiikAUUUUANRAmcHgnOPSnU2TcIyV6jmlBDAMOh5FAC0UUUAVH/5CB/65D+dSVG//ACED/wBch/OpKvsAUUUVIHxp4+/5KF4j/wCwlcf+jDXO10Xj7/koXiP/ALCVx/6MNc7Wb3LCiiikAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFewfs4/wDJQ9Q/7BUn/o2KvH69g/Zx/wCSh6h/2CpP/RsVAH0/RRRQB8AUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAV73+zj/x7+JP9+2/lLXgle9/s4/8AHv4k/wB+2/lLTjuJnuVFFFakh3pth/x5p9T/ADp3em2H/Hmn1P8AOjoBZooo6ipAZG5fcf4c4HvT6RVCqFAwBS0AFFFFABRRTJJFiiaRjhVGSaAK1z/pNwloPuAB5vp2X8T/ACq5VWxjYRGaQfvJjvb29B+Aq1TYIKKKKACiiikAUUUUAFFFFAFa9/49v+Br/MVfqhe/8e3/AANf5ir9DGgooopDCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAKmof6hP+uq/zqXvUWof6hP8Arqv86l701sJ7hRRRQIKKKKACiiigAooooAgu4DcQFVO2RTujb0YdKW2nFxbrJjBPDL/dI6j86mqmP9G1Ar/yzuBkezjr+Y/lVCLlFFFSMKKKKACkGBgDA9qWo3B3o4ycHBHsaAJKKKKAKj/8hA/9ch/OpKjf/kIH/rkP51JV9gCiiipA+NPH3/JQvEf/AGErj/0Ya52ui8ff8lC8R/8AYSuP/Rhrnaze5YUUUUgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAr2D9nH/AJKHqH/YKk/9GxV4/XsH7OP/ACUPUP8AsFSf+jYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAr3v8AZx/49/En+/bfylrwSve/2cf+PfxJ/v238pacdxM9yooorUkO9NsP+PNPqf507vTbD/jzT6n+dHQCzUZJadQM4UZNSUAgjI6VIBRRRQAUUUUAFU7z99NDadmO+T/dXt+JwPzq5VOz/fSz3R6O2xP91eB+ZyfxpruDLlFFFIAooooAKKKKACiiigAooooArXv/AB7f8DX+Yq/VC9/49v8Aga/zFX6GNBRRRSGFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAVNQ/1Cf8AXVf51L3qLUP9Qn/XVf51L3prYT3CiiigQUUUUAFFFFABRRRQAVXvIWmtm2f61DvjP+0On+H41Yop7ARwTLcQRyr911BFSVTtf3NzPbfw581Po3X9c/nVyhggooopAFFFFADUYMuR0p1MVNpfnhjnFPoAqP8A8hA/9ch/OpKjf/kIH/rkP51JV9gCiiipA+NPH3/JQvEf/YSuP/Rhrna6Lx9/yULxH/2Erj/0Ya52s3uWFFFFIAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK9g/Zx/5KHqH/AGCpP/RsVeP17B+zj/yUPUP+wVJ/6NioA+n6KKKAPgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACve/2cf+PfxJ/v238pa8Er3v8AZx/49/En+/bfylpx3Ez3KiiitSQ702w/480+p/nTu9NsP+PNPqf50dALD52HaOccUka7I1X0FDMFKg5yxxTqkAooooAKKKKAIL2Uw2kjL98jan1PAp8EQggSJeigCoLn97eW0PYEyt9B0/U1bp9BbhRRRSGFFFFABRRRQAUUUUAFFFFAFa9/49v+Br/MVfqhe/8AHt/wNf5ir9DGgooopDCiiigAoopkkscMbSSuqIoyzMcACkA+mswVSzMABySTjFcZfeOZLu5aw8M2T6jcdDMRiJPfPf8ASo08GarrTibxLrMrg8/ZbY7UX8en6fjXVHDSSUqj5V57/duZOqr2hqbl94y8P6eSs2pws4/hiO8/pxWS3xN0RiRBBezgdSkPFbFh4R0HTQDb6ZAWH8cg3t+ZrYWGNF2pGigdgoovho939y/zF+9fZHJwfErw7K+ySW4t27+bERXQWOtaZqYBsr6CYn+FXG78utTz2FpdJsuLWGVfR4wa53UPh9oN4S8MD2U3Z7ZtuPw6UJYaXVx/H/IP3sez/A6qiuDNt4w8L/NbzDWrBescnEqj27/zrc0LxfpuunyUdre8Xhra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KKKKACiiigAooooAKq3nM9mnrNn8lJ/pVqqknzapAv8Acjdj9cgD+tNbgy3RRRSAKKKKACmBT5pftjAp9NV9zMP7pxmgCs//ACED/wBch/OpKjf/AJCB/wCuQ/nUlX2AKKKKkD408ff8lC8R/wDYSuP/AEYa52ui8ff8lC8R/wDYSuP/AEYa52s3uWFFFFIAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK9g/Zx/5KHqH/YKk/8ARsVeP17B+zj/AMlD1D/sFSf+jYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAr3v9nH/j38Sf79t/KWvBK97/Zx/wCPfxJ/v238pacdxM9yooorUkO9NsP+PNPqf507vTbD/jzT6n+dHQCfd+8KY6AHNOpu394Hz2I+tOqQCiiigAooopgVLD5Vni/55zPx7E7h/wChVbqon7vVJV7Sxhx9VOD/ADH5VboYkFFFFIYUUUUAFFFFABRRRQAUUUUwCobc+XezR9nAcfyP9KmqvOfKmhn/ALp2t9DQhl6iiioGFFFFMArnvEPhKx14ifm2vk5juouGB9/WuhoqqdSVOXNB2ZMoxkrM4JPEGv8AhVhb+ILR72yHC38AyQP9quq0zXNK1uIPZXcM3GdufmH1B5rRZVdSrAFT1BHBrjdW8KeGLydpUuF0+7B5e2kCc+46VtKrh561Pcfdbfd0+X3GahUjpHVHXPawOQWiQkdCR0rL1LWNJ0qdYbreJGXcFRS2B/nNc7Bpfi2zTdpPiK31GAcbbgc/TPP86w9cl1ea+Vtbt4IbsRgBYTlSuTg9TznNcWPnLDYd16clL5/pud2X0o4nEKlNNHeafrmj6ndi2t95lIJAdCAfpWT8RYkj8ORFEVc3S8gf7LVyukLqT6lGukyRR3pDeW0oyo4Oex7Zqz4p0XXLTSkvdY1o3bNMEECLiNSQTntzx6d65sFXni8LOrUaVrrr27anoVcNDCZhRpwu7tP8Tjj0r0aPRfEHi4q+tynT9LGCtnEfmcdtx/x/KvOj0r6Ai/1K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w339qFzyVDZx7cV6Wo2oF9BilorWnRjT+ErF4+tire16BRRRWpxBRRVa6nKARR8zPwo9B60ARSN9puhGOYojlvdvSrFRwxLDGEH4n1NSVRIUUUUgCiiigAooooAKKKKACiiigAooqrfOxiFuhxJOdgPoO5/KmAlj+9826P8Ay2b5f9wcL+fJ/GrdIiqiKijCqMAelLQwWwUUUUgCiimvkIxUZOOBQA4EHkYPvRTUXZGq+gp1MCo//IQP/XIfzqSo3/5CB/65D+dSVXYAoooqQPjTx9/yULxH/wBhK4/9GGudrovH3/JQvEf/AGErj/0Ya52s3uWFFFFIAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK9g/Zx/wCSh6h/2CpP/RsVeP17B+zj/wAlD1D/ALBUn/o2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK97/AGcf+PfxJ/v238pa8Er3v9nH/j38Sf79t/KWnHcTPcqKKK1JDvTbD/jzT6n+dO702w/480+p/nR0As02Rd8ZX16e1OopAIudo3DBxzS03cBIEx1GQfWnUAFFFFIApCAQQeQetLRTAp2RMTSWjdYuU90PT8uRVyql4rR7LqNSXhzuUfxJ3H17/hVpHWRFdSGVhkEdxQ+4LTQWiiikAUUUUAFFFFABRRRQAUUUUAFFFFAFZWNlL/07uf8Avg/4VfByMjkVAwDKQwBB6g1XSRrJtjkmA/dY/wAHsfahq47l+igHPNFIYUUUUAFFFFABRRRQAUUUUAFFFRzzpBHuf6ADqT6CgBJ51t49zcnooHUmq8ETBmll5lfr7D0oijeSTz5vv/wr/dH+NT09hMKKKKBBRRRQAUUUUAFFFFABRRRQAUUUUAFU7f8A0m6kuTyi5ij/AD+Y/nx+FOvJHCLBEf30x2qf7o7t+FTxRpDEkaDCKABT2FuPooooGFFFFIApu4eZs74z9KdTVTazHOSxoAdRRRQBUf8A5CB/65D+dSVG/wDyED/1yH86kq+wBRRRUgfGnj7/AJKF4j/7CVx/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y+we9OorSliq1G7pytc8SeLrT+KVzpNM8b6rpVnDawpbSJEmxTKjE4yTz83vV3/hZWtf8+9j/wB+2/8Aiq46isZTlKXM3qylmGIWimdj/wALK1r/AJ97H/v23/xVXbD4m3AlC6hYxtGTy8BII/A5z+dcDRSuWsxxKfxHnXjiQT+N9buUVhFcX000ZYEblZyQfyNc+a9E8X6el1pRuQoEsHII7r3FedmoZ9JgsUsTS5tn1EooooOsKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/2CpP8A0bFXj9ewfs4/8lD1D/sFSf8Ao2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA0tB/5Ddp/v/wBDXf1wGg/8hu0/3/6Gu/r18t+GR4ebfHH0CtDTdE1PWHK6fZS3GOrKMKPqTxWcehr6J8MGwi8P2EEQWDECEr0BJUEmunEV3RjdI48Lh1Xlyt2PKYfhj4jlXLJaRH0ebn9AaZcfDTxJApZYLebHaKb/ABAr3URRsMqSR7GkZIl5Z9o9zXB/aFS+yPT/ALMpW3Z8zX2nXumzmG9tZbeT+7IuM/T1qrXtvxKaym8I3ICrLNEyMjYzsO8A4/AkV4lXoYet7aPM1Y8zFYf2E+VO4jfdP0r6ehRZLGJHUMrRKCDyDxXzC33D9K+n7b/j0h/65r/KuXMNonZlXxSMkWupabIYNPCS20nKea3+oP8AUVZtdIRJhc3churr++44X/dHatKivPc2evyoYEKyZU/Keo9/Wn0UwsySfNyrcA+hqCh9FFFABRRRQAUf5xRRQBSMUtiS1upkgPLQjqvuv+FWYZo7iMSRMGU9xUlVZbUiQz2zCOY/ez91/wDeHr71W+4Fqiq0N2rv5MqmKf8AuN39we9WetJ6AFFFFIAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACikZgqksQAOTmqf2iW7+W1OyLvOw6/7o7/XpTSAknutjiGFfNnIyEzjA9T6Clt7Xy2M0r+ZOwwXxjA9AOwp8FvHboVQHnlmJyWPqT3NS0eggooopDCiiigAoooJA6nGaAGSPsHQkk4AolijniMc0aujDlWGQadtXduI+bGAaWgenUxzp95ppL6bJ5kPe1lbj/gJ7VLYWEpnN/fkPdsPlUfdiHoPf3rToq+Z2I5Thfikf+JHY/8AX1/7I1eV16n8Uv8AkCWP/X1/7I1eWVmz5rNv95+SCiitXw1HBL4m06O5x5RmGQeme364pHmwjzNI0LHwJrt/ai4WCOFGGVEz7WI+mD+tYmoabd6VdNbXsDQyjnB6EeoPcV9CJEXGeBnpXAfFCKEabZSMALgTFV9duDn9cUj2cRlkadBzi3dfceYUUUUzxTP13/kA33/XFq8qNeq67/yAL/8A64tXlNJn0WSfw5eoUUUUj2wooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK9g/Zx/5KHqH/YKk/wDRsVeP17B+zj/yUPUP+wVJ/wCjYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigDS0H/kN2n+//AENd/XAaD/yG7T/f/oa7+vXy74JHh5t8cfQQ9DXuOm/8gmy/694//QRXhx6Gvonws9hN4esJoCsx8hFZhg4IUAj2rTHStBGWWq82imFkPRW/AGkZXH3gw+orqRMgHAIHsKDKh4K5+oFeX7TyPZ9n5nm3jT/kUr7H+x/6GteSV7Z8TGsIfCdwMrFcTMgjX+/hgTx9ATXidergZXg2eLmKtUS8hG+430r6bsZo5bSHY3IjXI79K+ZG+6fpX0pFAr20DAlXEa4ZevQVnj9om2V/FI0KKqLcyQnbcDK/89F6fjVpWDDcpBB6EV5lj2RaKKKQDWcIyhuM8Zp1IyhlKsMg9aAAigZ4HrQAtFFFABRRRQAUUUUARzQR3CbJUDDt6g+oPaq2bm04Ia5hHf8A5aL/APFfz+tXaKdwsRwzxXCb4nDDv6j6ipKrzWccr+YN0cv/AD0Q4P4+v41GJbq34mj89B/y0iHzfiv+H5UW7Cv3LlFRQ3ENwu6Jw2OoHUfUdqloGFFFFIAooooAKKKKACiiigAooooAKKKKACiiigAooopgFFFVpb2JHMcYaaX/AJ5xDJH17D8aALNVprxEfyo1aab+4nb6noPxphhubn/XyeTGf+WcTcn6t/hViKGOBNkSKq+gFFgvcri1ech7xlYA5EK/cH19T9fyq5jHSiii4WCiiikAUUUUAFFFITtBJ7elAC0wRkvufBx90elCbySz8Z6L6U+gAooooAKKjlnjgGXPJ6KOpqsfOuPvkxRn+EH5j9adgOO+KEyPo9kitlhc5Pt8jV5ea9O+JiKmh2KqoA+09v8AcavMamR8xm3+8/JBW34W0KXXdYjiVzHBFiSeYHGxR7+tXvB+hW2ptNc3aiSOJgqxk4BOM813es6DJa+FZ7Lw/BFFJcEGUoypvHcZJpGeEwcqq9o/hX3mNqHxP8i/mhs7FZ7eM7YpGkKlsd8Y6VT8RH/hMvDsOvWmftNmCl1bA52jruA/zx9KwP8AhCdfx/x5x/8AgTH/APFV0fgvw/r2k635k0KJaSRlZk85GDjsMA/r/jRY6lWxFeXs6sXyvy2/4Y88680V6v4g8HaUySpa28cEpUujR8YPofavKKDz8ThZ4eVpGfr3/IAv/wDri1eU16trv/IBv/8Ari1eU0mezkn8OXqFFFFI9sKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf8Akoeof9gqT/0bFXj9ewfs4/8AJQ9Q/wCwVJ/6NioA+n6KKKAPgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKANLQf+Q3af7/APQ139ebWk5truKdRyjA16LBNHcwJNEwZGGQa9XLZK0keLm0HeMuhJV3T9W1DSpDJYXk1ux67G4P1HSqVFek4qSszyYylF6M62L4k+JolA+1QyY7yQgmmXHxF8TXClftqRZ7xRAGuVorL6vS/lNvrVbbmZPd3l1fTma7uJZ5T1eRiTUFFFaxSirIxlJyd5CN90/Svpm3/wCPWH/rmv8AKvn3w1pD634gtLJMbWcPJk4+QcmvoUAKAo6AYFedj5L3V1PWyuL96XQUgEYPSofKaJi0DbfVD901NRXn3PXEiu1dtkg8uT0PQ/Q1Yqs8ayLtdQRUatPb9Myxen8QosBdpCAwwQCD2NMimjmXKNnHUdxUlIBiKU43ZXtnqKfRUZV1bchzn7yn+lICSiiigAooooAKKKKACiiigCCazgnbc6Yk7OvDD8RUQju4P9XKsyf3ZeD/AN9D+tXKKd2FioL9U4uYpID6sNy/99D+uKsRyxzLuikV19VYGn1XksLaVy5iCv8A30JVvzHNGgtSxRVT7JOn+pvJB7SgOP6H9aM36dUglHsSposFy3RVT7XMv+ssph/uENS/2hEPvxzp/vRH+lFmO5aqK4uYbWMSTuEQsFBI7k4AqIalaf8APUj6ow/pWZrt7byafGEmBYXER6EcBhTUW3YTdkbtFVTqNmD/AK8fgp/wpP7StT91nb6Rt/hSsx3Rboqp9vB+5bXL/SPH86PtF233LPHvJIB/KizC5boqpsv3+9LBEP8AZUsf1xR9gVz+/nnl9i+0fkuP1osK5JLeW8DbZJVDHooOWP4Dmo/tNxLxBbED+/Mdo/Lr/Kp4beGBdsMSIPRVAqSjToPUp/Y3l5up2cf880+Rf8asxxRwoEjRUUdlGBT6KLhYKKKKQBRRRQAUUUUAFFFM8wF9ijcR1I6CgBXcIB3J6Ad6VSSvzYBxyBS479/WigAooqvLdKrbIx5knoOg+tMCdmCLuY4HqaqtcyTHEAwv/PRv6Cm+S0jb7htx7KOgqansBHHCqHcSWc9WbrUlFFFwOI+Jw/4kll/19f8AsjV5fXs/jPSm1Xw3OkYHmwnzkyeuOo/LNeMdehyPWokfNZvBqupdGjX0HX5tDmfaglhk+/GTj8R71c13xZJq9r9lig8iBjl8tlmx2rnKKRwwxNSEOSL0E2j0FXNL1CbSb5Lq3C7l4Know7g1UooM1UmndM66/wDHMtzZPBbWnku67S7NnA74rkaKKC61edZ3mzP13/kA33/XFq8qNeheMNRS20s2gYGWfjA7L3rz01LPfyWDVFyezYlFFFB7AUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFewfs4/wDJQ9Q/7BUn/o2KvH69g/Zx/wCSh6h/2CpP/RsVAH0/RRRQB8AUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAtaWmaxc6a2EO+I9Y26fhWZRVQnKDvFkzhGa5ZK6OwTxdakfPbzA/7OCP6U7/hLbH/AJ43H5D/ABrjaK61j63kcLy2g31Oy/4S2x/543H5D/Gj/hLbH/njcfkP8a42ij+0K3kL+zKHmdl/wltj/wA8bj8h/jTJfFtvsPk28hb/AGyAP0zXIUUPH1vIayygn1NKbW7+W+S8S4eGaI5iMTFdh9sV6z4L+O91aGOy8UxNdQD5RexD94v++vRvqOfrXilFcsqkpO7O6EIwXLFWR9v6TrOm67YJfaXeRXVu38UZzj2I7H2NXq+KNC8Sat4avlvNIvZbaUddp+VvZh0Ne9eC/jnpmq+XZeI0TTrw4AuV/wBQ59/7h/MfShSCx67RTY5EmjSSJ1eNwCrKcgj1B7inVQiKSEM29SUkH8S0q3LxHbcLgf316fjUlBAIwehp3AmBDAEHIPQilqkInhJa3bHqh6GporpZG2ODHJ/db+lKwErqWGAxU9jQm8gh1wR3HQ06jvQAUVGRIrblIYd1PH61JQAUUUUAFFFFIAooooAKKKKYBRRRSAKPxoopgHXrWT4hA/s6M4H/AB8xf+hCtasnxF/yDY/+vmL/ANCqofEhS2ZrEAE4Ao59aU9TSVIwooooAKKKKQBRRRQAUUUUAFFFFABRRRQAUjMqrliAPWmiRWfCZb1I6D8acVVmDEZI6UAIrblzggH1pQoUYUAD2paRiFUsxAA7mmAtRyzxwrl2+g7moGuXlO23HHeRun4URwKjFmJd+7HrTsA0ma465ijPYfeNSJGsa7VXAp1FFwCiisvXvEekeGbA3msX0dtEOm45Zz6Ko5JpAalcj4v+I/h/wdEy3lz597jKWcB3Pn37L+P5V494z+Oep6sJLPw9G2m2RypnY5mcfX+EfTn3rySaWSaVpZXZ5GOWdjksfUmpcirHb+Mvil4g8Xs8DzfYtOPS0t2IBH+23Vv5e1ZGkeK7rT41gmX7RCOmThl+hrnKKhu5nVo060eWaujvh450/HNvc59gv+NL/wAJzp3/AD73P5L/AI1wFFO5wf2RhvM7/wD4TnTv+fe5/Jf8aP8AhOdO/wCfe5/Jf8a4Cii4f2RhvP7zv/8AhONOP/Lvc/kv+NVrrxyhjIs7Vg/ZpSOPwFcTRSuxxynDJ3af3k91dTXk7TTyM8jHkmoTSUUHpRioqy2CiiigYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFewfs4/wDJQ9Q/7BUn/o2KvH69g/Zx/wCSh6h/2CpP/RsVAH0/RRRQB8AUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQB2HhD4keIPBsqrZ3Pn2OctZzndGfp/dP0r6F8G/FPw94vVIFm+w6icA2twwG4/7DdG+nX2r5KpwYqwKsQRyCO1NMVj7ror5m8F/GvWdAEVlq4bVLBeAzN++jHsx+99D+de/eG/Fui+LbP7TpF6k2B88TcSJ/vKef6VaaYrG3TZI0lXa4yP5U6iqEQq81v1zLH/AOPD/GrUcyTLlGzjr6io6ieEM29CY3/vL/WjcC5SMAykHP4VVW6aMhbhdvo45H/1qtAggEEEHvSAaiuhwWDLjgnrTsjOMjPpS010Vx8wz/OkA6ikVdqgZJx3JpnmqG2uCp7EjrTAkooopAFFFFABRRRQAUUUUAFZPiL/AJBsf/XzF/6EK1qyfEX/ACDY/wDr5i/9CFVD4kKWzNc9TSUp6mkqRhRRRQAUUUUAFFFFABRRSZGQCRk9qAFoprl8DYAT7nGKEVgDubJ+mBTAa0mDtVSzfkB+NPxlfmA56ilooAAAAAOg6UVHLNHCuXbHoO5qszT3HrFH/wCPGiwE0t0qNsQeZJ/dHb61D5TykNcNux0QfdH+NSJGka4RQKdTAO3HSiiikAVFc3VvZW0lxdTRwQRjLySMFVR7k9K4Hxn8YNB8LeZa2jDU9SXI8qFvkQ/7Tf4ZNfPfizx5rvjG536ndkQKcx2sWViT8O59zmk5Idj17xp8eLS08yy8LRi5mGVN7KuI1/3V7/U4rwrWNZ1HXr5r3VLyW6uG6vI2cewHYewqiTSVDZVgooopAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABXsH7OP/JQ9Q/7BUn/AKNirx+vYP2cf+Sh6h/2CpP/AEbFQB9P0UUUAfAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFAC1a0/UrzSryO7sLqW2uYzlZImKkflVSigD3jwV8eQ3l2PiuLB4Av4E/V1H81/KvbLG/s9Ts47yxuorm3kGVlicMpr4cBxW74a8Y634SvBcaRevCM/PCx3RuPQqeDVKQrH2fRXmHgv41aJ4i8uz1bbpeoHAG9v3Mh9mP3T7H869PBBGQQQehFWmIQgEEHp6etRCKSA7oG47o3T8PSpqKYgiuUkbY2Uk/utU9VZIklXDDPv3FMEk1vjdmWP1/iH+NFgLtFMjlSVdyMCO/tT6QxCMgjJHvTVWQEAuGX3GDT6KQhrOEGSDj2GaEkRwdrA4p1FMAopjxhznLA+xxTlXauNxPuaQC0UxhLuyrJj0INOGcDPWgBayfEX/INj/6+Yv8A0KtLdLn/AFYx6hv/AK1ZviL/AJBkfGT9pi/9CqofEhS2ZrnqaSmbnL4MeB67qc2QPlAJ9zipGLRTFMhPzhQPY0rhj919v4ZoAdSEgdSB9aRVKjli3uaGjRm3MoJ96YCggjIORTC0hJCx4APVjgVIAAMAYFFACEZUg9/Q01I0T7qjPr3p9FIAooqCW6SM7FG+T+6P60wJiQoySAB61Va6aUlbdcj/AJ6Hp+FN8t5iGuGyOyDoKmAAGAAAKYESQBW3sS8ndmqWiigAoqlq2sadoVi97ql5FaW6dXlbH4AdSfYc14X40+PNzdeZZeFomtouVN7Mv7xv91f4fqcn6UrjPXvFXjnQfB9sX1S8XzyMpbRfNK/0X09zxXz340+MOu+KfMtbRjpumtx5MLfPIP8Abf8AoMD61wF1eXF7cvcXU8k87nLSSMWJP1NQVDkOw4nOetNooqRhRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABXsH7OP8AyUPUP+wVJ/6Nirx+vYP2cf8Akoeof9gqT/0bFQB9P0UUUAfAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAKDiu78GfFbxB4RMdv5v27TV4+yzsTtH+w3Vf5VwdLmi4H2B4Q+Ivh/xlEq2Nz5N6BlrOfCyD6dmH0rrP518LRTSQSrLE7RyIcq6HBU+oIr13wX8dNR0wR2XiRG1C0GALlf8AXIPfs/8AP61akTY+jKKzND8Q6T4ksFvdIvYrqE9dp+ZPZh1B+tadWBE8ALb0by5P7w7/AFpyXRjIW4Xb6OOh/wAKfSEBgQQCD2o33EWAQRkHNFUhHJAcwHK/8826fh6VPDcpKdpyj/3WpWAmooopAFFFFABRRRQAVk+If+QbH/18xf8AoQrWrlvF3iHTLCKOznuB9o82OQxqCxChs5OOlaU4ylNKKuyZtKLudUeppKq2Go2mq2q3VlMs0LdGXt7H0NWqhpp2ZSd9gooopAFFFFABRRSEgAk8Ad6YC0ySZIV3OwHp71A900h2267v9s9B/jTUhCtvcl5P7x7fSnYBGea46Zij/wDHj/hUkcaRDCLj+dOoouAUUVxPjL4o+H/B6vBJN9t1EDi0tyCQf9o9F/nSGdpJIkMbSSuqRoMszMAFHqTXk3jT45aXo/mWfh5F1G8GQbg8Qofbu34cV494w+JXiDxlIyXdx9nsc5WzgJCf8C7sfr+lcfmoch2NbX/E2r+Jr83mr3slzJ/CCcKg9FXoBWRQaKkYUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABXsH7OP/JQ9Q/7BUn/AKNirx+vYP2cf+Sh6h/2CpP/AEbFQB9P0UUUAfAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRmiigDQ0fXNT0C+W90q9ltbhT96NsZ9iOhHsa938F/HazvRHZeKY1tLg4AvIx+6b/eHVT79PpXzxS5pp2A+6Le4hu7dLi2lSaGQZWSNgysPYipK+OvCfj7X/B1wG0y7Jtycvay/NG34dvqK+hPBfxd0HxZ5drOw03U2wPs8zfLIf9hu/wBDg/WrTTJseg0ySJJRhhz2I6in0VQiJZZrfhwZY/7w+8P8asxypMu5GDCo6ieD5vMiJjf1HQ/WgC5RVVLsqQlwuwnow+6f8KtA56YpAFFFFIArwnxnZ3dr4pv2ulb99KZI3boynpg+w4/CvdqjlghuABPDHKByBIobH512YHFfVqvO1fQxr0fawtexwvwts7uDTL2eZXWCaRTEGGM4By36gfhXfUgAACgAAdAKWs8VX9vVlUta5VKn7OCgFFFFc5oFFMklSJNzsAKrNLNccLmKM9/4jTsBLNcpEdgBeQ9FWoTHJOd07cdkHT8fWnxxJEuFXGep7mn0wEAAGAMAdKWiq99fWmm2cl3fXMVtbxjLyyuFVfxNICxWL4j8V6L4Usjc6xepAD9yPrJIf9lRya8m8afHpU8yy8Jw7j0N/OnH/AEP8z+VeIajqd7q1695qF1Lc3LnLSStk0nKw0j0nxr8bdZ14yWmih9L085BZT++kHuw+79B+Zry1nZ3LuxZicknkmmk5oqG7lBmiiikAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAV7B+zj/AMlD1D/sFSf+jYq8fr2D9nH/AJKHqH/YKk/9GxUAfT9FFFAHwBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABS5OetJRQB6V4L+Meu+GfLtb9m1PTV48uVv3iD/AGXP8jX0F4W8b6D4wtvN0q8VpQMyW0nyyp65XuPccV8Z5qe0vLixuo7m0nkgnjO5JImKsp9iKpSFY+5qK8B8F/HmeAx2XiqIzR9Bewr84/31HB+o/KvctL1bT9asUvdMvIrq2cZEkbA49j6H2q07isWyoYEEZB6iogksBzC2U7xt/SpqKdxCw3KS/LyrjqrdamqpJEkgG4cjow6ikE00HEgMkf8AeA5H1osBcopsciSpuRgQfSnUgCiioZrlIjtGXc9FXrQBMSB16VVe6LkrbruP98/dFMKSTnM5wnaNf61KAFGAAB6CnawEaQYbfITJJ6noPpUtFHtRcAoPAJJwBXK+LfiF4f8AB0JF/dCW8IylpCQ0h+v90e5r568Z/FfX/F2+2En2DTW4+ywMRvH+23Vvp09qTaQ7HsXjP40aH4d8y00orqmoDjCH9zGfdu/0FfP3ifxlrni678/Vr15FBykC/LHH9F/r1rBzSVm5NjsGaKKKQwooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/wBgqT/0bFXj9ewfs4/8lD1D/sFSf+jYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACtjw94n1jwxfC70i+ktpP4lByrj0ZTwR9ax6KAPpTwX8cNJ1vy7LX1TTL0/KJs/uJD9Tyv0OR716wjrIgkRlZGGQynII+tfCgrsvB3xM8QeDXWO2uPtNhn5rSckrj/AGT1U/SrUhWPrqiuL8G/E/w/4xVYYJ/smokc2c7AMT/sHo34c+1dpVXJIWgw2+JjG/t0P1py3mz5bhdjf3uxqSggEYOD9adwImlmuOIwYo/7x6mnRxJEMKOe5PU0+ii4BRUc88NtA89xKkUKDLySMFVR3JJ6V4940+O9lYeZZeGI1vLjkG8kH7pT/sjq38vrSbGep63r+leHbBr3Vr6K1gHQueWPoo6k/SvB/Gnx11DUvMsvDSNYWpypuX/1zj27J/P3FeXazrup+IL5r3Vb2W6uGP3pG4A9AOgH0rNPWochpEk80txO800jySOcs7nJJ9zUdFFSMKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/2CpP/AEbFXj9ewfs4/wDJQ9Q/7BUn/o2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAHpI0bKyMVZTkFTgg16p4L+N+r6GI7PXQ2p2I4EhP79B/vfxfj+deUUU07Afavh3xTo3iqyF3o96k6gZdOkkfsy9R/Ktivh7TdVvtHvo73T7ua2uIzlZImwf/AK49q9s8J/H5Ftjb+KbVjKikrdWqf6w/7SdifUcewqlIVj3X8M1wHjP4ueH/AAn5ltDINR1JcjyIGBVD/tt0H0GTXjnjX4y654m8y005m0zTW4KRN+9kH+0/9B+teak5zySTQ5BY6nxb8QNe8Yzk6jdlbUHKWkPyxL6cdz7muWJzSUVAwooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAr2D9nH/AJKHqH/YKk/9GxV4/XsH7OP/ACUPUP8AsFSf+jYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/2CpP8A0bFXj9ewfs4/8lD1D/sFSf8Ao2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiinrEzjKqT9KAGUU943TG5SM+tMoAKKKkEEp/gb8qAI6KUjBwetJQAUUUUAFFFORd7hfU4oAbRVl7RkQtuBwKrU2mgCiiikAUUUUAFFKFLEADJNPMEgBJRgBRYCOiinKjOcKCTQA2ipDDIBko2KjoAKKcsbOcKpJ9qVonQZZSB70WAZRS0lABRRRQAUUUUAFFFFABRRRQAUUUUAFFTxWxlTcGApksXlPtJzTs7XC5HRRRSAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/wBgqT/0bFXj9ewfs4/8lD1D/sFSf+jYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKK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5S5hJWLtrIiwkM6g57mobplabKkEY7VBRT5tLBbW5JEQJkJOBmrsssZiYB1Jx61nUUoysgauFOU7WBHam0VIzT86M/xr+dVbuQO4CkEAdjVairc7qxKjqKODmtITRlR+8X86zKKUZco2rlq7kV9oVgQOeDVWiik3d3BKxet7hSgVjhh609xb53ttz9azqKpT0sxWLq3amXHRMYFSSmB1yzqcdMGs6ihT6MOUXvWjHOjqPmAbHQ1m0UoysNq5cnWERkrt3H0NVFYqwI6ikook7gkaEdzG64YgHuDS7IFbd8n58VnUVXP3QuXsXZrpQpWM5J4z6VS70UVMpNjSsXbWRFhwzqDnuahumVpsqQRgdKgooctLBbW5JEQJUJOBmrsssZiYB1Jwe9Z1FEZWBq4UUUVIwooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAr2D9nH/AJKHqH/YKk/9GxV4/XsH7OP/ACUPUP8AsFSf+jYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/2CpP8A0bFXj9ewfs4/8lD1D/sFSf8Ao2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKALlrpV5ewmW3h3oDtJ3Ac/ialfQtRRCzW+FAyfnXp+dXbO2N14YeMSxRkXOd0jbR90VSl0poomkN5ZsFGcLLkn6CrsrCuZ1TW1rNeTiGBC8h6KKirU8P8A/IVX/rm/8qlbjZmyRPFI0cgKupwwPY0+a2ltxGZV2iRQ6e49a074DU7IaggHnxfJcAd/RqZrX+r0/wD69F/mabQrmT1rSTQdSkRWW2yGGR868/rWbWp4e5121/3v6UkDIZ9HvraFppodsa9TvU/1qjUtwT9ol/3j/OoqGCLdppl3fIz20W9VOCdwGPzNTnQNSAybbjr99f8AGrmmQG58PXsQkjjJmQ7pGwOnrVN9JdI2Y3tkQBnAmyTTtoFzNIwSD2qWCCS5mWGFd0jHCr61FWjoX/Iatf8Af/oaS3GO/wCEf1P/AJ9j/wB9r/jVGe3ltpTHNGyOOoYYrUm0S/lvZTGiHdIxH7xc9frSa3MjJaW/miaaCPbJIpyCfTPfFNoVzHq7baRfXcImggLxkkBtwH8zVKt+OzuLzwzAltE0jLOxIHpSSBmZc6Ve2kfmT27Kn94YI/MVTrobS2n0uyvTfjy45IiiRMwyzHoQK580NBcmtbSe9m8q3Qu+CcA1bOganj/j2J+jqf5Gp/DQLamyjvE4/SmRaHqBcFQibeS/mj5R69aaWgGZJE8MjRyKUdTgqwwRTK1NduIrjUQYnEgSNUaQfxsOprLpPcaJpLWaKCKZ0xHLnY2euOtQ1saif+JFpX0k/mKx6GgLFrZXF65S3iLkcnsB+JqafR763iMskP7sdWVg2PyNWtOnt5NMnsJpzbtI4dZMEg47HFOGn6hYwyzWc8c0LKQ5gcN8vuKdhXMbFSW9vLdzrDCu6Rui561Ga1PDn/Idtv8AgX/oJpJajG/8I/qf/Pt/4+v+NUrm1ms5jFOm1wM4yD/KtCTSHaVz9tsuWPBmrOuIjBO0ZdHK/wASHIP0NNqwkRUUUVIwooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/2CpP/AEbFXj9ewfs4/wDJQ9Q/7BUn/o2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKANuz+z3GgNaSXkMEn2jf+8z0wB2qE6XbAH/ibWfTp83P6VlZozTuKwprQ0WaK31ESSuEQIwyfpWdRQhl3Tr37Fd7mG6F8rIn95TVnXZLZ5bZbWYSxxwhNw+prJozQmKwVoaJNHb6xbyyuEjVssx6Dis+ikhkk5BnkIOQWOD+NR0UUAbWmtby6LdWkt1FA7yqy+ZnBA+lRf2VbdP7Xs/8Ax7/CsrpS5p3EDDaxAOcHqO9XtHljg1W3llcIitkseg4qhRmi+oy4100GpvcwPyspZSO4zU2q/ZZZVubV1AmG54u6N3rOzRmi4rCDrWpJcRHw7BAJB5qzMxTuBWXRQnYYuT60lFFIDU0K4ht79nmkCL5TjJ9SKrWF69jdpOvIHDL2Ze4qpRmncVi7qUVsl2WtJVeB/mUD+HP8JqlRmikxmpfTxS6Rp0SSAyR796jquSMVl0uaSm3cDRtIrG5tGjkmFvchsiR8lWHp7VcsRbaRK9y99FM2xlWKEk7iRjn2rCzS5oTFYVjkk+9X9Dnit9XglmcJGM5Y9uDWdRRfUZrvpls8jN/a9nySf4v8KoXdulvKEjuY5wVzujzge3NV6KGxBRRRSGFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAV7B+zj/AMlD1D/sFSf+jYq8fr2D9nH/AJKHqH/YKk/9GxUAfT9FFFAHwBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFewfs4/8lD1D/sFSf+jYq8fr2D9nH/koeof9gqT/ANGxUAfT9FFFAHwBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAVfh08NaJcz3CQRuSEyCS2OvAqhWnFeeVZwwX1l5sHLRMSVYA9cHuKaBkF3ZfZ0jkSaOaKTO1kPcdQR2qqY3ChijBT0JHBrZjsLOWWyuIDJ9nknEbxy9QfqOoqO5v7xru8h/1keXUxEZCqD1A7Yp2FcyljkYEqjEDqQOlIFJzgE4rfjeS0WyilvmhYqrLFDFuyCeNxyMk1I+La81wxqFKgbRjodwo5Quc6yOhw6sp9xim1rzTSXXh/zJ3MjpcbVZjkgEVm2yRSXCJNL5UZPzPjOPwpNDI60V0xPssM8t7FCJQSqsCT+lZ5xng5Fbc8trHpOnfabZ5iUbG2Xbjn6U0JmbcW0UIXybqOcseiKePzquY3CltjbRxnHFX7aS2l1SyFvbtEBKu7dJuzyPatCC6mm1m8t3cmArMPL/AIRgHHFFgOfEbkZCMR14FSzRxoyCJ2fKgncuOfStOa5lt/D9isTlPMMoYjgkZ6Zq5gLeNKFBkh04PHkZwwA5osFznkgYzxxurJvYDkepqW7tGtrmeJdzrE5Xft9KsxXt1c+Uk2ZUWdSJGGSpz0zWkt3PJ4mlti58gu6GP+EjHpQkFzmqKeww7DsDT50hRYjFL5hZcuNuNp9PepGS2Fib0y/vkiWJN7MwPT8KsJpSzkrbX0E0uCRGAQT9M0/Q/L233m7vL+zndt64yOlWbL7FDFNe2SXElxAMhJWAwDxu4HOKpITZhhGZ9qqS3oBmk2tu27Tu9Mc1uWjRxaIZvtLW7yzkPIibjwPu+w71Nbz29xq2mlJTLKuVkkaMru4OPrRyhc57y3ChijbT0OOtIyMhw6sp9CMVuWd9PJZakXfPloHjBHCHdjj0qSDF/BphumL5uShZu68cUWC5gGNwgcowU9CRxQsbvkqjHHXAziuhN7AL2YXF9JLE25Wt/JIA64A54xVSeeS00ixFu5jEm53ZeCxzjmiwXK01jFbyRLJM22S3EwITOCR069PeqSxu4OxGbHXAziuncl9UVmABOmEkY6HaaoRNJa6fah71rcPl0SGPLNz1Y5FNxC5l21rLdOyRISVUsfYDmoxG7ttVGZh2A5rpnZoNcvhESga0LnHHzbQc/nVaKRY9FimN29vJNK2+RU3M2MYBOaXKFzAIIOCCD70laWrTwXBt3jkaSUJtkkKbd3PBx9KzaljCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf8Akoeof9gqT/0bFXj9ewfs4/8AJQ9Q/wCwVJ/6NioA+n6KKKAPgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAq9Bqc8MAh/dyRDlVlQNj6VRooAt3GoT3OzcwVYzlFRdoU+wFSyavcyxup8sGQYd1QBmHuaz6Kd2KxfGrXPlov7vdGu1ZNg3gemaSXVLibztxTMyBJCExuA5/OqNFF2Fib7TJ9kNrkeUX34xznGKhoopDFFXo9XuI7eODZAyRjC74gxH41QooAvPqk0jxPsgVo3DqUjA5HrUUd9NFdPcqV8x92444+brVaincCeS6kktoYGI8uLdsGPU5NS/2lci5jnDgPGgRcDsOxqnRRdgXZdTnlVFHlxojbwkaADd6mmC/nW+N4CvnFixOOMn2qrRRdgOY7iT3NNoopAT291JbLKsZAEq7GyM8UWt1LZzCaFgGAIwRkEHsagoouBbt9Qlt1dFCNG5y0bLlc+uKcdUuPtcVwCqvEMRgLhVH0qlRTuBPFdyQxTxoQFmXa+R2zmlF3KLeOAPhI3Lrgcg/Wq9FFwNB9YuXDH90JHGGkWMBj+NMg1KaG3EGI3jB3KJEDbT7VSoouBebVrp5/PZ1MnlGEnb1U9fx5oj1OdLdIcRsIwQjMgJXPoao0UXYWND+17r7Qk5ZGkVNhYpncPRvWmR6nNEsiBYmjc7jGyAqD6gdqpUUXYrE91dy3cgeUjIG0BRgKPQCoKKKQwooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAr2D9nH/AJKHqH/YKk/9GxV4/XsH7OP/ACUPUP8AsFSf+jYqAPp+iiigD4AooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAoopcUAJRXR6N4Nv8AV4hOWW3t2+68g5b6CtkfDY451Uf+A/8A9lXVTwVeouaMdDGeIpQdpM4Oiu9/4Vt/1Ff/ACX/APsqP+Fbf9RX/wAl/wD7KtP7NxX8n5EfW6P8xwVFd7/wrb/qK/8Akv8A/ZUf8K2/6iv/AJL/AP2VH9m4r+T8g+t0f5jgqK7S7+HV3FEWtbyOdgPuMmwn6ckVyE9vLbTPDMjJIhwysMEGuerh6tH+IrGtOrCp8LuRUVLDBJczJDCjSSOQqqoySfSvQ9M+D2p3Vust/fw2bMM+WE8xh9cED9a46+IpUI81WVkbwpym7RVzzeivV/8AhSp/6D4/8BP/ALOj/hSp/wCg+P8AwE/+zrj/ALXwX/Pxfj/ka/Va38p5RRXq/wDwpU/9B8f+An/2dH/ClT/0Hx/4Cf8A2dH9sYL/AJ+L8f8AIPqtb+U8oor1f/hSp/6D4/8AAT/7Ouf8Q/DHV9DtXu4ZEvbZOXMQIdR6lfT6E1pSzPCVZcsJq5MsPVirtHEUUuK0NI0S91u7+zWURdurMeFUepPau1tJXZkk27IzqK9Eh+FUrRgzasiP3CQlh+ZI/lUn/CqP+oz/AOS3/wBlXI8wwydnM7VluKauofkeb0V6R/wqj/qM/wDkt/8AZUf8Ko/6jP8A5Lf/AGVL+0cL/P8AmH9mYv8Ak/I83or0j/hVH/UZ/wDJb/7Kkf4UsFymsKT2Bt8D/wBCo/tHC/z/AJh/ZmL/AJPyPOKK2td8Mah4fmVbtA0T/cmTlG/wPtWNiuuE4zXNF3RxzhKEnGSsxKK3dG8K3+sr5qbYbf8A56ydD9B3reHw4451T/yB/wDZVMqsI6NnTRwGJrR5qcG0cJRXef8ACuP+op/5A/8AsqP+Fcf9RT/yB/8AZVPt6fc1/srGfyfl/mcHRXef8K4/6in/AJA/+yo/4Vx/1FP/ACB/9lR7en3D+ysZ/J+X+ZwdFdtcfDq4SMm3v45H/uumzP6muRvLKexuWt7mMxyr1UirjUjL4Wc9fCVqH8WNivRS4pKs5wooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAK9g/Zx/5KHqH/AGCpP/RsVeP17B+zj/yUPUP+wVJ/6NioA+n6KKKAPgCiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAFFaOh2a3+tWdq/3JJAG9x1P8qzhVrTrxrDUbe7UZMThsevqKuFuZX2E72dj25VVFCqAqgYAHYUtV7K9g1C0S5tpA8TjII7ex96sV9zBxcVy7HzUk7vm3CiiiqJCiiimAe1cD8RbGNWtL5VAkcmNyO/cV330rzTx3rMV/eRWdu4eO3zuYHILH0+grzszcFhnzfL1OvBKXtlY3Pg9pcNzq97qEqhntEVYgezNnn8lP517LXhHwx8RwaHrskF44jtb1Qhc9EcH5SfbqPxr3fORkHI9fWvxziFVfrScvhtp+p9rgWvZ2W4UUUV4B2hRRRQAUEAgggEEYIPINFQXt7badZy3d5KsUES7ndqErvQTtbU+ePG2mRaR4v1C0gULEHDovoGAYD9a9I8B6dFY+F7eVFHmXP7127nsK8s8Sasdc8Q3molSqzSEoD2UcD9AK9D+Hmuw3ekrpTuFurfIRSfvp7fSvvMXGt9Qipb2V/u1/E48tdP647+dvU7aigUV80tj6sKKKKACiiigDO13TotU0S7tZVBDxkqT2Ycg/mK8Jsrf7Vf29vnHmyKmfqcV7P4v16HRdFmBcfap0KQxg888Z+grxS3ma3uY5k+9GwYfUV9Hkymqcr7dP1/Q+aztwdWCW/X9D26CGO3gjhiUJHGoVQOwqSqel6lBqtjHdQMDkfOueUPcGrlVK6bUj6mi4OmnT2toFFFFSahRRRQAVxvxBsY30+3vgoEsb+WW9Qen8q7KuB8eaxFN5WmwOHMbb5SDwD2FbUL86sefmrgsJPn7aevQ4ekp1Nr1D4MKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACvYP2cf+Sh6h/2CpP8A0bFXj9ewfs4/8lD1D/sFSf8Ao2KgD6fooooA+AKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAUUUlFAF2x1W+01y9pcyRE9dp4P1HQ1pjxpr/8Az/D/AL8p/hXP0VvDE1qatCTRnKlTl8UUzoP+E11//n+H/flP8KP+E11//n+H/flP8K5+ir+u4j+d/eL2FL+VfcdB/wAJrr//AD/D/vyn+FH/AAmuv/8AP8P+/Kf4Vz9FL67iP5394ewpfyr7jYu/E+s30RinvnKEYKqAgP1wBWSST1ptFZ1K1So7zk36lxhGHwqwucVvab408RaRAILLVJUiHCo4DqPoGBxWBRXPUpU6q5ZxTXnqaRnKOsXY63/hZni7/oKj/wABov8A4mj/AIWZ4u/6Co/8B4v/AImuSorn+oYT/n1H7kX7er/Mzrf+FmeLv+gqP/AeL/4mj/hZni7/AKCo/wDAeL/4muSoo+oYT/n1H7kHt6v8zOt/4WZ4u/6Co/8AAeL/AOJrH1XxHq+tsp1G/lnCnKqxwoPqFHFZVFXDB4enLmhTSfohOtUas5MdmnRyyQuskbMjqchlOCDUdGa6GQnbU6OLxz4jgjCLqTEDu8asfzIzTv8AhP8AxL/0EB/34j/+JrmqK53haD1cF9yOhY3ELRTf3nS/8J/4l/6CA/78R/8AxNH/AAn/AIl/6CA/78R//E1zVFH1TD/yL7kP67if+fj+86b/AIT/AMS/9BAf9+I//iaa3j3xI6lTqOAf7sKA/mBXN0UfU8P/ACL7kH17E/8APx/eWLq8uL2dp7mZ5pW6u7ZNQUlFbpKKskc8pOTvJ3Zbs9Qu9Pl820neJ+5U4zWr/wAJnrwHF6P+/Sf4Vz9FJwi90bU8VXpLlhNpep0H/Caa/wD8/o/78p/hR/wmmv8A/P6P+/Kf4Vz9FT7Kn/Ki/r+K/wCfj+86D/hNNf8A+f0f9+U/wo/4TTXv+f0f9+k/wrn6KPZU+yD6/iv+fj+82rjxVrd1EUkv3CnghAEz+QFY5Ysckk02jNVGMY7Iyq16tX+JJv1YtJRRVGIUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFewfs4/8lD1D/sFSf+jYq8fr2D9nH/koeof9gqT/ANGxUAfT9FFFAHwBRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFewfs4/wDJQ9Q/7BUn/o2KvH69g/Zx/wCSh6h/2CpP/RsVAH0/RRRQB//Z" alt="VulnWatch Enterprise logo" />
                <h1>VulnWatch Enterprise &mdash; Fleet Vulnerability Dashboard</h1>
            </div>
            <p>Generated: $(Get-Date -Format 'MMMM dd, yyyy HH:mm:ss') | Devices: $($fleetStats.TotalDevices) | Total Vulnerabilities: $($fleetStats.TotalVulnerabilities)</p>
        </div>

        <!-- Fleet Statistics -->
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-number">$($fleetStats.Critical)</div>
                <div class="stat-label">Critical</div>
                <div class="stat-sublabel">CVSS 9.0-10.0 | Avg: $([Math]::Round($fleetStats.Critical / $fleetStats.TotalDevices, 1)) per device</div>
            </div>
            
            <div class="stat-card high">
                <div class="stat-number">$($fleetStats.High)</div>
                <div class="stat-label">High</div>
                <div class="stat-sublabel">CVSS 7.0-8.9 | Avg: $([Math]::Round($fleetStats.High / $fleetStats.TotalDevices, 1)) per device</div>
            </div>
            
            <div class="stat-card medium">
                <div class="stat-number">$($fleetStats.Medium)</div>
                <div class="stat-label">Medium</div>
                <div class="stat-sublabel">CVSS 4.0-6.9 | Avg: $([Math]::Round($fleetStats.Medium / $fleetStats.TotalDevices, 1)) per device</div>
            </div>
            
            <div class="stat-card low">
                <div class="stat-number">$($fleetStats.Low)</div>
                <div class="stat-label">Low</div>
                <div class="stat-sublabel">CVSS 0.1-3.9 | Avg: $([Math]::Round($fleetStats.Low / $fleetStats.TotalDevices, 1)) per device</div>
            </div>
        </div>

        <!-- Additional Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$($fleetStats.TotalDevices)</div>
                <div class="stat-label">Total Devices</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">$($fleetStats.MSRCCount)</div>
                <div class="stat-label">Microsoft (MSRC)</div>
                <div class="stat-sublabel">Windows & Office vulnerabilities</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">$($fleetStats.ThirdPartyCount)</div>
                <div class="stat-label">Third-Party Apps</div>
                <div class="stat-sublabel">Chrome, Firefox, Adobe, etc.</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-number">$($fleetStats.UnpatchedCount)</div>
                <div class="stat-label">Unpatched</div>
                <div class="stat-sublabel">Require immediate attention</div>
            </div>
        </div>

        <!-- Top Vulnerable Devices -->
        <div class="section">
            <h2>🔴 Top 20 Most Vulnerable Devices</h2>
            <div class="table-container">
                <table id="deviceTable">
                    <thead>
                        <tr>
                            <th onclick="sortDeviceTable(0)">Device Name</th>
                            <th onclick="sortDeviceTable(1)">Total</th>
                            <th onclick="sortDeviceTable(2)">Critical</th>
                            <th onclick="sortDeviceTable(3)">High</th>
                            <th onclick="sortDeviceTable(4)">Medium</th>
                            <th onclick="sortDeviceTable(5)">Low</th>
                            <th onclick="sortDeviceTable(6)">Unpatched</th>
                            <th onclick="sortDeviceTable(7)">Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        $deviceTableRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- All Vulnerabilities -->
        <div class="section">
            <h2>📋 All Unique Vulnerabilities</h2>
            
            <div class="controls">
                <input type="text" 
                       class="search-box" 
                       id="searchBox" 
                       placeholder="🔍 Search by CVE, KB Article, Product, Update (e.g., 2026-Feb), Title..." 
                       onkeyup="filterTable()">
                
                <select id="severityFilter" onchange="filterTable()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                
                <select id="sourceFilter" onchange="filterTable()">
                    <option value="">All Sources</option>
                    <option value="msrc">Microsoft (MSRC)</option>
                    <option value="thirdparty">Third-Party</option>
                </select>
                
                <select id="patchedFilter" onchange="filterTable()">
                    <option value="">All Status</option>
                    <option value="patched">Patched</option>
                    <option value="unpatched">Unpatched</option>
                </select>
            </div>
            
            <div class="table-container">
                <table id="vulnTable">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)">CVE</th>
                            <th onclick="sortTable(1)">Severity</th>
                            <th onclick="sortTable(2)">CVSS</th>
                            <th onclick="sortTable(3)">Product</th>
                            <th onclick="sortTable(4)">Title</th>
                            <th onclick="sortTable(5)">Devices</th>
                            <th onclick="sortTable(6)">KB Articles</th>
                            <th onclick="sortTable(7)">Update</th>
                            <th onclick="sortTable(8)">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        $tableRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Enterprise Vulnerability Management System v2.0 | Powered by MSRC & NVD APIs</p>
            <p>For issues or questions, contact your IT Security team</p>
        </div>
    </div>

    <script>
        // ===== THEME TOGGLE =====
        const currentTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', currentTheme);
        updateThemeIcon(currentTheme);
        
        function toggleTheme() {
            const current = document.documentElement.getAttribute('data-theme');
            const next = current === 'light' ? 'dark' : 'light';
            
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
            updateThemeIcon(next);
        }
        
        function updateThemeIcon(theme) {
            const button = document.getElementById('themeToggle');
            button.textContent = theme === 'light' ? '🌙' : '☀️';
            button.title = theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode';
        }
        
        // Auto-detect system preference on first visit
        if (!localStorage.getItem('theme')) {
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const theme = prefersDark ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            updateThemeIcon(theme);
        }
        
        // ===== TABLE FILTERING =====
        function filterTable() {
            const searchValue = document.getElementById('searchBox').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value;
            const sourceFilter = document.getElementById('sourceFilter').value;
            const patchedFilter = document.getElementById('patchedFilter').value;
            
            const table = document.getElementById('vulnTable');
            const rows = table.getElementsByTagName('tr');
            
            let visibleCount = 0;
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const cells = row.getElementsByTagName('td');
                
                if (cells.length === 0) continue;
                
                // Get all searchable text
                const cve = cells[0].textContent.toLowerCase();
                const product = cells[3].textContent.toLowerCase();
                const title = cells[4].textContent.toLowerCase();
                const kbArticles = row.getAttribute('data-kbs') ? row.getAttribute('data-kbs').toLowerCase() : '';
                const update = row.getAttribute('data-update') ? row.getAttribute('data-update').toLowerCase() : '';
                
                const searchableText = cve + ' ' + product + ' ' + title + ' ' + kbArticles + ' ' + update;
                
                // Get filter attributes
                const severity = row.getAttribute('data-severity');
                const source = row.getAttribute('data-source');
                const patched = row.getAttribute('data-patched');
                
                // Apply filters
                const matchesSearch = searchValue === '' || searchableText.includes(searchValue);
                const matchesSeverity = severityFilter === '' || severity === severityFilter;
                const matchesSource = sourceFilter === '' || source === sourceFilter;
                const matchesPatched = patchedFilter === '' || patched === patchedFilter;
                
                if (matchesSearch && matchesSeverity && matchesSource && matchesPatched) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            }
        }
        
        // ===== TABLE SORTING =====
        let sortDirection = {};
        
        function sortTable(columnIndex) {
            const table = document.getElementById('vulnTable');
            const tbody = table.getElementsByTagName('tbody')[0];
            const rows = Array.from(tbody.getElementsByTagName('tr'));
            
            const direction = sortDirection[columnIndex] === 'asc' ? 'desc' : 'asc';
            sortDirection[columnIndex] = direction;
            
            rows.sort((a, b) => {
                const aValue = a.getElementsByTagName('td')[columnIndex].textContent.trim();
                const bValue = b.getElementsByTagName('td')[columnIndex].textContent.trim();
                
                // Try numeric comparison first
                const aNum = parseFloat(aValue);
                const bNum = parseFloat(bValue);
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return direction === 'asc' ? aNum - bNum : bNum - aNum;
                }
                
                // Text comparison
                return direction === 'asc' ? 
                    aValue.localeCompare(bValue) : 
                    bValue.localeCompare(aValue);
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }
        
        function sortDeviceTable(columnIndex) {
            const table = document.getElementById('deviceTable');
            const tbody = table.getElementsByTagName('tbody')[0];
            const rows = Array.from(tbody.getElementsByTagName('tr'));
            
            const direction = sortDirection['device_' + columnIndex] === 'asc' ? 'desc' : 'asc';
            sortDirection['device_' + columnIndex] = direction;
            
            rows.sort((a, b) => {
                const aValue = a.getElementsByTagName('td')[columnIndex].textContent.trim();
                const bValue = b.getElementsByTagName('td')[columnIndex].textContent.trim();
                
                const aNum = parseFloat(aValue);
                const bNum = parseFloat(bValue);
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return direction === 'asc' ? aNum - bNum : bNum - aNum;
                }
                
                return direction === 'asc' ? 
                    aValue.localeCompare(bValue) : 
                    bValue.localeCompare(aValue);
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }
    </script>
</body>
</html>
"@

# Save dashboard
try {
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "✓ Dashboard generated successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Dashboard saved to: $OutputPath" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Open the dashboard in your browser to view:" -ForegroundColor White
    Write-Host "  • Dark/Light mode toggle (🌙/☀️ button)" -ForegroundColor Cyan
    Write-Host "  • Interactive filtering and search" -ForegroundColor Cyan
    Write-Host "  • Sortable columns" -ForegroundColor Cyan
    Write-Host "  • Top vulnerable devices" -ForegroundColor Cyan
    Write-Host "  • All unique vulnerabilities" -ForegroundColor Cyan
    Write-Host ""
} catch {
    Write-Host "✗ Failed to save dashboard: $_" -ForegroundColor Red
    exit 1
}

exit 0
