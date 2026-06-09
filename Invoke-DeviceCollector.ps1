#Requires -Version 5.1
<#
.SYNOPSIS
    VulnWatch Device Collector v1.0 - Lightweight Intune Agent

.DESCRIPTION
    Collects raw device inventory (OS info, installed KBs, installed applications)
    via WMI/CIM and uploads a structured JSON file to SharePoint Online using the
    Microsoft Graph API (client_credentials / app-only auth).

    Designed to run as an Intune Proactive Remediation DETECTION script on every
    managed device. No external vulnerability API calls are made here - MSRC and
    NVD enrichment happens centrally on the admin machine via Invoke-VulnerabilityScan-v2.ps1.

    Compatible: PowerShell 5.1 (Windows PowerShell) and PowerShell 7.x (pwsh)
    Run context: SYSTEM account via Intune - no interactive login required
    Scheduled task: NOT required - Intune handles scheduling
    Throttling: No MSRC/NVD/Graph write throttling concerns; single PUT per device

.PARAMETER SharePointSiteUrl
    Full URL of the SharePoint site.
    Example: https://contoso.sharepoint.com/sites/VulnerabilityManagement

.PARAMETER DriveId
    Graph API drive ID for the VulnerabilityScans document library.
    Obtain via: GET https://graph.microsoft.com/v1.0/sites/{siteId}/drives
    This is stable and does not change unless the library is deleted.

.PARAMETER LocalOutputPath
    Optional. Save a local copy of the JSON to this path (for troubleshooting).
    Defaults to C:\ProgramData\VulnWatch\collector_<hostname>_<date>.json

.PARAMETER LocalOnly
    Skip SharePoint upload. Useful for local testing before Intune deployment.

.EXAMPLE
    # Local test - no upload
    .\Invoke-DeviceCollector.ps1 -LocalOnly

.EXAMPLE
    # Full run - uploads to SharePoint (credentials read from env vars)
    .\Invoke-DeviceCollector.ps1

.NOTES
    Version : 1.0.0
    Author  : Enterprise IT Security
    Requires: PowerShell 5.1+, outbound HTTPS to graph.microsoft.com and
              login.microsoftonline.com
    Secrets : Client Secret read from $env:PLANNER_CLIENT_SECRET (never hardcoded
              in the GitHub/source-controlled version - bake in only the Intune copy)
    [!]  NEVER commit the Intune credential-baked version to source control.
        Keep the clean env-var version in GitHub and bake credentials into
        the copy you upload to Intune only.
    Graph permission required: Sites.ReadWrite.All (Application, admin-consented)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    # Your SharePoint Online site that stores scan results.
    # Format: https://<YOUR-TENANT>.sharepoint.com/sites/<YOUR-SITE>
    # See SHAREPOINT_SETUP_GUIDE.md for how to create the site/library.
    [string]$SharePointSiteUrl = "https://<YOUR-TENANT>.sharepoint.com/sites/<YOUR-SITE>",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    # SharePoint document-library Drive ID (Graph). Obtain with:
    #   GET https://graph.microsoft.com/v1.0/sites/{site-id}/drives
    # See SHAREPOINT_SETUP_GUIDE.md.
    [string]$DriveId = "<YOUR_SHAREPOINT_DRIVE_ID>",

    [Parameter(Mandatory = $false)]
    [string]$LocalOutputPath = "C:\ProgramData\VulnWatch\collector_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",

    [Parameter(Mandatory = $false)]
    [switch]$LocalOnly
)

# -- Script-wide settings ----------------------------------------------------
$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"
$script:CollectorVersion = "1.0.0"

# -- Intune Deployment: credential fallbacks ---------------------------------
# These activate when the matching environment variable is absent (e.g. on a
# managed device running as SYSTEM). Supply values via environment variables
# wherever possible. If you must bake values in for Intune, do so on a LOCAL
# copy only and NEVER commit that copy. Leave the placeholders below in the
# version you publish to GitHub.
#
# Where to get each value (see CONFIGURATION_GUIDE.md):
#   TENANT_ID     -> Entra admin center > Overview > Tenant ID (GUID)
#   CLIENT_ID     -> Entra > App registrations > your app > Application (client) ID
#   CLIENT_SECRET -> Entra > App registrations > your app > Certificates & secrets
#                    > New client secret > copy the secret VALUE (shown once)
if (-not $env:PLANNER_TENANT_ID)     { $env:PLANNER_TENANT_ID     = "<YOUR_ENTRA_TENANT_ID>" }
if (-not $env:PLANNER_CLIENT_ID)     { $env:PLANNER_CLIENT_ID     = "<YOUR_APP_CLIENT_ID>" }
if (-not $env:PLANNER_CLIENT_SECRET) { $env:PLANNER_CLIENT_SECRET = "<YOUR_CLIENT_SECRET>" }

# -- Ensure local output directory exists (SYSTEM context may lack write access elsewhere) --
try {
    $localOutputDir = Split-Path $LocalOutputPath -Parent
    if (-not (Test-Path $localOutputDir)) {
        New-Item -ItemType Directory -Path $localOutputDir -Force | Out-Null
    }
} catch {
    Write-Warning "Could not create output directory '$localOutputDir': $_"
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  VulnWatch Device Collector v$script:CollectorVersion" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Device : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "  Mode   : $(if ($LocalOnly) { 'LOCAL ONLY (no upload)' } else { 'SharePoint upload enabled' })" -ForegroundColor $(if ($LocalOnly) { 'Yellow' } else { 'Green' })
Write-Host ""

# ============================================================================
#  SECTION 1 - SYSTEM INFORMATION
# ============================================================================
function Get-DeviceSystemInfo {
    <#
    .SYNOPSIS
        Collects OS and hardware details via CIM. Falls back to WMI on older systems.
    #>
    Write-Host "  [1/4] Collecting system information..." -ForegroundColor Cyan
    try {
        $os = Get-CimInstance Win32_OperatingSystem  -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem   -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS           -ErrorAction SilentlyContinue

        return [PSCustomObject]@{
            ComputerName     = $env:COMPUTERNAME
            Domain           = $cs.Domain
            Manufacturer     = $cs.Manufacturer
            Model            = $cs.Model
            BIOSVersion      = if ($bios) { $bios.SMBIOSBIOSVersion } else { "Unknown" }
            OSName           = $os.Caption
            OSVersion        = $os.Version
            OSBuildNumber    = $os.BuildNumber
            OSArchitecture   = $os.OSArchitecture
            ServicePack      = $os.ServicePackMajorVersion
            LastBootTime     = ($os.LastBootUpTime).ToString("yyyy-MM-ddTHH:mm:ss")
            TotalMemoryGB    = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            ScanTimestamp    = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
            CollectorVersion = $script:CollectorVersion
        }
    } catch {
        Write-Warning "  System info collection failed: $_"
        # Minimal fallback so the JSON still uploads something useful
        return [PSCustomObject]@{
            ComputerName     = $env:COMPUTERNAME
            OSName           = "Unknown (CIM failed)"
            ScanTimestamp    = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
            CollectorVersion = $script:CollectorVersion
            Error            = $_.ToString()
        }
    }
}

# ============================================================================
#  SECTION 2 - INSTALLED WINDOWS UPDATES (KBs)
# ============================================================================
function Get-InstalledWindowsUpdates {
    <#
    .SYNOPSIS
        Returns a list of installed KB numbers from Get-HotFix and the
        Windows Update COM object (catches more updates than Get-HotFix alone).
    #>
    Write-Host "  [2/4] Collecting installed Windows updates..." -ForegroundColor Cyan

    $kbList = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Source 1: Get-HotFix (fast, covers security patches)
    try {
        Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object {
            $kbList.Add([PSCustomObject]@{
                KBID        = $_.HotFixID
                Description = $_.Description
                InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                InstalledBy = $_.InstalledBy
                Source      = "HotFix"
            })
        }
    } catch {
        Write-Warning "  Get-HotFix failed: $_"
    }

    # Source 2: Windows Update history via COM (catches Feature Updates and Cumulative Updates
    # that sometimes don't appear in Get-HotFix)
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $count    = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            $history = $searcher.QueryHistory(0, [math]::Min($count, 200))
            foreach ($entry in $history) {
                if ($entry.ResultCode -eq 2 -and $entry.Title -match 'KB(\d+)') {
                    $kbId = "KB$($Matches[1])"
                    # Add only if not already captured from HotFix
                    if (-not ($kbList | Where-Object { $_.KBID -eq $kbId })) {
                        $kbList.Add([PSCustomObject]@{
                            KBID        = $kbId
                            Description = $entry.Title
                            InstalledOn = $entry.Date.ToString("yyyy-MM-dd")
                            InstalledBy = "Windows Update"
                            Source      = "WUHistory"
                        })
                    }
                }
            }
        }
    } catch {
        Write-Verbose "  Windows Update COM history unavailable: $_"
    }

    Write-Host "    ? $($kbList.Count) updates found" -ForegroundColor Gray
    return $kbList
}

# ============================================================================
#  SECTION 3 - INSTALLED APPLICATIONS
# ============================================================================
function Get-InstalledApps {
    <#
    .SYNOPSIS
        Reads installed application names and versions from the registry
        (both 64-bit and 32-bit uninstall keys), plus Chrome beacon key.
    #>
    Write-Host "  [3/4] Collecting installed applications..." -ForegroundColor Cyan

    $appList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $regPaths) {
        try {
            Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" } |
                ForEach-Object {
                    $key = "$($_.DisplayName)|$($_.DisplayVersion)"
                    if ($seen.Add($key)) {
                        $appList.Add([PSCustomObject]@{
                            Name        = $_.DisplayName.Trim()
                            Version     = if ($_.DisplayVersion) { $_.DisplayVersion.Trim() } else { "Unknown" }
                            Publisher   = if ($_.Publisher)      { $_.Publisher.Trim()      } else { "Unknown" }
                            InstallDate = if ($_.InstallDate)    { $_.InstallDate           } else { "" }
                            Source      = "Registry"
                        })
                    }
                }
        } catch {
            Write-Verbose "  Registry path error ($path): $_"
        }
    }

    # Chrome beacon key (more reliable version than registry uninstall entry)
    try {
        $chromeReg = Get-ItemProperty "HKLM:\SOFTWARE\Google\Chrome\BLBeacon" -ErrorAction SilentlyContinue
        if ($chromeReg -and $chromeReg.version) {
            $key = "Google Chrome|$($chromeReg.version)"
            if ($seen.Add($key)) {
                $appList.Add([PSCustomObject]@{
                    Name      = "Google Chrome"
                    Version   = $chromeReg.version
                    Publisher = "Google LLC"
                    Source    = "ChromeBeacon"
                })
            }
        }
    } catch {
        Write-Verbose "  Chrome beacon key unavailable: $_"
    }

    Write-Host "    ? $($appList.Count) applications found" -ForegroundColor Gray
    return $appList
}

# ============================================================================
#  SECTION 4 - ASSEMBLE & SAVE JSON PAYLOAD
# ============================================================================
Write-Host "  Collecting device data..." -ForegroundColor White

$systemInfo  = Get-DeviceSystemInfo
$installedKBs   = Get-InstalledWindowsUpdates
$installedApps  = Get-InstalledApps

Write-Host "  [4/4] Building JSON payload..." -ForegroundColor Cyan

$payload = [PSCustomObject]@{
    SchemaVersion  = "1.0"
    CollectorVersion = $script:CollectorVersion
    ScanTimestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    Device         = $systemInfo
    InstalledKBs   = $installedKBs
    InstalledApps  = $installedApps
    KBCount        = $installedKBs.Count
    AppCount       = $installedApps.Count
}

# Serialize - pretty-print for readability in SharePoint/CurrentScan
$jsonPayload = $payload | ConvertTo-Json -Depth 10

# Save local copy
try {
    $jsonPayload | Out-File -FilePath $LocalOutputPath -Encoding UTF8 -Force
    Write-Host "  ? Local JSON saved: $LocalOutputPath" -ForegroundColor Green
} catch {
    Write-Warning "  Failed to save local JSON: $_"
}

# ============================================================================
#  SECTION 5 - SHAREPOINT UPLOAD (Graph API, client_credentials)
# ============================================================================
if (-not $LocalOnly) {

    $tenantId     = $env:PLANNER_TENANT_ID
    $clientId     = $env:PLANNER_CLIENT_ID
    $clientSecret = $env:PLANNER_CLIENT_SECRET

    if (-not $tenantId -or -not $clientId -or -not $clientSecret) {
        Write-Warning "SharePoint credentials not set. Set PLANNER_TENANT_ID, PLANNER_CLIENT_ID, PLANNER_CLIENT_SECRET."
        Write-Warning "Skipping SharePoint upload."
    } else {
        Write-Host ""
        Write-Host "  Uploading to SharePoint..." -ForegroundColor Cyan

        # -- Step 5a: Obtain Graph API access token -------------------------
        # OAuth2 client_credentials flow - no interactive login, safe under SYSTEM
        # Graph permission required: Sites.ReadWrite.All (Application, admin-consented)
        try {
            $tokenBody = @{
                client_id     = $clientId
                scope         = "https://graph.microsoft.com/.default"
                client_secret = $clientSecret
                grant_type    = "client_credentials"
            }
            $tokenResponse = Invoke-RestMethod `
                -Uri     "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
                -Method  Post `
                -Body    $tokenBody `
                -ContentType "application/x-www-form-urlencoded" `
                -UseBasicParsing `
                -ErrorAction Stop

            $accessToken = $tokenResponse.access_token

            if (-not $accessToken) {
                Write-Warning "  Token response received but access_token is empty. Check Client ID and Secret."
                exit 1
            }
            Write-Host "    ? Graph API token acquired" -ForegroundColor Green

        } catch {
            Write-Warning "  Failed to obtain Graph API token: $_"
            Write-Warning "  Check PLANNER_TENANT_ID, PLANNER_CLIENT_ID, PLANNER_CLIENT_SECRET."
            exit 1
        }

        # -- Step 5b: Ensure /CurrentScan/ folder exists --------------------
        # Graph API PUT to /root:/Folder/file.json:/content requires the folder
        # to already exist - it will NOT auto-create parent folders.
        # We use a PATCH (folder upsert) to create it if missing; if it already
        # exists this call is a no-op and returns the existing item.
        try {
            $folderBody = @{
                name   = "CurrentScan"
                folder = @{}
                "@microsoft.graph.conflictBehavior" = "replace"
            } | ConvertTo-Json

            $folderHeaders = @{
                "Authorization" = "Bearer $accessToken"
                "Content-Type"  = "application/json"
            }

            Invoke-RestMethod `
                -Uri     "https://graph.microsoft.com/v1.0/drives/$DriveId/root/children" `
                -Method  Post `
                -Headers $folderHeaders `
                -Body    $folderBody `
                -UseBasicParsing `
                -ErrorAction SilentlyContinue | Out-Null

            Write-Host "    ? CurrentScan folder verified/created" -ForegroundColor Green

        } catch {
            # 409 Conflict = folder already exists - that is fine, continue
            if ($_ -notmatch "409") {
                Write-Warning "  Could not verify CurrentScan folder: $_"
            }
        }

        # -- Step 5c: Upload JSON to SharePoint /CurrentScan/ ---------------
        # File name: device-HOSTNAME_YYYYMMDD_HHMMSS.json
        # One file per scan run - fleet dashboard reads all files in this folder.
        # Graph API drive upload throttle: 10,000 req/10 min per app.
        # 1,000 devices staggered across a schedule window is well within limits.
        try {
            $fileName  = "device-$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $uploadUrl = "https://graph.microsoft.com/v1.0/drives/$DriveId/root:/CurrentScan/$fileName`:/content"

            $uploadHeaders = @{
                "Authorization" = "Bearer $accessToken"
                "Content-Type"  = "application/octet-stream"
            }

            $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)

            Invoke-RestMethod `
                -Uri     $uploadUrl `
                -Method  Put `
                -Headers $uploadHeaders `
                -Body    $jsonBytes `
                -UseBasicParsing `
                -ErrorAction Stop | Out-Null

            Write-Host "    ? Uploaded: CurrentScan/$fileName" -ForegroundColor Green

        } catch {
            Write-Warning "  SharePoint upload failed: $_"
            Write-Warning "  Upload URL: $uploadUrl"
            Write-Warning "  Drive ID used: $DriveId"
            Write-Warning "  Checks: Is Drive ID correct? Does app have Sites.ReadWrite.All (admin-consented)?"
            exit 1
        }
    }
}

# ============================================================================
#  COMPLETION
# ============================================================================
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  ? Device collection complete" -ForegroundColor Green
Write-Host "    Device  : $($systemInfo.ComputerName)" -ForegroundColor White
Write-Host "    KBs     : $($installedKBs.Count)" -ForegroundColor White
Write-Host "    Apps    : $($installedApps.Count)" -ForegroundColor White
Write-Host "    Duration: $([math]::Round(((Get-Date) - [datetime]$systemInfo.ScanTimestamp).TotalSeconds, 1))s" -ForegroundColor White
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# Intune Proactive Remediation: exit 0 = "Compliant / no remediation needed"
# The detection script always exits 0 - we're a data collector, not a compliance check.
exit 0
