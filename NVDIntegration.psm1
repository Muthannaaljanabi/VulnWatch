# NVD Integration Module v2.0
# National Vulnerability Database API Integration

<#
.SYNOPSIS
    PowerShell module for querying the NIST National Vulnerability Database (NVD) API

.DESCRIPTION
    Provides functions to query NVD for CVE information, manage rate limiting,
    and cache results for improved performance.

.NOTES
    Requires: NVD API key (free from https://nvd.nist.gov/developers/request-an-api-key)
    Rate Limit: 50 requests per 30 seconds with API key
#>

# Module variables
$script:NVDApiKey = $env:NVD_API_KEY
$script:NVDCallCount = 0
$script:NVDCallWindow = Get-Date
$script:NVDCache = @{}

function Get-NVDApiKey {
    <#
    .SYNOPSIS
        Gets the NVD API key from environment variable or returns null
    #>
    return $env:NVD_API_KEY
}

function Test-NVDApiKey {
    <#
    .SYNOPSIS
        Tests if NVD API key is configured
    #>
    $key = Get-NVDApiKey
    if ([string]::IsNullOrEmpty($key)) {
        Write-Warning "NVD API key not configured. Set NVD_API_KEY environment variable."
        Write-Warning "Get free API key: https://nvd.nist.gov/developers/request-an-api-key"
        return $false
    }
    return $true
}

function Invoke-NVDRateLimitCheck {
    <#
    .SYNOPSIS
        Manages rate limiting for NVD API calls (50 requests per 30 seconds)
    #>
    $elapsed = (Get-Date) - $script:NVDCallWindow
    
    if ($script:NVDCallCount -ge 50 -and $elapsed.TotalSeconds -lt 30) {
        $waitTime = 30 - $elapsed.TotalSeconds
        Write-Verbose "NVD Rate limit: waiting $([math]::Ceiling($waitTime)) seconds..."
        Start-Sleep -Seconds ([math]::Ceiling($waitTime))
        
        # Reset counter
        $script:NVDCallCount = 0
        $script:NVDCallWindow = Get-Date
    }
    
    $script:NVDCallCount++
}

function Get-NVDCVEById {
    <#
    .SYNOPSIS
        Retrieves a specific CVE by ID from NVD
    
    .PARAMETER CVE
        CVE identifier (e.g., CVE-2026-21222)
    
    .EXAMPLE
        Get-NVDCVEById -CVE "CVE-2026-21222"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$CVE
    )
    
    if (-not (Test-NVDApiKey)) {
        return $null
    }
    
    # Check cache first
    if ($script:NVDCache.ContainsKey($CVE)) {
        Write-Verbose "Returning cached result for $CVE"
        return $script:NVDCache[$CVE]
    }
    
    Invoke-NVDRateLimitCheck
    
    try {
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CVE"
        $headers = @{ "apiKey" = (Get-NVDApiKey) }
        
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -TimeoutSec 30
        
        if ($response.vulnerabilities -and $response.vulnerabilities.Count -gt 0) {
            $cve = $response.vulnerabilities[0].cve
            
            $result = [PSCustomObject]@{
                CVE = $cve.id
                Description = if ($cve.descriptions) { $cve.descriptions[0].value } else { "" }
                Published = $cve.published
                LastModified = $cve.lastModified
                CVSS = Get-NVDCVSSScore -CVEData $cve
                Severity = Get-NVDSeverity -CVEData $cve
                References = if ($cve.references) { $cve.references.url } else { @() }
                VendorAdvisory = ($cve.references | Where-Object { $_.tags -contains "Vendor Advisory" } | Select-Object -First 1).url
            }
            
            # Cache the result
            $script:NVDCache[$CVE] = $result
            
            return $result
        }
        
        return $null
        
    } catch {
        Write-Warning "Error querying NVD for $CVE: $_"
        return $null
    }
}

function Search-NVDByProduct {
    <#
    .SYNOPSIS
        Searches NVD for vulnerabilities affecting a specific product
    
    .PARAMETER ProductName
        Product name to search for (e.g., "Chrome", "Firefox")
    
    .PARAMETER Version
        Optional version number to filter results
    
    .PARAMETER MaxResults
        Maximum number of results to return (default: 20)
    
    .EXAMPLE
        Search-NVDByProduct -ProductName "Chrome" -Version "130.0.6723.58"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProductName,
        
        [Parameter(Mandatory = $false)]
        [string]$Version = "",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxResults = 20
    )
    
    if (-not (Test-NVDApiKey)) {
        return @()
    }
    
    # Create cache key
    $cacheKey = "SEARCH_${ProductName}_${Version}"
    if ($script:NVDCache.ContainsKey($cacheKey)) {
        Write-Verbose "Returning cached results for $ProductName"
        return $script:NVDCache[$cacheKey]
    }
    
    Invoke-NVDRateLimitCheck
    
    try {
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        $headers = @{ "apiKey" = (Get-NVDApiKey) }
        
        $queryParams = @{
            keywordSearch = $ProductName
            resultsPerPage = $MaxResults
        }
        
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -Body $queryParams -TimeoutSec 30
        
        $results = @()
        
        foreach ($vuln in $response.vulnerabilities) {
            $cve = $vuln.cve
            
            $results += [PSCustomObject]@{
                CVE = $cve.id
                Description = if ($cve.descriptions) { $cve.descriptions[0].value } else { "" }
                Published = $cve.published
                CVSS = Get-NVDCVSSScore -CVEData $cve
                Severity = Get-NVDSeverity -CVEData $cve
                References = if ($cve.references) { ($cve.references.url | Select-Object -First 3) } else { @() }
            }
        }
        
        # Cache results
        $script:NVDCache[$cacheKey] = $results
        
        # Auto-cleanup old cache entries (keep last 100)
        if ($script:NVDCache.Count -gt 100) {
            $oldestKeys = $script:NVDCache.Keys | Select-Object -First 20
            foreach ($key in $oldestKeys) {
                $script:NVDCache.Remove($key)
            }
        }
        
        return $results
        
    } catch {
        Write-Warning "Error searching NVD for $ProductName: $_"
        return @()
    }
}

function Get-NVDCVSSScore {
    <#
    .SYNOPSIS
        Extracts CVSS score from CVE data
    #>
    param($CVEData)
    
    if ($CVEData.metrics.cvssMetricV31) {
        return $CVEData.metrics.cvssMetricV31[0].cvssData.baseScore
    }
    elseif ($CVEData.metrics.cvssMetricV30) {
        return $CVEData.metrics.cvssMetricV30[0].cvssData.baseScore
    }
    elseif ($CVEData.metrics.cvssMetricV2) {
        return $CVEData.metrics.cvssMetricV2[0].cvssData.baseScore
    }
    
    return 0.0
}

function Get-NVDSeverity {
    <#
    .SYNOPSIS
        Extracts severity rating from CVE data
    #>
    param($CVEData)
    
    if ($CVEData.metrics.cvssMetricV31) {
        return $CVEData.metrics.cvssMetricV31[0].cvssData.baseSeverity
    }
    elseif ($CVEData.metrics.cvssMetricV30) {
        return $CVEData.metrics.cvssMetricV30[0].cvssData.baseSeverity
    }
    
    # Map CVSS v2 score to severity
    $cvssScore = Get-NVDCVSSScore -CVEData $CVEData
    if ($cvssScore -ge 9.0) { return "CRITICAL" }
    elseif ($cvssScore -ge 7.0) { return "HIGH" }
    elseif ($cvssScore -ge 4.0) { return "MEDIUM" }
    elseif ($cvssScore -gt 0) { return "LOW" }
    
    return "UNKNOWN"
}

function Get-NVDRemediationGuidance {
    <#
    .SYNOPSIS
        Gets remediation guidance for a CVE from NVD references
    
    .PARAMETER CVE
        CVE identifier
    
    .EXAMPLE
        Get-NVDRemediationGuidance -CVE "CVE-2026-21222"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$CVE
    )
    
    $cveData = Get-NVDCVEById -CVE $CVE
    
    if (-not $cveData) {
        return $null
    }
    
    $guidance = [PSCustomObject]@{
        CVE = $CVE
        Description = $cveData.Description
        Severity = $cveData.Severity
        CVSS = $cveData.CVSS
        VendorAdvisory = $cveData.VendorAdvisory
        References = $cveData.References
        Steps = @()
    }
    
    # Generate generic remediation steps
    $guidance.Steps = @(
        "1. Review vendor advisory: $($cveData.VendorAdvisory)",
        "2. Identify affected systems",
        "3. Test patches in non-production environment",
        "4. Deploy patches during maintenance window",
        "5. Verify patch installation",
        "6. Re-scan to confirm remediation"
    )
    
    return $guidance
}

function Clear-NVDCache {
    <#
    .SYNOPSIS
        Clears the NVD result cache
    #>
    $script:NVDCache = @()
    Write-Verbose "NVD cache cleared"
}

# Export module members
Export-ModuleMember -Function @(
    'Get-NVDApiKey',
    'Test-NVDApiKey',
    'Get-NVDCVEById',
    'Search-NVDByProduct',
    'Get-NVDRemediationGuidance',
    'Clear-NVDCache'
)
