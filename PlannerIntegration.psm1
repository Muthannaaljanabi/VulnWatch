# Microsoft Planner Integration Module v2.0
# Automated remediation task creation in Microsoft Planner

<#
.SYNOPSIS
    PowerShell module for creating and managing tasks in Microsoft Planner via Graph API

.DESCRIPTION
    Provides functions to automatically create remediation tasks for vulnerabilities,
    assign them to team members, and track completion.

.NOTES
    Requires: Azure AD App Registration with appropriate Graph API permissions
    Permissions needed: Tasks.ReadWrite, Group.Read.All
#>

function Get-PlannerAccessToken {
    <#
    .SYNOPSIS
        Gets access token for Microsoft Graph API using client credentials
    
    .PARAMETER TenantId
        Azure AD Tenant ID
    
    .PARAMETER ClientId
        Application (client) ID from Azure AD app registration
    
    .PARAMETER ClientSecret
        Client secret from Azure AD app registration
    
    .EXAMPLE
        $token = Get-PlannerAccessToken -TenantId "xxx" -ClientId "yyy" -ClientSecret "zzz"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )
    
    try {
        $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        $body = @{
            client_id = $ClientId
            scope = "https://graph.microsoft.com/.default"
            client_secret = $ClientSecret
            grant_type = "client_credentials"
        }
        
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        
        return $response.access_token
        
    } catch {
        Write-Error "Failed to get access token: $_"
        return $null
    }
}

function New-PlannerTask {
    <#
    .SYNOPSIS
        Creates a new task in Microsoft Planner
    
    .PARAMETER AccessToken
        Microsoft Graph API access token
    
    .PARAMETER PlanId
        Planner plan ID where task will be created
    
    .PARAMETER BucketId
        Bucket ID within the plan
    
    .PARAMETER Title
        Task title
    
    .PARAMETER Notes
        Task description/notes
    
    .PARAMETER DueDate
        Due date in ISO format (yyyy-MM-ddTHH:mm:ssZ)
    
    .PARAMETER Priority
        Task priority (1-10, where 1 is most urgent)
    
    .PARAMETER AssignedTo
        User UPN or Object ID to assign task to
    
    .EXAMPLE
        New-PlannerTask -AccessToken $token -PlanId $planId -BucketId $bucketId `
                        -Title "Patch CVE-2026-21222" -Priority 1
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$PlanId,
        
        [Parameter(Mandatory = $true)]
        [string]$BucketId,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [string]$Notes = "",
        
        [Parameter(Mandatory = $false)]
        [string]$DueDate = "",
        
        [Parameter(Mandatory = $false)]
        [int]$Priority = 5,
        
        [Parameter(Mandatory = $false)]
        [string]$AssignedTo = ""
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }
        
        # Create task
        $taskUrl = "https://graph.microsoft.com/v1.0/planner/tasks"
        
        $taskBody = @{
            planId = $PlanId
            bucketId = $BucketId
            title = $Title
            priority = $Priority
        }
        
        if ($DueDate) {
            $taskBody.dueDateTime = $DueDate
        }
        
        $taskJson = $taskBody | ConvertTo-Json -Depth 10
        
        $task = Invoke-RestMethod -Uri $taskUrl -Method Post -Headers $headers -Body $taskJson
        
        Write-Verbose "Task created: $($task.id)"
        
        # Add task details (notes)
        if ($Notes) {
            Start-Sleep -Seconds 1  # Brief delay for task creation
            
            $detailsUrl = "https://graph.microsoft.com/v1.0/planner/tasks/$($task.id)/details"
            
            $detailsBody = @{
                description = $Notes
            } | ConvertTo-Json
            
            try {
                Invoke-RestMethod -Uri $detailsUrl -Method Patch -Headers $headers -Body $detailsBody -ErrorAction Stop
                Write-Verbose "Task details added"
            } catch {
                Write-Warning "Failed to add task details: $_"
            }
        }
        
        # Assign to user
        if ($AssignedTo) {
            Start-Sleep -Seconds 1
            
            $assignmentUrl = "https://graph.microsoft.com/v1.0/planner/tasks/$($task.id)"
            
            $assignmentBody = @{
                assignments = @{
                    $AssignedTo = @{
                        "@odata.type" = "#microsoft.graph.plannerAssignment"
                        orderHint = " !"
                    }
                }
            } | ConvertTo-Json -Depth 10
            
            try {
                Invoke-RestMethod -Uri $assignmentUrl -Method Patch -Headers $headers -Body $assignmentBody -ErrorAction Stop
                Write-Verbose "Task assigned to $AssignedTo"
            } catch {
                Write-Warning "Failed to assign task: $_"
            }
        }
        
        Write-Host "✓ Created task: $Title" -ForegroundColor Green
        return $task
        
    } catch {
        Write-Error "Failed to create task: $_"
        return $null
    }
}

function Get-PlannerPlans {
    <#
    .SYNOPSIS
        Lists all Planner plans in a Microsoft 365 Group
    
    .PARAMETER AccessToken
        Microsoft Graph API access token
    
    .PARAMETER GroupId
        Microsoft 365 Group ID
    
    .EXAMPLE
        Get-PlannerPlans -AccessToken $token -GroupId "group-id-here"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )
    
    try {
        $url = "https://graph.microsoft.com/v1.0/groups/$GroupId/planner/plans"
        $headers = @{ "Authorization" = "Bearer $AccessToken" }
        
        $response = Invoke-RestMethod -Uri $url -Headers $headers
        
        return $response.value
        
    } catch {
        Write-Error "Failed to get plans: $_"
        return @()
    }
}

function Get-PlannerBuckets {
    <#
    .SYNOPSIS
        Lists all buckets in a Planner plan
    
    .PARAMETER AccessToken
        Microsoft Graph API access token
    
    .PARAMETER PlanId
        Planner plan ID
    
    .EXAMPLE
        Get-PlannerBuckets -AccessToken $token -PlanId "plan-id-here"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$PlanId
    )
    
    try {
        $url = "https://graph.microsoft.com/v1.0/planner/plans/$PlanId/buckets"
        $headers = @{ "Authorization" = "Bearer $AccessToken" }
        
        $response = Invoke-RestMethod -Uri $url -Headers $headers
        
        return $response.value
        
    } catch {
        Write-Error "Failed to get buckets: $_"
        return @()
    }
}

function New-VulnerabilityRemediationTask {
    <#
    .SYNOPSIS
        Creates a Planner task for a specific vulnerability
    
    .PARAMETER AccessToken
        Microsoft Graph API access token
    
    .PARAMETER PlanId
        Planner plan ID
    
    .PARAMETER BucketId
        Bucket ID for vulnerability tasks
    
    .PARAMETER Vulnerability
        Vulnerability object containing CVE, Severity, etc.
    
    .PARAMETER AssignTo
        User to assign the task to
    
    .EXAMPLE
        New-VulnerabilityRemediationTask -AccessToken $token -PlanId $plan -BucketId $bucket -Vulnerability $vuln
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$PlanId,
        
        [Parameter(Mandatory = $true)]
        [string]$BucketId,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Vulnerability,
        
        [Parameter(Mandatory = $false)]
        [string]$AssignTo = ""
    )
    
    # Calculate due date based on severity
    $dueDate = switch ($Vulnerability.Severity) {
        "Critical" { (Get-Date).AddDays(7).ToString("yyyy-MM-ddTHH:mm:ssZ") }
        "Important" { (Get-Date).AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ") }
        "High" { (Get-Date).AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ") }
        "Moderate" { (Get-Date).AddDays(90).ToString("yyyy-MM-ddTHH:mm:ssZ") }
        "Medium" { (Get-Date).AddDays(90).ToString("yyyy-MM-ddTHH:mm:ssZ") }
        default { (Get-Date).AddDays(180).ToString("yyyy-MM-ddTHH:mm:ssZ") }
    }
    
    # Set priority
    $priority = switch ($Vulnerability.Severity) {
        "Critical" { 1 }
        "Important" { 3 }
        "High" { 3 }
        "Moderate" { 5 }
        "Medium" { 5 }
        default { 9 }
    }
    
    # Create task title
    $title = "Patch $($Vulnerability.CVE) - $($Vulnerability.Severity)"
    
    # Create task notes
    $notes = @"
Vulnerability Details:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CVE ID: $($Vulnerability.CVE)
Severity: $($Vulnerability.Severity)
CVSS Score: $($Vulnerability.CVSSScore)

Description:
$($Vulnerability.Title)

Affected Product: $($Vulnerability.Product)
Current Version: $($Vulnerability.CurrentVersion)
Fixed Version: $($Vulnerability.FixedVersion)

Remediation Steps:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(if ($Vulnerability.Source -eq "MSRC") {
@"
1. Download KB article: $($Vulnerability.KBArticles)
   Link: https://catalog.update.microsoft.com/Search.aspx?q=$($Vulnerability.KBArticles)

2. Test patch in non-production environment

3. Deploy to production systems during maintenance window

4. Verify patch installation:
   Get-HotFix | Where-Object { `$_.HotFixID -eq '$($Vulnerability.KBArticles)' }

5. Re-scan to confirm remediation
"@
} else {
@"
1. Update to version $($Vulnerability.FixedVersion) or higher

2. Download from vendor website

3. Test in non-production environment

4. Deploy to production systems

5. Verify installation and version

6. Re-scan to confirm remediation
"@
})

References:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
$(if ($Vulnerability.Source -eq "MSRC") {
"MSRC: https://msrc.microsoft.com/update-guide/vulnerability/$($Vulnerability.CVE)"
} else {
"NVD: https://nvd.nist.gov/vuln/detail/$($Vulnerability.CVE)"
})

Generated by: Vulnerability Management System v2.0
Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
    
    # Create the task
    return New-PlannerTask -AccessToken $AccessToken `
                          -PlanId $PlanId `
                          -BucketId $BucketId `
                          -Title $title `
                          -Notes $notes `
                          -DueDate $dueDate `
                          -Priority $priority `
                          -AssignedTo $AssignTo
}

function New-BulkVulnerabilityTasks {
    <#
    .SYNOPSIS
        Creates Planner tasks for multiple vulnerabilities at once
    
    .PARAMETER AccessToken
        Microsoft Graph API access token
    
    .PARAMETER PlanId
        Planner plan ID
    
    .PARAMETER BucketId
        Bucket ID for vulnerability tasks
    
    .PARAMETER Vulnerabilities
        Array of vulnerability objects
    
    .PARAMETER AssignTo
        User to assign tasks to
    
    .PARAMETER OnlyNewCritical
        Only create tasks for new critical/high vulnerabilities
    
    .EXAMPLE
        New-BulkVulnerabilityTasks -AccessToken $token -PlanId $plan -BucketId $bucket -Vulnerabilities $vulns -OnlyNewCritical
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory = $true)]
        [string]$PlanId,
        
        [Parameter(Mandatory = $true)]
        [string]$BucketId,
        
        [Parameter(Mandatory = $true)]
        [array]$Vulnerabilities,
        
        [Parameter(Mandatory = $false)]
        [string]$AssignTo = "",
        
        [Parameter(Mandatory = $false)]
        [switch]$OnlyNewCritical
    )
    
    $created = 0
    $filtered = $Vulnerabilities
    
    if ($OnlyNewCritical) {
        $filtered = $Vulnerabilities | Where-Object { 
            $_.Severity -in @("Critical", "Important", "High") -and 
            -not $_.IsPatched 
        }
    }
    
    Write-Host "`nCreating Planner tasks for $($filtered.Count) vulnerabilities..." -ForegroundColor Cyan
    
    foreach ($vuln in $filtered) {
        try {
            $task = New-VulnerabilityRemediationTask -AccessToken $AccessToken `
                                                     -PlanId $PlanId `
                                                     -BucketId $BucketId `
                                                     -Vulnerability $vuln `
                                                     -AssignTo $AssignTo
            
            if ($task) {
                $created++
            }
            
            # Rate limiting - don't overwhelm Graph API
            Start-Sleep -Milliseconds 500
            
        } catch {
            Write-Warning "Failed to create task for $($vuln.CVE): $_"
        }
    }
    
    Write-Host "✓ Created $created Planner tasks" -ForegroundColor Green
    return $created
}

# Export module members
Export-ModuleMember -Function @(
    'Get-PlannerAccessToken',
    'New-PlannerTask',
    'Get-PlannerPlans',
    'Get-PlannerBuckets',
    'New-VulnerabilityRemediationTask',
    'New-BulkVulnerabilityTasks'
)
