# Version 1.0
param(
    [string]$ParameterFile,
    [string] [ValidateSet("AzureCloud", "AzureUSGovernment")]
    $CloudEnvironment = "AzureCloud"
)

# Display usage instructions if no parameter file is provided
if (-not $ParameterFile) {
    Write-Host "Usage: ESA_MDC_DataExport.ps1 <ParameterFile>" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This script exports Defender for Cloud (MDC) or MCSB compliance recommendations from Azure Resource Graph."
    Write-Host "It requires a JSON parameter file specifying query details, output settings, and subscriptions."
    Write-Host ""
    Write-Host "Available parameter files (don't change the file names):"
    Write-Host "  - MDC_Params.json      (For Defender for Cloud Secure Score Recommendations)"
    Write-Host "  - MCSB_Params.json     (For MCSB regulatory compliance recommendations)"
    Write-Host ""
    Write-Host "Example usage:"
    Write-Host "  .\ESA_MDC_DataExport.ps1 MDC_Params.json" -ForegroundColor Green
    Write-Host "  .\ESA_MDC_DataExport.ps1 MCSB_Params.json" -ForegroundColor Green
    Write-Host "  .\ESA_MDC_DataExport.ps1 -CloudEnvironment AzureUSGovernment MDC_Params.json" -ForegroundColor Green
    Write-Host "  .\ESA_MDC_DataExport.ps1 -CloudEnvironment AzureUSGovernment MCSB_Params.json" -ForegroundColor Green
    Write-Host ""
    Write-Host "(The script needs to be executed twice to download both the MDC and MCSB recommendations)."
    Write-Host ""
    Write-Host "Note: Required PowerShell modules:" -ForegroundColor Yellow
    Write-Host "  - Az.Accounts"
    Write-Host "  - Az.ResourceGraph"
    Write-Host ""
    Write-Host "After login, you may see messages such as 'WARNING: Unable to acquire token for tenant ...' or 'WARNING: To override which subscription Connect-AzAccount selects by default...'. These messages can be ignored.`n"
    Write-Host "Connect-AzAccount may require you to select a subscription and tenant, but this script will handle that independently."
    
    exit 1
}

# Check if the script is running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "Error: This script must NOT be run as Administrator!" -ForegroundColor Red
    exit 1
}

$StartTime = Get-Date

# Required PowerShell modules
$requiredModules = @("Az.Accounts", "Az.ResourceGraph")
$missingModules = @()

# Check for missing modules
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $missingModules += $module
    }
}

# Display message if modules are missing
if ($missingModules.Count -gt 0) {
    Write-Host "The following required PowerShell modules are missing:" -ForegroundColor Red
    Write-Host "  $($missingModules -join ', ')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please install them using the following command:" -ForegroundColor Cyan
    Write-Host "  Install-Module $($missingModules -join ', ') -Force" -ForegroundColor Green
    exit 1
}

# Ensure parameter file exists
if (-Not (Test-Path $ParameterFile)) {
    Write-Host "Error: Parameter file '$ParameterFile' not found!" -ForegroundColor Red
    exit 1
}

# Read parameters from JSON file
$parameters = Get-Content -Path $ParameterFile | ConvertFrom-Json

# Extract and validate required parameters
if (-Not $parameters.QueryFile) {
    Write-Host "Error: No QueryFile specified in '$ParameterFile'" -ForegroundColor Red
    exit 1
}
if (-Not $parameters.CSVFileName) {
    Write-Host "Error: CSVFileName is missing in the parameter file." -ForegroundColor Red
    exit 1
}

# Parse ParallelWorkers (default 1 = serial, opt-in parallelism via JSON)
$ParallelWorkers = 1
if ($null -ne $parameters.ParallelWorkers) {
    $parsedWorkers = 0
    if (-not [int]::TryParse([string]$parameters.ParallelWorkers, [ref]$parsedWorkers)) {
        Write-Host "Error: ParallelWorkers must be an integer between 1 and 50." -ForegroundColor Red
        exit 1
    }
    $ParallelWorkers = $parsedWorkers
}
if ($ParallelWorkers -lt 1 -or $ParallelWorkers -gt 50) {
    Write-Host "Error: ParallelWorkers must be between 1 and 50 (got: $ParallelWorkers)." -ForegroundColor Red
    exit 1
}
if ($ParallelWorkers -gt 1) {
    if (-not (Get-Module -ListAvailable -Name ThreadJob)) {
        Write-Host "Error: ParallelWorkers > 1 requires the 'ThreadJob' module." -ForegroundColor Red
        Write-Host "  Install with: Install-Module ThreadJob -Scope CurrentUser" -ForegroundColor Green
        exit 1
    }
}

# Read the KQL Query
$kqlQuery = Get-Content -Path $parameters.QueryFile -Raw -Encoding UTF8

# Suppress warnings and errors during authentication
# https://learn.microsoft.com/en-us/powershell/azure/authenticate-interactive
Update-AzConfig -LoginExperienceV2 Off -DisplayBreakingChangeWarning $false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue *>$null

# Check if user is already authenticated
$existingContext = Get-AzContext

if ($existingContext) {
    Write-Host "You are currently authenticated as: $($existingContext.Account) | Tenant: $(Get-AzTenant | Where-Object { $_.Id -eq $existingContext.Tenant.Id } | Select-Object -ExpandProperty Name) ($($existingContext.Tenant.Id))" -ForegroundColor Cyan

    $response = Read-Host "Do you want to continue with this session? (Y/N)"

    if ($response -match "^[Nn]$") {
        Disconnect-AzAccount -ErrorAction SilentlyContinue *>$null  
        Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue *>$null
        $azContext = $null  # Force re-authentication
    } else {
        # Test if the session is valid by checking authentication against the specified tenant
        $sessionValid = $true
        $currentTenantId = $existingContext.Tenant.Id

        try {
            if (-not $existingContext) {
                throw "No valid session available."
            }

            # Request an Azure access token for tenant validation
            $resourceUrl = (Get-AzContext).Environment.ResourceManagerUrl
            $token = Get-AzAccessToken -ResourceUrl $resourceUrl -TenantId $currentTenantId -ErrorAction Stop

            if (-not $token) {
                throw "Session is invalid."
            }
        } catch {
            Write-Host "Existing session is invalid or expired. Re-authentication required." -ForegroundColor Yellow
            $sessionValid = $false
        }

        if ($sessionValid) {
            Write-Host "Proceeding with the existing session..." -ForegroundColor Green
            $azContext = $existingContext
        } else {
            # Force re-authentication
            Write-Host "Please log in to Azure..." -ForegroundColor Cyan
            try {
                $azContext = Connect-AzAccount -Environment $CloudEnvironment -TenantId $currentTenantId -ErrorAction Stop
                Write-Host "Re-authentication successful." -ForegroundColor Green
            } catch {
                Write-Host "Authentication failed. Exiting." -ForegroundColor Red
                exit 1
            }
        }
    }
}

# If no valid authentication context, log in first and select tenant
if (-not $azContext) {
    Write-Host "Please log in to Azure..." -ForegroundColor Cyan
    try {
        $azContext = Connect-AzAccount -Environment $CloudEnvironment -ErrorAction Stop
    } catch {
        Write-Host "Authentication failed. Exiting." -ForegroundColor Red
        exit 1
    }

    # Fetch available tenants after authentication
    try {
        $tenants = Get-AzTenant | Select-Object Id, Name
    } catch {
        Write-Host "Error retrieving tenant list. Please check your permissions." -ForegroundColor Red
        exit 1
    }

    if ($tenants.Count -eq 0) {
        Write-Host "No tenants found. Exiting." -ForegroundColor Red
        exit 1
    }

    # If only one tenant is available, automatically select it
    if ($tenants.Count -eq 1) {
        $tenantId = $tenants[0].Id
    } else {
        # Display available tenants for selection
        Write-Host "`nAvailable Tenants:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $tenants.Count; $i++) {
            Write-Host ("[{0}] {1} ({2})" -f ($i + 1), $tenants[$i].Name, $tenants[$i].Id)
        }

        # Ask user to select a tenant
        $selectedTenantIndex = Read-Host "`nEnter the number of the tenant you want to use"

        # Validate selection
        if ($selectedTenantIndex -match "^\d+$" -and $selectedTenantIndex -gt 0 -and $selectedTenantIndex -le $tenants.Count) {
            $tenantId = $tenants[$selectedTenantIndex - 1].Id
            $tenantName = $tenants[$selectedTenantIndex - 1].Name
        } else {
            Write-Host "Invalid selection. Exiting." -ForegroundColor Red
            exit 1
        }

        if ($existingContext -and $tenantId -ne $existingContext.Tenant.Id) {
            Write-Host "Re-authenticating to selected tenant: $tenantName ($tenantId) | Current Tenant $($existingContext.Tenant.Name) ($($existingContext.Tenant.Id))" -ForegroundColor Yellow
            try {
                Disconnect-AzAccount -ErrorAction SilentlyContinue *>$null  # Ensure clean logout
                $azContext = Connect-AzAccount -Environment $CloudEnvironment -TenantId $tenantId -ErrorAction Stop
            } catch {
                Write-Host "Authentication to selected tenant failed. Exiting." -ForegroundColor Red
                exit 1
            }
            Write-Host "Successfully authenticated to: $tenantName ($tenantId)" -ForegroundColor Green
        } else {
            Write-Host "No re-authentication required. Proceeding with current session...$tenantName ($tenantId)" -ForegroundColor Cyan
        }
    }
}
else {
    $tenantId = $existingContext.Tenant.Id
}

# Display Tenant Information
$tenantName = (Get-AzTenant | Where-Object { $_.Id -eq $tenantId } | Select-Object -ExpandProperty Name)

Write-Host "Current tenant: $tenantName ($tenantId)" -ForegroundColor Cyan

# Retrieve subscriptions for the selected tenant
if ($parameters.SubscriptionIds -contains '*') {
    Write-Host "Retrieving available subscriptions for the selected tenant ($tenantId)..."
    try {
        $SubscriptionIds = (Get-AzSubscription -TenantId $tenantId | Select-Object -ExpandProperty Id)
        if (-Not $SubscriptionIds) {
            Write-Host "Error: No available subscriptions found for tenant $tenantId." -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "Error retrieving subscriptions for tenant $tenantId. Please check your access permissions." -ForegroundColor Red
        exit 1
    }
} else {
    $SubscriptionIds = $parameters.SubscriptionIds
}


# Define file names
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseFileName = [System.IO.Path]::GetFileNameWithoutExtension($parameters.CSVFileName)
$FileExtension = [System.IO.Path]::GetExtension($parameters.CSVFileName)
$TempOutputFile = "$BaseFileName`_$Timestamp.incomplete"        # Temporary file used while the script is running
$FinalOutputFile = "$BaseFileName`_$Timestamp$FileExtension"    # Final output file for Power BI import
$FailedSubscriptionsFile = "$BaseFileName`_$Timestamp.failed"   # Log file containing failed subscriptions and errors

$PageSize = 1000 # Maximum allowed value is 1000. Do not change!
$SubscriptionCount = 0
$secureScoresList = @()  

# Delete all .incomplete files before starting a new export
$incompleteFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*.incomplete"

if ($incompleteFiles) {
    Write-Host "Deleting all previous .incomplete files..." -ForegroundColor Yellow
    $incompleteFiles | ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
}

# ============================================================================
# Helper functions (used by the serial path; the parallel worker contains
# functionally equivalent inline copies because ThreadJobs run in isolated
# runspaces. Keep the two implementations in sync.)
# ============================================================================

function Get-ResourceGraphErrorCode {
    param([Parameter(Mandatory)] $ErrorRecord)

    $rawContent = $null
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.PSObject.Properties['Response'] `
        -and $ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.PSObject.Properties['Content']) {
        $rawContent = $ErrorRecord.Exception.Response.Content
    }
    if (-not $rawContent) { return "Unknown" }

    try {
        $details = $rawContent | ConvertFrom-Json -ErrorAction Stop
        if ($details -and $details.error -and $details.error.code) {
            return [string]$details.error.code
        }
    } catch {
        Write-Debug "Get-ResourceGraphErrorCode: failed to parse error body as JSON; returning 'Unknown'."
    }
    return "Unknown"
}

function Test-IsRetriableResourceGraphError {
    param(
        [Parameter(Mandatory)] $ErrorRecord,
        [string] $ErrorCode = "Unknown"
    )

    if ($ErrorCode -in @("GatewayTimeout", "InternalServerError", "ServiceUnavailable", "RateLimiting", "TooManyRequests")) {
        return $true
    }

    $errorText = $ErrorRecord | Out-String
    if ($errorText -match "RateLimiting|TooManyRequests|throttled") { return $true }

    $exception = $ErrorRecord.Exception
    while ($exception) {
        if ($exception -is [System.TimeoutException] -or
            $exception -is [System.Threading.Tasks.TaskCanceledException] -or
            $exception -is [System.OperationCanceledException] -or
            $exception -is [System.Net.Http.HttpRequestException] -or
            $exception -is [System.IO.IOException]) {
            return $true
        }
        $exception = $exception.InnerException
    }

    return ($errorText -match "task was canceled|timed out|connection reset by peer|ssl connection could not be established|error while copying content to a stream")
}

function Invoke-SearchAzGraphWithRetry {
    param(
        [Parameter(Mandatory)] [string] $SubscriptionId,
        [Parameter(Mandatory)] [string] $Query,
        [Parameter(Mandatory)] [int]    $First,
        [int]    $Skip = 0,
        [string] $OperationName = "Resource Graph query",
        [int]    $MaxRetries = 3,
        [int]    $RetryDelaySeconds = 2,
        [int]    $RateLimitMaxRetries = 10,
        [int]    $RateLimitRetryDelaySeconds = 5
    )

    $retryCount = 0
    while ($true) {
        try {
            if ($Skip -gt 0) {
                $result = @(Search-AzGraph -Query $Query -Subscription $SubscriptionId -First $First -Skip $Skip -ErrorAction Stop)
            } else {
                $result = @(Search-AzGraph -Query $Query -Subscription $SubscriptionId -First $First -ErrorAction Stop)
            }
            return [pscustomobject]@{
                Succeeded    = $true
                Result       = $result
                ErrorMessage = $null
                ErrorCode    = $null
            }
        } catch {
            $errorRecord  = $_
            $errorMessage = $errorRecord | Format-List -Force | Out-String
            $errorCode    = Get-ResourceGraphErrorCode -ErrorRecord $errorRecord
            $isRetriable  = Test-IsRetriableResourceGraphError -ErrorRecord $errorRecord -ErrorCode $errorCode
            $isRateLimited = ($errorCode -in @("RateLimiting", "TooManyRequests")) -or
                             (($errorRecord | Out-String) -match "RateLimiting|TooManyRequests|throttled")
            $retryLimit   = if ($isRateLimited) { $RateLimitMaxRetries } else { $MaxRetries }

            if (-not $isRetriable -or $retryCount -ge $retryLimit) {
                return [pscustomobject]@{
                    Succeeded    = $false
                    Result       = @()
                    ErrorMessage = $errorMessage
                    ErrorCode    = $errorCode
                }
            }

            $retryCount++
            $backoffDelay = if ($isRateLimited) {
                $RateLimitRetryDelaySeconds * $retryCount
            } else {
                [math]::Pow(2, $retryCount) * $RetryDelaySeconds
            }
            $reason = if ([string]::IsNullOrWhiteSpace($errorCode)) { "Unknown" } else { $errorCode }
            Write-Host "Warning: $OperationName for subscription $SubscriptionId hit $reason. Retrying in $backoffDelay seconds... (Attempt $retryCount of $retryLimit)" -ForegroundColor Yellow
            Start-Sleep -Seconds $backoffDelay
        }
    }
}

function Merge-CsvFile {
    param(
        [string[]] $SourceFiles,
        [string]   $DestinationFile
    )

    $existing = @($SourceFiles | Where-Object { $_ -and (Test-Path $_) })
    if ($existing.Count -eq 0) { return $false }

    $utf8   = [System.Text.UTF8Encoding]::new($false)
    $writer = [System.IO.StreamWriter]::new($DestinationFile, $false, $utf8)
    try {
        $first = $true
        foreach ($file in $existing) {
            $reader = [System.IO.StreamReader]::new($file)
            try {
                if (-not $first -and -not $reader.EndOfStream) {
                    [void]$reader.ReadLine()  # skip header on subsequent fragments
                }
                while (-not $reader.EndOfStream) {
                    $writer.WriteLine($reader.ReadLine())
                }
                $first = $false
            } finally { $reader.Dispose() }
        }
    } finally { $writer.Dispose() }
    return $true
}

function Merge-TextFile {
    param(
        [string[]] $SourceFiles,
        [string]   $DestinationFile
    )

    $existing = @($SourceFiles | Where-Object { $_ -and (Test-Path $_) })
    if ($existing.Count -eq 0) { return $false }

    $utf8   = [System.Text.UTF8Encoding]::new($false)
    $writer = [System.IO.StreamWriter]::new($DestinationFile, $false, $utf8)
    try {
        foreach ($file in $existing) {
            $reader = [System.IO.StreamReader]::new($file)
            try {
                while (-not $reader.EndOfStream) {
                    $writer.WriteLine($reader.ReadLine())
                }
            } finally { $reader.Dispose() }
        }
    } finally { $writer.Dispose() }
    return $true
}

function Get-FormattedFileSize {
    param([long] $Bytes)

    if ($Bytes -lt 1KB) { return ("{0:N0} Bytes" -f $Bytes) }
    if ($Bytes -lt 1MB) { return ("{0:N2} KB"    -f ($Bytes / 1KB)) }
    if ($Bytes -lt 1GB) { return ("{0:N2} MB"    -f ($Bytes / 1MB)) }
    return ("{0:N2} GB" -f ($Bytes / 1GB))
}

# ============================================================================
# Shared queries and work items
# ============================================================================

$secureScoreQuery = @'
securityresources
| where type == "microsoft.security/securescores"
| where properties.environment == "Azure"
| extend subscriptionSecureScore = round(100 * bin((todouble(properties.score.current))/ todouble(properties.score.max), 0.001))
| where subscriptionSecureScore > 0
| project subscriptionSecureScore, subscriptionId
'@
$totalRecordsQuery = "$kqlQuery | summarize totalRecords = count()"

$workItems = for ($i = 0; $i -lt $SubscriptionIds.Count; $i++) {
    [pscustomobject]@{
        Index          = $i + 1
        SubscriptionId = $SubscriptionIds[$i]
    }
}
$TotalSubscriptions = $workItems.Count
$workerResults     = @()
$RunTempDirectory  = $null
$cleanupRunTempDirectory = $false

# ============================================================================
# Main execution: serial path (default) or parallel path (opt-in)
# ============================================================================
try {
    if ($ParallelWorkers -gt 1) {
        # ------------------------------------------------------------
        # Parallel execution path (ThreadJob + ARG REST API)
        # ------------------------------------------------------------

        $RunTempDirectory = Join-Path -Path (Get-Location).Path -ChildPath "$BaseFileName`_$Timestamp.parts"
        New-Item -ItemType Directory -Path $RunTempDirectory -Force | Out-Null

        # Derive ARM endpoint from current Az environment (works for AzureCloud + AzureUSGovernment)
        $azContextNow      = Get-AzContext
        $resourceManagerUrl = $azContextNow.Environment.ResourceManagerUrl.TrimEnd('/')
        $argEndpoint       = "$resourceManagerUrl/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"

        # Bearer token (env-aware via the current Az context). Captured once.
        # The token is held only in process memory and passed by argument to workers.
        $accessToken = (Get-AzAccessToken -ResourceUrl ($resourceManagerUrl + '/') -TenantId $tenantId -ErrorAction Stop).Token

        # Synchronized progress counter so output is monotonic across workers.
        $progressState = [hashtable]::Synchronized(@{
            Completed = 0
            Total     = $TotalSubscriptions
        })

        Import-Module ThreadJob -ErrorAction Stop | Out-Null

        Write-Host "Starting parallel export with $ParallelWorkers workers across $TotalSubscriptions subscriptions..." -ForegroundColor Cyan
        Write-Host "Note: the bearer token captured at start expires in ~60 minutes. For larger tenants, prefer ParallelWorkers=1 (serial) which auto-refreshes via the Az SDK." -ForegroundColor DarkGray

        $workerScript = {
            param(
                $work, $endpoint, $token, $kql, $ssQuery, $countQuery,
                $pageSize, $runTempDir, $progress
            )

            $subscriptionId    = $work.SubscriptionId
            $subscriptionIndex = $work.Index
            $csvFragment       = Join-Path $runTempDir ("{0:D6}_{1}.csv"    -f $subscriptionIndex, $subscriptionId)
            $failedFragment    = Join-Path $runTempDir ("{0:D6}_{1}.failed" -f $subscriptionIndex, $subscriptionId)
            $secureScore        = $null
            $retrievedRecords   = 0
            $totalRecords       = 0
            $subscriptionFailed = $false
            $failureMessage     = $null

            # ---- Inline ARG REST query with retry (mirrors Invoke-SearchAzGraphWithRetry) ----
            function Invoke-ArgRestWithRetry {
                param(
                    [string] $SubscriptionId,
                    [string] $Query,
                    [int]    $First,
                    [int]    $Skip,
                    [string] $OperationName,
                    [string] $Endpoint,
                    [string] $Token
                )

                $maxRetries                 = 3
                $retryDelaySeconds          = 2
                $rateLimitMaxRetries        = 10
                $rateLimitRetryDelaySeconds = 5
                $retryCount                 = 0

                $headers = @{
                    Authorization  = "Bearer $Token"
                    'Content-Type' = 'application/json'
                }

                while ($true) {
                    try {
                        $body = @{
                            subscriptions = @($SubscriptionId)
                            query         = $Query
                            options       = @{
                                '$top'       = $First
                                '$skip'      = $Skip
                                resultFormat = 'objectArray'
                            }
                        } | ConvertTo-Json -Depth 5 -Compress

                        $response = Invoke-RestMethod -Method Post -Uri $Endpoint -Headers $headers -Body $body -ErrorAction Stop

                        $rows = @()
                        if ($null -ne $response.data) {
                            $rows = @($response.data)
                        }

                        return [pscustomobject]@{
                            Succeeded    = $true
                            Result       = $rows
                            ErrorMessage = $null
                            ErrorCode    = $null
                        }
                    } catch {
                        $errorRecord  = $_
                        $errorMessage = $errorRecord | Format-List -Force | Out-String
                        $errorCode    = "Unknown"

                        # Try to parse error code from REST response body
                        try {
                            $errResponse = $errorRecord.Exception.Response
                            $body = $null
                            if ($errResponse) {
                                if ($errResponse -is [System.Net.Http.HttpResponseMessage]) {
                                    $body = $errResponse.Content.ReadAsStringAsync().Result
                                } elseif ($errResponse.GetResponseStream) {
                                    $stream = $errResponse.GetResponseStream()
                                    $reader = [System.IO.StreamReader]::new($stream)
                                    $body = $reader.ReadToEnd()
                                    $reader.Dispose()
                                }
                            }
                            if (-not $body -and $errorRecord.ErrorDetails) {
                                $body = $errorRecord.ErrorDetails.Message
                            }
                            if ($body) {
                                $details = $body | ConvertFrom-Json -ErrorAction Stop
                                if ($details -and $details.error -and $details.error.code) {
                                    $errorCode = [string]$details.error.code
                                }
                            }
                        } catch {
                            Write-Debug "Invoke-ArgRestWithRetry: failed to parse error body as JSON; errorCode left as 'Unknown'."
                        }

                        $errorText  = $errorRecord | Out-String
                        $isRetriable = ($errorCode -in @("GatewayTimeout", "InternalServerError", "ServiceUnavailable", "RateLimiting", "TooManyRequests")) -or
                                       ($errorText -match "RateLimiting|TooManyRequests|throttled|task was canceled|timed out|connection reset by peer|ssl connection could not be established|error while copying content to a stream")
                        if (-not $isRetriable) {
                            $exception = $errorRecord.Exception
                            while ($exception) {
                                if ($exception -is [System.TimeoutException] -or
                                    $exception -is [System.Threading.Tasks.TaskCanceledException] -or
                                    $exception -is [System.OperationCanceledException] -or
                                    $exception -is [System.Net.Http.HttpRequestException] -or
                                    $exception -is [System.IO.IOException]) {
                                    $isRetriable = $true
                                    break
                                }
                                $exception = $exception.InnerException
                            }
                        }

                        $isRateLimited = ($errorCode -in @("RateLimiting", "TooManyRequests")) -or
                                         ($errorText -match "RateLimiting|TooManyRequests|throttled")
                        $retryLimit = if ($isRateLimited) { $rateLimitMaxRetries } else { $maxRetries }

                        if (-not $isRetriable -or $retryCount -ge $retryLimit) {
                            return [pscustomobject]@{
                                Succeeded    = $false
                                Result       = @()
                                ErrorMessage = $errorMessage
                                ErrorCode    = $errorCode
                            }
                        }

                        $retryCount++
                        $backoffDelay = if ($isRateLimited) {
                            $rateLimitRetryDelaySeconds * $retryCount
                        } else {
                            [math]::Pow(2, $retryCount) * $retryDelaySeconds
                        }
                        $reason = if ([string]::IsNullOrWhiteSpace($errorCode)) { "Unknown" } else { $errorCode }
                        Write-Host "Warning: $OperationName for subscription $SubscriptionId hit $reason. Retrying in $backoffDelay seconds... (Attempt $retryCount of $retryLimit)" -ForegroundColor Yellow
                        Start-Sleep -Seconds $backoffDelay
                    }
                }
            }

            # Secure score (best-effort)
            try {
                $ssResult = Invoke-ArgRestWithRetry -SubscriptionId $subscriptionId -Query $ssQuery -First 1 -Skip 0 -OperationName "Secure score query" -Endpoint $endpoint -Token $token
                if ($ssResult.Succeeded -and $ssResult.Result.Count -gt 0 -and $ssResult.Result[0].subscriptionSecureScore) {
                    $secureScore = [double]$ssResult.Result[0].subscriptionSecureScore
                }
            } catch {
                Write-Verbose "Secure score query failed for $subscriptionId"
            }

            # Total records (best-effort)
            $countResult = Invoke-ArgRestWithRetry -SubscriptionId $subscriptionId -Query $countQuery -First 1 -Skip 0 -OperationName "Record count query" -Endpoint $endpoint -Token $token
            if ($countResult.Succeeded -and $countResult.Result.Count -gt 0 -and $countResult.Result[0].totalRecords) {
                $totalRecords = [int64]$countResult.Result[0].totalRecords
            }

            # Page through results
            $skip = 0
            while ($true) {
                $pageResult = Invoke-ArgRestWithRetry -SubscriptionId $subscriptionId -Query $kql -First $pageSize -Skip $skip -OperationName "Recommendation query" -Endpoint $endpoint -Token $token
                if (-not $pageResult.Succeeded) {
                    Add-Content -Path $failedFragment -Value "Subscription ID: $subscriptionId - Error: $($pageResult.ErrorMessage)" -Encoding UTF8
                    $subscriptionFailed = $true
                    $failureMessage = $pageResult.ErrorMessage
                    break
                }

                $batch = $pageResult.Result
                $batchCount = $batch.Count
                if ($batchCount -eq 0) { break }

                $batch | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Value -is [datetime] } | ForEach-Object {
                        $_.Value = $_.Value.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
                    }
                    $_
                } | Export-Csv -Path $csvFragment -NoTypeInformation -Append

                $retrievedRecords += $batchCount
                $skip += $pageSize
                if ($batchCount -lt $pageSize) { break }
            }

            # Increment ordered progress counter and emit a single status line
            [System.Threading.Monitor]::Enter($progress.SyncRoot)
            try {
                $progress.Completed++
                $position = $progress.Completed
            } finally {
                [System.Threading.Monitor]::Exit($progress.SyncRoot)
            }

            $statusColor = if ($subscriptionFailed) { 'Red' } elseif ($retrievedRecords -eq 0) { 'Yellow' } else { 'Green' }
            $statusText  = if ($subscriptionFailed) { "FAILED" } else { "$retrievedRecords records (total: $totalRecords)" }
            Write-Host ("[{0}/{1}] {2} - {3}" -f $position, $progress.Total, $subscriptionId, $statusText) -ForegroundColor $statusColor

            [pscustomobject]@{
                SubscriptionId   = $subscriptionId
                Index            = $subscriptionIndex
                SecureScore      = $secureScore
                RetrievedRecords = $retrievedRecords
                Failed           = $subscriptionFailed
                FailureMessage   = $failureMessage
                CsvPath          = if (Test-Path $csvFragment) { $csvFragment } else { $null }
                FailedPath       = if (Test-Path $failedFragment) { $failedFragment } else { $null }
            }
        }

        # Submit all jobs
        $jobs = foreach ($work in $workItems) {
            Start-ThreadJob -ThrottleLimit $ParallelWorkers `
                -ScriptBlock $workerScript `
                -ArgumentList @($work, $argEndpoint, $accessToken, $kqlQuery, $secureScoreQuery, $totalRecordsQuery, $PageSize, $RunTempDirectory, $progressState)
        }

        # Wait, collect, clean up
        $workerResults = @($jobs | Wait-Job | Receive-Job)
        $jobs | Remove-Job -Force -ErrorAction SilentlyContinue

        # Merge fragments in original subscription order
        $orderedResults = @($workerResults | Sort-Object Index)
        $csvFragments    = @($orderedResults | Where-Object { $_.CsvPath }    | Select-Object -ExpandProperty CsvPath)
        $failedFragments = @($orderedResults | Where-Object { $_.FailedPath } | Select-Object -ExpandProperty FailedPath)

        if ($csvFragments.Count -gt 0) {
            Merge-CsvFile -SourceFiles $csvFragments -DestinationFile $TempOutputFile | Out-Null
        }
        if ($failedFragments.Count -gt 0) {
            Merge-TextFile -SourceFiles $failedFragments -DestinationFile $FailedSubscriptionsFile | Out-Null
        }

        $cleanupRunTempDirectory = $true

    } else {
        # ------------------------------------------------------------
        # Serial execution path (default; PS5.1-compatible; uses Search-AzGraph)
        # ------------------------------------------------------------

        $workerResults = foreach ($work in $workItems) {
            $SubscriptionId   = $work.SubscriptionId
            $subscriptionIndex = $work.Index
            $secureScore      = $null
            $retrievedRecords = 0
            $totalRecords     = 0
            $subscriptionFailed = $false
            $failureMessage   = $null

            # Secure score (best-effort)
            try {
                $ssResult = Invoke-SearchAzGraphWithRetry -SubscriptionId $SubscriptionId -Query $secureScoreQuery -First 1 -OperationName "Secure score query"
                if ($ssResult.Succeeded -and $ssResult.Result.Count -gt 0 -and $ssResult.Result[0].subscriptionSecureScore) {
                    $secureScore = [double]$ssResult.Result[0].subscriptionSecureScore
                }
            } catch {
                Write-Verbose "Secure score query failed for $SubscriptionId"
            }

            Write-Host ("[{0}/{1}] Querying subscription: {2}" -f $subscriptionIndex, $TotalSubscriptions, $SubscriptionId)

            # Total records (best-effort)
            $countResult = Invoke-SearchAzGraphWithRetry -SubscriptionId $SubscriptionId -Query $totalRecordsQuery -First 1 -OperationName "Record count query"
            if ($countResult.Succeeded -and $countResult.Result.Count -gt 0 -and $countResult.Result[0].totalRecords) {
                $totalRecords = [int64]$countResult.Result[0].totalRecords
            }

            # Page through results
            $Skip = 0
            while ($true) {
                $pageResult = Invoke-SearchAzGraphWithRetry -SubscriptionId $SubscriptionId -Query $kqlQuery -First $PageSize -Skip $Skip -OperationName "Recommendation query"
                if (-not $pageResult.Succeeded) {
                    Write-Host "Warning: Error executing query for subscription $SubscriptionId" -ForegroundColor Yellow
                    Add-Content -Path $FailedSubscriptionsFile -Value "Subscription ID: $SubscriptionId - Error: $($pageResult.ErrorMessage)"
                    $subscriptionFailed = $true
                    $failureMessage = $pageResult.ErrorMessage
                    break
                }

                $batch = $pageResult.Result
                $batchCount = $batch.Count
                if ($batchCount -eq 0) {
                    Write-Host "Subscription $SubscriptionId - Retrieved 0 records" -ForegroundColor Yellow
                    break
                }

                $batch | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Value -is [datetime] } | ForEach-Object {
                        $_.Value = $_.Value.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
                    }
                    $_
                } | Export-Csv -Path $TempOutputFile -NoTypeInformation -Append

                $retrievedRecords += $batchCount
                $Skip += $PageSize
                $remainingRecords = [Math]::Max(0, $totalRecords - $retrievedRecords)
                Write-Host "Subscription $SubscriptionId - Retrieved $batchCount records, remaining: $remainingRecords" -ForegroundColor Green

                if ($batchCount -lt $PageSize) { break }
            }

            [pscustomobject]@{
                SubscriptionId   = $SubscriptionId
                Index            = $subscriptionIndex
                SecureScore      = $secureScore
                RetrievedRecords = $retrievedRecords
                Failed           = $subscriptionFailed
                FailureMessage   = $failureMessage
            }
        }
        $workerResults = @($workerResults)
    }

    # ------------------------------------------------------------
    # Common: aggregate results, finalize files
    # ------------------------------------------------------------

    $SubscriptionCount = $workerResults.Count
    $secureScoresList  = @($workerResults | Where-Object { $null -ne $_.SecureScore } | Select-Object -ExpandProperty SecureScore)

    Write-Host ""
    if ($secureScoresList.Count -gt 0) {
        $overallSecureScore = [math]::Round(($secureScoresList | Measure-Object -Average).Average, 2)
        Write-Host ("Overall Secure Score across {0} subscriptions: {1}" -f $secureScoresList.Count, $overallSecureScore) -ForegroundColor Green
    } else {
        Write-Host "No Secure Score data found across subscriptions." -ForegroundColor Yellow
    }
    Write-Host ""

    if (Test-Path $TempOutputFile) {
        Move-Item -Path $TempOutputFile -Destination $FinalOutputFile -Force

        $fileSizeBytes     = (Get-Item $FinalOutputFile).Length
        $fileSizeFormatted = Get-FormattedFileSize -Bytes $fileSizeBytes

        Write-Host "Data export completed: $FinalOutputFile ($fileSizeFormatted)" -ForegroundColor Green
    } else {
        Write-Host "Warning: No data was exported." -ForegroundColor Red
    }

    if (Test-Path $FailedSubscriptionsFile) {
        Write-Host "Some subscriptions failed. See log file: $FailedSubscriptionsFile" -ForegroundColor Yellow
    }
} catch {
    $errorMessage = $Error[0] | Format-List -Force | Out-String
    Write-Host "Error encountered during execution: $errorMessage" -ForegroundColor Red
    exit 1
} finally {
    if ($cleanupRunTempDirectory -and $RunTempDirectory -and (Test-Path $RunTempDirectory)) {
        Remove-Item -Path $RunTempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$EndTime = Get-Date
$Duration = $EndTime - $StartTime
Write-Host "Total subscriptions queried: $SubscriptionCount" 
Write-Host "Script execution time: $($Duration.Hours)h $($Duration.Minutes)m $($Duration.Seconds)s"
