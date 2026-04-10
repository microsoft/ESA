# Version 1.0
param(
    [string]$ParameterFile
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
            $token = Get-AzAccessToken -ResourceUrl "https://management.azure.com" -TenantId $currentTenantId -ErrorAction Stop

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
                $azContext = Connect-AzAccount -TenantId $currentTenantId -ErrorAction Stop
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
        $azContext = Connect-AzAccount -ErrorAction Stop
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
                $azContext = Connect-AzAccount -TenantId $tenantId -ErrorAction Stop 
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

function Merge-CsvFiles {
    param(
        [string[]]$SourceFiles,
        [string]$DestinationFile
    )

    $existingSourceFiles = @($SourceFiles | Where-Object { $_ -and (Test-Path $_) })
    if ($existingSourceFiles.Count -eq 0) {
        return $false
    }

    $utf8Encoding = [System.Text.UTF8Encoding]::new($false)
    $destinationWriter = [System.IO.StreamWriter]::new($DestinationFile, $false, $utf8Encoding)

    try {
        $includeHeader = $true

        foreach ($sourceFile in $existingSourceFiles) {
            $sourceReader = [System.IO.StreamReader]::new($sourceFile)

            try {
                if (-not $includeHeader -and -not $sourceReader.EndOfStream) {
                    [void]$sourceReader.ReadLine()
                }

                while (-not $sourceReader.EndOfStream) {
                    $destinationWriter.WriteLine($sourceReader.ReadLine())
                }

                $includeHeader = $false
            } finally {
                $sourceReader.Dispose()
            }
        }
    } finally {
        $destinationWriter.Dispose()
    }

    return $true
}

function Merge-TextFiles {
    param(
        [string[]]$SourceFiles,
        [string]$DestinationFile
    )

    $existingSourceFiles = @($SourceFiles | Where-Object { $_ -and (Test-Path $_) })
    if ($existingSourceFiles.Count -eq 0) {
        return $false
    }

    $utf8Encoding = [System.Text.UTF8Encoding]::new($false)
    $destinationWriter = [System.IO.StreamWriter]::new($DestinationFile, $false, $utf8Encoding)

    try {
        foreach ($sourceFile in $existingSourceFiles) {
            $sourceReader = [System.IO.StreamReader]::new($sourceFile)

            try {
                while (-not $sourceReader.EndOfStream) {
                    $destinationWriter.WriteLine($sourceReader.ReadLine())
                }
            } finally {
                $sourceReader.Dispose()
            }
        }
    } finally {
        $destinationWriter.Dispose()
    }

    return $true
}

function Get-FormattedFileSize {
    param(
        [long]$Bytes
    )

    if ($Bytes -lt 1KB) {
        return ("{0:N0} Bytes" -f $Bytes)
    }

    if ($Bytes -lt 1MB) {
        return ("{0:N2} KB" -f ($Bytes / 1KB))
    }

    if ($Bytes -lt 1GB) {
        return ("{0:N2} MB" -f ($Bytes / 1MB))
    }

    return ("{0:N2} GB" -f ($Bytes / 1GB))
}

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
$OutputDirectory = (Get-Location).Path
$TempOutputFile = Join-Path -Path $OutputDirectory -ChildPath "$BaseFileName`_$Timestamp.incomplete"        # Temporary file used while the script is running
$FinalOutputFile = Join-Path -Path $OutputDirectory -ChildPath "$BaseFileName`_$Timestamp$FileExtension"    # Final output file for Power BI import
$FailedSubscriptionsFile = Join-Path -Path $OutputDirectory -ChildPath "$BaseFileName`_$Timestamp.failed"   # Log file containing failed subscriptions and errors
$RunTempDirectory = Join-Path -Path $OutputDirectory -ChildPath "$BaseFileName`_$Timestamp.parts"
$ContextFile = Join-Path -Path $RunTempDirectory -ChildPath "AzContext.json"

$PageSize = 1000 # Maximum allowed value is 1000. Do not change!
$ParallelWorkerCount = 20
$MaxRetries = 3
$RetryDelay = 2  # Initial delay in seconds (the total wait time is 28 seconds if all (3) retries are exhausted)
$RateLimitMaxRetries = 10
$RateLimitRetryDelaySeconds = 5  # Linear delay in seconds for Resource Graph throttling retries
$SubscriptionCount = 0
$secureScoresList = @()  
$TotalSubscriptions = $SubscriptionIds.Count
$SecureScoreQuery = @'
securityresources
| where type == "microsoft.security/securescores"
| where properties.environment == "Azure"
| extend subscriptionSecureScore = round(100 * bin((todouble(properties.score.current))/ todouble(properties.score.max), 0.001))
| where subscriptionSecureScore > 0
| project subscriptionSecureScore, subscriptionId
'@
$cleanupRunTempDirectory = $false

# Delete all .incomplete files before starting a new export
$incompleteFiles = Get-ChildItem -Path $OutputDirectory -Filter "*.incomplete" -File -ErrorAction SilentlyContinue

if ($incompleteFiles) {
    Write-Host "Deleting all previous .incomplete files..." -ForegroundColor Yellow
    $incompleteFiles | ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
}

# Process subscriptions in parallel and merge the fragments after all workers finish
try {
    New-Item -ItemType Directory -Path $RunTempDirectory -Force | Out-Null
    Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue *>$null
    Save-AzContext -Path $ContextFile -Force -ErrorAction Stop *>$null

    $subscriptionWorkItems = for ($i = 0; $i -lt $SubscriptionIds.Count; $i++) {
        [pscustomobject]@{
            Index = $i + 1
            SubscriptionId = $SubscriptionIds[$i]
        }
    }

    Write-Host "Starting parallel export with $ParallelWorkerCount workers across $TotalSubscriptions subscriptions..." -ForegroundColor Cyan

    $workerResults = @(
        $subscriptionWorkItems | ForEach-Object -ThrottleLimit $ParallelWorkerCount -Parallel {
            $workItem = $_
            $subscriptionId = $workItem.SubscriptionId
            $subscriptionIndex = $workItem.Index
            $csvFragmentFile = Join-Path -Path $using:RunTempDirectory -ChildPath ("{0:D6}_{1}.csv" -f $subscriptionIndex, $subscriptionId)
            $failedFragmentFile = Join-Path -Path $using:RunTempDirectory -ChildPath ("{0:D6}_{1}.failed" -f $subscriptionIndex, $subscriptionId)
            $secureScore = $null
            $retrievedRecords = 0
            $totalRecords = 0
            $skip = 0
            $subscriptionFailed = $false

            function Get-ResourceGraphErrorCode {
                param(
                    [System.Management.Automation.ErrorRecord]$ErrorRecord
                )

                $rawContent = $null
                if ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.Content) {
                    $rawContent = $ErrorRecord.Exception.Response.Content
                }

                if (-not $rawContent) {
                    return "Unknown"
                }

                try {
                    $errorDetails = $rawContent | ConvertFrom-Json
                    if ($errorDetails -and $errorDetails.error -and $errorDetails.error.code) {
                        return $errorDetails.error.code
                    }
                } catch {
                }

                return "Unknown"
            }

            function Test-IsRetriableResourceGraphError {
                param(
                    [System.Management.Automation.ErrorRecord]$ErrorRecord,
                    [string]$ErrorCode
                )

                if ($ErrorCode -in @("GatewayTimeout", "InternalServerError", "ServiceUnavailable", "RateLimiting", "TooManyRequests")) {
                    return $true
                }

                $errorText = $ErrorRecord | Out-String
                if ($errorText -match "RateLimiting|TooManyRequests|throttled") {
                    return $true
                }

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

            function Invoke-ResourceGraphQueryWithRetry {
                param(
                    [string]$SubscriptionId,
                    [string]$Query,
                    [int]$First,
                    [int]$Skip = 0,
                    [string]$OperationName
                )

                $retryCount = 0

                while ($true) {
                    try {
                        $result = if ($Skip -gt 0) {
                            @(Search-AzGraph -Query $Query -Subscription $SubscriptionId -First $First -Skip $Skip -ErrorAction Stop)
                        } else {
                            @(Search-AzGraph -Query $Query -Subscription $SubscriptionId -First $First -ErrorAction Stop)
                        }

                        return [pscustomobject]@{
                            Succeeded = $true
                            Result = $result
                            ErrorMessage = $null
                            ErrorCode = $null
                        }
                    } catch {
                        $errorMessage = $_ | Format-List -Force | Out-String
                        $errorCode = Get-ResourceGraphErrorCode -ErrorRecord $_
                        $isRetriable = Test-IsRetriableResourceGraphError -ErrorRecord $_ -ErrorCode $errorCode
                        $isRateLimited = $errorCode -in @("RateLimiting", "TooManyRequests") -or (($_ | Out-String) -match "RateLimiting|TooManyRequests|throttled")
                        $retryLimit = if ($isRateLimited) { $using:RateLimitMaxRetries } else { $using:MaxRetries }

                        if (-not $isRetriable -or $retryCount -ge $retryLimit) {
                            return [pscustomobject]@{
                                Succeeded = $false
                                Result = @()
                                ErrorMessage = $errorMessage
                                ErrorCode = $errorCode
                            }
                        }

                        $retryCount++
                        $backoffDelay = if ($isRateLimited) {
                            $using:RateLimitRetryDelaySeconds * $retryCount
                        } else {
                            [math]::Pow(2, $retryCount) * $using:RetryDelay
                        }

                        $retryReason = if ([string]::IsNullOrWhiteSpace($errorCode)) { "Unknown" } else { $errorCode }
                        Write-Host "Warning: $OperationName for subscription $SubscriptionId hit $retryReason. Retrying in $backoffDelay seconds... (Attempt $retryCount of $retryLimit)" -ForegroundColor Yellow
                        Start-Sleep -Seconds $backoffDelay
                    }
                }
            }

            try {
                Import-Module Az.Accounts, Az.ResourceGraph -ErrorAction Stop
                Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue *>$null
                Import-AzContext -Path $using:ContextFile -Scope Process -ErrorAction Stop *>$null

                try {
                    $secureScoreQueryResult = Invoke-ResourceGraphQueryWithRetry -SubscriptionId $subscriptionId -Query $using:SecureScoreQuery -First 1 -OperationName "Secure score query"
                    if ($secureScoreQueryResult.Succeeded -and $secureScoreQueryResult.Result.Count -gt 0 -and $secureScoreQueryResult.Result[0].subscriptionSecureScore) {
                        $secureScore = [double]$secureScoreQueryResult.Result[0].subscriptionSecureScore
                    }
                } catch {
                    # Continue silently on errors (no logging, just skip)
                }

                Write-Host "Querying subscription ($subscriptionIndex/$using:TotalSubscriptions): $subscriptionId"

                $totalRecordsQuery = "$using:kqlQuery | summarize totalRecords = count()"
                try {
                    $totalRecordsQueryResult = Invoke-ResourceGraphQueryWithRetry -SubscriptionId $subscriptionId -Query $totalRecordsQuery -First 1 -OperationName "Record count query"
                    if ($totalRecordsQueryResult.Succeeded -and $totalRecordsQueryResult.Result.Count -gt 0 -and $totalRecordsQueryResult.Result[0].totalRecords) {
                        $totalRecords = [int64]$totalRecordsQueryResult.Result[0].totalRecords
                    } else {
                        $totalRecords = 0
                    }
                } catch {
                    $totalRecords = 0
                }

                while ($true) {
                    $queryInvocation = Invoke-ResourceGraphQueryWithRetry -SubscriptionId $subscriptionId -Query $using:kqlQuery -First $using:PageSize -Skip $skip -OperationName "Recommendation query"
                    if (-not $queryInvocation.Succeeded) {
                        Write-Host "Warning: Error executing query for subscription $subscriptionId" -ForegroundColor Yellow
                        Add-Content -Path $failedFragmentFile -Value "Subscription ID: $subscriptionId - Error: $($queryInvocation.ErrorMessage)" -Encoding UTF8
                        $subscriptionFailed = $true
                        break
                    }

                    $queryResults = $queryInvocation.Result
                    $batchCount = $queryResults.Count
                    if ($batchCount -eq 0) {
                        Write-Host "Subscription $subscriptionId - Retrieved 0 records" -ForegroundColor Yellow
                        break
                    }

                    $queryResults | ForEach-Object {
                        $_.PSObject.Properties | Where-Object { $_.Value -is [datetime] } | ForEach-Object {
                            $_.Value = $_.Value.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
                        }
                        $_
                    } | Export-Csv -Path $csvFragmentFile -NoTypeInformation -Append

                    $retrievedRecords += $batchCount
                    $skip += $using:PageSize
                    $remainingRecords = $totalRecords - $retrievedRecords

                    if ($remainingRecords -lt 0) {
                        $remainingRecords = 0
                    }

                    Write-Host "Subscription $subscriptionId - Retrieved $batchCount records, remaining: $remainingRecords" -ForegroundColor Green

                    if ($batchCount -lt $using:PageSize) {
                        break
                    }
                }
            } catch {
                $subscriptionFailed = $true
                $errorMessage = $_ | Format-List -Force | Out-String
                Write-Host "Warning: Error executing query for subscription $subscriptionId" -ForegroundColor Yellow
                Add-Content -Path $failedFragmentFile -Value "Subscription ID: $subscriptionId - Error: $errorMessage" -Encoding UTF8
            }

            [pscustomobject]@{
                SubscriptionId = $subscriptionId
                Index = $subscriptionIndex
                CsvPath = if (Test-Path $csvFragmentFile) { $csvFragmentFile } else { $null }
                FailedPath = if (Test-Path $failedFragmentFile) { $failedFragmentFile } else { $null }
                SecureScore = $secureScore
                RetrievedRecords = $retrievedRecords
                TotalRecords = $totalRecords
                Failed = $subscriptionFailed
            }
        }
    )

    $SubscriptionCount = $workerResults.Count
    $secureScoresList = @($workerResults | Where-Object { $null -ne $_.SecureScore } | Select-Object -ExpandProperty SecureScore)

    $csvFragments = @($workerResults | Sort-Object Index | Where-Object { $_.CsvPath } | Select-Object -ExpandProperty CsvPath)
    $failedFragments = @($workerResults | Sort-Object Index | Where-Object { $_.FailedPath } | Select-Object -ExpandProperty FailedPath)

    Write-Host ""
    # Calculate Overall Secure Score across all subscriptions
    if ($secureScoresList.Count -gt 0) {
        $overallSecureScore = [math]::Round(($secureScoresList | Measure-Object -Average).Average, 2)
        Write-Host ("Overall Secure Score across {0} subscriptions: {1}" -f $secureScoresList.Count, $overallSecureScore) -ForegroundColor Green
    } else {
        Write-Host "No Secure Score data found across subscriptions." -ForegroundColor Yellow
    }
    Write-Host ""

    if (Merge-CsvFiles -SourceFiles $csvFragments -DestinationFile $TempOutputFile) {
        # Rename the temporary file to the final output file
        Move-Item -Path $TempOutputFile -Destination $FinalOutputFile -Force

        # Get file size in a readable format
        $fileSizeBytes = (Get-Item $FinalOutputFile).Length
        $fileSizeFormatted = Get-FormattedFileSize -Bytes $fileSizeBytes

        Write-Host "Data export completed: $(Split-Path -Path $FinalOutputFile -Leaf) ($fileSizeFormatted)" -ForegroundColor Green
    } else {
        Write-Host "Warning: No data was exported." -ForegroundColor Red
    }

    if (Merge-TextFiles -SourceFiles $failedFragments -DestinationFile $FailedSubscriptionsFile) {
        Write-Host "Some subscriptions failed. See log file: $(Split-Path -Path $FailedSubscriptionsFile -Leaf)" -ForegroundColor Yellow
    }

    $cleanupRunTempDirectory = $true
} catch {
    $errorMessage = $Error[0] | Format-List -Force | Out-String
    Write-Host "Error encountered during execution: $errorMessage" -ForegroundColor Red
    exit 1
} finally {
    if (Test-Path $ContextFile) {
        Remove-Item -Path $ContextFile -Force -ErrorAction SilentlyContinue
    }

    if ($cleanupRunTempDirectory -and (Test-Path $RunTempDirectory)) {
        Remove-Item -Path $RunTempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$EndTime = Get-Date
$Duration = $EndTime - $StartTime
Write-Host "Total subscriptions queried: $SubscriptionCount" 
Write-Host "Script execution time: $($Duration.Hours)h $($Duration.Minutes)m $($Duration.Seconds)s"
