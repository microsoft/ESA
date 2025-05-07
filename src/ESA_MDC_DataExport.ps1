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

# Loop through each Subscription ID
try {
    foreach ($SubscriptionId in $SubscriptionIds) {
        
        # Query Secure Score for the subscription
        $secureScoreQuery = @'
        securityresources
        | where type == "microsoft.security/securescores"
        | where properties.environment == "Azure"
        | extend subscriptionSecureScore = round(100 * bin((todouble(properties.score.current))/ todouble(properties.score.max), 0.001))
        | where subscriptionSecureScore > 0
        | project subscriptionSecureScore, subscriptionId
'@
        try {
            $secureScoreResult = Search-AzGraph -Query $secureScoreQuery -Subscription $SubscriptionId -First 1 -ErrorAction Stop
            if ($secureScoreResult -and $secureScoreResult.subscriptionSecureScore) {
                $secureScoresList += $secureScoreResult.subscriptionSecureScore  # Store only valid values
            }
        } catch {
            # Continue silently on errors (no logging, just skip)
        }

        $SubscriptionCount++
        Write-Host "Querying subscription ($SubscriptionCount/$($SubscriptionIds.Count)): $SubscriptionId"
        $Skip = 0

        # Retrieve Total Record Count Before Querying
        $totalRecordsQuery = "$kqlQuery | summarize totalRecords = count()"
        try {
            $totalRecordsResult = Search-AzGraph -Query $totalRecordsQuery -Subscription $SubscriptionId -First 1 -ErrorAction Stop 
            $totalRecords = if ($totalRecordsResult.totalRecords) { $totalRecordsResult.totalRecords } else { 0 }
        } catch {
            $totalRecords = 0
        }

        $retrievedRecords = 0

        # Execute the query with retry and exponential backoff
        $maxRetries = 3
        $retryDelay = 2  # Initial delay in seconds (the total wait time is 28 seconds if all (3) retries are exhausted)
        while ($true) {
            $retryCount = 0
            while ($retryCount -le $maxRetries) {
                try {
                    if ($Skip -eq 0) {
                        $queryResults = Search-AzGraph -Query $kqlQuery -Subscription $SubscriptionId -First $PageSize -ErrorAction Stop
                    } else {
                        $queryResults = Search-AzGraph -Query $kqlQuery -Subscription $SubscriptionId -First $PageSize -Skip $Skip -ErrorAction Stop
                    }
            
                    if (-not $queryResults) {
                        Write-Host "No records retrieved for subscription $SubscriptionId." -ForegroundColor Yellow
                        break
                    }
                    break # If query is successful, break out of the retry loop
                } catch {
                    # Extract and parse the error details 
                    $errorMessage = $Error[0] | Format-List -Force | Out-String
                    $rawContent = $Error[0].Exception.Response.Content
                
                    if ($rawContent) {
                        try {
                            $errorDetails = $rawContent | ConvertFrom-Json 
                            if ($errorDetails -and $errorDetails.error -and $errorDetails.error.code) {
                                $errorCode = $errorDetails.error.code
                            } else {
                                $errorCode = "Unknown"
                            }
                        } catch {
                            $errorCode = "Unknown"
                        }
                    } else {
                        $errorCode = "Unknown"
                    }
                
                    # Check if the error is GatewayTimeout or InternalServerError
                    if ($errorCode -eq "GatewayTimeout" -or $errorCode -eq "InternalServerError") {
                        # Increment retry count
                        $retryCount++
                        
                        # If max retries reached, log the error and break the loop
                        if ($retryCount -gt $maxRetries) {
                            Write-Host "Warning: Error executing query for subscription $SubscriptionId" -ForegroundColor Yellow
                            Add-Content -Path $FailedSubscriptionsFile -Value "Subscription ID: $SubscriptionId - Error: $errorMessage"
                            break  # Skip further processing for this subscription and move to the next one
                        }
                
                        $backoffDelay = [math]::Pow(2, $retryCount) * $retryDelay # Exponential backoff delay 
                        Write-Host "Warning: Error executing query for subscription $SubscriptionId. Retrying in $backoffDelay seconds... (Attempt $retryCount of $maxRetries)" -ForegroundColor Yellow
                        Start-Sleep -Seconds $backoffDelay
                    } else {
                        # For other errors, log and break the loop (no retry)
                        Write-Host "Warning: Error executing query for subscription $SubscriptionId" -ForegroundColor Yellow
                        Add-Content -Path $FailedSubscriptionsFile -Value "Subscription ID: $SubscriptionId - Error: $errorMessage"
                        break  # Skip further processing for this subscription and move to the next one
                    }
                }
                
            }

            # Ensure datetime fields are correctly formatted
            if ($queryResults) {
                $queryResults | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Value -is [datetime] } | ForEach-Object { $_.Value = $_.Value.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ") }
                    $_
                } | Export-Csv -Path $TempOutputFile -NoTypeInformation -Append

                $retrievedRecords += $queryResults.Count
                $Skip += $PageSize
            }

            $remainingRecords = $totalRecords - $retrievedRecords
            
            # Display Progress with Remaining Records
            if ($remainingRecords -lt 0) { $remainingRecords = 0 }
            if ($queryResults.Count -eq 0) {
                Write-Host "Subscription $SubscriptionId - Retrieved 0 records" -ForegroundColor Yellow
            } else {
                Write-Host "Subscription $SubscriptionId - Retrieved $($queryResults.Count) records, remaining: $(if ($remainingRecords -lt 0) { 'not available' } else { $remainingRecords })" -ForegroundColor Green
            }
            
            if ($queryResults.Count -lt $PageSize) {
                break
            }

            # Explicitly release the reference to allow memory cleanup in large data processing
            $queryResults = $null

        }
    }

    Write-Host ""
    # Calculate Overall Secure Score across all subscriptions
    if ($secureScoresList.Count -gt 0) {
        $overallSecureScore = [math]::Round(($secureScoresList | Measure-Object -Average).Average, 2)
        Write-Host ("Overall Secure Score across {0} subscriptions: {1}" -f $secureScoresList.Count, $overallSecureScore) -ForegroundColor Green
    } else {
        Write-Host "No Secure Score data found across subscriptions." -ForegroundColor Yellow
    }
    Write-Host ""


    if (Test-Path $TempOutputFile) {
        # Rename the temporary file to the final output file
        Rename-Item -Path $TempOutputFile -NewName $FinalOutputFile

        # Get file size in a readable format
        $fileSizeBytes = (Get-Item $FinalOutputFile).Length
        $sizeUnits = @("KB", "MB", "GB")
        $sizeThresholds = @(1KB, 1MB, 1GB)
        $index = ($sizeThresholds | Where-Object { $fileSizeBytes -ge $_ } | Measure-Object).Count - 1
        $fileSizeFormatted = "{0:N2} {1}" -f ($fileSizeBytes / $sizeThresholds[$index]), $sizeUnits[$index]

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
}

$EndTime = Get-Date
$Duration = $EndTime - $StartTime
Write-Host "Total subscriptions queried: $SubscriptionCount" 
Write-Host "Script execution time: $($Duration.Hours)h $($Duration.Minutes)m $($Duration.Seconds)s"
