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
    Write-Host "The following required PowerShell modules are missing:" -ForegroundColor Yellow
    Write-Host "  $($missingModules -join ', ')" -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "Install missing module(s) now from PSGallery (CurrentUser scope)? [Y/n]"
    if ([string]::IsNullOrWhiteSpace($response) -or $response -match '^(y|yes)$') {
        try {
            Write-Host "Installing: $($missingModules -join ', ') (CurrentUser scope)..." -ForegroundColor Cyan
            Install-Module -Name $missingModules -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            # Verify
            $stillMissing = @()
            foreach ($module in $missingModules) {
                if (-not (Get-Module -ListAvailable -Name $module)) {
                    $stillMissing += $module
                }
            }
            if ($stillMissing.Count -gt 0) {
                Write-Host "Error: installation reported success but the following module(s) are still not available: $($stillMissing -join ', ')" -ForegroundColor Red
                exit 1
            }
            Write-Host "Module(s) installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Error: failed to install module(s): $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Try manually: Install-Module $($missingModules -join ', ') -Scope CurrentUser -Force -AllowClobber" -ForegroundColor Green
            exit 1
        }
    } else {
        Write-Host "Cannot continue without required modules. Install manually with:" -ForegroundColor Cyan
        Write-Host "  Install-Module $($missingModules -join ', ') -Scope CurrentUser -Force" -ForegroundColor Green
        exit 1
    }
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

# Parse parallel-mode configuration.
#   * 'Parallel' (bool, default false) - simple opt-in. When true, the script
#     auto-sizes the worker pool from the subscription count using:
#       subscriptions <= 4 -> workers = subscriptions (1 worker per sub)
#       subscriptions > 4  -> workers = ceil(subscriptions / 2), capped at 20
# (No manual override; the auto-size rule above is the only knob.)
$Parallel = $false
if ($null -ne $parameters.Parallel) {
    try {
        $Parallel = [bool]::Parse([string]$parameters.Parallel)
    } catch {
        Write-Host "Error: 'Parallel' must be true or false (got: $($parameters.Parallel))." -ForegroundColor Red
        exit 1
    }
}
# $ParallelWorkers is computed later (after sub list is built). Default = 1 (serial).
$ParallelWorkers = 1

# PS7 + ThreadJob prerequisites. Run when parallel mode is requested.
if ($Parallel) {
    # Parallel mode is an EXPERIMENTAL feature and requires PowerShell 7+.
    # On Windows PowerShell 5.1 the parallel code path is intentionally blocked
    # because the ARG REST + ThreadJob combination is only validated on PS 7+.
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Host "Error: Parallel mode requires PowerShell 7 or later (current: $($PSVersionTable.PSVersion))." -ForegroundColor Red
        Write-Host "  Install PowerShell 7+: https://aka.ms/powershell" -ForegroundColor Green
        Write-Host "  Or set 'Parallel': false in the JSON to use the supported serial path." -ForegroundColor Green
        exit 1
    }
    # Check whether Start-ThreadJob is available. It can be provided by either:
    #   * 'ThreadJob' (PSGallery, required on Windows PowerShell 5.1)
    #   * 'Microsoft.PowerShell.ThreadJob' (built-in starting with PowerShell 7)
    # Get-Command works for both, since the cmdlet name is the same.
    if (-not (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue)) {
        Write-Host ""
        Write-Host "Parallel mode requires the 'Start-ThreadJob' cmdlet, which is not currently available." -ForegroundColor Yellow
        Write-Host "It is provided by the 'ThreadJob' module from the PowerShell Gallery." -ForegroundColor Yellow
        $response = Read-Host "Install 'ThreadJob' module now from PSGallery (CurrentUser scope)? [Y/n]"
        if ([string]::IsNullOrWhiteSpace($response) -or $response -match '^[Yy]') {
            try {
                Write-Host "Installing 'ThreadJob' module (CurrentUser scope, -AllowClobber)..." -ForegroundColor Cyan
                # -AllowClobber handles the case where Start-ThreadJob is already provided
                # by another (built-in) module on this machine.
                Install-Module -Name ThreadJob -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                if (-not (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue)) {
                    Write-Host "Error: installation reported success but 'Start-ThreadJob' is still not available." -ForegroundColor Red
                    Write-Host "  Open a new PowerShell session and re-run the script." -ForegroundColor Green
                    exit 1
                }
                Write-Host "'ThreadJob' module installed successfully." -ForegroundColor Green
            } catch {
                Write-Host "Error: failed to install 'ThreadJob' module: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "  Try manually: Install-Module ThreadJob -Scope CurrentUser -AllowClobber" -ForegroundColor Green
                exit 1
            }
        } else {
            Write-Host "Aborted by user. Set 'Parallel': false in the JSON to use the serial path." -ForegroundColor Yellow
            exit 1
        }
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
            # Skip the first rate-limit warning - the first retry almost always
            # succeeds and the noise is more confusing than helpful. Surface it
            # only from attempt 2 onwards (or immediately for non-rate-limit errors).
            if (-not ($isRateLimited -and $retryCount -eq 1)) {
                Write-Host "Warning: $OperationName for subscription $SubscriptionId hit $reason. Retrying in $backoffDelay seconds... (Attempt $retryCount of $retryLimit)" -ForegroundColor Yellow
            }
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
# Auto-size the worker pool when Parallel=true:
#   subscriptions <= 4 -> workers = subscriptions
#   subscriptions > 4  -> workers = ceil(subscriptions / 2), capped at 20
if ($Parallel -and $TotalSubscriptions -gt 0) {
    if ($TotalSubscriptions -le 4) {
        $ParallelWorkers = $TotalSubscriptions
    } else {
        $ParallelWorkers = [int][Math]::Min(20, [Math]::Ceiling($TotalSubscriptions / 2.0))
    }
}
$workerResults     = @()
$RunTempDirectory  = $null
$cleanupRunTempDirectory = $false

# ============================================================================
# Main execution: serial path (default) or parallel path (opt-in)
# ============================================================================
try {
    if ($ParallelWorkers -gt 1) {
        # ------------------------------------------------------------
        # Parallel execution path (ThreadJob + Search-AzGraph)
        #
        # ThreadJob workers run in separate runspaces inside the SAME process,
        # so they share Az session state. We force in-memory (process-scope)
        # context to avoid any disk autosave races, then explicitly Set-AzContext
        # in each worker as belt-and-suspenders. No bearer token capture, no
        # REST endpoint - the Az SDK handles auth, refresh, and pagination.
        # ------------------------------------------------------------

        $RunTempDirectory = Join-Path -Path (Get-Location).Path -ChildPath "$BaseFileName`_$Timestamp.parts"
        New-Item -ItemType Directory -Path $RunTempDirectory -Force | Out-Null

        # Make Az context process-scoped (in-memory only). Idempotent and safe.
        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
        $sharedContext = Get-AzContext
        if (-not $sharedContext) {
            throw "No Az context available; cannot proceed with parallel mode."
        }

        # Synchronized progress counter so output is monotonic across workers.
        $progressState = [hashtable]::Synchronized(@{
            Completed = 0
            Total     = $TotalSubscriptions
        })

        # Auto-detect which ThreadJob module to import (Start-ThreadJob may be
        # provided by either the gallery 'ThreadJob' module or the built-in
        # 'Microsoft.PowerShell.ThreadJob' module that ships with PowerShell 7).
        $threadJobModuleName = if (Get-Module -ListAvailable -Name 'ThreadJob' -ErrorAction SilentlyContinue) {
            'ThreadJob'
        } elseif (Get-Module -ListAvailable -Name 'Microsoft.PowerShell.ThreadJob' -ErrorAction SilentlyContinue) {
            'Microsoft.PowerShell.ThreadJob'
        } else {
            $null
        }
        if ($threadJobModuleName) {
            Import-Module $threadJobModuleName -ErrorAction Stop | Out-Null
        } elseif (-not (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue)) {
            throw "Start-ThreadJob cmdlet is not available and no ThreadJob module was found."
        }

        Write-Host "Starting parallel export with $ParallelWorkers workers across $TotalSubscriptions subscriptions..." -ForegroundColor Cyan
        Write-Host "Informational: parallel mode is an EXPERIMENTAL feature." -ForegroundColor DarkGray

        # InitializationScript runs once per worker runspace. We use it to import
        # the Az modules (so Search-AzGraph is available) and to define a small
        # retry helper that mirrors the serial path's Invoke-SearchAzGraphWithRetry.
        # Function names are kept distinct ('Worker*') so they can't collide with
        # the parent's helpers if PS happens to share scope.
        $initScript = {
            Import-Module Az.Accounts -ErrorAction Stop | Out-Null
            Import-Module Az.ResourceGraph -ErrorAction Stop | Out-Null

            function Get-WorkerRGErrorCode {
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
                } catch { }
                return "Unknown"
            }

            function Test-WorkerRetriableRGError {
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

            function Invoke-WorkerSearchAzGraph {
                param(
                    [Parameter(Mandatory)] [string] $SubscriptionId,
                    [Parameter(Mandatory)] [string] $Query,
                    [Parameter(Mandatory)] [int]    $First,
                    [int]    $Skip = 0,
                    [string] $OperationName = "Resource Graph query",
                    [System.Collections.Generic.List[string]] $OutputBuffer
                )
                $maxRetries                 = 3
                $retryDelaySeconds          = 2
                $rateLimitMaxRetries        = 10
                $rateLimitRetryDelaySeconds = 5
                $retryCount                 = 0

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
                        $errorCode    = Get-WorkerRGErrorCode -ErrorRecord $errorRecord
                        $isRetriable  = Test-WorkerRetriableRGError -ErrorRecord $errorRecord -ErrorCode $errorCode
                        $isRateLimited = ($errorCode -in @("RateLimiting", "TooManyRequests")) -or
                                         (($errorRecord | Out-String) -match "RateLimiting|TooManyRequests|throttled")
                        $retryLimit   = if ($isRateLimited) { $rateLimitMaxRetries } else { $maxRetries }

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
                        # Skip the first rate-limit warning (the first retry almost
                        # always succeeds). Surface it only from attempt 2 onwards.
                        if (-not ($isRateLimited -and $retryCount -eq 1)) {
                            $msg = "Warning: $OperationName for subscription $SubscriptionId hit $reason. Retrying in $backoffDelay seconds... (Attempt $retryCount of $retryLimit)"
                            if ($OutputBuffer) { $OutputBuffer.Add($msg) | Out-Null } else { Write-Host $msg -ForegroundColor Yellow }
                        }
                        Start-Sleep -Seconds $backoffDelay
                    }
                }
            }
        }

        $workerScript = {
            param(
                $work, $sharedContext, $kql, $ssQuery, $countQuery,
                $pageSize, $runTempDir, $progress
            )

            # Belt-and-suspenders: explicitly set the Az context in this worker's
            # runspace. Disable-AzContextAutosave -Scope Process in the parent
            # already shares context, but Set-AzContext makes it deterministic.
            Set-AzContext -Context $sharedContext -ErrorAction Stop | Out-Null

            $subscriptionId    = $work.SubscriptionId
            $subscriptionIndex = $work.Index
            $csvFragment       = Join-Path $runTempDir ("{0:D6}_{1}.csv"    -f $subscriptionIndex, $subscriptionId)
            $failedFragment    = Join-Path $runTempDir ("{0:D6}_{1}.failed" -f $subscriptionIndex, $subscriptionId)
            $secureScore        = $null
            $retrievedRecords   = 0
            $totalRecords       = 0
            $subscriptionFailed = $false
            $failureMessage     = $null

            # Buffer per-sub output so the entire block prints atomically (in
            # completion order) when the worker finishes. Output format matches
            # the serial path line-for-line.
            $outputBuffer = New-Object 'System.Collections.Generic.List[string]'
            $outputBuffer.Add(("[{0}/{1}] Querying subscription: {2}" -f $subscriptionIndex, $progress.Total, $subscriptionId)) | Out-Null

            # Secure score (best-effort)
            try {
                $ssResult = Invoke-WorkerSearchAzGraph -SubscriptionId $subscriptionId -Query $ssQuery -First 1 -OperationName "Secure score query" -OutputBuffer $outputBuffer
                if ($ssResult.Succeeded -and $ssResult.Result.Count -gt 0 -and $ssResult.Result[0].subscriptionSecureScore) {
                    $secureScore = [double]$ssResult.Result[0].subscriptionSecureScore
                }
            } catch {
                # silent best-effort; matches serial behavior
            }

            # Total records (best-effort)
            $countResult = Invoke-WorkerSearchAzGraph -SubscriptionId $subscriptionId -Query $countQuery -First 1 -OperationName "Record count query" -OutputBuffer $outputBuffer
            if ($countResult.Succeeded -and $countResult.Result.Count -gt 0 -and $countResult.Result[0].totalRecords) {
                $totalRecords = [int64]$countResult.Result[0].totalRecords
            }

            # Page through results
            $skip = 0
            while ($true) {
                $pageResult = Invoke-WorkerSearchAzGraph -SubscriptionId $subscriptionId -Query $kql -First $pageSize -Skip $skip -OperationName "Recommendation query" -OutputBuffer $outputBuffer
                if (-not $pageResult.Succeeded) {
                    $outputBuffer.Add("Warning: Error executing query for subscription $subscriptionId") | Out-Null
                    Add-Content -Path $failedFragment -Value "Subscription ID: $subscriptionId - Error: $($pageResult.ErrorMessage)" -Encoding UTF8
                    $subscriptionFailed = $true
                    $failureMessage = $pageResult.ErrorMessage
                    break
                }

                $batch = $pageResult.Result
                $batchCount = $batch.Count
                if ($batchCount -eq 0) {
                    $outputBuffer.Add("Subscription $subscriptionId - Retrieved 0 records") | Out-Null
                    break
                }

                $batch | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Value -is [datetime] } | ForEach-Object {
                        $_.Value = $_.Value.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
                    }
                    $_
                } | Export-Csv -Path $csvFragment -NoTypeInformation -Append

                $retrievedRecords += $batchCount
                $skip += $pageSize
                $remainingRecords = [Math]::Max(0, $totalRecords - $retrievedRecords)
                $outputBuffer.Add("Subscription $subscriptionId - Retrieved $batchCount records, remaining: $remainingRecords") | Out-Null

                if ($batchCount -lt $pageSize) { break }
            }

            # Print buffered lines atomically (per-sub block, in completion order).
            [System.Threading.Monitor]::Enter($progress.SyncRoot)
            try {
                $progress.Completed++
                foreach ($line in $outputBuffer) {
                    if ($line -match '^Warning:') {
                        Write-Host $line -ForegroundColor Yellow
                    } elseif ($line -match '- Retrieved 0 records') {
                        Write-Host $line -ForegroundColor Yellow
                    } elseif ($line -match '- Retrieved') {
                        Write-Host $line -ForegroundColor Green
                    } else {
                        Write-Host $line
                    }
                }
            } finally {
                [System.Threading.Monitor]::Exit($progress.SyncRoot)
            }

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
                -InitializationScript $initScript `
                -ScriptBlock $workerScript `
                -ArgumentList @($work, $sharedContext, $kqlQuery, $secureScoreQuery, $totalRecordsQuery, $PageSize, $RunTempDirectory, $progressState)
        }

        # Drain output live while jobs run.
        # Wait-Job | Receive-Job buffers ALL output until every job completes,
        # which makes the run look frozen. Polling Receive-Job every 250ms
        # streams worker Write-Host output to the console as soon as workers
        # emit it, while still capturing return values into $workerResults.
        $workerResults = @()
        $running = $true
        while ($running) {
            $workerResults += @($jobs | Receive-Job)
            $running = [bool]($jobs | Where-Object { $_.State -in @('Running','NotStarted') })
            if ($running) {
                Start-Sleep -Milliseconds 250
            }
        }
        # Final drain to capture anything emitted between the last poll and job completion.
        $workerResults += @($jobs | Receive-Job)
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
