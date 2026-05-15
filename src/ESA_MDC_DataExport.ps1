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

# Check FullLanguage mode (constrained language mode breaks several Az cmdlets we rely on)
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host "Error: PowerShell must run in FullLanguage mode. Current mode: $($ExecutionContext.SessionState.LanguageMode)" -ForegroundColor Red
    exit 1
}

# Check not running in Azure Cloud Shell (unsupported environment)
if ($env:AZUREPS_HOST_ENVIRONMENT -match 'cloud-shell' -or $env:ACC_CLOUD -eq 'true') {
    Write-Host "Error: This script must not be executed within Azure Cloud Shell." -ForegroundColor Red
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
                $azContext = Connect-AzAccount -Environment $CloudEnvironment -TenantId $currentTenantId -ErrorAction Stop -WarningAction SilentlyContinue
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
        $azContext = Connect-AzAccount -Environment $CloudEnvironment -ErrorAction Stop -WarningAction SilentlyContinue
    } catch {
        Write-Host "Authentication failed. Exiting." -ForegroundColor Red
        exit 1
    }

    # Fetch available tenants after authentication
    try {
        $tenants = Get-AzTenant -WarningAction SilentlyContinue | Select-Object Id, Name
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
                $azContext = Connect-AzAccount -Environment $CloudEnvironment -TenantId $tenantId -ErrorAction Stop -WarningAction SilentlyContinue
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
$tenantName = (Get-AzTenant -WarningAction SilentlyContinue | Where-Object { $_.Id -eq $tenantId } | Select-Object -ExpandProperty Name)

Write-Host "Current tenant: $tenantName ($tenantId)" -ForegroundColor Cyan

# Retrieve subscriptions for the selected tenant
if ($parameters.SubscriptionIds -contains '*') {
    Write-Host "Retrieving available subscriptions for the selected tenant ($tenantId)..."
    try {
        $SubscriptionIds = (Get-AzSubscription -TenantId $tenantId -WarningAction SilentlyContinue | Select-Object -ExpandProperty Id)
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

# ============================================================================
# Pre-flight: classify subscriptions to avoid querying ones that can't return
# MCSB-aligned data. Three batched ARG queries (~3s) bucket each subscription:
#   - MCSB enabled (ascScore present)              -> queryable, goes through the per-sub loop
#   - MCSB not assigned                            -> Defender registered but MCSB compliance standard not assigned; skip
#   - Defender Foundational CSPM not enabled       -> no Microsoft.Security/* resources exist; skip
#   - No access (pre-flight)                       -> sub not visible at ARM at all (no RBAC); skip
# Failures are non-fatal: on any error we fall back to querying every input
# subscription (existing behavior).
# ============================================================================
$AllInputSubscriptionIds  = @($SubscriptionIds)
$totalInputSubscriptions  = $AllInputSubscriptionIds.Count
$subsMcsbNotEnabled       = @()  # securityresources visible but no ascScore (MCSB compliance standard not assigned)
$subsNoSecurityVisibility = @()  # zero securityresources visible (Defender Foundational CSPM not enabled on the sub)
$subsNoSubscriptionAccess = @()  # subscription not visible at ARM at all (no RBAC)
$preflightSucceeded       = $false

if ($totalInputSubscriptions -gt 0) {
    Write-Host ""
    Write-Host ("Pre-flight: classifying {0} subscription(s)..." -f $totalInputSubscriptions) -ForegroundColor Cyan
    $preflightStartTime = Get-Date
    try {
        # Probe 1: subs visible at ARM (Reader or higher)
        $r1 = Search-AzGraph -Subscription $AllInputSubscriptionIds -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | distinct subscriptionId" -First 1000 -ErrorAction Stop
        $visibleArmIds = if ($r1.PSObject.Properties.Name -contains 'Data') { @(@($r1.Data).subscriptionId) } else { @(@($r1).subscriptionId) }

        # Probe 2: subs with at least one securityresources entry (Security Reader)
        $r2 = Search-AzGraph -Subscription $AllInputSubscriptionIds -Query "securityresources | distinct subscriptionId" -First 1000 -ErrorAction Stop
        $secVisibleIds = if ($r2.PSObject.Properties.Name -contains 'Data') { @(@($r2.Data).subscriptionId) } else { @(@($r2).subscriptionId) }

        # Probe 3: subs with the MCSB ascScore baseline
        $r3 = Search-AzGraph -Subscription $AllInputSubscriptionIds -Query "securityresources | where type == 'microsoft.security/securescores' and name == 'ascScore' | distinct subscriptionId" -First 1000 -ErrorAction Stop
        $mcsbReadyIds = if ($r3.PSObject.Properties.Name -contains 'Data') { @(@($r3.Data).subscriptionId) } else { @(@($r3).subscriptionId) }

        # Bucket every input sub. Order matters: ascScore set is the strictest
        # so we check it first; everything else falls through to the relevant
        # 'why was this skipped' bucket.
        $subsMcsbEnabled          = @($AllInputSubscriptionIds | Where-Object { $_ -in $mcsbReadyIds })
        $subsMcsbNotEnabled       = @($AllInputSubscriptionIds | Where-Object { $_ -in $secVisibleIds  -and $_ -notin $mcsbReadyIds })
        $subsNoSecurityVisibility = @($AllInputSubscriptionIds | Where-Object { $_ -in $visibleArmIds  -and $_ -notin $secVisibleIds })
        $subsNoSubscriptionAccess = @($AllInputSubscriptionIds | Where-Object { $_ -notin $visibleArmIds })

        $preflightDuration  = ((Get-Date) - $preflightStartTime).TotalSeconds
        $preflightSucceeded = $true
        Write-Host ("Pre-flight complete in {0:N1}s" -f $preflightDuration) -ForegroundColor DarkGray
        Write-Host ("  MCSB enabled, will query:                  {0}" -f $subsMcsbEnabled.Count) -ForegroundColor Green
        if ($subsMcsbNotEnabled.Count       -gt 0) { Write-Host ("  MCSB not assigned, skipped:                {0}" -f $subsMcsbNotEnabled.Count)       -ForegroundColor Yellow }
        if ($subsNoSecurityVisibility.Count -gt 0) { Write-Host ("  Defender Foundational CSPM not enabled:    {0}" -f $subsNoSecurityVisibility.Count) -ForegroundColor Yellow }
        if ($subsNoSubscriptionAccess.Count -gt 0) { Write-Host ("  No access (pre-flight), skipped:           {0}" -f $subsNoSubscriptionAccess.Count) -ForegroundColor Red }

        # Restrict the per-sub loop to MCSB-enabled subscriptions only.
        $SubscriptionIds = $subsMcsbEnabled
    } catch {
        Write-Host ("Pre-flight failed; will query all {0} input subscription(s). Reason: {1}" -f $totalInputSubscriptions, $_.Exception.Message) -ForegroundColor Yellow
    }
    Write-Host ""
}

# Define file names
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseFileName = [System.IO.Path]::GetFileNameWithoutExtension($parameters.CSVFileName)
$FileExtension = [System.IO.Path]::GetExtension($parameters.CSVFileName)
$TempOutputFile = "$BaseFileName`_$Timestamp.incomplete"        # Temporary file used while the script is running
$FinalOutputFile = "$BaseFileName`_$Timestamp$FileExtension"    # Final output file for Power BI import
$FailedSubscriptionsFile = "$BaseFileName`_$Timestamp.failed"   # Log file containing failed subscriptions and errors
$ReportFile = "$BaseFileName`_$Timestamp.report.txt"            # Auto-generated end-of-run summary report

$PageSize = 1000 # Maximum allowed value is 1000. Do not change!
$SubscriptionCount = 0
$secureScoresList = @()  

# Subscription tracking for end-of-run summary statistics. Populated after the
# common aggregation step from each worker's per-subscription return object.
$subsSuccessful     = @()  # Returned data
$subsNoData         = @()  # Returned 0 records (DfC possibly not onboarded)
$subsPermissionFail = @()  # AuthorizationFailed / Forbidden / AccessDenied
$subsOtherFail      = @()  # Gateway timeout after retries, other errors

# Secure score sub-tracking. Distinguishes between subs that returned a score,
# subs that returned no securescores resource, and subs where the query errored.
$subsWithSecureScore    = @()
$subsNoSecureScore      = @()
$subsSecureScoreFailed  = @()

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
                $response = Search-AzGraph -Query $Query -Subscription $SubscriptionId -First $First -Skip $Skip -ErrorAction Stop
            } else {
                $response = Search-AzGraph -Query $Query -Subscription $SubscriptionId -First $First -ErrorAction Stop
            }
            # Search-AzGraph (Az.ResourceGraph >= 0.10.0) returns a PSResourceGraphResponse<PSObject>
            # wrapper with rows under .Data; older versions returned a flat PSObject[].
            # Normalize so callers always see an array of rows.
            $result = if ($null -eq $response) {
                @()
            } elseif ($response.PSObject.Properties.Name -contains 'Data') {
                @($response.Data)
            } else {
                @($response)
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

        # Synchronized progress + live output queue.
        # EXPERIMENTAL: workers enqueue each output line into LiveQueue as it
        # happens; the main loop drains the queue every tick and prints lines
        # immediately. Lines from different subs may interleave, but each line
        # carries the subscription ID so output stays parseable. CSV merge
        # still happens in submission order (separate concern).
        # WorkerStatus carries a short live-progress label per in-flight sub
        # (e.g. "page 3/14"); the main thread folds it into Write-Progress.
        $progressState = [hashtable]::Synchronized(@{
            Completed    = 0
            Total        = $TotalSubscriptions
            LiveQueue    = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
            WorkerStatus = @{}   # int Index -> string  (short live label)
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
                            $response = Search-AzGraph -Query $Query -Subscription $SubscriptionId -First $First -Skip $Skip -ErrorAction Stop
                        } else {
                            $response = Search-AzGraph -Query $Query -Subscription $SubscriptionId -First $First -ErrorAction Stop
                        }
                        # Search-AzGraph (Az.ResourceGraph >= 0.10.0) returns a PSResourceGraphResponse<PSObject>
                        # wrapper with rows under .Data; older versions returned a flat PSObject[].
                        # Normalize so callers always see an array of rows.
                        $result = if ($null -eq $response) {
                            @()
                        } elseif ($response.PSObject.Properties.Name -contains 'Data') {
                            @($response.Data)
                        } else {
                            @($response)
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

            # EXPERIMENTAL live-output mode: workers enqueue each line into a
            # shared ConcurrentQueue as it happens, and the main loop prints
            # them out interleaved. We retain a local list ($outputBuffer) only
            # because Invoke-WorkerSearchAzGraph still expects a List[string]
            # for retry warnings - we drain it into the queue after each call.
            $outputBuffer = New-Object 'System.Collections.Generic.List[string]'
            $emitLine = {
                param($line)
                $progress.LiveQueue.Enqueue($line)
            }
            $drainBuffer = {
                if ($outputBuffer.Count -gt 0) {
                    foreach ($l in $outputBuffer) { $progress.LiveQueue.Enqueue($l) }
                    $outputBuffer.Clear()
                }
            }
            & $emitLine ("[{0}/{1}] Querying subscription: {2}" -f $subscriptionIndex, $progress.Total, $subscriptionId)

            # Tiny helper: update this sub's live status in the shared progress
            # dict. Main thread reads this and renders it into Write-Progress.
            $setStatus = {
                param($label)
                [System.Threading.Monitor]::Enter($progress.SyncRoot)
                try { $progress.WorkerStatus[$subscriptionIndex] = $label }
                finally { [System.Threading.Monitor]::Exit($progress.SyncRoot) }
            }
            & $setStatus 'secscore'

            # Secure score (best-effort). Track outcome so the end-of-run
            # summary can distinguish 'no securescores resource' from 'query
            # failed' - both leave $secureScore = $null otherwise.
            $secureScoreError = $null
            try {
                $ssResult = Invoke-WorkerSearchAzGraph -SubscriptionId $subscriptionId -Query $ssQuery -First 1 -OperationName "Secure score query" -OutputBuffer $outputBuffer
                if ($ssResult.Succeeded -and $ssResult.Result.Count -gt 0 -and $ssResult.Result[0].subscriptionSecureScore) {
                    $secureScore = [double]$ssResult.Result[0].subscriptionSecureScore
                } elseif (-not $ssResult.Succeeded) {
                    $secureScoreError = $ssResult.ErrorMessage
                }
            } catch {
                $secureScoreError = $_.Exception.Message
            }
            & $drainBuffer

            & $setStatus 'count'

            # Total records (best-effort)
            $countResult = Invoke-WorkerSearchAzGraph -SubscriptionId $subscriptionId -Query $countQuery -First 1 -OperationName "Record count query" -OutputBuffer $outputBuffer
            if ($countResult.Succeeded -and $countResult.Result.Count -gt 0 -and $countResult.Result[0].totalRecords) {
                $totalRecords = [int64]$countResult.Result[0].totalRecords
            }
            & $drainBuffer
            $totalPages = if ($totalRecords -gt 0) { [int][Math]::Ceiling($totalRecords / [double]$pageSize) } else { 1 }
            $currentPage = 0

            # Page through results
            $skip = 0
            while ($true) {
                $currentPage++
                & $setStatus ("page {0}/{1}" -f $currentPage, $totalPages)
                $pageResult = Invoke-WorkerSearchAzGraph -SubscriptionId $subscriptionId -Query $kql -First $pageSize -Skip $skip -OperationName "Recommendation query" -OutputBuffer $outputBuffer
                & $drainBuffer
                if (-not $pageResult.Succeeded) {
                    & $emitLine "Warning: Error executing query for subscription $subscriptionId"
                    Add-Content -Path $failedFragment -Value "Subscription ID: $subscriptionId - Error: $($pageResult.ErrorMessage)" -Encoding UTF8
                    $subscriptionFailed = $true
                    $failureMessage = $pageResult.ErrorMessage
                    break
                }

                $batch = $pageResult.Result
                $batchCount = $batch.Count
                if ($batchCount -eq 0) {
                    & $emitLine "Subscription $subscriptionId - Retrieved 0 records"
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
                & $emitLine "Subscription $subscriptionId - Retrieved $batchCount records, remaining: $remainingRecords"

                if ($batchCount -lt $pageSize) { break }
            }

            # Mark this sub complete and clear its WorkerStatus entry. No
            # buffered block to hand off in live-output mode.
            [System.Threading.Monitor]::Enter($progress.SyncRoot)
            try {
                $progress.Completed++
                [void]$progress.WorkerStatus.Remove($subscriptionIndex)
            } finally {
                [System.Threading.Monitor]::Exit($progress.SyncRoot)
            }

            [pscustomobject]@{
                SubscriptionId    = $subscriptionId
                Index             = $subscriptionIndex
                SecureScore       = $secureScore
                SecureScoreError  = $secureScoreError
                RetrievedRecords  = $retrievedRecords
                Failed            = $subscriptionFailed
                FailureMessage    = $failureMessage
                CsvPath           = if (Test-Path $csvFragment) { $csvFragment } else { $null }
                FailedPath        = if (Test-Path $failedFragment) { $failedFragment } else { $null }
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
        #
        # EXPERIMENTAL live-output mode: workers enqueue each output line into
        # $progressState.LiveQueue as it happens. This loop drains the queue
        # every tick and prints lines immediately. Lines from different subs
        # may interleave, but each line carries the subscription ID so output
        # stays parseable. CSV merge still happens in submission order.
        $workerResults    = @()
        $progressActivity = "Querying $TotalSubscriptions subscriptions"

        $printLine = {
            param($line)
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

        while ($true) {
            $workerResults += @($jobs | Receive-Job)

            # Drain the live queue.
            $line = $null
            while ($progressState.LiveQueue.TryDequeue([ref]$line)) {
                & $printLine $line
            }

            # Update progress bar. WorkerStatus is read under lock and folded
            # into the status string so the user sees live per-worker page
            # progress (e.g. "in-flight: #2(3/14), #3(5/12)").
            $running   = @($jobs | Where-Object { $_.State -in @('Running','NotStarted') })
            $inFlight  = @($jobs | Where-Object { $_.State -eq 'Running' }).Count
            $done      = $progressState.Completed
            $pct       = if ($TotalSubscriptions -gt 0) { [int](($done / $TotalSubscriptions) * 100) } else { 0 }

            $inFlightDetail = ""
            [System.Threading.Monitor]::Enter($progressState.SyncRoot)
            try {
                if ($progressState.WorkerStatus.Count -gt 0) {
                    $parts = foreach ($k in ($progressState.WorkerStatus.Keys | Sort-Object)) {
                        "#$k($($progressState.WorkerStatus[$k]))"
                    }
                    $inFlightDetail = ": " + ($parts -join ', ')
                }
            } finally { [System.Threading.Monitor]::Exit($progressState.SyncRoot) }

            Write-Progress -Activity $progressActivity `
                           -Status ("{0}/{1} done; {2} in-flight{3}" -f $done, $TotalSubscriptions, $inFlight, $inFlightDetail) `
                           -PercentComplete $pct

            if ($running.Count -eq 0) { break }
            Start-Sleep -Milliseconds 250
        }

        # Final drain: capture any remaining return values + any lines workers
        # enqueued between the last poll and job completion.
        $workerResults += @($jobs | Receive-Job)
        $line = $null
        while ($progressState.LiveQueue.TryDequeue([ref]$line)) {
            & $printLine $line
        }
        Write-Progress -Activity $progressActivity -Completed

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

            # Print the per-subscription header FIRST so the user sees activity
            # immediately. The secure-score query below can take several seconds
            # and previously made the console appear stuck between subs.
            Write-Host ("[{0}/{1}] Querying subscription: {2}" -f $subscriptionIndex, $TotalSubscriptions, $SubscriptionId)

            # Secure score (best-effort). Track outcome so the end-of-run
            # summary can distinguish 'no securescores resource' from 'query
            # failed' - both leave $secureScore = $null otherwise.
            $secureScoreError = $null
            try {
                $ssResult = Invoke-SearchAzGraphWithRetry -SubscriptionId $SubscriptionId -Query $secureScoreQuery -First 1 -OperationName "Secure score query"
                if ($ssResult.Succeeded -and $ssResult.Result.Count -gt 0 -and $ssResult.Result[0].subscriptionSecureScore) {
                    $secureScore = [double]$ssResult.Result[0].subscriptionSecureScore
                } elseif (-not $ssResult.Succeeded) {
                    $secureScoreError = $ssResult.ErrorMessage
                }
            } catch {
                $secureScoreError = $_.Exception.Message
                Write-Verbose "Secure score query failed for $SubscriptionId"
            }

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
                SecureScoreError = $secureScoreError
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

    # Categorize each subscription's outcome for the end-of-run summary.
    # Permission errors are detected by pattern-matching the failure message;
    # everything else that failed is grouped as 'other'.
    foreach ($r in $workerResults) {
        if ($r.Failed) {
            if ($r.FailureMessage -match 'AuthorizationFailed|does not have authorization|Forbidden|AccessDenied') {
                $subsPermissionFail += $r.SubscriptionId
            } else {
                $subsOtherFail += $r.SubscriptionId
            }
        } elseif ($r.RetrievedRecords -gt 0) {
            $subsSuccessful += $r.SubscriptionId
        } else {
            $subsNoData += $r.SubscriptionId
        }

        # Secure score categorization (independent of recommendation outcome).
        if ($null -ne $r.SecureScore) {
            $subsWithSecureScore += $r.SubscriptionId
        } elseif ($r.SecureScoreError) {
            $subsSecureScoreFailed += $r.SubscriptionId
        } else {
            $subsNoSecureScore += $r.SubscriptionId
        }
    }

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
$durationFormatted = "{0:D1}h {1:D2}m {2:D2}s" -f $Duration.Hours, $Duration.Minutes, $Duration.Seconds

# ----------------------------------------------------------------------------
# EXPORT SUMMARY
# ----------------------------------------------------------------------------
$separator = ('=' * 60)
Write-Host ""
Write-Host $separator -ForegroundColor Cyan
Write-Host " EXPORT SUMMARY" -ForegroundColor Cyan
Write-Host $separator -ForegroundColor Cyan
Write-Host ""
if ($preflightSucceeded -and $totalInputSubscriptions -gt 0) {
    Write-Host ("Total input subscriptions:             {0}" -f $totalInputSubscriptions)
    Write-Host ("Subscriptions queried (MCSB enabled):  {0}" -f $SubscriptionCount)
} else {
    Write-Host ("Total subscriptions queried:           {0}" -f $SubscriptionCount)
}
Write-Host ("Subscriptions with data:               {0}" -f $subsSuccessful.Count) -ForegroundColor Green
if ($subsNoData.Count -gt 0) {
    Write-Host ("Subscriptions with no data (DfC gap):  {0}" -f $subsNoData.Count) -ForegroundColor Yellow
}
if ($subsPermissionFail.Count -gt 0) {
    Write-Host ("Failed - access denied (per-query): {0}" -f $subsPermissionFail.Count) -ForegroundColor Red
}
if ($subsOtherFail.Count -gt 0) {
    Write-Host ("Subscriptions failed (other errors):   {0}" -f $subsOtherFail.Count) -ForegroundColor Red
}
if ($preflightSucceeded) {
    if ($subsMcsbNotEnabled.Count -gt 0) {
        Write-Host ("Skipped - MCSB not assigned:                     {0}" -f $subsMcsbNotEnabled.Count) -ForegroundColor Yellow
    }
    if ($subsNoSecurityVisibility.Count -gt 0) {
        Write-Host ("Skipped - Defender Foundational CSPM not enabled: {0}" -f $subsNoSecurityVisibility.Count) -ForegroundColor Yellow
    }
    if ($subsNoSubscriptionAccess.Count -gt 0) {
        Write-Host ("Skipped - no access (pre-flight):                {0}" -f $subsNoSubscriptionAccess.Count) -ForegroundColor Red
    }
}
# Secure-score visibility: surface the X-of-Y rate explicitly so a 1-of-87 case
# does not get presented as a tenant-wide average.
$ssReturnedCount = $subsWithSecureScore.Count
$ssColor = if ($ssReturnedCount -eq $SubscriptionCount -and $SubscriptionCount -gt 0) { 'Green' }
           elseif ($ssReturnedCount -gt 0) { 'Yellow' }
           else { 'Red' }
Write-Host ("Secure score returned:                 {0} of {1} subscriptions" -f $ssReturnedCount, $SubscriptionCount) -ForegroundColor $ssColor
if ($subsSecureScoreFailed.Count -gt 0) {
    Write-Host ("Secure score query failed:             {0}" -f $subsSecureScoreFailed.Count) -ForegroundColor Red
}
Write-Host ("Script execution time:                 {0}" -f $durationFormatted)
Write-Host ""

# ----------------------------------------------------------------------------
# Generate Report File ({BaseFileName}_{Timestamp}.report.txt)
# ----------------------------------------------------------------------------
try {
    $reportLines = @()
    $reportLines += $separator
    $reportLines += " Enterprise Security Assessment - Export Report"
    $reportLines += (" Generated: {0} UTC" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))
    $reportLines += $separator
    $reportLines += ""
    $reportLines += "ENVIRONMENT"
    $reportLines += ("  User:           {0}" -f (Get-AzContext).Account)
    $reportLines += ("  Tenant:         {0} ({1})" -f $tenantName, $tenantId)
    $reportLines += ("  Parameter File: {0}" -f $ParameterFile)
    $reportLines += ""
    $reportLines += "EXPORT SUMMARY"
    if ($preflightSucceeded -and $totalInputSubscriptions -gt 0) {
        $reportLines += ("  Total input subscriptions:          {0}" -f $totalInputSubscriptions)
        $reportLines += ("  Queried (MCSB enabled):             {0}" -f $SubscriptionCount)
    } else {
        $reportLines += ("  Subscriptions queried:              {0}" -f $SubscriptionCount)
    }
    $reportLines += ("  Subscriptions with data:            {0}" -f $subsSuccessful.Count)
    $reportLines += ("  Subscriptions with no data:         {0}" -f $subsNoData.Count)
    $reportLines += ("  Failed - access denied (per-query): {0}" -f $subsPermissionFail.Count)
    $reportLines += ("  Failed - other errors:              {0}" -f $subsOtherFail.Count)
    if ($preflightSucceeded) {
        $reportLines += ("  Skipped - MCSB not assigned:                      {0}" -f $subsMcsbNotEnabled.Count)
        $reportLines += ("  Skipped - Defender Foundational CSPM not enabled: {0}" -f $subsNoSecurityVisibility.Count)
        $reportLines += ("  Skipped - no access (pre-flight):                 {0}" -f $subsNoSubscriptionAccess.Count)
    }
    if (Test-Path $FinalOutputFile) {
        $reportLines += ("  Output file:                        {0}" -f $FinalOutputFile)
        $reportLines += ("  Output size:                        {0}" -f (Get-FormattedFileSize -Bytes (Get-Item $FinalOutputFile).Length))
    }
    $reportLines += ("  Duration:                           {0}" -f $durationFormatted)
    $reportLines += ""
    if ($secureScoresList.Count -gt 0) {
        $reportLines += "SECURE SCORE"
        $reportLines += ("  Defender for Cloud Secure Score:    {0}% (avg across {1} of {2} subscription(s) that reported a score)" -f $overallSecureScore, $secureScoresList.Count, $SubscriptionCount)
        if ($subsNoSecureScore.Count -gt 0 -or $subsSecureScoreFailed.Count -gt 0) {
            $reportLines += ("  Note: {0} subscription(s) did not have a 'microsoft.security/securescores' resource (MDC likely not enabled or no Azure resources to evaluate)." -f $subsNoSecureScore.Count)
            if ($subsSecureScoreFailed.Count -gt 0) {
                $reportLines += ("        {0} subscription(s) had a query error during secure-score retrieval (see SUBSCRIPTIONS WITH SECURE SCORE QUERY FAILURE below)." -f $subsSecureScoreFailed.Count)
            }
        }
        $reportLines += ""
    } elseif ($SubscriptionCount -gt 0) {
        $reportLines += "SECURE SCORE"
        $reportLines += ("  No subscription returned a Defender for Cloud secure score (0 of {0})." -f $SubscriptionCount)
        $reportLines += "  This typically means MDC is not enabled on the queried subscriptions."
        $reportLines += ""
    }
    if ($subsSuccessful.Count -gt 0) {
        $reportLines += "SUBSCRIPTIONS WITH DATA"
        foreach ($subId in $subsSuccessful) { $reportLines += "  - $subId" }
        $reportLines += ""
    }
    if ($subsSecureScoreFailed.Count -gt 0) {
        $reportLines += "SUBSCRIPTIONS WITH SECURE SCORE QUERY FAILURE"
        foreach ($subId in $subsSecureScoreFailed) { $reportLines += "  - $subId" }
        $reportLines += ""
    }
    if ($subsNoData.Count -gt 0) {
        $reportLines += "SUBSCRIPTIONS WITH NO DATA"
        $reportLines += "  No 'microsoft.security/assessments' rows returned. Typically MDC is not"
        $reportLines += "  enabled on these subscriptions, or there are no Azure resources to evaluate."
        foreach ($subId in $subsNoData) { $reportLines += "  - $subId" }
        $reportLines += ""
    }
    # Only enumerate the secure-score gap separately when it diverges from
    # the no-data list (the two normally collapse to the same root cause).
    $noScoreOnly = @($subsNoSecureScore | Where-Object { $subsNoData -notcontains $_ })
    if ($noScoreOnly.Count -gt 0) {
        $reportLines += "SUBSCRIPTIONS WITHOUT SECURE SCORE (but returned recommendations)"
        $reportLines += "  These returned 'microsoft.security/assessments' rows but no 'securescores' resource."
        foreach ($subId in $noScoreOnly) { $reportLines += "  - $subId" }
        $reportLines += ""
    }
    if ($subsPermissionFail.Count -gt 0) {
        $reportLines += "SUBSCRIPTIONS FAILED - ACCESS DENIED (PER-QUERY)"
        $reportLines += "  These subscriptions passed pre-flight (visible at ARM) but the per-sub"
        $reportLines += "  Search-AzGraph call returned AuthorizationFailed / Forbidden / AccessDenied."
        $reportLines += "  This is rare. Likely causes: RBAC removed mid-run, token refresh failure"
        $reportLines += "  during a long run, or the subscription state changed (disabled / moved"
        $reportLines += "  to another tenant) between pre-flight and the per-sub query."
        $reportLines += "  Action: re-run the export. If it persists, verify the running identity"
        $reportLines += "  still has Reader on these subs."
        foreach ($subId in $subsPermissionFail) { $reportLines += "  - $subId" }
        $reportLines += ""
    }
    if ($subsOtherFail.Count -gt 0) {
        $reportLines += "SUBSCRIPTIONS FAILED - OTHER ERRORS"
        foreach ($subId in $subsOtherFail) { $reportLines += "  - $subId" }
        $reportLines += ""
    }
    if ($preflightSucceeded -and $subsMcsbNotEnabled.Count -gt 0) {
        $reportLines += "SUBSCRIPTIONS SKIPPED - MCSB NOT ASSIGNED"
        $reportLines += "  These subscriptions ARE registered with Defender for Cloud (a"
        $reportLines += "  'Microsoft.Security/pricings' resource exists) but the Microsoft cloud"
        $reportLines += "  security benchmark (MCSB) compliance standard is not assigned, so no"
        $reportLines += "  ascScore baseline is produced and no MCSB-aligned recommendations exist."
        $reportLines += "  Action: assign the 'Microsoft cloud security benchmark' policy initiative"
        $reportLines += "  to these subscriptions (or to a parent management group)."
        foreach ($subId in $subsMcsbNotEnabled) { $reportLines += "  - $subId" }
        $reportLines += ""
    }
    if ($preflightSucceeded -and $subsNoSecurityVisibility.Count -gt 0) {
        $reportLines += "SUBSCRIPTIONS SKIPPED - DEFENDER FOUNDATIONAL CSPM NOT ENABLED"
        $reportLines += "  These subscriptions returned zero rows from the 'securityresources' table,"
        $reportLines += "  meaning Defender for Cloud Foundational CSPM is not enabled on them"
        $reportLines += "  (no 'Microsoft.Security/pricings' resource, and the 'Microsoft.Security'"
        $reportLines += "  resource provider may also be unregistered)."
        $reportLines += "  Action: enable Defender for Cloud Foundational CSPM (free) on each"
        $reportLines += "  subscription, or assign the built-in policy 'Enable Microsoft Defender for"
        $reportLines += "  Cloud on your subscription' at a parent management group to onboard them"
        $reportLines += "  in bulk. See https://learn.microsoft.com/azure/defender-for-cloud/onboard-management-group"
        foreach ($subId in $subsNoSecurityVisibility) { $reportLines += "  - $subId" }
        $reportLines += ""
    }
    if ($preflightSucceeded -and $subsNoSubscriptionAccess.Count -gt 0) {
        $reportLines += "SUBSCRIPTIONS SKIPPED - NO ACCESS (PRE-FLIGHT)"
        $reportLines += "  These subscription IDs were not visible at ARM at all (Azure Resource Graph"
        $reportLines += "  reported no 'microsoft.resources/subscriptions' container for them), which"
        $reportLines += "  means the running identity has no RBAC on the subscription."
        $reportLines += "  Action: confirm the subscription IDs are correct and that the running"
        $reportLines += "  identity has at least Reader role on each subscription (or a parent"
        $reportLines += "  management group). If a sub was deleted or moved to a different tenant,"
        $reportLines += "  remove it from the input list."
        foreach ($subId in $subsNoSubscriptionAccess) { $reportLines += "  - $subId" }
        $reportLines += ""
    }
    $hasPreflightGap = $preflightSucceeded -and ($subsMcsbNotEnabled.Count -gt 0 -or $subsNoSecurityVisibility.Count -gt 0 -or $subsNoSubscriptionAccess.Count -gt 0)
    if ($subsNoData.Count -gt 0 -or $subsPermissionFail.Count -gt 0 -or $hasPreflightGap) {
        $reportLines += "NEXT STEPS"
        $reportLines += "  - Engage the CSA to remediate the gaps listed above before continuing."
        $reportLines += "  - Or proceed with the ESA based on the current data quality."
        if ($parameters.RemediationUrls -and @($parameters.RemediationUrls).Count -gt 0) {
            $reportLines += "  Remediation references:"
            foreach ($entry in $parameters.RemediationUrls) {
                if ($entry.Label -and $entry.Url) {
                    $reportLines += ("    - {0}: {1}" -f $entry.Label, $entry.Url)
                }
            }
        }
        $reportLines += ""
    }
    $reportLines += "REMINDER"
    $reportLines += "  XDR and Purview data must be exported manually."
    $reportLines | Out-File -FilePath $ReportFile -Encoding UTF8
    Write-Host ("Export report saved: {0}" -f $ReportFile) -ForegroundColor Green
    if ($subsNoData.Count -gt 0 -or $subsPermissionFail.Count -gt 0 -or $subsOtherFail.Count -gt 0 -or $subsSecureScoreFailed.Count -gt 0 -or ($preflightSucceeded -and ($subsMcsbNotEnabled.Count -gt 0 -or $subsNoSecurityVisibility.Count -gt 0 -or $subsNoSubscriptionAccess.Count -gt 0))) {
        Write-Host ("ATTENTION: Data quality gaps detected. See report file {0} for details." -f $ReportFile) -ForegroundColor Yellow
    }
} catch {
    Write-Host ("Warning: failed to write report file: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}
