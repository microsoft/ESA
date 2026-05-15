# Enterprise Security Assessment – Data Gathering Script

This repository contains the necessary files for collecting security and compliance data as part of an Enterprise Security Assessment (ESA). The included scripts and configuration files are used to extract Defender for Cloud recommendations for both:

- **MDC (Microsoft Defender for Cloud Secure Score Recommendations)**
- **MCSB (Microsoft Cloud Security Benchmark – Regulatory Compliance)**

## Contents

| Filename                | Purpose                                                                 |
|-------------------------|-------------------------------------------------------------------------|
| ESA_MDC_DataExport.ps1  | PowerShell script that downloads Defender for Cloud recommendations (MCSB regulatory compliance and MDC Secure Score recommendations.) |
| MDC_Params.json         | Parameter file containing export settings for MDC.                      |
| MCSB_Params.json        | Parameter file containing export settings for MCSB.                     |
| MDC.kql                 | The KQL (Kusto Query Language) query executed by the script for MDC.    |
| MCSB.kql                | The KQL (Kusto Query Language) query executed by the script for MCSB.   |



## Required PowerShell Modules

> ⚠️ The script has only been tested with PowerShell 7.x.


This script requires the following Azure PowerShell modules:

- `Az.Accounts`  
- `Az.ResourceGraph`

The script checks for the required modules at startup. If any are missing, it will offer to install them for you (CurrentUser scope, no admin rights required). You can also install them manually:
```powershell
Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser -Force
```

> **Optional (parallel mode only):** If you enable `"Parallel": true` (see below), the script also needs the `ThreadJob` module. It will detect and offer to install it on first use - no manual setup required.

## Usage

To run the script, pass the path to a JSON parameter file:

```powershell
.\ESA_MDC_DataExport.ps1 <ParameterFile>

.\ESA_MDC_DataExport.ps1 MDC_Params.json
.\ESA_MDC_DataExport.ps1 MCSB_Params.json
.\ESA_MDC_DataExport.ps1 -CloudEnvironment AzureUSGovernment MDC_Params.json
.\ESA_MDC_DataExport.ps1 -CloudEnvironment AzureUSGovernment MCSB_Params.json
```

If you run the script without any parameters, a help message will be displayed.

To export both MDC and MCSB data, run the script twice - once with each parameter file.

**Retry Logic:** The script retries transient Azure Resource Graph failures automatically. General transient failures (`GatewayTimeout`, `InternalServerError`, `ServiceUnavailable`, network errors, TLS resets) use *exponential backoff* with up to 3 retries (delays of 4 / 8 / 16 seconds). Resource Graph throttling (`RateLimiting`, `TooManyRequests`) uses a more patient *linear* policy with up to 10 retries (delays of 5, 10, 15, … seconds) before a subscription is marked as failed. Status messages are shown during retries.

**Parallel Execution (opt-in, EXPERIMENTAL):** By default the script processes subscriptions one at a time using the supported serial path (works on Windows PowerShell 5.1 and PowerShell 7+). To speed up large tenants, set `"Parallel": true` in the JSON parameter file - the script auto-sizes the worker pool based on the number of subscriptions. The parallel path is **experimental** and requires **PowerShell 7 or later** (Windows PowerShell 5.1 is not supported in this mode) plus the `ThreadJob` module (the script will offer to install it if missing). Each worker writes its own temporary CSV fragment; the script merges them into the final CSV in original subscription order after all workers finish. Per-subscription console output is buffered and printed in submission order; a `Write-Progress` bar shows live `done / in-flight / buffered` counts together with a per-worker label (e.g. `#2(page 8/14)`) so forward motion is visible even while a heavy low-index sub holds back the in-order text flush.

**Error Logging:** If any errors occur during the execution of the KQL query, they will be logged in a file with the `.failed` extension.

**Pre-flight categorization:** Before running per-subscription queries, three batched Azure Resource Graph probes (~3s) classify each input subscription into one of: `MCSB enabled` (queryable, has the `ascScore` baseline), `MCSB not assigned` (Defender for Cloud is registered but the MCSB compliance standard is not assigned), `Defender not enabled` (no `Microsoft.Security/*` resources exist on the sub), or `no access (pre-flight)` (sub not visible at ARM at all - no RBAC). Only `MCSB enabled` subs go through the per-sub loop; the others are skipped and listed in the report with targeted remediation guidance. If pre-flight itself fails (network, throttling), the script falls back to querying every input subscription.

**Subscription categorization:** After the per-sub loop, each queried subscription is classified as **with data**, **no data** (no `microsoft.security/assessments` rows returned), **Failed - access denied (per-query)** (passed pre-flight but the per-sub Search-AzGraph call returned `AuthorizationFailed` / `Forbidden` / `AccessDenied` - rare; usually mid-run RBAC change or token refresh failure), or **Failed - other errors**. Counts are shown in an `EXPORT SUMMARY` block at the end of the run, and the per-subscription IDs are written to the report file (see below).

**CSA remediation guidance:** When data quality gaps are detected (no-data, per-query failures, or any pre-flight skip bucket), the script prints a guidance block listing the affected subscription IDs, the root cause, and the configurable `RemediationUrls` from the JSON parameter file.

**Auto-generated report file:** After every run a `{BaseFileName}_{Timestamp}.report.txt` file is written next to the CSV. It includes environment info (user, tenant, parameter file), the export summary, secure score, per-category subscription ID lists, and next steps when gaps are present.

**Secure-score visibility:** The `EXPORT SUMMARY` block shows `Secure score returned: X of Y subscriptions` so a partial result (e.g., only 1 of 87 subs has a `microsoft.security/securescores` resource) is immediately obvious instead of being presented as a tenant-wide average. The report file lists the affected subscriptions in `SUBSCRIPTIONS WITHOUT SECURE SCORE` (no securescores resource) and `SUBSCRIPTIONS WITH SECURE SCORE QUERY FAILURE` (query errored) sections.


## Execution

If there is an existing Azure session you may proceed with it or select ‘N’ to re-authenticate:

![alt text](images/session.png)

You may see yellow warning messages after authentication. These can be ignored!

![alt text](images/yelwarn.png)


If you have access to multiple tenants, you will be prompted to select the desired tenant.
![alt text](images/tenants.png)



In the following example, 5 subscriptions were queried, and data was exported for 4 of them.  
The missing subscription (Yellow) was likely due to lack of access or other reasons.  
**This is not an error.**  
Depending on the number of subscriptions and the size of the data sets, the script may run for multiple hours.  
**The script calculates the overall secure score across the subscriptions at the end.**
![alt text](images/execution.png)



# Script Parameter File: `MDC_Params.json`

This JSON file defines input parameters for the `ESA_MDC_DataExport.ps1` script when exporting **MDC secure score recommendations**.

```json
{
  "CSVFileName": "Export_MDC_Recommendations.csv",
  "QueryFile": "MDC.kql",
  "SubscriptionIds": ["*"],
  "Parallel": false,
  "RemediationUrls": [
    { "Label": "Onboard Defender for Cloud at management group level", "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-defender-for-cloud-management-groups" },
    { "Label": "Microsoft Cloud Security Benchmark overview",          "Url": "https://learn.microsoft.com/en-us/security/benchmark/azure/overview" }
  ],
  "_comments": {
    "CSVFileName": "Final CSV output file for Power BI import",
    "QueryFile": "KQL Query file. Do not change!",
    "SubscriptionIds": "Comma-separated subscription IDs or '*' for all available subscriptions. If you specify specific subscriptions, ensure you connect to the correct tenant (if you have access to multiple tenants) during script execution. If you don't have access to some subscriptions, the script will continue with the remaining ones.",
    "Parallel": "Default false. Set to true to query subscriptions in parallel for faster runs on large tenants - the script auto-sizes the worker pool. EXPERIMENTAL: requires PowerShell 7+ AND the 'ThreadJob' module (the script will offer to install it).",
    "RemediationUrls": "Optional. Links shown in the CSA remediation guidance block (and the report file) when data quality gaps are detected. Each entry needs a Label and a Url. Leave the array empty to suppress the reference list."
  }
}
```

| **Parameter**     | **Description**                                                                                                                                                                                                                                                                            |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `CSVFileName`     | The name of the file containing the exported MDC recommendations. This file needs to be imported into the Power BI report. You may change it, but it is recommended to keep the default value.                                                                                            |
| `QueryFile`       | The file containing the KQL query. **Do not modify.**                                                                                                                                                                                                                                      |
| `SubscriptionIds` | To export data for all available subscriptions, keep the default value `'*'`. Otherwise, specify the subscription IDs to be exported. Example: `["09b43e75...", "4fc2c46b...", ...]`<br>If you don’t have access to some subscriptions, the script will continue with the remaining ones. |
| `Parallel`       | Default `false` (serial). Set to `true` to query subscriptions in parallel for faster runs on large tenants - the script auto-sizes the worker pool. **EXPERIMENTAL** and requires **PowerShell 7+** plus the `ThreadJob` module (the script will offer to install it if missing). Not supported on Windows PowerShell 5.1.      |
| `RemediationUrls` | Optional. Array of `{Label, Url}` entries shown in the CSA remediation guidance block (and the report file) when data quality gaps are detected. Leave empty to suppress the reference list.                                                                                              |



# Script Parameter File: `MCSB_Params.json`

This JSON file defines input parameters for the `ESA_MDC_DataExport.ps1` script when exporting **MCSB regulatory compliance** data.

---



```json
{
  "CSVFileName": "Export_MCSB_Compliance.csv",
  "QueryFile": "MCSB.kql",
  "SubscriptionIds": ["*"],
  "Parallel": false,
  "RemediationUrls": [
    { "Label": "Onboard Defender for Cloud at management group level", "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-defender-for-cloud-management-groups" },
    { "Label": "Microsoft Cloud Security Benchmark overview",          "Url": "https://learn.microsoft.com/en-us/security/benchmark/azure/overview" }
  ],
  "_comments": {
    "CSVFileName": "Final CSV output file for Power BI import",
    "QueryFile": "KQL Query file. Do not change!",
    "SubscriptionIds": "Comma-separated subscription IDs or '*' for all available subscriptions. If you specify specific subscriptions, ensure you connect to the correct tenant (if you have access to multiple tenants) during script execution. If you don't have access to some subscriptions, the script will continue with the remaining ones.",
    "Parallel": "Default false. Set to true to query subscriptions in parallel for faster runs on large tenants - the script auto-sizes the worker pool. EXPERIMENTAL: requires PowerShell 7+ AND the 'ThreadJob' module (the script will offer to install it).",
    "RemediationUrls": "Optional. Links shown in the CSA remediation guidance block (and the report file) when data quality gaps are detected. Each entry needs a Label and a Url. Leave the array empty to suppress the reference list."
  }
}
```

## Parameter Descriptions

| **Parameter**      | **Description**                                                                                                                                                                                                                                                                            |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `CSVFileName`      | The name of the file containing the exported MCSB recommendations. This file needs to be imported into the Power BI report. You may change it, but it is recommended to keep the default value.                                                                                          |
| `QueryFile`        | The file containing the KQL query. **Do not modify.**                                                                                                                                                                                                                                      |
| `SubscriptionIds`  | To export data for all available subscriptions, keep the default value `'*'`. Otherwise, specify the subscription IDs to be exported. Example: `["09b43e75...", "4fc2c46b...", ...]`<br>If you don’t have access to some subscriptions, the script will continue with the remaining ones. |
| `Parallel`         | Default `false` (serial). Set to `true` to query subscriptions in parallel for faster runs on large tenants - the script auto-sizes the worker pool. **EXPERIMENTAL** and requires **PowerShell 7+** plus the `ThreadJob` module (the script will offer to install it if missing). Not supported on Windows PowerShell 5.1.      |
| `RemediationUrls`  | Optional. Array of `{Label, Url}` entries shown in the CSA remediation guidance block (and the report file) when data quality gaps are detected. Leave empty to suppress the reference list.                                                                                              |

## 📦 Downloads

- [ESA_MDC_DataExport.ps1](https://github.com/microsoft/ESA/blob/main/src/ESA_MDC_DataExport.ps1)
- [MCSB.kql](https://github.com/microsoft/ESA/blob/main/src/MCSB.kql)
- [MCSB_Params.json](https://github.com/microsoft/ESA/blob/main/src/MCSB_Params.json)
- [MDC.kql](https://github.com/microsoft/ESA/blob/main/src/MDC.kql)
- [MDC_Params.json](https://github.com/microsoft/ESA/blob/main/src/MDC_Params.json)

### 📥 Download All Files via PowerShell

To download all files listed above automatically, run the following script:

```powershell
param(    
    [Parameter()][string]
    $Branch = "main"
)

$baseURL = "https://raw.githubusercontent.com/microsoft/ESA/$Branch/src"

$workingDirectory = (Get-Location).Path
Write-Host "Working Directory: $workingDirectory"

Invoke-WebRequest "$baseURL/files-list.txt" -OutFile "$workingDirectory\files-list.txt"

Write-Host "Downloading from: $baseURL"
Write-Host "We will get these files:"
Get-Content "$workingDirectory\files-list.txt" | ForEach-Object { Write-Host "   $_" }

# Download each file in the list
Get-Content "$workingDirectory\files-list.txt" | ForEach-Object {
    $fileName = $_
    Invoke-WebRequest "$baseURL/$fileName" -OutFile "$workingDirectory\$fileName"
}
```

# Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
