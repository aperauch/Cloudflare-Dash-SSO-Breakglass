#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Adds a One-Time PIN backup IdP to bypass Cloudflare Dashboard SSO lockout.

.DESCRIPTION
    Implements "Option 1: Add a backup IdP" from:
    https://developers.cloudflare.com/fundamentals/manage-members/dashboard-sso/#bypass-dashboard-sso

    Steps performed:
      1. Adds Cloudflare One-Time PIN as an Access identity provider.
      2. Fetches the current SSO App configuration (to preserve all existing fields).
      3. Updates the SSO App with allowed_idps = [] so ALL identity providers
         (including the newly added OTP) are accepted at login.

    After running this script, users can log in at https://dash.cloudflare.com
    by entering their email and receiving a one-time PIN.

.PARAMETER ApiToken
    Cloudflare API token. If omitted, the script reads $env:CLOUDFLARE_API_TOKEN,
    then prompts interactively.

    Required token permissions (both must be on the same token, or run the
    script twice with different tokens and comment out the unneeded step):
      - Access: Organizations, Identity Providers, and Groups Write  (Step 1)
      - Access: Apps and Policies Write                              (Step 3)

.EXAMPLE
    # Set token in environment, then run:
    $env:CLOUDFLARE_API_TOKEN = "your_token_here"
    ./Add-BackupIdP.ps1

.EXAMPLE
    # Pass token directly:
    ./Add-BackupIdP.ps1 -ApiToken "your_token_here"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApiToken
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Configuration — hardcoded per your account
# ---------------------------------------------------------------------------
$AccountId = "INSERT CLOUDFLARE ACCOUNT ID HERE"
$SsoAppId  = "INSERT SSO APP ID HERE"
$BaseUrl   = "https://api.cloudflare.com/client/v4"

# ---------------------------------------------------------------------------
# Resolve API token
# ---------------------------------------------------------------------------
if (-not $ApiToken) {
    $ApiToken = $env:CLOUDFLARE_API_TOKEN
}

if (-not $ApiToken) {
    $secureToken = Read-Host -Prompt "Enter Cloudflare API token" -AsSecureString
    $ApiToken = [System.Net.NetworkCredential]::new("", $secureToken).Password
}

if (-not $ApiToken) {
    Write-Error "No API token supplied. Set CLOUDFLARE_API_TOKEN or pass -ApiToken."
    exit 1
}

$Headers = @{
    "Authorization" = "Bearer $ApiToken"
    "Content-Type"  = "application/json"
}

# ---------------------------------------------------------------------------
# Helper: call the CF API and surface errors clearly
# ---------------------------------------------------------------------------
function Invoke-CfApi {
    param(
        [string]$Method,
        [string]$Path,
        [string]$Body = $null,   # pre-serialised JSON string
        [string]$Description = ""
    )

    $uri    = "$BaseUrl$Path"
    $params = @{
        Method      = $Method
        Uri         = $uri
        Headers     = $Headers
        ErrorAction = "Stop"
    }
    if ($Body) { $params.Body = $Body }

    Write-Verbose "$Method $uri"

    try {
        $response = Invoke-RestMethod @params
    } catch {
        $excResp   = $_.Exception.Response
        $statusCode = if ($excResp) { $excResp.StatusCode.value__ } else { 'unknown' }
        Write-Error "HTTP $statusCode — $Description`n$_"
        throw
    }

    if (-not $response.success) {
        $errDetails = $response.errors | ConvertTo-Json -Compress
        Write-Error "API call failed — $Description`nErrors: $errDetails"
        throw "CF API error"
    }

    return $response
}

# ---------------------------------------------------------------------------
# Helper: recursively convert a PSCustomObject tree into nested hashtables
# so individual keys can be mutated before re-serialising to JSON.
# Required because ConvertFrom-Json -AsHashtable was only added in PS 6.
# ---------------------------------------------------------------------------
function ConvertTo-NestedHashtable {
    param([Parameter(ValueFromPipeline)] $InputObject)
    process {
        if ($null -eq $InputObject) { return $null }

        # Recurse into arrays / collections, but leave plain strings alone
        if ($InputObject -is [System.Collections.IEnumerable] -and
            $InputObject -isnot [string]) {
            $arr = @()
            foreach ($item in $InputObject) {
                $arr += ConvertTo-NestedHashtable $item
            }
            return $arr
        }

        if ($InputObject -is [psobject]) {
            $hash = @{}
            foreach ($prop in $InputObject.PSObject.Properties) {
                $hash[$prop.Name] = ConvertTo-NestedHashtable $prop.Value
            }
            return $hash
        }

        return $InputObject
    }
}

# ---------------------------------------------------------------------------
# Step 1: Ensure One-Time PIN identity provider exists; get its ID
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[Step 1/3] Ensuring Cloudflare One-Time PIN identity provider exists..." `
    -ForegroundColor Cyan

$otpIdpId = $null

try {
    $otpPayload  = '{"type":"onetimepin","config":{}}'
    $otpResponse = Invoke-CfApi `
        -Method      "POST" `
        -Path        "/accounts/$AccountId/access/identity_providers" `
        -Body        $otpPayload `
        -Description "Add OTP identity provider"

    $otpIdpId = $otpResponse.result.id
    Write-Host "  Created OTP IdP  id: $otpIdpId" -ForegroundColor Green

} catch {
    # CF error 12132 = a onetimepin connection already exists — that's fine.
    if ($_ -match '12132' -or $_ -match 'already exists') {
        Write-Host "  OTP IdP already exists — looking up its ID..." -ForegroundColor Yellow

        $idpListResponse = Invoke-CfApi `
            -Method      "GET" `
            -Path        "/accounts/$AccountId/access/identity_providers" `
            -Description "List identity providers"

        $otpIdp   = $idpListResponse.result | Where-Object { $_.type -eq "onetimepin" } | Select-Object -First 1
        $otpIdpId = $otpIdp.id

        if (-not $otpIdpId) {
            Write-Error "Could not find an existing OTP identity provider in the list."
            throw
        }
        Write-Host "  Found existing OTP IdP  id: $otpIdpId" -ForegroundColor Green
    } else {
        throw   # unexpected error — re-raise
    }
}

# ---------------------------------------------------------------------------
# Step 2: Fetch the full current SSO App config (required for safe PUT)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[Step 2/3] Fetching current SSO App config (id: $SsoAppId)..." `
    -ForegroundColor Cyan

$getResponse = Invoke-CfApi `
    -Method      "GET" `
    -Path        "/accounts/$AccountId/access/apps/$SsoAppId" `
    -Description "Get SSO App"

Write-Host "  App name         : $($getResponse.result.name)" -ForegroundColor Green
Write-Host "  App type         : $($getResponse.result.type)"  -ForegroundColor Green
$currentAllowed = $getResponse.result.allowed_idps
Write-Host "  Current allowed  : $(if ($currentAllowed) { $currentAllowed -join ', ' } else { '[] (all)' })" `
    -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 3: PUT back with allowed_idps = [] (accept every configured IdP)
#
# Setting allowed_idps to an empty array means "accept ALL configured IdPs",
# which will include the OTP IdP above and any existing IdPs (Okta, Azure AD…).
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[Step 3/3] Updating SSO App to accept all identity providers..." `
    -ForegroundColor Cyan

# Convert the PSCustomObject returned by Invoke-RestMethod into a nested
# hashtable so we can mutate a single key without losing any other fields.
$appHashtable = ConvertTo-NestedHashtable $getResponse.result

# Empty array = "accept all" — this enables OTP alongside Okta / Azure AD.
$appHashtable["allowed_idps"] = @()

$putPayload = $appHashtable | ConvertTo-Json -Depth 20

if ($PSCmdlet.ShouldProcess("SSO App $SsoAppId", "Set allowed_idps = [] (accept all)")) {
    $putResponse = Invoke-CfApi `
        -Method      "PUT" `
        -Path        "/accounts/$AccountId/access/apps/$SsoAppId" `
        -Body        $putPayload `
        -Description "Update SSO App allowed_idps"

    $finalIdps = $putResponse.result.allowed_idps
    if ($null -eq $finalIdps -or $finalIdps.Count -eq 0) {
        Write-Host "  allowed_idps: [] — all identity providers are now accepted" `
            -ForegroundColor Green
    } else {
        Write-Host "  allowed_idps: $($finalIdps -join ', ')" -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Done." -ForegroundColor Yellow
Write-Host "  One-Time PIN is now available as a login option." -ForegroundColor Yellow
Write-Host "  Users can visit https://dash.cloudflare.com, enter their email," -ForegroundColor Yellow
Write-Host "  and select 'Send me a code' to receive a one-time PIN." -ForegroundColor Yellow
Write-Host ""
