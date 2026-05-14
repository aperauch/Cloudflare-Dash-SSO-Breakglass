#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Breakglass script for Cloudflare Dashboard SSO lockout recovery.

.DESCRIPTION
    Implements both bypass options from:
    https://developers.cloudflare.com/fundamentals/manage-members/dashboard-sso/#bypass-dashboard-sso

    Option 1 — Add a backup IdP
      Ensures Cloudflare One-Time PIN is registered as an identity provider,
      then updates the SSO App to accept all available IdPs.  Users can log in
      with a one-time code sent to their email.

    Option 2 — Disable dashboard SSO
      Disables all SSO connectors on the account so users can log in with
      their Cloudflare email and password.  Users without a password can use
      the "Forgot password" flow on the login page.

.PARAMETER ApiToken
    Cloudflare API token. If omitted, reads $env:CLOUDFLARE_API_TOKEN,
    then prompts interactively.

    Required token permissions vary by option:
      Option 1:
        - Access: Organizations, Identity Providers, and Groups Write
        - Access: Apps and Policies Write
      Option 2:
        - SSO Connector Edit

.EXAMPLE
    $env:CLOUDFLARE_API_TOKEN = "your_token_here"
    ./Add-BackupIdP.ps1

.EXAMPLE
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
# Configuration
# ---------------------------------------------------------------------------
$AccountId = "<your-cloudflare-account-id>"    # Replace with your Cloudflare account ID
$SsoAppId  = "<your-sso-app-id>"              # Replace with your SSO App application ID
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
        [string]$Body = $null,
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
        $excResp    = $_.Exception.Response
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
# Helper: recursively convert PSCustomObject to nested hashtables (PS5)
# ---------------------------------------------------------------------------
function ConvertTo-NestedHashtable {
    param([Parameter(ValueFromPipeline)] $InputObject)
    process {
        if ($null -eq $InputObject) { return $null }

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

# ===================================================================
# Option 1: Add a backup IdP
# ===================================================================
function Invoke-Option1 {
    # ---------------------------------------------------------------
    # Step 1: Ensure One-Time PIN identity provider exists
    # ---------------------------------------------------------------
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
        if ($_ -match '12132' -or $_ -match 'already exists') {
            Write-Host "  OTP IdP already exists — looking up its ID..." -ForegroundColor Yellow

            $idpListResponse = Invoke-CfApi `
                -Method      "GET" `
                -Path        "/accounts/$AccountId/access/identity_providers" `
                -Description "List identity providers"

            $otpIdp   = $idpListResponse.result |
                        Where-Object { $_.type -eq "onetimepin" } |
                        Select-Object -First 1
            $otpIdpId = $otpIdp.id

            if (-not $otpIdpId) {
                Write-Error "Could not find an existing OTP identity provider."
                throw
            }
            Write-Host "  Found existing OTP IdP  id: $otpIdpId" -ForegroundColor Green
        } else {
            throw
        }
    }

    # ---------------------------------------------------------------
    # Step 2: Fetch the full current SSO App config
    # ---------------------------------------------------------------
    Write-Host ""
    Write-Host "[Step 2/3] Fetching current SSO App config (id: $SsoAppId)..." `
        -ForegroundColor Cyan

    $getResponse = Invoke-CfApi `
        -Method      "GET" `
        -Path        "/accounts/$AccountId/access/apps/$SsoAppId" `
        -Description "Get SSO App"

    Write-Host "  App name         : $($getResponse.result.name)"   -ForegroundColor Green
    Write-Host "  App type         : $($getResponse.result.type)"   -ForegroundColor Green
    Write-Host "  App domain       : $($getResponse.result.domain)" -ForegroundColor Green
    $currentAllowed = $getResponse.result.allowed_idps
    Write-Host "  Current allowed  : $(if ($currentAllowed) { $currentAllowed -join ', ' } else { '[] (all)' })" `
        -ForegroundColor Green

    # ---------------------------------------------------------------
    # Step 3: PUT updated config with allowed_idps = []
    # ---------------------------------------------------------------
    Write-Host ""
    Write-Host "[Step 3/3] Updating SSO App to accept all identity providers..." `
        -ForegroundColor Cyan

    $appHashtable = ConvertTo-NestedHashtable $getResponse.result

    # Strip read-only fields.
    foreach ($key in @('aud', 'created_at', 'updated_at')) {
        if ($appHashtable.ContainsKey($key)) { $appHashtable.Remove($key) }
    }

    # Convert policies to {id, precedence} link refs (PUT rejects full objects).
    if ($appHashtable.ContainsKey('policies') -and $null -ne $appHashtable['policies']) {
        $policyRefs = @()
        foreach ($p in @($appHashtable['policies'])) {
            $policyRefs += @{ id = $p['id']; precedence = $p['precedence'] }
        }
        $appHashtable['policies'] = $policyRefs
    }

    # Empty array = accept ALL configured IdPs.
    $appHashtable['allowed_idps'] = @()
    Write-Host "  Setting allowed_idps = [] (accept all available identity providers)." `
        -ForegroundColor Green

    $putPayload = $appHashtable | ConvertTo-Json -Depth 20

    if ($PSCmdlet.ShouldProcess("SSO App $SsoAppId", "Set allowed_idps = []")) {
        $putResponse = Invoke-CfApi `
            -Method      "PUT" `
            -Path        "/accounts/$AccountId/access/apps/$SsoAppId" `
            -Body        $putPayload `
            -Description "Update SSO App allowed_idps"

        $finalIdps = @($putResponse.result.allowed_idps)
        if ($finalIdps.Count -eq 0) {
            Write-Host "  allowed_idps = [] — all identity providers are now accepted." `
                -ForegroundColor Green
        } else {
            Write-Host "  allowed_idps: $($finalIdps -join ', ')" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "Done. One-Time PIN is now available as a login option." -ForegroundColor Yellow
    Write-Host "  Users can visit https://dash.cloudflare.com, enter their email," -ForegroundColor Yellow
    Write-Host "  and select 'Send me a code' to receive a one-time PIN." -ForegroundColor Yellow
}

# ===================================================================
# Option 2: Disable dashboard SSO
# ===================================================================
function Invoke-Option2 {
    # ---------------------------------------------------------------
    # Step 1: List SSO connectors
    # ---------------------------------------------------------------
    Write-Host ""
    Write-Host "[Step 1/2] Listing SSO connectors..." -ForegroundColor Cyan

    $listResponse = Invoke-CfApi `
        -Method      "GET" `
        -Path        "/accounts/$AccountId/sso_connectors" `
        -Description "List SSO connectors"

    $connectors = @($listResponse.result)

    if ($connectors.Count -eq 0) {
        Write-Host "  No SSO connectors found — nothing to disable." -ForegroundColor Yellow
        return
    }

    foreach ($c in $connectors) {
        $state = if ($c.enabled) { "ENABLED" } else { "disabled" }
        Write-Host "  $($c.id)  $($c.email_domain)  [$state]" -ForegroundColor Green
    }

    $enabledConnectors = @($connectors | Where-Object { $_.enabled -eq $true })

    if ($enabledConnectors.Count -eq 0) {
        Write-Host ""
        Write-Host "  All connectors are already disabled." -ForegroundColor Yellow
        return
    }

    # ---------------------------------------------------------------
    # Step 2: Disable each enabled connector
    # ---------------------------------------------------------------
    Write-Host ""
    Write-Host "[Step 2/2] Disabling $($enabledConnectors.Count) SSO connector(s)..." `
        -ForegroundColor Cyan

    foreach ($c in $enabledConnectors) {
        $connectorId = $c.id

        if ($PSCmdlet.ShouldProcess("SSO connector $connectorId ($($c.email_domain))", "Disable")) {
            $patchPayload = '{"enabled":false}'
            $patchResponse = Invoke-CfApi `
                -Method      "PATCH" `
                -Path        "/accounts/$AccountId/sso_connectors/$connectorId" `
                -Body        $patchPayload `
                -Description "Disable SSO connector $connectorId"

            Write-Host "  Disabled: $connectorId  ($($c.email_domain))" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "Done. Dashboard SSO has been disabled." -ForegroundColor Yellow
    Write-Host "  Users can now log in with their Cloudflare email and password." -ForegroundColor Yellow
    Write-Host "  If a user has no password, they can use 'Forgot password' at:" -ForegroundColor Yellow
    Write-Host "  https://dash.cloudflare.com/forgot-password" -ForegroundColor Yellow
}

# ===================================================================
# Option 3: Remove backup IdP (reverses Option 1)
# ===================================================================
function Invoke-Option3 {
    # ---------------------------------------------------------------
    # Step 1: Find the OTP identity provider
    # ---------------------------------------------------------------
    Write-Host ""
    Write-Host "[Step 1/2] Looking up One-Time PIN identity provider..." `
        -ForegroundColor Cyan

    $idpListResponse = Invoke-CfApi `
        -Method      "GET" `
        -Path        "/accounts/$AccountId/access/identity_providers" `
        -Description "List identity providers"

    $allIdps = @($idpListResponse.result)
    $otpIdp  = $allIdps | Where-Object { $_.type -eq "onetimepin" } | Select-Object -First 1

    if (-not $otpIdp) {
        Write-Host "  No One-Time PIN identity provider found — nothing to remove." `
            -ForegroundColor Yellow
        return
    }

    $otpIdpId = $otpIdp.id
    Write-Host "  Found OTP IdP  id: $otpIdpId" -ForegroundColor Green

    # List non-OTP IdPs for restoring allowed_idps.
    $nonOtpIdps = @($allIdps | Where-Object { $_.type -ne "onetimepin" })
    Write-Host "  Other IdPs ($($nonOtpIdps.Count)):" -ForegroundColor Green
    foreach ($idp in $nonOtpIdps) {
        Write-Host "    - $($idp.id)  $($idp.name)  ($($idp.type))" -ForegroundColor Green
    }

    # ---------------------------------------------------------------
    # Step 2: Restore SSO App allowed_idps to only non-OTP IdPs
    # ---------------------------------------------------------------
    Write-Host ""
    Write-Host "[Step 2/2] Restoring SSO App to only allow non-OTP identity providers..." `
        -ForegroundColor Cyan

    $getResponse = Invoke-CfApi `
        -Method      "GET" `
        -Path        "/accounts/$AccountId/access/apps/$SsoAppId" `
        -Description "Get SSO App"

    $appHashtable = ConvertTo-NestedHashtable $getResponse.result

    # Strip read-only fields.
    foreach ($key in @('aud', 'created_at', 'updated_at')) {
        if ($appHashtable.ContainsKey($key)) { $appHashtable.Remove($key) }
    }

    # Convert policies to {id, precedence} link refs.
    if ($appHashtable.ContainsKey('policies') -and $null -ne $appHashtable['policies']) {
        $policyRefs = @()
        foreach ($p in @($appHashtable['policies'])) {
            $policyRefs += @{ id = $p['id']; precedence = $p['precedence'] }
        }
        $appHashtable['policies'] = $policyRefs
    }

    # Set allowed_idps to only non-OTP providers (disables "Accept all").
    $nonOtpIds = @($nonOtpIdps | ForEach-Object { $_.id })
    $appHashtable['allowed_idps'] = $nonOtpIds

    Write-Host "  Setting allowed_idps to $($nonOtpIds.Count) non-OTP IdP(s)." `
        -ForegroundColor Green

    $putPayload = $appHashtable | ConvertTo-Json -Depth 20

    if ($PSCmdlet.ShouldProcess("SSO App $SsoAppId", "Restore allowed_idps without OTP")) {
        $putResponse = Invoke-CfApi `
            -Method      "PUT" `
            -Path        "/accounts/$AccountId/access/apps/$SsoAppId" `
            -Body        $putPayload `
            -Description "Update SSO App allowed_idps"

        $finalIdps = @($putResponse.result.allowed_idps)
        Write-Host "  allowed_idps now contains $($finalIdps.Count) IdP(s):" `
            -ForegroundColor Green
        foreach ($idp in $finalIdps) {
            Write-Host "    - $idp" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "Done. One-Time PIN has been disabled as a login method." -ForegroundColor Yellow
    Write-Host "  The OTP IdP still exists on the account but is no longer" -ForegroundColor Yellow
    Write-Host "  accepted by the SSO App." -ForegroundColor Yellow
}

# ===================================================================
# Option 4: Re-enable dashboard SSO (reverses Option 2)
# ===================================================================
function Invoke-Option4 {
    # ---------------------------------------------------------------
    # Step 1: List SSO connectors
    # ---------------------------------------------------------------
    Write-Host ""
    Write-Host "[Step 1/2] Listing SSO connectors..." -ForegroundColor Cyan

    $listResponse = Invoke-CfApi `
        -Method      "GET" `
        -Path        "/accounts/$AccountId/sso_connectors" `
        -Description "List SSO connectors"

    $connectors = @($listResponse.result)

    if ($connectors.Count -eq 0) {
        Write-Host "  No SSO connectors found." -ForegroundColor Yellow
        return
    }

    foreach ($c in $connectors) {
        $state = if ($c.enabled) { "ENABLED" } else { "disabled" }
        Write-Host "  $($c.id)  $($c.email_domain)  [$state]" -ForegroundColor Green
    }

    $disabledConnectors = @($connectors | Where-Object { $_.enabled -eq $false })

    if ($disabledConnectors.Count -eq 0) {
        Write-Host ""
        Write-Host "  All connectors are already enabled." -ForegroundColor Yellow
        return
    }

    # ---------------------------------------------------------------
    # Step 2: Re-enable each disabled connector
    # ---------------------------------------------------------------
    Write-Host ""
    Write-Host "[Step 2/2] Re-enabling $($disabledConnectors.Count) SSO connector(s)..." `
        -ForegroundColor Cyan

    foreach ($c in $disabledConnectors) {
        $connectorId = $c.id

        if ($PSCmdlet.ShouldProcess("SSO connector $connectorId ($($c.email_domain))", "Enable")) {
            $patchPayload = '{"enabled":true}'
            Invoke-CfApi `
                -Method      "PATCH" `
                -Path        "/accounts/$AccountId/sso_connectors/$connectorId" `
                -Body        $patchPayload `
                -Description "Enable SSO connector $connectorId"

            Write-Host "  Enabled: $connectorId  ($($c.email_domain))" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "Done. Dashboard SSO has been re-enabled." -ForegroundColor Yellow
    Write-Host "  Users will now be required to authenticate via SSO." -ForegroundColor Yellow
}

# ===================================================================
# Main: prompt user to choose an option
# ===================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  Cloudflare Dashboard SSO — Breakglass Recovery" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
Write-Host "  Breakglass" -ForegroundColor Yellow
Write-Host ""
Write-Host "  [1] Add a backup IdP (One-Time PIN)" -ForegroundColor Cyan
Write-Host "      Adds OTP as a login method and enables all IdPs on the" -ForegroundColor Gray
Write-Host "      SSO App. SSO remains active — users get an extra login" -ForegroundColor Gray
Write-Host "      option alongside your existing IdP." -ForegroundColor Gray
Write-Host ""
Write-Host "  [2] Disable dashboard SSO" -ForegroundColor Cyan
Write-Host "      Turns off all SSO connectors. Users log in with their" -ForegroundColor Gray
Write-Host "      Cloudflare email and password instead of SSO." -ForegroundColor Gray
Write-Host ""
Write-Host "  Restore" -ForegroundColor Yellow
Write-Host ""
Write-Host "  [3] Disable backup IdP (One-Time PIN)" -ForegroundColor Cyan
Write-Host "      Disables OTP as a login method on the SSO App." -ForegroundColor Gray
Write-Host "      Restores allowed_idps to only your original providers." -ForegroundColor Gray
Write-Host ""
Write-Host "  [4] Re-enable dashboard SSO" -ForegroundColor Cyan
Write-Host "      Re-enables all disabled SSO connectors. Users will be" -ForegroundColor Gray
Write-Host "      required to authenticate via SSO again." -ForegroundColor Gray
Write-Host ""

do {
    $choice = Read-Host "Select an option (1-4)"
} while ($choice -notmatch '^[1-4]$')

switch ($choice) {
    '1' { Invoke-Option1 }
    '2' { Invoke-Option2 }
    '3' { Invoke-Option3 }
    '4' { Invoke-Option4 }
}

Write-Host ""
