# Cloudflare Dashboard SSO — Breakglass Recovery

Interactive PowerShell script for recovering access to the Cloudflare dashboard when SSO login is broken or misconfigured.

Implements the bypass and restore procedures from the [Cloudflare documentation](https://developers.cloudflare.com/fundamentals/manage-members/dashboard-sso/#bypass-dashboard-sso).

## Requirements

- PowerShell 5.0 or later (Windows PowerShell or PowerShell Core / pwsh)
- A Cloudflare API token with the appropriate permissions (see [Permissions](#api-token-permissions) below)

## Quick Start

```powershell
# Option A — set the token as an environment variable
$env:CLOUDFLARE_API_TOKEN = "<your-token>"
./Add-BackupIdP.ps1

# Option B — pass the token directly
./Add-BackupIdP.ps1 -ApiToken "<your-token>"

# Option C — the script will prompt securely if no token is provided
./Add-BackupIdP.ps1
```

## Menu Options

The script presents an interactive menu with four options grouped into **Breakglass** (emergency access recovery) and **Restore** (return to normal operation):

```
============================================================
  Cloudflare Dashboard SSO — Breakglass Recovery
============================================================

  Breakglass

  [1] Add a backup IdP (One-Time PIN)
  [2] Disable dashboard SSO

  Restore

  [3] Disable backup IdP (One-Time PIN)
  [4] Re-enable dashboard SSO
```

### Option 1 — Add a backup IdP (One-Time PIN)

Use when your primary SSO identity provider (e.g. Okta, Azure AD) is down or misconfigured and users cannot log in.

**What it does:**

1. Registers Cloudflare One-Time PIN as an identity provider on the account (or finds the existing one if already created).
2. Fetches the current SSO App configuration.
3. Updates the SSO App to accept **all** available identity providers (`allowed_idps = []`).

**Result:** Users visiting `https://dash.cloudflare.com` can choose to receive a one-time code via email instead of authenticating through the broken IdP.

### Option 2 — Disable dashboard SSO

Use when you need to completely bypass SSO enforcement — for example, during an IdP migration or extended outage.

**What it does:**

1. Lists all SSO connectors on the account.
2. Disables each enabled connector via `PATCH` with `{"enabled": false}`.

**Result:** SSO enforcement is removed. Users log in with their Cloudflare email and password. Users without a password can use the [Forgot password](https://dash.cloudflare.com/forgot-password) flow.

### Option 3 — Disable backup IdP (One-Time PIN)

Reverses Option 1 after the primary IdP is restored.

**What it does:**

1. Lists all identity providers on the account and identifies the OTP IdP.
2. Updates the SSO App's `allowed_idps` to only include non-OTP identity providers (turns off the "Accept all available identity providers" toggle).

**Result:** OTP is no longer a valid login method on the SSO App. The OTP identity provider remains on the account for future use.

### Option 4 — Re-enable dashboard SSO

Reverses Option 2 after the issue is resolved.

**What it does:**

1. Lists all SSO connectors on the account.
2. Re-enables each disabled connector via `PATCH` with `{"enabled": true}`.

**Result:** SSO enforcement is restored. Users must authenticate through the configured identity provider.

## API Token Permissions

Different options require different API token permissions. A single token can cover all options if it has all the listed permissions.

| Option | Required Permissions |
|--------|---------------------|
| 1 — Add backup IdP | `Access: Organizations, Identity Providers, and Groups Write` + `Access: Apps and Policies Write` |
| 2 — Disable SSO | `SSO Connector Edit` |
| 3 — Disable backup IdP | `Access: Apps and Policies Write` |
| 4 — Re-enable SSO | `SSO Connector Edit` |

Create an API token at: **Cloudflare Dashboard > My Profile > API Tokens > Create Token**

## Configuration (Required Before First Use)

Before running the script, you **must** edit the configuration section near the top of `Add-BackupIdP.ps1` and replace the placeholder values with your own:

```powershell
# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$AccountId = "<your-cloudflare-account-id>"
$SsoAppId  = "<your-sso-app-id>"
```

| Variable | Description |
|----------|-------------|
| `$AccountId` | Your Cloudflare account ID |
| `$SsoAppId` | The Access application ID for your SSO App |

**How to find these values:**

- **Account ID** — visible in the Cloudflare dashboard URL: `https://dash.cloudflare.com/<account-id>`, or on the **Account Home** overview page under **Account ID**.
- **SSO App ID** — navigate to **Zero Trust > Access > Applications**, select the **SSO App**, and copy the Application ID from the URL or the **Basic Information** section.

## WhatIf / Dry Run

The script supports PowerShell's `-WhatIf` parameter to preview changes without making them:

```powershell
./Add-BackupIdP.ps1 -WhatIf
```

## Verbose Output

Use `-Verbose` to see the full API URLs being called:

```powershell
./Add-BackupIdP.ps1 -Verbose
```

## Verifying Changes in the Dashboard

After running the script, verify the changes took effect:

| Option | Where to check |
|--------|----------------|
| 1 | **Zero Trust > Access > Applications > SSO App > Login methods** — "Accept all available identity providers" should be toggled on, and One-Time PIN should be listed. |
| 2 | **Account Home > Members > Settings** — SSO connectors should show as disabled. |
| 3 | **Zero Trust > Access > Applications > SSO App > Login methods** — One-Time PIN should be unchecked; only your original IdPs should be checked. |
| 4 | **Account Home > Members > Settings** — SSO connectors should show as enabled. |

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `HTTP 403` | Token lacks required permissions | Create a new token with the permissions listed in the table above |
| `HTTP 409 — already exists` | OTP IdP was previously created | Handled automatically — the script looks up the existing IdP |
| `HTTP 400 — invalid_request` | Request body contains fields the API rejects | The script strips read-only fields and converts policies to link references; if this persists, check for API changes |
| `HTTP 500 — internal_server_error` | Missing required fields in the PUT body | Ensure the SSO App GET response includes a `domain` field; the script preserves it automatically |

## Reference

- [Set up dashboard SSO](https://developers.cloudflare.com/fundamentals/manage-members/dashboard-sso/)
- [Bypass dashboard SSO](https://developers.cloudflare.com/fundamentals/manage-members/dashboard-sso/#bypass-dashboard-sso)
- [Access Applications API — Update](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/update/)
- [Identity Providers API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/)
- [SSO Connectors API](https://developers.cloudflare.com/api/resources/accounts/subresources/sso_connectors/)
