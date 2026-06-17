Set-StrictMode -Version Latest

function Get-CodexSharedHome {
    if ($env:CODEX_SHARED_HOME) {
        return $env:CODEX_SHARED_HOME
    }

    return Join-Path $env:USERPROFILE ".codex"
}

function Get-CodexAuthStore {
    if ($env:CODEX_AUTH_STORE) {
        return $env:CODEX_AUTH_STORE
    }

    return Join-Path $env:USERPROFILE ".codex-auths"
}

function Assert-CodexAccountName {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Name -notmatch '^[A-Za-z0-9._-]+$') {
        throw "Account name may only contain letters, numbers, dot, underscore, and hyphen."
    }
}

function Save-CodexAccount {
    param([Parameter(Mandatory = $true)][string]$Name)

    Assert-CodexAccountName -Name $Name

    $codexHome = Get-CodexSharedHome
    $authPath = Join-Path $codexHome "auth.json"
    if (!(Test-Path $authPath)) {
        throw "No auth.json found at $authPath. Sign in to Codex first, then run Save-CodexAccount $Name."
    }

    $accountDir = Join-Path (Get-CodexAuthStore) $Name
    New-Item -ItemType Directory -Force -Path $accountDir | Out-Null

    Copy-Item -LiteralPath $authPath -Destination (Join-Path $accountDir "auth.json") -Force

    [pscustomobject]@{
        name = $Name
        saved_at = (Get-Date).ToString("o")
        codex_home = $codexHome
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $accountDir "meta.json") -Encoding UTF8

    Write-Host "Saved Codex account '$Name' from $authPath"
}

function Use-CodexAccount {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$NoBackup
    )

    Assert-CodexAccountName -Name $Name

    $codexHome = Get-CodexSharedHome
    $src = Join-Path (Join-Path (Get-CodexAuthStore) $Name) "auth.json"
    $dest = Join-Path $codexHome "auth.json"

    if (!(Test-Path $src)) {
        throw "No saved Codex account '$Name'. Sign in with that account, then run Save-CodexAccount $Name."
    }

    New-Item -ItemType Directory -Force -Path $codexHome | Out-Null

    if ((Test-Path $dest) -and !$NoBackup) {
        $backupDir = Join-Path $codexHome "auth-backups"
        New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        Copy-Item -LiteralPath $dest -Destination (Join-Path $backupDir "auth.before-switch.$stamp.json") -Force
    }

    Copy-Item -LiteralPath $src -Destination $dest -Force
    Set-Content -LiteralPath (Join-Path $codexHome "active_account") -Value $Name -Encoding UTF8

    Write-Host "Switched Codex account to '$Name'"
    Write-Host "Shared context remains in $codexHome"
    Write-Host "Restart Codex app or start a new Codex CLI session if the old account is still shown."
}

function List-CodexAccounts {
    $store = Get-CodexAuthStore
    if (!(Test-Path $store)) {
        Write-Host "No saved Codex accounts yet. Store path: $store"
        return
    }

    Get-ChildItem -LiteralPath $store -Directory |
        Sort-Object Name |
        ForEach-Object {
            $metaPath = Join-Path $_.FullName "meta.json"
            $savedAt = ""
            if (Test-Path $metaPath) {
                try {
                    $savedAt = ((Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json).saved_at)
                } catch {
                    $savedAt = ""
                }
            }

            [pscustomobject]@{
                Name = $_.Name
                SavedAt = $savedAt
                Path = $_.FullName
            }
        } | Format-Table -AutoSize
}

function Show-CodexAccountHelp {
    @"
Codex account rotation helpers

Shared context:
  $(Get-CodexSharedHome)

Saved account store:
  $(Get-CodexAuthStore)

Commands:
  codex-account save acc-a    Save the currently logged-in account token.
  codex-account use acc-b     Switch auth.json to a saved account.
  codex-account list          List saved accounts.
  codex-account help          Show this help.

Short alias:
  cx save acc-a
  cx use acc-b
  cx list

Direct script usage:
  .\codex-account-switch.ps1 save acc-a
  .\codex-account-switch.ps1 use acc-b

Typical flow:
  1. Sign in to Codex as account A.
  2. codex-account save acc-a
  3. Sign in to Codex as account B.
  4. codex-account save acc-b
  5. codex-account use acc-a

Only auth.json is switched. config.toml, sessions, memories, and history stay shared.
"@ | Write-Host
}

function Invoke-CodexAccountCommand {
    param(
        [Parameter(Position = 0)][string]$Command,
        [Parameter(Position = 1)][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Command)) {
        Show-CodexAccountHelp
        return
    }

    switch -Regex ($Command.ToLowerInvariant()) {
        '^(save|s)$' {
            if ([string]::IsNullOrWhiteSpace($Name)) {
                throw "Missing account name. Example: codex-account save acc-a"
            }
            Save-CodexAccount -Name $Name
            return
        }
        '^(use|switch|u)$' {
            if ([string]::IsNullOrWhiteSpace($Name)) {
                throw "Missing account name. Example: codex-account use acc-a"
            }
            Use-CodexAccount -Name $Name
            return
        }
        '^(list|ls|l)$' {
            List-CodexAccounts
            return
        }
        '^(help|h|\?|--help|-h)$' {
            Show-CodexAccountHelp
            return
        }
        default {
            throw "Unknown command '$Command'. Run: codex-account help"
        }
    }
}

function codex-account {
    Invoke-CodexAccountCommand @args
}

function cx {
    Invoke-CodexAccountCommand @args
}

if ($MyInvocation.InvocationName -ne ".") {
    Invoke-CodexAccountCommand @args
}
