<#
.SYNOPSIS
Creates the initial kautuka-auth Worker secrets file or adds a refresh-token
encryption key for rotation.

.DESCRIPTION
The generated .cloudflare-secrets.json contains production secrets. It is
ignored by Git. Back it up in a password manager before uploading or rotating.
This script only prepares the file; it does not contact Cloudflare or deploy.

.EXAMPLE
./scripts/manage-cloudflare-secrets.ps1

.EXAMPLE
./scripts/manage-cloudflare-secrets.ps1 -RotateRefreshTokenKey
#>
[CmdletBinding()]
param(
    [switch]$RotateRefreshTokenKey
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$secretFile = Join-Path $repoRoot '.cloudflare-secrets.json'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Get-RandomBase64Url([int]$ByteCount) {
    $bytes = [byte[]]::new($ByteCount)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) }
    finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-NewKeyId([System.Collections.IDictionary]$ExistingKeys) {
    do {
        $suffix = (Get-RandomBase64Url 6).ToLowerInvariant().Replace('-', '').Replace('_', '')
        $keyId = 'k' + (Get-Date -Format 'yyyyMMdd') + '-' + $suffix
    } while ($ExistingKeys.Contains($keyId))
    return $keyId
}

if (-not $RotateRefreshTokenKey) {
    if (Test-Path -LiteralPath $secretFile) {
        throw "Refusing to overwrite $secretFile. Keep the existing key material; use -RotateRefreshTokenKey to add a new AES key without discarding old keys."
    }

    $keyId = Get-NewKeyId @{}
    $keyBytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($keyBytes) }
    finally { $rng.Dispose() }
    $refreshKey = [Convert]::ToBase64String($keyBytes)
    [Array]::Clear($keyBytes, 0, $keyBytes.Length)

    $secrets = [ordered]@{
        AUTH_TICKET_HMAC_KEY = Get-RandomBase64Url 32
        REFRESH_TOKEN_KEYS = (@{ $keyId = $refreshKey } | ConvertTo-Json -Compress)
        REFRESH_TOKEN_ACTIVE_KID = $keyId
    }
    $json = $secrets | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($secretFile, $json + [Environment]::NewLine, $utf8NoBom)
    $refreshKey = $null
    $secrets = $null
    $json = $null
    Write-Host "Created ignored secrets file: $secretFile"
    Write-Host 'Back it up in your password manager, then upload with: npx wrangler secret bulk .cloudflare-secrets.json --name kautuka-auth'
    exit 0
}

if (-not (Test-Path -LiteralPath $secretFile)) {
    throw "Cannot rotate without the current keyring file: $secretFile. Restore it from your secure backup first."
}

$existing = Get-Content -LiteralPath $secretFile -Raw | ConvertFrom-Json -AsHashtable
foreach ($required in @('AUTH_TICKET_HMAC_KEY', 'REFRESH_TOKEN_KEYS', 'REFRESH_TOKEN_ACTIVE_KID')) {
    if (-not $existing.ContainsKey($required) -or [string]::IsNullOrWhiteSpace([string]$existing[$required])) {
        throw "The secrets file is missing required value '$required'; no changes made."
    }
}

$keyring = ConvertFrom-Json -InputObject ([string]$existing.REFRESH_TOKEN_KEYS) -AsHashtable
if ($keyring -isnot [System.Collections.IDictionary] -or $keyring.Count -eq 0) {
    throw 'REFRESH_TOKEN_KEYS is not a non-empty JSON keyring; no changes made.'
}
$newKeyId = Get-NewKeyId $keyring
$newBytes = [byte[]]::new(32)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($newBytes) }
finally { $rng.Dispose() }
$keyring[$newKeyId] = [Convert]::ToBase64String($newBytes)
[Array]::Clear($newBytes, 0, $newBytes.Length)

$existing.REFRESH_TOKEN_KEYS = $keyring | ConvertTo-Json -Compress
$existing.REFRESH_TOKEN_ACTIVE_KID = $newKeyId
$json = $existing | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($secretFile, $json + [Environment]::NewLine, $utf8NoBom)
$json = $null
$keyring = $null
$existing = $null
Write-Host "Added key '$newKeyId' and made it active. Previous keys were retained."
Write-Host 'Back up the updated secrets file, then upload with: npx wrangler secret bulk .cloudflare-secrets.json --name kautuka-auth'
