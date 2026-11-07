[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8085,

    [ValidateRange(1, 256)]
    [int]$Workers = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-SovereignSecret {
    $bytes = New-Object byte[] 48
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try {
        $rng.GetBytes($bytes)
        return [Convert]::ToBase64String($bytes)
    }
    finally {
        $rng.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Test-SovereignSecret {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return $false }
    $byteLength = [Text.Encoding]::UTF8.GetByteCount($Value)
    return $byteLength -ge 32 -and $byteLength -le 256
}

$projectRoot = $PSScriptRoot
$stackRoot = Join-Path $projectRoot 'stack'
$stackModulePath = Join-Path $stackRoot 'SovereignStack.psm1'
Import-Module $stackModulePath -Force
Initialize-SovereignStackLayout
$buildDirectory = Join-Path $projectRoot 'KR_BUILD'
$serverExecutable = Get-ChildItem -LiteralPath $buildDirectory -Filter 'kr-sovereign-server-*.exe' -File |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1

if ($null -eq $serverExecutable) {
    throw 'Keine gebaute Server-EXE in KR_BUILD gefunden. Bitte das Projekt zuerst neu bauen.'
}

$newestSource = Get-ChildItem -LiteralPath $projectRoot -Filter '*.kr' -File -Recurse |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1

if ($null -ne $newestSource -and $serverExecutable.LastWriteTimeUtc -lt $newestSource.LastWriteTimeUtc) {
    throw 'Die Server-EXE ist aelter als der Quellcode. Bitte neu bauen, bevor sie gestartet wird.'
}

$originalJwtSecret = [Environment]::GetEnvironmentVariable('SOVEREIGN_JWT_SECRET', 'Process')
$originalBootstrapToken = [Environment]::GetEnvironmentVariable('SOVEREIGN_BOOTSTRAP_TOKEN', 'Process')
$usingEphemeralSecrets = $false
$phpModule = Get-SovereignActiveModule -Module php
$phpEnvironment = [ordered]@{
    SOVEREIGN_PHP_ENABLED = if ($null -eq $phpModule) { '0' } else { '1' }
    SOVEREIGN_PHP_CGI = if ($null -eq $phpModule) { $null } else { $phpModule.EntryPoint }
    SOVEREIGN_DOCUMENT_ROOT = if ($null -eq $phpModule) { $null } else { Join-Path $projectRoot 'www' }
    SOVEREIGN_PHP_INI = if ($null -eq $phpModule) { $null } else { Join-Path $phpModule.PayloadRoot 'php.ini' }
    SOVEREIGN_RUNTIME_TEMP = if ($null -eq $phpModule) { $null } else { Join-Path $stackRoot 'runtime\tmp' }
    SOVEREIGN_PHP_CGI_LOG = if ($null -eq $phpModule) { $null } else { Join-Path $stackRoot 'runtime\logs\php-cgi.log' }
    SOVEREIGN_PHP_MAX_PROCESSES = if ($null -eq $phpModule) { $null } else { [string][Math]::Min(8, $Workers) }
    SOVEREIGN_SERVER_PORT = [string]$Port
    TEMP = Join-Path $stackRoot 'runtime\tmp'
    TMP = Join-Path $stackRoot 'runtime\tmp'
}
if ($null -ne $phpModule -and -not (Test-Path -LiteralPath $phpEnvironment.SOVEREIGN_PHP_INI -PathType Leaf)) {
    throw 'php.ini fehlt im aktiven PHP-Modul.'
}
$originalPhpEnvironment = @{}
foreach ($name in $phpEnvironment.Keys) {
    $originalPhpEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    foreach ($name in $phpEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $phpEnvironment[$name], 'Process')
    }
    $jwtSecret = $originalJwtSecret
    $bootstrapToken = $originalBootstrapToken

    if (-not (Test-SovereignSecret $jwtSecret) -or
        -not (Test-SovereignSecret $bootstrapToken) -or
        $jwtSecret -ceq $bootstrapToken) {
        $jwtSecret = New-SovereignSecret
        do {
            $bootstrapToken = New-SovereignSecret
        } while ($bootstrapToken -ceq $jwtSecret)

        [Environment]::SetEnvironmentVariable('SOVEREIGN_JWT_SECRET', $jwtSecret, 'Process')
        [Environment]::SetEnvironmentVariable('SOVEREIGN_BOOTSTRAP_TOKEN', $bootstrapToken, 'Process')
        $usingEphemeralSecrets = $true

        Write-Host ''
        Write-Host '[SICHERER LOKALSTART] Einmalige Sitzungsschluessel wurden erzeugt.' -ForegroundColor Green
        Write-Host 'Bootstrap-Token (als Bearer-Token fuer /auth/token verwenden):' -ForegroundColor Yellow
        Write-Host $bootstrapToken -ForegroundColor Cyan
        Write-Host 'Hinweis: Nach einem Neustart sind damit ausgestellte JWTs ungueltig.' -ForegroundColor DarkYellow
        Write-Host ''
    }
    else {
        Write-Host '[SICHERER START] Gueltige, getrennte Umgebungsvariablen werden verwendet.' -ForegroundColor Green
    }

    & $serverExecutable.FullName --host '127.0.0.1' --port $Port --workers $Workers
    $serverExitCode = $LASTEXITCODE
    if ($serverExitCode -ne 0) {
        throw "Der Server wurde mit Rueckgabewert $serverExitCode beendet."
    }
}
finally {
    if ($usingEphemeralSecrets) {
        [Environment]::SetEnvironmentVariable('SOVEREIGN_JWT_SECRET', $originalJwtSecret, 'Process')
        [Environment]::SetEnvironmentVariable('SOVEREIGN_BOOTSTRAP_TOKEN', $originalBootstrapToken, 'Process')
    }
    foreach ($name in $originalPhpEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalPhpEnvironment[$name], 'Process')
    }
}
