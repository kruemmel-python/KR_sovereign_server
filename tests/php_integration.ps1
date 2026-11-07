$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function New-RandomSecret {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes); return [Convert]::ToBase64String($bytes) }
    finally { $rng.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Get-FreeTcpPort {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Invoke-RawHttp([string]$Request, [int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    $client.ReceiveTimeout = 35000
    $client.SendTimeout = 5000
    try {
        $client.Connect([Net.IPAddress]::Loopback, $Port)
        $stream = $client.GetStream()
        $bytes = [Text.Encoding]::UTF8.GetBytes($Request)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        $buffer = New-Object byte[] 16384
        $output = New-Object IO.MemoryStream
        try {
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) { $output.Write($buffer, 0, $read) }
            return [Text.Encoding]::UTF8.GetString($output.ToArray())
        } finally { $output.Dispose() }
    } finally { $client.Dispose() }
}

function Assert-Status([string]$Name, [string]$Response, [int[]]$Expected) {
    if ($Response -notmatch '^HTTP/1\.1\s+(\d{3})\s') { throw "$Name lieferte keine HTTP-Statuszeile." }
    $actual = [int]$Matches[1]
    if ($Expected -notcontains $actual) { throw "$Name erwartete $($Expected -join '/'), erhielt $actual.`n$Response" }
    Write-Host "[OK] $Name -> HTTP $actual"
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$stackRoot = Join-Path $projectRoot 'stack'
$runtimeRoot = Join-Path $stackRoot 'runtime'
$taskTemp = Join-Path $runtimeRoot 'tmp'
$env:TEMP = $taskTemp
$env:TMP = $taskTemp
Import-Module (Join-Path $stackRoot 'SovereignStack.psm1') -Force
Initialize-SovereignStackLayout
$php = Get-SovereignActiveModule -Module php
if ($null -eq $php) { throw 'PHP ist nicht aktiviert.' }
$exe = Get-ChildItem -LiteralPath (Join-Path $projectRoot 'KR_BUILD') -Filter 'kr-sovereign-server-*.exe' -File |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($null -eq $exe) { throw 'Keine gebaute Server-EXE gefunden.' }
$newestSource = Get-ChildItem -LiteralPath $projectRoot -Filter '*.kr' -File -Recurse |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($exe.LastWriteTimeUtc -lt $newestSource.LastWriteTimeUtc) { throw 'Die Server-EXE muss neu gebaut werden.' }

$port = Get-FreeTcpPort
$testName = '_sovereign-' + [Guid]::NewGuid().ToString('N') + '.php'
$testPath = Join-Path (Join-Path $projectRoot 'www') $testName
$sensitiveName = '_sovereign-' + [Guid]::NewGuid().ToString('N') + '.ini'
$sensitivePath = Join-Path (Join-Path $projectRoot 'www') $sensitiveName
$testCode = @'
<?php
declare(strict_types=1);
header('Content-Type: text/plain; charset=UTF-8');
echo "method=" . ($_SERVER['REQUEST_METHOD'] ?? '') . "\n";
echo "body=" . file_get_contents('php://input') . "\n";
echo "secret=" . (getenv('SOVEREIGN_JWT_SECRET') === false ? 'absent' : 'LEAKED') . "\n";
echo "db_secret=" . (getenv('SOVEREIGN_CMS_DB_PASSWORD') === false ? 'absent' : 'LEAKED') . "\n";
'@
[IO.File]::WriteAllText($testPath, $testCode, (New-Object Text.UTF8Encoding($false)))
[IO.File]::WriteAllText($sensitivePath, 'secret=must-not-be-served', (New-Object Text.UTF8Encoding($false)))

$names = @('SOVEREIGN_JWT_SECRET','SOVEREIGN_BOOTSTRAP_TOKEN','SOVEREIGN_PHP_ENABLED','SOVEREIGN_PHP_CGI',
    'SOVEREIGN_DOCUMENT_ROOT','SOVEREIGN_PHP_INI','SOVEREIGN_RUNTIME_TEMP','SOVEREIGN_PHP_CGI_LOG',
    'SOVEREIGN_PHP_MAX_PROCESSES','SOVEREIGN_SERVER_PORT','SOVEREIGN_CMS_DB_HOST','SOVEREIGN_CMS_DB_PORT',
    'SOVEREIGN_CMS_DB_NAME','SOVEREIGN_CMS_DB_USER','SOVEREIGN_CMS_DB_PASSWORD','TEMP','TMP')
$old = @{}
foreach ($name in $names) { $old[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$server = $null
try {
    $env:SOVEREIGN_JWT_SECRET = New-RandomSecret
    $env:SOVEREIGN_BOOTSTRAP_TOKEN = New-RandomSecret
    $env:SOVEREIGN_PHP_ENABLED = '1'
    $env:SOVEREIGN_PHP_CGI = $php.EntryPoint
    $env:SOVEREIGN_DOCUMENT_ROOT = Join-Path $projectRoot 'www'
    $env:SOVEREIGN_PHP_INI = Join-Path $php.PayloadRoot 'php.ini'
    $env:SOVEREIGN_RUNTIME_TEMP = $taskTemp
    $env:SOVEREIGN_PHP_CGI_LOG = Join-Path $runtimeRoot 'logs\php-cgi-test.log'
    $env:SOVEREIGN_PHP_MAX_PROCESSES = '2'
    $env:SOVEREIGN_SERVER_PORT = [string]$port
    $env:SOVEREIGN_CMS_DB_HOST = $null
    $env:SOVEREIGN_CMS_DB_PORT = $null
    $env:SOVEREIGN_CMS_DB_NAME = $null
    $env:SOVEREIGN_CMS_DB_USER = $null
    $env:SOVEREIGN_CMS_DB_PASSWORD = $null
    $stdout = Join-Path $runtimeRoot 'logs\php-integration.stdout.log'
    $stderr = Join-Path $runtimeRoot 'logs\php-integration.stderr.log'
    $server = Start-Process -FilePath $exe.FullName -ArgumentList @('--host','127.0.0.1','--port',"$port",'--workers','4') `
        -WorkingDirectory $projectRoot -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $ready = $false
    for ($i = 0; $i -lt 50; $i++) {
        if ($server.HasExited) { throw "Server endete vorzeitig mit Exit $($server.ExitCode)." }
        $probe = $null
        try {
            $probe = New-Object Net.Sockets.TcpClient
            $probe.Connect([Net.IPAddress]::Loopback, $port)
            $ready = $true
            break
        } catch { Start-Sleep -Milliseconds 100 } finally { if ($null -ne $probe) { $probe.Dispose() } }
    }
    if (-not $ready) { throw 'PHP-Testserver wurde nicht rechtzeitig erreichbar.' }

    $root = Invoke-RawHttp "GET / HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n" $port
    Assert-Status 'PHP-CMS-Startseite' $root @(200)
    if ($root -notmatch 'PHP ist aktiv') { throw 'Die PHP-Startseite wurde nicht ausgefuehrt.' }

    $frontController = Invoke-RawHttp "GET /cms/front-controller-route HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n" $port
    Assert-Status 'PHP-CMS-Front-Controller' $frontController @(200)
    if ($frontController -notmatch 'PHP ist aktiv') { throw 'Die CMS-Front-Controller-Route wurde nicht durch index.php ausgefuehrt.' }

    $body = 'cms=bereit&wert=42'
    $post = Invoke-RawHttp "POST /$testName HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`nContent-Type: application/x-www-form-urlencoded`r`nContent-Length: $([Text.Encoding]::UTF8.GetByteCount($body))`r`n`r`n$body" $port
    Assert-Status 'PHP POST-Body' $post @(200)
    if ($post -notmatch 'body=cms=bereit&wert=42' -or $post -notmatch 'secret=absent' -or $post -notmatch 'db_secret=absent') {
        throw 'PHP erhielt den Body nicht korrekt oder erbte ein Server-Secret.'
    }
    Write-Host '[OK] CGI-Umgebung enthaelt keine Server-Secrets'

    Assert-Status 'Kodierte Traversal-Sequenz' `
        (Invoke-RawHttp "GET /%2e%2e/$testName HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n" $port) @(400,403)
    Assert-Status 'PHP-Konfiguration nicht auslieferbar' `
        (Invoke-RawHttp "GET /$sensitiveName HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n" $port) @(403)
    Write-Host '[ERFOLG] PHP/CMS-Integrationstests bestanden.'
}
finally {
    if ($null -ne $server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force; $server.WaitForExit() }
    if (Test-Path -LiteralPath $testPath -PathType Leaf) { Remove-Item -LiteralPath $testPath -Force }
    if (Test-Path -LiteralPath $sensitivePath -PathType Leaf) { Remove-Item -LiteralPath $sensitivePath -Force }
    foreach ($name in $old.Keys) { [Environment]::SetEnvironmentVariable($name, $old[$name], 'Process') }
}
