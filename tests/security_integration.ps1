$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function New-RandomSecret {
    $bytes = New-Object byte[] 48
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes)
}

function Get-FreeTcpPort {
    $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Invoke-RawHttp([string]$Request, [int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.ReceiveTimeout = 5000
    $client.SendTimeout = 5000
    try {
        $client.Connect([Net.IPAddress]::Loopback, $Port)
        $stream = $client.GetStream()
        $bytes = [Text.Encoding]::ASCII.GetBytes($Request)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        $buffer = New-Object byte[] 16384
        $output = New-Object IO.MemoryStream
        try {
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $output.Write($buffer, 0, $read)
            }
            return [Text.Encoding]::UTF8.GetString($output.ToArray())
        } finally { $output.Dispose() }
    } finally { $client.Dispose() }
}

function Assert-Status([string]$Name, [string]$Response, [int]$Expected) {
    if ($Response -notmatch '^HTTP/1\.1\s+(\d{3})\s') {
        throw "$Name lieferte keine gueltige HTTP-Statuszeile."
    }
    $actual = [int]$Matches[1]
    if ($actual -ne $Expected) {
        throw "$Name erwartete HTTP $Expected, erhielt HTTP $actual.`n$Response"
    }
    Write-Host "[OK] $Name -> HTTP $actual"
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$buildRoot = Join-Path $projectRoot 'KR_BUILD'
$taskTemp = Join-Path $projectRoot 'stack\runtime\tmp'
if (-not (Test-Path -LiteralPath $taskTemp -PathType Container)) {
    New-Item -ItemType Directory -Path $taskTemp -Force | Out-Null
}
$environmentNames = @('SOVEREIGN_JWT_SECRET','SOVEREIGN_BOOTSTRAP_TOKEN','SOVEREIGN_PHP_ENABLED','SOVEREIGN_PHP_CGI','TEMP','TMP')
$originalEnvironment = @{}
foreach ($name in $environmentNames) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$env:TEMP = $taskTemp
$env:TMP = $taskTemp
$exe = Get-ChildItem -LiteralPath $buildRoot -Filter 'kr-sovereign-server-*.exe' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($null -eq $exe) { throw 'Keine gebaute Server-EXE in KR_BUILD gefunden.' }
$newestSource = Get-ChildItem -LiteralPath $projectRoot -Recurse -File -Filter '*.kr' |
    Where-Object { $_.FullName -notlike "$buildRoot*" } |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($null -ne $newestSource -and $exe.LastWriteTimeUtc -lt $newestSource.LastWriteTimeUtc) {
    throw "Die EXE ist aelter als $($newestSource.Name). Bitte das KR-Projekt vor dem Security-Test neu bauen."
}

$port = Get-FreeTcpPort
$env:SOVEREIGN_JWT_SECRET = New-RandomSecret
$env:SOVEREIGN_BOOTSTRAP_TOKEN = New-RandomSecret
[Environment]::SetEnvironmentVariable('SOVEREIGN_PHP_CGI', $null, 'Process')
$env:SOVEREIGN_PHP_ENABLED = '0'
$stdout = Join-Path $buildRoot 'security-integration.stdout.log'
$stderr = Join-Path $buildRoot 'security-integration.stderr.log'
$server = Start-Process -FilePath $exe.FullName -ArgumentList @('--host','127.0.0.1','--port',"$port",'--workers','4') `
    -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr

try {
    $ready = $false
    for ($i = 0; $i -lt 50; $i++) {
        if ($server.HasExited) { throw "Server endete vorzeitig mit Exit-Code $($server.ExitCode)." }
        $probe = New-Object Net.Sockets.TcpClient
        try {
            $probe.Connect([Net.IPAddress]::Loopback, $port)
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 100
        } finally { $probe.Dispose() }
    }
    if (-not $ready) { throw 'Server wurde nicht rechtzeitig erreichbar.' }

    $close = "Connection: close`r`n"
    $hostHeader = "Host: localhost`r`n"
    Start-Sleep -Milliseconds 250

    # Bei vier Workern sind hoechstens vier aktive plus acht wartende Sockets
    # zugelassen. Der dreizehnte Socket muss bereits an der Accept-Grenze 503
    # erhalten und darf nicht in einer grossen Vorqueue landen.
    $heldClients = New-Object Collections.Generic.List[Net.Sockets.TcpClient]
    try {
        for ($i = 0; $i -lt 12; $i++) {
            $held = New-Object Net.Sockets.TcpClient
            $held.Connect([Net.IPAddress]::Loopback, $port)
            $heldClients.Add($held)
        }
        Start-Sleep -Milliseconds 250
        $overflowRejected = $false
        try {
            $overflowResponse = Invoke-RawHttp "GET /health HTTP/1.1`r`n$hostHeader$close`r`n" $port
            $overflowRejected = [string]::IsNullOrEmpty($overflowResponse) -or $overflowResponse -match '^HTTP/1\.1 503 '
        } catch [IO.IOException] {
            $overflowRejected = $true
        }
        if (-not $overflowRejected) { throw 'Admission-Control liess einen Socket ueber der Kapazitaetsgrenze zu.' }
        Write-Host '[OK] Admission vor Pending-Queue -> Ueberkapazitaet geschlossen'
    } finally {
        foreach ($held in $heldClients) { $held.Dispose() }
    }
    Start-Sleep -Milliseconds 500

    $response = Invoke-RawHttp "POST /auth/token HTTP/1.1`r`n$hostHeader$close`r`n" $port
    Assert-Status 'Tokenausgabe ohne Bootstrap-Authentisierung' $response 401

    $response = Invoke-RawHttp "POST /auth/token HTTP/1.1`r`n$hostHeader${close}Authorization: Bearer $env:SOVEREIGN_BOOTSTRAP_TOKEN`r`n`r`n" $port
    Assert-Status 'Tokenausgabe mit Bootstrap-Authentisierung' $response 200
    if ($response -notmatch '"token":"([^"]+)"') { throw 'Tokenantwort enthielt kein JWT.' }
    $jwt = $Matches[1]

    Assert-Status 'Geschuetzte Route ohne JWT' `
        (Invoke-RawHttp "GET /api/secure HTTP/1.1`r`n$hostHeader$close`r`n" $port) 401
    Assert-Status 'Geschuetzte Route mit ungueltigem JWT' `
        (Invoke-RawHttp "GET /api/secure HTTP/1.1`r`n$hostHeader${close}Authorization: Bearer invalid.invalid.invalid`r`n`r`n" $port) 403
    Assert-Status 'Geschuetzte Route mit gueltigem JWT' `
        (Invoke-RawHttp "GET /api/secure HTTP/1.1`r`n$hostHeader${close}Authorization: Bearer $jwt`r`n`r`n" $port) 200

    Assert-Status 'Task-Route ohne JWT' `
        (Invoke-RawHttp "POST /api/tasks HTTP/1.1`r`n$hostHeader$close`r`n" $port) 401
    Assert-Status 'Task-Route mit JWT' `
        (Invoke-RawHttp "POST /api/tasks HTTP/1.1`r`n$hostHeader${close}Authorization: Bearer $jwt`r`n`r`n" $port) 202

    Assert-Status 'Doppelte Content-Length' `
        (Invoke-RawHttp "POST /auth/token HTTP/1.1`r`n$hostHeader${close}Content-Length: 0`r`nContent-Length: 0`r`n`r`n" $port) 400
    Assert-Status 'Transfer-Encoding' `
        (Invoke-RawHttp "POST /api/tasks HTTP/1.1`r`n$hostHeader${close}Transfer-Encoding: chunked`r`n`r`n" $port) 400
    Assert-Status 'Body an internem bodylosen Endpunkt' `
        (Invoke-RawHttp "POST /auth/token HTTP/1.1`r`n$hostHeader${close}Content-Length: 1`r`n`r`nx" $port) 400
    Assert-Status 'Ueberzaehlige Bytes nach Content-Length 0' `
        (Invoke-RawHttp "POST /auth/token HTTP/1.1`r`n$hostHeader${close}Content-Length: 0`r`n`r`nx" $port) 400
    Assert-Status 'Fehlender Host-Header' `
        (Invoke-RawHttp "GET /health HTTP/1.1`r`n$close`r`n" $port) 400
    Assert-Status 'Nichtlokaler Host-Header' `
        (Invoke-RawHttp "GET /health HTTP/1.1`r`nHost: attacker.example`r`n$close`r`n" $port) 400
    Assert-Status 'Mehrdeutige Request-Line' `
        (Invoke-RawHttp "GET  /health HTTP/1.1`r`n$hostHeader$close`r`n" $port) 400

    $jsonEscapeResponse = Invoke-RawHttp "GET /bad`"path HTTP/1.1`r`n$hostHeader$close`r`n" $port
    Assert-Status 'JSON-maskierter Fehlerpfad' $jsonEscapeResponse 404
    $jsonBody = ($jsonEscapeResponse -split "`r`n`r`n", 2)[1] | ConvertFrom-Json
    if ($jsonBody.path -cne '/bad"path') { throw 'Fehlerantwort maskierte den Request-Pfad nicht korrekt.' }
    Write-Host '[OK] Dynamischer Fehlerpfad ist gueltiges, korrekt maskiertes JSON'

    $wsRequest = "GET /ws HTTP/1.1`r`n${hostHeader}Connection: Upgrade, close`r`nUpgrade: websocket`r`nSec-WebSocket-Version: 13`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`n`r`n"
    Assert-Status 'WebSocket-Upgrade ohne JWT' (Invoke-RawHttp $wsRequest $port) 401
    $noncanonicalWsRequest = "GET /ws HTTP/1.1`r`n${hostHeader}Connection: Upgrade, close`r`nUpgrade: websocket`r`nSec-WebSocket-Version: 13`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZR==`r`n`r`n"
    Assert-Status 'Nichtkanonischer WebSocket-Key' (Invoke-RawHttp $noncanonicalWsRequest $port) 400

    $wsClient = New-Object Net.Sockets.TcpClient
    $wsClient.ReceiveTimeout = 3000
    $wsClient.SendTimeout = 3000
    try {
        $wsClient.Connect([Net.IPAddress]::Loopback, $port)
        $wsStream = $wsClient.GetStream()
        $authenticatedUpgrade = "GET /ws HTTP/1.1`r`n${hostHeader}Connection: Upgrade`r`nUpgrade: websocket`r`nSec-WebSocket-Version: 13`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`nAuthorization: Bearer $jwt`r`n`r`n"
        $upgradeBytes = [Text.Encoding]::ASCII.GetBytes($authenticatedUpgrade)
        $wsStream.Write($upgradeBytes, 0, $upgradeBytes.Length)
        $wsBuffer = New-Object byte[] 4096
        $upgradeRead = $wsStream.Read($wsBuffer, 0, $wsBuffer.Length)
        $upgradeResponse = [Text.Encoding]::ASCII.GetString($wsBuffer, 0, $upgradeRead)
        if ($upgradeResponse -notmatch '^HTTP/1\.1 101 ') { throw 'Authentifizierter WebSocket-Upgrade schlug fehl.' }

        # Clientframes muessen maskiert sein. Dieser unmaskierte Leerframe muss
        # zum sofortigen, sicheren Verbindungsabbruch fuehren.
        $wsStream.Write([byte[]](0x81, 0x00), 0, 2)
        $closed = $false
        try {
            $closed = ($wsStream.Read($wsBuffer, 0, $wsBuffer.Length) -eq 0)
        } catch [IO.IOException] {
            $closed = $true
        }
        if (-not $closed) { throw 'Unmaskierter WebSocket-Frame wurde nicht durch Verbindungsabbruch abgelehnt.' }
        Write-Host '[OK] Unmaskierter WebSocket-Frame -> Verbindung geschlossen'
    } finally { $wsClient.Dispose() }

    # Periodische Einzelbytes duerfen den absoluten Header-Timeout nicht
    # verlaengern. Der Server muss die Verbindung nach etwa fuenf Sekunden
    # schliessen, obwohl jedes Byte vor dem relativen Sockettimeout ankommt.
    $slowClient = New-Object Net.Sockets.TcpClient
    $slowClient.ReceiveTimeout = 2500
    $slowClient.SendTimeout = 2500
    try {
        $slowClient.Connect([Net.IPAddress]::Loopback, $port)
        $slowStream = $slowClient.GetStream()
        $slowClosed = $false
        for ($i = 0; $i -lt 7; $i++) {
            try {
                $slowStream.WriteByte([byte][char]'G')
                $slowStream.Flush()
            } catch [IO.IOException] {
                $slowClosed = $true
                break
            }
            Start-Sleep -Seconds 1
        }
        if (-not $slowClosed) {
            $slowBuffer = New-Object byte[] 1024
            try {
                do { $slowRead = $slowStream.Read($slowBuffer, 0, $slowBuffer.Length) } while ($slowRead -gt 0)
                $slowClosed = $true
            } catch [IO.IOException] {
                $slowClosed = $false
            }
        }
        if (-not $slowClosed) { throw 'Slowloris-Verbindung ueberlebte die absolute Header-Deadline.' }
        Write-Host '[OK] Slowloris-Einzelbytes -> Verbindung innerhalb der Deadline geschlossen'
    } finally { $slowClient.Dispose() }

    # Ein zweiter Prozess ohne Secrets muss vor Socket-/Listener-Aufbau
    # fail-closed enden. Der bereits laufende Server besitzt seine eigene,
    # unveraenderte Prozessumgebung.
    $savedJwtSecret = $env:SOVEREIGN_JWT_SECRET
    $savedBootstrapToken = $env:SOVEREIGN_BOOTSTRAP_TOKEN
    $missingSecretOut = Join-Path $buildRoot 'security-missing-secret.stdout.log'
    $missingSecretErr = Join-Path $buildRoot 'security-missing-secret.stderr.log'
    try {
        [Environment]::SetEnvironmentVariable('SOVEREIGN_JWT_SECRET', $null, 'Process')
        [Environment]::SetEnvironmentVariable('SOVEREIGN_BOOTSTRAP_TOKEN', $null, 'Process')
        $missingSecret = Start-Process -FilePath $exe.FullName -ArgumentList @('--host','127.0.0.1','--port',"$port",'--workers','1') `
            -PassThru -Wait -WindowStyle Hidden -RedirectStandardOutput $missingSecretOut -RedirectStandardError $missingSecretErr
        if ($missingSecret.ExitCode -eq 0) { throw 'Server startete ohne erforderliche Secrets.' }
        Write-Host "[OK] Fehlende Secrets abgelehnt -> Exit $($missingSecret.ExitCode)"
    } finally {
        [Environment]::SetEnvironmentVariable('SOVEREIGN_JWT_SECRET', $savedJwtSecret, 'Process')
        [Environment]::SetEnvironmentVariable('SOVEREIGN_BOOTSTRAP_TOKEN', $savedBootstrapToken, 'Process')
    }

    $remoteOut = Join-Path $buildRoot 'security-remote-bind.stdout.log'
    $remoteErr = Join-Path $buildRoot 'security-remote-bind.stderr.log'
    $remote = Start-Process -FilePath $exe.FullName -ArgumentList @('--host','0.0.0.0','--port',"$port",'--workers','1') `
        -PassThru -Wait -WindowStyle Hidden -RedirectStandardOutput $remoteOut -RedirectStandardError $remoteErr
    if ($remote.ExitCode -eq 0) { throw 'Unsichere Remote-Bindung wurde nicht abgelehnt.' }
    Write-Host "[OK] Remote-Bindung abgelehnt -> Exit $($remote.ExitCode)"

    Write-Host '[ERFOLG] Alle Security-Integrationstests bestanden.'
} finally {
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        $server.WaitForExit()
    }
    foreach ($name in $originalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
    }
}
