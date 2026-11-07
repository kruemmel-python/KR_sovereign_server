$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$projectRoot = Split-Path -Parent $PSScriptRoot
$taskTemp = Join-Path $projectRoot 'stack\runtime\tmp'
[IO.Directory]::CreateDirectory($taskTemp) | Out-Null
$env:TEMP = $taskTemp
$env:TMP = $taskTemp

$hostName = '127.0.0.1'
$port = 8085
$baseUri = "http://${hostName}:$port/"
$script:passed = 0
$script:failed = New-Object Collections.Generic.List[string]

function Add-Pass([string]$Name) {
    $script:passed++
    Write-Host "[OK] $Name" -ForegroundColor Green
}

function Add-Failure([string]$Name, [string]$Detail) {
    $script:failed.Add("${Name}: $Detail")
    Write-Host "[FUND] $Name - $Detail" -ForegroundColor Red
}

function Get-StatusCode([string]$Response) {
    if ($Response -match '^HTTP/1\.[01]\s+(\d{3})(?:\s|$)') { return [int]$Matches[1] }
    return 0
}

function Invoke-RawHttpBytes([byte[]]$RequestBytes, [int]$TimeoutMs = 6000) {
    $client = New-Object Net.Sockets.TcpClient
    $client.ReceiveTimeout = $TimeoutMs
    $client.SendTimeout = $TimeoutMs
    try {
        $client.Connect([Net.IPAddress]::Loopback, $port)
        $stream = $client.GetStream()
        $stream.Write($RequestBytes, 0, $RequestBytes.Length)
        $stream.Flush()
        $buffer = New-Object byte[] 16384
        $output = New-Object IO.MemoryStream
        try {
            while ($true) {
                try { $read = $stream.Read($buffer, 0, $buffer.Length) }
                catch [IO.IOException] { break }
                if ($read -le 0) { break }
                $output.Write($buffer, 0, $read)
                if ($output.Length -gt 2MB) { break }
            }
            return [Text.Encoding]::UTF8.GetString($output.ToArray())
        } finally { $output.Dispose() }
    } finally { $client.Dispose() }
}

function Invoke-RawHttp([string]$Request, [int]$TimeoutMs = 6000) {
    return Invoke-RawHttpBytes ([Text.Encoding]::UTF8.GetBytes($Request)) $TimeoutMs
}

function Test-RawStatus([string]$Name, [string]$Request, [int[]]$Expected) {
    $response = Invoke-RawHttp $Request
    $actual = Get-StatusCode $response
    if ($Expected -contains $actual) { Add-Pass "$Name -> HTTP $actual" }
    else { Add-Failure $Name "erwartet $($Expected -join '/'), erhalten $actual" }
    return $response
}

function Test-NoSensitiveBody([string]$Name, [string]$Response) {
    if ($Response -match '(?i)SOVEREIGN_(JWT_SECRET|BOOTSTRAP_TOKEN|CMS_DB_PASSWORD)|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|password\s*=') {
        Add-Failure $Name 'Antwort enthaelt ein Secret-Muster'
    } else { Add-Pass "$Name ohne Secret-Offenlegung" }
}

function Get-CsrfToken([string]$Html) {
    if ($Html -notmatch 'name="csrf_token"\s+value="([a-f0-9]{64})"') { throw 'CSRF-Token nicht gefunden.' }
    return $Matches[1]
}

function New-WebSession {
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.UseCookies = $true
    $handler.CookieContainer = New-Object Net.CookieContainer
    $handler.AllowAutoRedirect = $true
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(15)
    return [pscustomobject]@{ Client = $client; Handler = $handler }
}

function Invoke-FormPost($Client, [hashtable]$Values) {
    $pairs = New-Object 'Collections.Generic.List[Collections.Generic.KeyValuePair[string,string]]'
    foreach ($entry in $Values.GetEnumerator()) {
        $pairs.Add([Collections.Generic.KeyValuePair[string,string]]::new([string]$entry.Key, [string]$entry.Value))
    }
    $content = [Net.Http.FormUrlEncodedContent]::new($pairs)
    try { return $Client.PostAsync($baseUri, $content).GetAwaiter().GetResult() }
    finally { $content.Dispose() }
}

Write-Host '========================================================'
Write-Host '  SOVEREIGN LIVE ATTACK TEST (nur 127.0.0.1)'
Write-Host '========================================================'

$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object LocalPort -in @(8085, 3308))
foreach ($requiredPort in @(8085, 3308)) {
    $bound = @($listeners | Where-Object LocalPort -eq $requiredPort)
    if ($bound.Count -eq 1 -and $bound[0].LocalAddress -eq '127.0.0.1') {
        Add-Pass "Port $requiredPort lauscht ausschließlich auf IPv4-Loopback"
    } else {
        Add-Failure "Listener Port $requiredPort" (($bound | Select-Object LocalAddress,LocalPort,OwningProcess | Out-String).Trim())
    }
}

$crlf = "`r`n"
$close = "Connection: close${crlf}${crlf}"

$baseline = Test-RawStatus 'Baseline-Startseite' "GET / HTTP/1.1${crlf}Host: 127.0.0.1:8085${crlf}$close" @(200)
foreach ($requiredHeader in @('X-Content-Type-Options: nosniff','X-Frame-Options: DENY','Referrer-Policy: no-referrer','Content-Security-Policy:','Cache-Control: no-store','Permissions-Policy:')) {
    if ($baseline -match [regex]::Escape($requiredHeader)) { Add-Pass "Header $requiredHeader" }
    else { Add-Failure 'Browser-Sicherheitsheader' "$requiredHeader fehlt" }
}
Test-NoSensitiveBody 'Baseline' $baseline

[void](Test-RawStatus 'Fehlender Host-Header' "GET / HTTP/1.1${crlf}$close" @(400))
[void](Test-RawStatus 'Fremder Host-Header' "GET / HTTP/1.1${crlf}Host: attacker.invalid${crlf}$close" @(400))
[void](Test-RawStatus 'Doppelter Host-Header' "GET / HTTP/1.1${crlf}Host: localhost${crlf}Host: attacker.invalid${crlf}$close" @(400))
[void](Test-RawStatus 'Absolute Request-URI mit Fremdhost' "GET http://attacker.invalid/ HTTP/1.1${crlf}Host: 127.0.0.1:8085${crlf}$close" @(400))
[void](Test-RawStatus 'Doppelte Content-Length' "POST / HTTP/1.1${crlf}Host: localhost${crlf}Content-Length: 0${crlf}Content-Length: 4${crlf}$close" @(400))
[void](Test-RawStatus 'Transfer-Encoding chunked' "POST / HTTP/1.1${crlf}Host: localhost${crlf}Transfer-Encoding: chunked${crlf}${crlf}0${crlf}${crlf}" @(400))
[void](Test-RawStatus 'CL plus Transfer-Encoding' "POST / HTTP/1.1${crlf}Host: localhost${crlf}Content-Length: 0${crlf}Transfer-Encoding: chunked${crlf}${crlf}0${crlf}${crlf}" @(400))
[void](Test-RawStatus 'Ungueltige Content-Length' "POST / HTTP/1.1${crlf}Host: localhost${crlf}Content-Length: +1${crlf}${crlf}x" @(400))
[void](Test-RawStatus 'Deklarierter Body ueber 16 MiB' "POST / HTTP/1.1${crlf}Host: localhost${crlf}Content-Length: 16777217${crlf}$close" @(400,413))
[void](Test-RawStatus 'Header-Folding' "GET / HTTP/1.1${crlf}Host: localhost${crlf}X-Test: a${crlf} folded${crlf}$close" @(400))
[void](Test-RawStatus 'Mehrdeutige Request-Line' "GET  / HTTP/1.1${crlf}Host: localhost${crlf}$close" @(400))
[void](Test-RawStatus 'TRACE-Methode' "TRACE / HTTP/1.1${crlf}Host: localhost${crlf}$close" @(405))
[void](Test-RawStatus 'CONNECT-Methode' "CONNECT localhost:8085 HTTP/1.1${crlf}Host: localhost${crlf}$close" @(400,405))

$largeHeader = 'A' * 9000
$largeHeaderResponse = Invoke-RawHttp "GET / HTTP/1.1${crlf}Host: localhost${crlf}X-Fill: $largeHeader${crlf}$close"
$largeHeaderStatus = Get-StatusCode $largeHeaderResponse
if ($largeHeaderStatus -in @(0,400,431)) { Add-Pass "Header ueber Parsergrenze sicher abgewiesen -> HTTP/Abbruch $largeHeaderStatus" }
else { Add-Failure 'Header ueber Parsergrenze' "unerwartet HTTP $largeHeaderStatus" }

foreach ($path in @('/../stack/state.json','/%2e%2e/stack/state.json','/%252e%252e/stack/state.json','/%2e%2e%5cstack%5cstate.json','/C%3a/Windows/win.ini','/index.php%00.txt')) {
    $response = Test-RawStatus "Traversal/Dateipfad $path" "GET $path HTTP/1.1${crlf}Host: localhost${crlf}$close" @(200,400,403,404)
    Test-NoSensitiveBody "Pfad $path" $response
    if ((Get-StatusCode $response) -eq 200 -and $response -notmatch 'Sovereign Notizen') {
        Add-Failure "Traversal-Inhaltskontrolle $path" 'HTTP 200 enthielt nicht den erwarteten Frontcontroller'
    }
}
foreach ($path in @('/.env','/php.ini','/stack/state.json','/server_main.kr','/.git/config')) {
    $response = Test-RawStatus "Sensible Datei $path" "GET $path HTTP/1.1${crlf}Host: localhost${crlf}$close" @(200,400,403,404)
    Test-NoSensitiveBody "Datei $path" $response
    if ((Get-StatusCode $response) -eq 200 -and $response -notmatch 'Sovereign Notizen') {
        Add-Failure "Datei-Inhaltskontrolle $path" 'HTTP 200 enthielt nicht den erwarteten Frontcontroller'
    }
}

[void](Test-RawStatus 'Token-Endpunkt ohne Bootstrap-Token' "POST /auth/token HTTP/1.1${crlf}Host: localhost${crlf}Content-Length: 0${crlf}$close" @(401))
[void](Test-RawStatus 'Geschuetzte API ohne JWT' "GET /api/secure HTTP/1.1${crlf}Host: localhost${crlf}$close" @(401))
[void](Test-RawStatus 'Geschuetzte API mit gefaelschtem JWT' "GET /api/secure HTTP/1.1${crlf}Host: localhost${crlf}Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.invalid${crlf}$close" @(403))
$api405 = Test-RawStatus 'Reservierte API-Route mit falscher Methode' "POST /api/secure HTTP/1.1${crlf}Host: localhost${crlf}Content-Length: 0${crlf}$close" @(405)
if ($api405 -match '(?i)Content-Type:\s*application/json' -and $api405 -notmatch 'Sovereign Notizen') { Add-Pass 'Reservierte API-Route faellt nicht in den PHP-Frontcontroller' }
else { Add-Failure 'API-Routentrennung' 'Reservierte Route lieferte keine isolierte JSON-Antwort' }
[void](Test-RawStatus 'WebSocket-Upgrade ohne JWT' "GET /ws HTTP/1.1${crlf}Host: localhost${crlf}Upgrade: websocket${crlf}Connection: Upgrade${crlf}Sec-WebSocket-Version: 13${crlf}Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==${crlf}${crlf}" @(401))

$session = New-WebSession
$createdMarkers = New-Object Collections.Generic.List[string]
try {
    $get = $session.Client.GetAsync($baseUri).GetAwaiter().GetResult()
    $html = $get.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $csrf = Get-CsrfToken $html
    $cookie = $get.Headers.GetValues('Set-Cookie') -join '; '
    if ($cookie -match 'PHPSESSID=' -and $cookie -match '(?i)HttpOnly' -and $cookie -match '(?i)SameSite=Lax') {
        Add-Pass 'Session-Cookie ist HttpOnly und SameSite=Lax'
    } else { Add-Failure 'Session-Cookie' 'HttpOnly oder SameSite=Lax fehlt' }

    $nonce = [Guid]::NewGuid().ToString('N')
    $csrfMarker = "csrf-$nonce"
    $invalidCsrf = Invoke-FormPost $session.Client @{ action='add'; message=$csrfMarker; csrf_token=('0' * 64) }
    if ([int]$invalidCsrf.StatusCode -eq 403) { Add-Pass 'Manipulierter CSRF-Token wird abgewiesen -> HTTP 403' }
    else { Add-Failure 'CSRF-Abwehr' "HTTP $([int]$invalidCsrf.StatusCode)" }
    $invalidCsrf.Dispose()

    $xssMarker = "xss-$nonce-<script>window.attack=1</script>"
    $sqliMarker = "sqli-$nonce-'); DROP TABLE sovereign_notes;--"
    foreach ($marker in @($xssMarker, $sqliMarker)) {
        $posted = Invoke-FormPost $session.Client @{ action='add'; message=$marker; csrf_token=$csrf }
        if ([int]$posted.StatusCode -eq 200) { $createdMarkers.Add($marker); Add-Pass 'Kontrollierter Angriffswert gespeichert' }
        else { Add-Failure 'Testdatensatz anlegen' "HTTP $([int]$posted.StatusCode)" }
        $posted.Dispose()
    }

    $verify = $session.Client.GetAsync($baseUri).GetAwaiter().GetResult()
    $verifyHtml = $verify.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $verify.Dispose()
    if ($verifyHtml -match [regex]::Escape("xss-$nonce-&lt;script&gt;window.attack=1&lt;/script&gt;") -and
        $verifyHtml -notmatch [regex]::Escape("xss-$nonce-<script>")) {
        Add-Pass 'Gespeicherte XSS-Nutzlast wird HTML-maskiert'
    } else { Add-Failure 'Stored XSS' 'Nutzlast fehlt oder wird unmaskiert ausgegeben' }
    $sqliHtmlMarker = $sqliMarker -replace "'", '&#039;'
    if ($verifyHtml -match [regex]::Escape($sqliHtmlMarker) -and $verifyHtml -match 'MariaDB verbunden') {
        Add-Pass 'SQL-Injection-Nutzlast bleibt Datenwert; Tabelle ist intakt'
    } else { Add-Failure 'SQL-Injection-Abwehr' 'Nutzlast nicht literal gespeichert oder Tabelle nicht erreichbar' }
    if ($verifyHtml -notmatch [regex]::Escape($csrfMarker)) { Add-Pass 'Abgewiesene CSRF-Anfrage hat nichts gespeichert' }
    else { Add-Failure 'CSRF-Nebenwirkung' 'Abgewiesene Anfrage wurde dennoch gespeichert' }

    $tamper = Invoke-FormPost $session.Client @{ action='delete'; id='1 OR 1=1'; csrf_token=$csrf }
    $tamperBody = $tamper.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    if ([int]$tamper.StatusCode -eq 200 -and $tamperBody -match 'Ungültige Notiz-ID') { Add-Pass 'Manipulierte Delete-ID wird validiert' }
    else { Add-Failure 'ID-Manipulation' "HTTP $([int]$tamper.StatusCode) oder erwartete Validierungsantwort fehlt" }
    $tamper.Dispose()
}
finally {
    if ($null -ne $session) {
        try {
            $cleanupGet = $session.Client.GetAsync($baseUri).GetAwaiter().GetResult()
            $cleanupHtml = $cleanupGet.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $cleanupGet.Dispose()
            $cleanupCsrf = Get-CsrfToken $cleanupHtml
            foreach ($marker in $createdMarkers) {
                $needle = [regex]::Escape(($marker -replace '<','&lt;' -replace '>','&gt;' -replace "'",'&#039;'))
                $match = [regex]::Match($cleanupHtml, ('(?s)<li>.*?' + $needle + '.*?name="id" value="(\d+)".*?</li>'))
                if ($match.Success) {
                    $deleted = Invoke-FormPost $session.Client @{ action='delete'; id=$match.Groups[1].Value; csrf_token=$cleanupCsrf }
                    $deleted.Dispose()
                }
            }
        } catch { Add-Failure 'Aufraeumen der Testnotizen' $_.Exception.Message }
        $session.Client.Dispose()
        $session.Handler.Dispose()
    }
}

$burstTasks = New-Object 'Collections.Generic.List[Threading.Tasks.Task[Net.Http.HttpResponseMessage]]'
$burstClient = New-Object Net.Http.HttpClient
$burstClient.Timeout = [TimeSpan]::FromSeconds(15)
try {
    1..20 | ForEach-Object { $burstTasks.Add($burstClient.GetAsync($baseUri)) }
    [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$burstTasks.ToArray(), 20000) | Out-Null
    $codes = @($burstTasks | Where-Object IsCompletedSuccessfully | ForEach-Object { [int]$_.Result.StatusCode })
    if ($codes.Count -eq 20 -and @($codes | Where-Object { $_ -notin @(200,429,503) }).Count -eq 0) {
        Add-Pass 'Moderater Paralleltest: 20/20 kontrollierte Antworten, Server bleibt erreichbar'
    } else { Add-Failure 'Moderater Paralleltest' "Antworten=$($codes.Count), Codes=$($codes -join ',')" }
    foreach ($task in $burstTasks) { if ($task.IsCompletedSuccessfully) { $task.Result.Dispose() } }
} finally { $burstClient.Dispose() }

$health = Test-RawStatus 'Abschließender Verfügbarkeitstest' "GET / HTTP/1.1${crlf}Host: localhost${crlf}$close" @(200)
Test-NoSensitiveBody 'Abschlussantwort' $health

Write-Host '========================================================'
if ($script:failed.Count -eq 0) {
    Write-Host "[ERFOLG] Alle $($script:passed) Live-Angriffspruefungen bestanden." -ForegroundColor Green
    exit 0
}
Write-Host "[ERGEBNIS] $($script:passed) bestanden, $($script:failed.Count) Befund(e):" -ForegroundColor Yellow
$script:failed | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
exit 1
