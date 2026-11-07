$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$projectRoot = Split-Path -Parent $PSScriptRoot
$stackRoot = Join-Path $projectRoot 'stack'
$runtimeRoot = Join-Path $stackRoot 'runtime'
$taskTemp = Join-Path $runtimeRoot 'tmp'
$databasePort = 3308
$env:TEMP = $taskTemp
$env:TMP = $taskTemp
Import-Module (Join-Path $stackRoot 'SovereignStack.psm1') -Force
Initialize-SovereignStackLayout

function Invoke-DatabaseQuery {
    param(
        [Parameter(Mandatory)][string]$Client,
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$Sql,
        [string]$Database
    )
    $id = [Guid]::NewGuid().ToString('N')
    $inputPath = Join-Path $taskTemp ("mariadb-test-$id.sql")
    $outputPath = Join-Path $taskTemp ("mariadb-test-$id.stdout")
    $errorPath = Join-Path $taskTemp ("mariadb-test-$id.stderr")
    $oldPassword = [Environment]::GetEnvironmentVariable('MYSQL_PWD', 'Process')
    try {
        [IO.File]::WriteAllText($inputPath, $Sql, (New-Object Text.UTF8Encoding($false)))
        [Environment]::SetEnvironmentVariable('MYSQL_PWD', $Password, 'Process')
        $arguments = @('--protocol=tcp','--host=127.0.0.1',"--port=$databasePort", "--user=$User",'--connect-timeout=5','--batch','--raw','--skip-column-names')
        if (-not [string]::IsNullOrWhiteSpace($Database)) { $arguments += "--database=$Database" }
        $process = Start-Process -FilePath $Client -ArgumentList $arguments -WorkingDirectory $PayloadRoot `
            -RedirectStandardInput $inputPath -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath `
            -PassThru -Wait -WindowStyle Hidden
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = if (Test-Path -LiteralPath $outputPath) { [IO.File]::ReadAllText($outputPath) } else { '' }
            Error = if (Test-Path -LiteralPath $errorPath) { [IO.File]::ReadAllText($errorPath) } else { '' }
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable('MYSQL_PWD', $oldPassword, 'Process')
        foreach ($path in @($inputPath,$outputPath,$errorPath)) {
            if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
        }
    }
}

$module = Get-SovereignActiveModule -Module mariadb
if ($null -eq $module) { throw 'MariaDB ist nicht aktiviert.' }
$client = Get-ChildItem -LiteralPath $module.PayloadRoot -Filter 'mariadb.exe' -File -Recurse | Select-Object -First 1
if ($null -eq $client) { throw 'MariaDB-Client fehlt.' }
$status = Get-SovereignServiceStatus | Where-Object Service -eq 'mariadb'
if ($status.Running) { throw 'MariaDB laeuft bereits. Bitte zuerst ueber das Control Center stoppen, damit der Test keine bestehende Sitzung beeinflusst.' }

$dataDirectory = Join-Path $stackRoot 'data\mariadb'
$mysqlDirectory = Join-Path $dataDirectory 'mysql'
$startedByTest = $false
$cmsPassword = $null
try {
    if (-not (Test-Path -LiteralPath $mysqlDirectory -PathType Container)) {
        $existing = @(
            if (Test-Path -LiteralPath $dataDirectory -PathType Container) {
                Get-ChildItem -LiteralPath $dataDirectory -Force
            }
        )
        if ($existing.Count -gt 0) { throw 'Das MariaDB-Datenverzeichnis ist nicht leer, aber nicht gueltig initialisiert. Keine Daten wurden veraendert.' }
        $initialization = Initialize-SovereignMariaDb
        if (-not (Test-Path -LiteralPath $mysqlDirectory -PathType Container)) { throw 'MariaDB-Initialisierung erzeugte kein System-Schema.' }
        $initialization.RootPassword = $null
        $initialization = $null
        Write-Host '[OK] MariaDB-Datenverzeichnis auf F: initialisiert'
    }
    else {
        Write-Host '[OK] Vorhandenes MariaDB-Datenverzeichnis erkannt'
    }

    $null = Start-SovereignMariaDb
    $startedByTest = $true
    Write-Host '[OK] MariaDB authentisiert verbindungsbereit'

    $listeners = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() |
        Where-Object Port -eq $databasePort
    if (@($listeners).Count -lt 1) { throw "Kein Listener auf MariaDB-Port $databasePort gefunden." }
    $nonLoopback = @($listeners | Where-Object { -not [Net.IPAddress]::IsLoopback($_.Address) })
    if ($nonLoopback.Count -gt 0) { throw "MariaDB lauscht unerwartet nichtlokal: $($nonLoopback -join ', ')" }
    Write-Host "[OK] MariaDB lauscht ausschliesslich auf Loopback:$databasePort"

    $rootPassword = Unprotect-SovereignSecret -Name 'mariadb-root-password'
    try {
        $settings = Invoke-DatabaseQuery -Client $client.FullName -PayloadRoot $module.PayloadRoot -User 'root' `
            -Password $rootPassword -Sql 'SELECT @@GLOBAL.bind_address, @@GLOBAL.port, @@GLOBAL.local_infile, @@GLOBAL.secure_file_priv;'
        if ($settings.ExitCode -ne 0) { throw "MariaDB-Sicherheitsparameter konnten nicht gelesen werden: $($settings.Error)" }
        $values = ($settings.Output.Trim() -split "`t")
        if ($values.Count -ne 4 -or $values[0] -ne '127.0.0.1' -or $values[1] -ne [string]$databasePort -or $values[2] -ne '0') {
            throw "Unerwartete MariaDB-Sicherheitsparameter: $($settings.Output.Trim())"
        }
        $expectedImport = ([IO.Path]::GetFullPath((Join-Path $stackRoot 'data\mariadb-import'))).TrimEnd([char[]]'\/').Replace('\','/').ToLowerInvariant()
        $actualImport = $values[3].TrimEnd([char[]]'\/').Replace('\','/').ToLowerInvariant()
        if ($actualImport -ne $expectedImport) { throw "secure_file_priv zeigt auf einen unerwarteten Pfad: $($values[3])" }
        Write-Host '[OK] bind-address, Port, local_infile und secure_file_priv sind gehaertet'
    }
    finally { $rootPassword = $null }

    $cms = New-SovereignCmsDatabase
    $cmsPassword = $cms.Password
    if ($cms.Host -ne '127.0.0.1' -or $cms.Port -ne $databasePort -or $cms.Database -ne 'sovereign_cms' -or $cms.User -ne 'sovereign_cms') {
        throw 'CMS-Datenbankparameter sind unerwartet.'
    }
    Write-Host '[OK] Dediziertes CMS-Schema und CMS-Konto angelegt'

    $cmsQuery = Invoke-DatabaseQuery -Client $client.FullName -PayloadRoot $module.PayloadRoot -User 'sovereign_cms' `
        -Password $cmsPassword -Database 'sovereign_cms' `
        -Sql 'CREATE TABLE IF NOT EXISTS sovereign_security_probe (id INT PRIMARY KEY); INSERT IGNORE INTO sovereign_security_probe VALUES (1); SELECT DATABASE(), CURRENT_USER(), COUNT(*) FROM sovereign_security_probe; DROP TABLE sovereign_security_probe;'
    if ($cmsQuery.ExitCode -ne 0 -or $cmsQuery.Output -notmatch 'sovereign_cms\s+sovereign_cms@127\.0\.0\.1\s+1') {
        throw "CMS-Konto konnte sein eigenes Schema nicht korrekt verwenden: $($cmsQuery.Error)"
    }
    Write-Host '[OK] CMS-Konto besitzt Zugriff auf sein eigenes Schema'

    $forbidden = Invoke-DatabaseQuery -Client $client.FullName -PayloadRoot $module.PayloadRoot -User 'sovereign_cms' `
        -Password $cmsPassword -Sql 'SELECT COUNT(*) FROM mysql.user;'
    if ($forbidden.ExitCode -eq 0) { throw 'CMS-Konto konnte unerwartet das MariaDB-Systemschema lesen.' }
    Write-Host '[OK] CMS-Konto hat keinen Zugriff auf das MariaDB-Systemschema'

    $secretFile = Join-Path $stackRoot 'secrets\cms-database-password.dpapi'
    if (-not (Test-Path -LiteralPath $secretFile -PathType Leaf)) { throw 'DPAPI-Datei fuer das CMS-Passwort fehlt.' }
    $protectedText = [IO.File]::ReadAllText($secretFile)
    if ($protectedText.Contains($cmsPassword)) { throw 'CMS-Passwort wurde im Klartext in der Secret-Datei gefunden.' }
    Write-Host '[OK] CMS-Passwort ist nur DPAPI-geschuetzt gespeichert'

    if (-not (Stop-SovereignManagedService -Service mariadb)) { throw 'MariaDB konnte nicht geordnet gestoppt werden.' }
    $startedByTest = $false
    if ((Get-SovereignServiceStatus | Where-Object Service -eq 'mariadb').Running) { throw 'MariaDB wird nach dem Stop noch als laufend erkannt.' }
    Write-Host '[OK] MariaDB wurde geordnet heruntergefahren'
    Write-Host '[ERFOLG] Alle MariaDB-/CMS-Integrationstests bestanden.'
}
finally {
    $cmsPassword = $null
    if ($startedByTest) {
        try { [void](Stop-SovereignManagedService -Service mariadb) }
        catch { Write-Warning "MariaDB konnte beim Aufraeumen nicht geordnet gestoppt werden: $($_.Exception.Message)" }
    }
}
