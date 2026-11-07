Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:StackRoot = $PSScriptRoot
$script:ProjectRoot = Split-Path -Parent $script:StackRoot
$script:StatePath = Join-Path $script:StackRoot 'state.json'
$script:ModulesRoot = Join-Path $script:StackRoot 'modules'
$script:StagingRoot = Join-Path $script:ModulesRoot '.staging'
$script:RuntimeRoot = Join-Path $script:StackRoot 'runtime'
$script:DataRoot = Join-Path $script:StackRoot 'data'
$script:SecretsRoot = Join-Path $script:StackRoot 'secrets'
$script:WebRoot = Join-Path $script:ProjectRoot 'www'
$script:MariaDbPort = 3308

function Initialize-SovereignStackLayout {
    foreach ($path in @(
        $script:ModulesRoot,
        $script:StagingRoot,
        $script:RuntimeRoot,
        $script:DataRoot,
        $script:SecretsRoot,
        $script:WebRoot,
        (Join-Path $script:RuntimeRoot 'logs'),
        (Join-Path $script:RuntimeRoot 'tmp'),
        (Join-Path $script:RuntimeRoot 'sessions'),
        (Join-Path $script:DataRoot 'mariadb-import')
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

function Read-SovereignStackState {
    Initialize-SovereignStackLayout
    if (-not (Test-Path -LiteralPath $script:StatePath -PathType Leaf)) {
        throw "Stack-Status fehlt: $script:StatePath"
    }
    $raw = Get-Content -LiteralPath $script:StatePath -Raw
    $state = $raw | ConvertFrom-Json
    if ($null -eq $state -or $state.schemaVersion -ne 1) {
        throw 'Nicht unterstuetzte oder beschaedigte Stack-Statusdatei.'
    }
    return $state
}

function Write-SovereignStackState {
    param([Parameter(Mandatory)]$State)

    Initialize-SovereignStackLayout
    $temporary = Join-Path $script:StackRoot ('.state-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $json = $State | ConvertTo-Json -Depth 12
        [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $script:StatePath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Test-SovereignVersion {
    param([Parameter(Mandatory)][string]$Version)
    return $Version -match '^[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.-]+)?$' -and $Version.Length -le 64
}

function Assert-SovereignSha256 {
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )
    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
        throw "Paket nicht gefunden: $PackagePath"
    }
    $expected = $ExpectedSha256.Trim().ToUpperInvariant()
    if ($expected -notmatch '^[0-9A-F]{64}$') {
        throw 'Der erwartete SHA-256 muss aus genau 64 Hex-Zeichen bestehen.'
    }
    $actual = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -cne $expected) {
        throw "SHA-256 stimmt nicht ueberein. Erwartet: $expected; erhalten: $actual"
    }
    return $actual
}

function Assert-WindowsX64Pe {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 256) { throw "PE-Datei ist zu klein: $Path" }
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "Ungueltige MZ-Signatur: $Path" }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 24)) { throw "Ungueltiger PE-Offset: $Path" }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Ungueltige PE-Signatur: $Path" }
        if ($reader.ReadUInt16() -ne 0x8664) { throw "Modul ist nicht Windows x64: $Path" }
    }
    finally {
        $stream.Dispose()
    }
}

function Expand-SovereignZipSafely {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$Destination
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $destinationFull = [IO.Path]::GetFullPath($Destination)
    $destinationPrefix = $destinationFull.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not (Test-Path -LiteralPath $destinationFull -PathType Container)) {
        New-Item -ItemType Directory -Path $destinationFull -Force | Out-Null
    }

    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        if ($archive.Entries.Count -gt 100000) { throw 'ZIP enthaelt zu viele Eintraege.' }
        [UInt64]$totalLength = 0
        $targets = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($name) -or $name.StartsWith('/') -or
                $name -match '^[A-Za-z]:' -or $name.IndexOf([char]0) -ge 0) {
                throw "Unsicherer ZIP-Pfad: $name"
            }
            $segments = $name.Split('/')
            foreach ($segment in $segments) {
                if ($segment -eq '..' -or $segment.Contains(':')) {
                    throw "Unsicherer ZIP-Pfad: $name"
                }
            }
            if ($entry.Length -gt 1GB) { throw "ZIP-Eintrag ist zu gross: $name" }
            $totalLength += [UInt64]$entry.Length
            if ($totalLength -gt 4GB) { throw 'Entpackte ZIP-Gesamtgroesse ueberschreitet 4 GiB.' }
            if ($entry.CompressedLength -eq 0 -and $entry.Length -gt 0) {
                throw "Ungueltige ZIP-Kompressionsdaten: $name"
            }
            if ($entry.CompressedLength -gt 0 -and $entry.Length -gt 64MB -and
                ($entry.Length / $entry.CompressedLength) -gt 1000) {
                throw "Verdaechtiges ZIP-Kompressionsverhaeltnis: $name"
            }

            $target = [IO.Path]::GetFullPath((Join-Path $destinationFull $name))
            if (-not $target.StartsWith($destinationPrefix, [StringComparison]::OrdinalIgnoreCase) -and
                $target -cne $destinationFull) {
                throw "ZIP-Pfad verlaesst das Staging-Verzeichnis: $name"
            }
            if (-not $targets.Add($target)) { throw "Doppelter ZIP-Zielpfad: $name" }
        }

        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            $target = [IO.Path]::GetFullPath((Join-Path $destinationFull $name))
            if ([string]::IsNullOrEmpty($entry.Name)) {
                New-Item -ItemType Directory -Path $target -Force | Out-Null
                continue
            }
            $parent = Split-Path -Parent $target
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }
            $input = $entry.Open()
            $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $input.CopyTo($output) }
            finally { $output.Dispose(); $input.Dispose() }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Get-RelativeSovereignPath {
    param([string]$BasePath, [string]$ChildPath)
    $baseUri = New-Object Uri(([IO.Path]::GetFullPath($BasePath).TrimEnd('\') + '\'))
    $childUri = New-Object Uri([IO.Path]::GetFullPath($ChildPath))
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($childUri).ToString()).Replace('/', '\')
}

function Install-SovereignModulePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('php','mariadb')][string]$Module,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )

    Initialize-SovereignStackLayout
    if (-not (Test-SovereignVersion $Version)) { throw "Ungueltige Modulversion: $Version" }
    $hash = Assert-SovereignSha256 -PackagePath $PackagePath -ExpectedSha256 $ExpectedSha256
    $moduleRoot = Join-Path $script:ModulesRoot $Module
    $finalPath = Join-Path $moduleRoot $Version
    if (Test-Path -LiteralPath $finalPath) { throw "Modulversion ist bereits installiert: $Module $Version" }

    $stage = Join-Path $script:StagingRoot ([Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        Expand-SovereignZipSafely -ArchivePath $PackagePath -Destination $stage
        if ($Module -eq 'php') {
            $entryCandidates = @(Get-ChildItem -LiteralPath $stage -Filter 'php-cgi.exe' -File -Recurse)
            if ($entryCandidates.Count -ne 1) { throw 'PHP-Paket muss genau eine php-cgi.exe enthalten.' }
            $entryPoint = $entryCandidates[0]
            $payloadRoot = $entryPoint.Directory.FullName
        }
        else {
            $entryCandidates = @(Get-ChildItem -LiteralPath $stage -Include 'mariadbd.exe','mysqld.exe' -File -Recurse)
            if ($entryCandidates.Count -lt 1) { throw 'MariaDB-Paket enthaelt keine mariadbd.exe/mysqld.exe.' }
            $entryPoint = $entryCandidates | Sort-Object @{Expression={ if ($_.Name -ieq 'mariadbd.exe') { 0 } else { 1 } }} | Select-Object -First 1
            if ($entryPoint.Directory.Name -ine 'bin') { throw 'MariaDB-Server muss im bin-Verzeichnis liegen.' }
            $payloadRoot = Split-Path -Parent $entryPoint.Directory.FullName
            $initializer = Get-ChildItem -LiteralPath $payloadRoot -Include 'mariadb-install-db.exe','mysql_install_db.exe' -File -Recurse | Select-Object -First 1
            if ($null -eq $initializer) { throw 'MariaDB-Paket enthaelt kein Windows-Initialisierungsprogramm.' }
            Assert-WindowsX64Pe -Path $initializer.FullName
        }
        Assert-WindowsX64Pe -Path $entryPoint.FullName
        $entryHash = (Get-FileHash -LiteralPath $entryPoint.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        $criticalCandidates = @($entryPoint)
        if ($Module -eq 'php') {
            $criticalCandidates += @(Get-ChildItem -LiteralPath $payloadRoot -Filter '*.dll' -File -Recurse)
        }
        else {
            $admin = Get-ChildItem -LiteralPath $payloadRoot -Filter 'mariadb-admin.exe' -File -Recurse | Select-Object -First 1
            $client = Get-ChildItem -LiteralPath $payloadRoot -Filter 'mariadb.exe' -File -Recurse | Select-Object -First 1
            $serverLibrary = Get-ChildItem -LiteralPath $payloadRoot -Filter 'server.dll' -File -Recurse | Select-Object -First 1
            if ($null -eq $admin -or $null -eq $client -or $null -eq $serverLibrary) { throw 'Kritische MariaDB-Laufzeitdateien fehlen.' }
            Assert-WindowsX64Pe -Path $admin.FullName
            Assert-WindowsX64Pe -Path $client.FullName
            $criticalCandidates += @($initializer, $admin, $client, $serverLibrary)
        }
        $criticalFiles = @($criticalCandidates | Sort-Object FullName -Unique | ForEach-Object {
            [ordered]@{
                path = Get-RelativeSovereignPath -BasePath $stage -ChildPath $_.FullName
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
            }
        })

        $payloadSubpath = Get-RelativeSovereignPath -BasePath $stage -ChildPath $payloadRoot
        $entrySubpath = Get-RelativeSovereignPath -BasePath $stage -ChildPath $entryPoint.FullName
        if (-not (Test-Path -LiteralPath $moduleRoot -PathType Container)) {
            New-Item -ItemType Directory -Path $moduleRoot -Force | Out-Null
        }
        Move-Item -LiteralPath $stage -Destination $finalPath
        $stage = $null

        $receipt = [ordered]@{
            schemaVersion = 1
            module = $Module
            version = $Version
            platform = 'windows-x64'
            packageFile = [IO.Path]::GetFileName($PackagePath)
            packageSha256 = $hash
            installedUtc = [DateTime]::UtcNow.ToString('o')
            payloadSubpath = $payloadSubpath
            entrySubpath = $entrySubpath
            entrySha256 = $entryHash
            criticalFiles = $criticalFiles
        }
        $receiptPath = Join-Path $finalPath 'install-receipt.json'
        [IO.File]::WriteAllText($receiptPath, (($receipt | ConvertTo-Json -Depth 5) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))

        $state = Read-SovereignStackState
        $record = [pscustomobject]@{ module=$Module; version=$Version; installedUtc=$receipt.installedUtc; sha256=$hash }
        $state.installed = @($state.installed) + $record
        Write-SovereignStackState -State $state
        return $record
    }
    finally {
        if ($null -ne $stage -and (Test-Path -LiteralPath $stage -PathType Container)) {
            $stageFull = [IO.Path]::GetFullPath($stage)
            $stagingPrefix = [IO.Path]::GetFullPath($script:StagingRoot).TrimEnd('\') + '\'
            if ($stageFull.StartsWith($stagingPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                Remove-Item -LiteralPath $stageFull -Recurse -Force
            }
        }
    }
}

function Enable-SovereignModule {
    param(
        [Parameter(Mandatory)][ValidateSet('php','mariadb')][string]$Module,
        [Parameter(Mandatory)][string]$Version
    )
    if (-not (Test-SovereignVersion $Version)) { throw 'Ungueltige Modulversion.' }
    $path = Join-Path (Join-Path $script:ModulesRoot $Module) $Version
    if (-not (Test-Path -LiteralPath (Join-Path $path 'install-receipt.json') -PathType Leaf)) {
        throw 'Modulversion ist nicht vollstaendig installiert.'
    }
    $state = Read-SovereignStackState
    $state.active.$Module = $Version
    Write-SovereignStackState -State $state
}

function Disable-SovereignModule {
    param([Parameter(Mandatory)][ValidateSet('php','mariadb')][string]$Module)
    $state = Read-SovereignStackState
    $state.active.$Module = $null
    Write-SovereignStackState -State $state
}

function Get-SovereignActiveModule {
    param([Parameter(Mandatory)][ValidateSet('php','mariadb')][string]$Module)
    $state = Read-SovereignStackState
    $version = $state.active.$Module
    if ([string]::IsNullOrWhiteSpace([string]$version)) { return $null }
    if (-not (Test-SovereignVersion ([string]$version))) { throw 'Aktive Modulversion ist ungueltig.' }
    $root = Join-Path (Join-Path $script:ModulesRoot $Module) $version
    $receiptPath = Join-Path $root 'install-receipt.json'
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { throw 'Aktives Modul ist beschaedigt.' }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if ($receipt.schemaVersion -ne 1 -or $receipt.module -cne $Module -or $receipt.version -cne $version -or
        [string]$receipt.packageSha256 -notmatch '^[0-9A-Fa-f]{64}$' -or
        [string]$receipt.entrySha256 -notmatch '^[0-9A-Fa-f]{64}$' -or
        $null -eq $receipt.criticalFiles -or @($receipt.criticalFiles).Count -lt 1) {
        throw 'Installationsbeleg des aktiven Moduls ist ungueltig.'
    }
    $rootFull = [IO.Path]::GetFullPath($root).TrimEnd('\')
    $rootPrefix = $rootFull + '\'
    $payloadRoot = [IO.Path]::GetFullPath((Join-Path $rootFull ([string]$receipt.payloadSubpath)))
    $entryPoint = [IO.Path]::GetFullPath((Join-Path $rootFull ([string]$receipt.entrySubpath)))
    if ((-not $payloadRoot.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -and $payloadRoot -ine $rootFull) -or
        -not $entryPoint.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $payloadRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) {
        throw 'Installationsbeleg verweist ausserhalb des Modulverzeichnisses oder auf fehlende Dateien.'
    }
    $entryHash = (Get-FileHash -LiteralPath $entryPoint -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($entryHash -cne ([string]$receipt.entrySha256).ToUpperInvariant()) {
        throw 'Aktiver Moduleinstieg wurde seit der Installation veraendert.'
    }
    foreach ($critical in @($receipt.criticalFiles)) {
        if ([string]$critical.path -eq '' -or [string]$critical.sha256 -notmatch '^[0-9A-Fa-f]{64}$') {
            throw 'Kritische Dateiliste im Installationsbeleg ist ungueltig.'
        }
        $criticalPath = [IO.Path]::GetFullPath((Join-Path $rootFull ([string]$critical.path)))
        if (-not $criticalPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $criticalPath -PathType Leaf)) {
            throw 'Kritische Moduldatei fehlt oder verlaesst den Versionsordner.'
        }
        $criticalHash = (Get-FileHash -LiteralPath $criticalPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($criticalHash -cne ([string]$critical.sha256).ToUpperInvariant()) {
            throw "Kritische Moduldatei wurde veraendert: $criticalPath"
        }
    }
    Assert-WindowsX64Pe -Path $entryPoint
    return [pscustomobject]@{
        Module = $Module
        Version = $version
        Root = $root
        PayloadRoot = $payloadRoot
        EntryPoint = $entryPoint
        Sha256 = $receipt.packageSha256
    }
}

function Initialize-SovereignDpapi {
    if ($null -ne ('System.Security.Cryptography.ProtectedData' -as [type])) { return }
    $loadErrors = @()
    foreach ($assembly in @('System.Security.Cryptography.ProtectedData','System.Security')) {
        try {
            Add-Type -AssemblyName $assembly -ErrorAction Stop
            if ($null -ne ('System.Security.Cryptography.ProtectedData' -as [type])) { return }
        }
        catch { $loadErrors += $_.Exception.Message }
    }
    throw "Windows-DPAPI konnte nicht geladen werden: $($loadErrors -join ' | ')"
}

function Protect-SovereignSecret {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    if ($Name -notmatch '^[a-z0-9-]{1,64}$') { throw 'Ungueltiger Secret-Name.' }
    Initialize-SovereignDpapi
    Initialize-SovereignStackLayout
    $plain = [Text.Encoding]::UTF8.GetBytes($Value)
    $entropy = [Text.Encoding]::UTF8.GetBytes('SovereignStack/v1/' + $Name)
    try {
        $protected = [System.Security.Cryptography.ProtectedData]::Protect(
            $plain, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $path = Join-Path $script:SecretsRoot ($Name + '.dpapi')
        [IO.File]::WriteAllText($path, [Convert]::ToBase64String($protected), (New-Object Text.UTF8Encoding($false)))
    }
    finally {
        [Array]::Clear($plain, 0, $plain.Length)
        [Array]::Clear($entropy, 0, $entropy.Length)
    }
}

function Unprotect-SovereignSecret {
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^[a-z0-9-]{1,64}$') { throw 'Ungueltiger Secret-Name.' }
    Initialize-SovereignDpapi
    $path = Join-Path $script:SecretsRoot ($Name + '.dpapi')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Secret fehlt: $Name" }
    $protected = [Convert]::FromBase64String((Get-Content -LiteralPath $path -Raw).Trim())
    $entropy = [Text.Encoding]::UTF8.GetBytes('SovereignStack/v1/' + $Name)
    try {
        $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $protected, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        try { return [Text.Encoding]::UTF8.GetString($plain) }
        finally { [Array]::Clear($plain, 0, $plain.Length) }
    }
    finally {
        [Array]::Clear($protected, 0, $protected.Length)
        [Array]::Clear($entropy, 0, $entropy.Length)
    }
}

function New-SovereignRandomSecret {
    param([ValidateRange(32,128)][int]$Bytes = 48)
    $buffer = New-Object byte[] $Bytes
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
        return [Convert]::ToBase64String($buffer)
    }
    finally {
        $rng.Dispose()
        [Array]::Clear($buffer, 0, $buffer.Length)
    }
}

function Set-SovereignServiceState {
    param([Parameter(Mandatory)][string]$Name, $Value)
    $state = Read-SovereignStackState
    $state.services | Add-Member -MemberType NoteProperty -Name $Name -Value $Value -Force
    Write-SovereignStackState -State $state
}

function Get-SovereignServiceStatus {
    $state = Read-SovereignStackState
    $result = @()
    foreach ($name in @('server','mariadb')) {
        $property = $state.services.PSObject.Properties[$name]
        $record = if ($null -eq $property) { $null } else { $property.Value }
        $running = $false
        $pidValue = $null
        if ($null -ne $record -and $null -ne $record.pid) {
            $pidValue = [int]$record.pid
            $process = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
            if ($null -ne $process) {
                try {
                    $running = [IO.Path]::GetFullPath($process.Path) -ieq [IO.Path]::GetFullPath([string]$record.executable)
                }
                catch { $running = $false }
            }
        }
        $result += [pscustomobject]@{ Service=$name; Running=$running; ProcessId=$pidValue }
    }
    return $result
}

function Initialize-SovereignMariaDb {
    [CmdletBinding()]
    param()

    $Port = $script:MariaDbPort

    Initialize-SovereignStackLayout
    $module = Get-SovereignActiveModule -Module mariadb
    if ($null -eq $module) { throw 'MariaDB ist nicht aktiviert.' }
    $dataDirectory = Join-Path $script:DataRoot 'mariadb'
    if (Test-Path -LiteralPath $dataDirectory -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $dataDirectory -Force).Count -gt 0) {
            throw 'MariaDB-Datenverzeichnis ist bereits initialisiert oder nicht leer.'
        }
    }
    else {
        New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
    }

    $initializer = Get-ChildItem -LiteralPath $module.PayloadRoot -Include 'mariadb-install-db.exe','mysql_install_db.exe' -File -Recurse |
        Sort-Object @{Expression={ if ($_.Name -ieq 'mariadb-install-db.exe') { 0 } else { 1 } }} |
        Select-Object -First 1
    if ($null -eq $initializer) { throw 'MariaDB-Initialisierungsprogramm fehlt.' }
    Assert-WindowsX64Pe -Path $initializer.FullName

    $rootPassword = New-SovereignRandomSecret -Bytes 48
    $configPath = Join-Path $script:StackRoot 'mariadb\my.ini'
    $stdout = Join-Path $script:RuntimeRoot 'logs\mariadb-init.stdout.log'
    $stderr = Join-Path $script:RuntimeRoot 'logs\mariadb-init.stderr.log'
    $arguments = @(
        "--datadir=$dataDirectory",
        "--password=$rootPassword",
        "--port=$Port",
        "--config=$configPath"
    )
    $process = Start-Process -FilePath $initializer.FullName -ArgumentList $arguments `
        -WorkingDirectory $module.PayloadRoot -PassThru -Wait -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if ($process.ExitCode -ne 0) {
        throw "MariaDB-Initialisierung fehlgeschlagen (Exit $($process.ExitCode)). Daten wurden nicht automatisch geloescht."
    }
    Protect-SovereignSecret -Name 'mariadb-root-password' -Value $rootPassword
    return [pscustomobject]@{ Port=$Port; RootPassword=$rootPassword; DataDirectory=$dataDirectory }
}

function Start-SovereignMariaDb {
    Initialize-SovereignStackLayout
    $existing = Get-SovereignServiceStatus | Where-Object Service -eq 'mariadb'
    if ($existing.Running) { throw 'MariaDB laeuft bereits.' }
    $module = Get-SovereignActiveModule -Module mariadb
    if ($null -eq $module) { throw 'MariaDB ist nicht aktiviert.' }
    $dataDirectory = Join-Path $script:DataRoot 'mariadb'
    if (-not (Test-Path -LiteralPath (Join-Path $dataDirectory 'mysql') -PathType Container)) {
        throw 'MariaDB wurde noch nicht initialisiert.'
    }
    Assert-WindowsX64Pe -Path $module.EntryPoint
    $configPath = Join-Path $script:StackRoot 'mariadb\my.ini'
    $stdout = Join-Path $script:RuntimeRoot 'logs\mariadb.stdout.log'
    $stderr = Join-Path $script:RuntimeRoot 'logs\mariadb.stderr.log'
    $client = Get-ChildItem -LiteralPath $module.PayloadRoot -Filter 'mariadb.exe' -File -Recurse |
        Select-Object -First 1
    if ($null -eq $client) { throw 'mariadb.exe fuer den authentisierten Bereitschaftstest fehlt.' }
    Assert-WindowsX64Pe -Path $client.FullName
    $occupied = @([Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() |
        Where-Object Port -eq $script:MariaDbPort)
    if ($occupied.Count -gt 0) {
        throw "MariaDB-Port $script:MariaDbPort ist bereits durch einen anderen Prozess belegt: $($occupied -join ', ')"
    }
    $rootPassword = Unprotect-SovereignSecret -Name 'mariadb-root-password'
    $oldPassword = [Environment]::GetEnvironmentVariable('MYSQL_PWD', 'Process')
    $readinessSql = Join-Path $script:RuntimeRoot 'tmp\mariadb-readiness.sql'
    [IO.File]::WriteAllText($readinessSql, 'SELECT 1;', (New-Object Text.UTF8Encoding($false)))
    $process = Start-Process -FilePath $module.EntryPoint -ArgumentList @(
        "--defaults-file=$configPath",'--bind-address=127.0.0.1',"--port=$script:MariaDbPort",'--skip-name-resolve','--local-infile=0','--console'
    ) `
        -WorkingDirectory (Split-Path -Parent $module.EntryPoint) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $ready = $false
    try {
        [Environment]::SetEnvironmentVariable('MYSQL_PWD', $rootPassword, 'Process')
        $pingOut = Join-Path $script:RuntimeRoot 'logs\mariadb-readiness.stdout.log'
        $pingErr = Join-Path $script:RuntimeRoot 'logs\mariadb-readiness.stderr.log'
        for ($attempt = 0; $attempt -lt 75; $attempt++) {
            if ($process.HasExited) { throw "MariaDB beendete sich vorzeitig (Exit $($process.ExitCode))." }
            $ping = Start-Process -FilePath $client.FullName -ArgumentList @(
                '--protocol=tcp','--host=127.0.0.1',"--port=$script:MariaDbPort",'--user=root','--connect-timeout=1','--batch','--skip-column-names'
            ) -WorkingDirectory $module.PayloadRoot -PassThru -Wait -WindowStyle Hidden `
              -RedirectStandardInput $readinessSql -RedirectStandardOutput $pingOut -RedirectStandardError $pingErr
            if ($ping.ExitCode -eq 0) {
                $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $script:MariaDbPort -ErrorAction SilentlyContinue)
                $foreign = @($listeners | Where-Object {
                    $_.OwningProcess -ne $process.Id -or -not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($_.LocalAddress))
                })
                if ($listeners.Count -lt 1 -or $foreign.Count -gt 0) {
                    throw 'MariaDB-Bereitschaftstest erreichte nicht ausschliesslich den gerade gestarteten Loopback-Prozess.'
                }
                $ready = $true
                break
            }
            Start-Sleep -Milliseconds 200
        }
    }
    catch {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
        throw
    }
    finally {
        [Environment]::SetEnvironmentVariable('MYSQL_PWD', $oldPassword, 'Process')
        $rootPassword = $null
        if (Test-Path -LiteralPath $readinessSql -PathType Leaf) { Remove-Item -LiteralPath $readinessSql -Force }
    }
    if (-not $ready) {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
        throw 'MariaDB wurde nicht innerhalb von 15 Sekunden verbindungsbereit.'
    }
    Set-SovereignServiceState -Name 'mariadb' -Value ([pscustomobject]@{
        pid=$process.Id; executable=$module.EntryPoint; startedUtc=[DateTime]::UtcNow.ToString('o'); port=$script:MariaDbPort
    })
    return $process
}

function New-SovereignCmsDatabase {
    Initialize-SovereignStackLayout
    $status = Get-SovereignServiceStatus | Where-Object Service -eq 'mariadb'
    if (-not $status.Running) { throw 'MariaDB muss zuerst gestartet werden.' }
    $module = Get-SovereignActiveModule -Module mariadb
    if ($null -eq $module) { throw 'MariaDB ist nicht aktiviert.' }
    $client = Get-ChildItem -LiteralPath $module.PayloadRoot -Filter 'mariadb.exe' -File -Recurse | Select-Object -First 1
    if ($null -eq $client) { throw 'MariaDB-Client fehlt.' }
    Assert-WindowsX64Pe -Path $client.FullName

    $databaseName = 'sovereign_cms'
    $userName = 'sovereign_cms'
    $cmsPassword = New-SovereignRandomSecret -Bytes 48
    $rootPassword = Unprotect-SovereignSecret -Name 'mariadb-root-password'
    $sqlPath = Join-Path (Join-Path $script:RuntimeRoot 'tmp') ('cms-database-' + [Guid]::NewGuid().ToString('N') + '.sql')
    $sql = @"
CREATE DATABASE IF NOT EXISTS ``$databaseName`` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$userName'@'127.0.0.1' IDENTIFIED BY '$cmsPassword';
ALTER USER '$userName'@'127.0.0.1' IDENTIFIED BY '$cmsPassword';
GRANT ALL PRIVILEGES ON ``$databaseName``.* TO '$userName'@'127.0.0.1';
FLUSH PRIVILEGES;
"@
    $oldRootPassword = [Environment]::GetEnvironmentVariable('MYSQL_PWD', 'Process')
    try {
        [IO.File]::WriteAllText($sqlPath, $sql, (New-Object Text.UTF8Encoding($false)))
        [Environment]::SetEnvironmentVariable('MYSQL_PWD', $rootPassword, 'Process')
        $stdout = Join-Path $script:RuntimeRoot 'logs\cms-database.stdout.log'
        $stderr = Join-Path $script:RuntimeRoot 'logs\cms-database.stderr.log'
        $process = Start-Process -FilePath $client.FullName -ArgumentList @(
            '--protocol=tcp','--host=127.0.0.1',"--port=$script:MariaDbPort",'--user=root','--batch','--skip-column-names'
        ) -WorkingDirectory $module.PayloadRoot -RedirectStandardInput $sqlPath `
          -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -Wait -WindowStyle Hidden
        if ($process.ExitCode -ne 0) { throw "CMS-Datenbank konnte nicht angelegt werden (Exit $($process.ExitCode))." }
        Protect-SovereignSecret -Name 'cms-database-password' -Value $cmsPassword
        return [pscustomobject]@{
            Host='127.0.0.1'; Port=$script:MariaDbPort; Database=$databaseName; User=$userName; Password=$cmsPassword
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable('MYSQL_PWD', $oldRootPassword, 'Process')
        $rootPassword = $null
        $cmsPassword = $null
        $sql = $null
        if (Test-Path -LiteralPath $sqlPath -PathType Leaf) { Remove-Item -LiteralPath $sqlPath -Force }
    }
}

function Stop-SovereignManagedService {
    param([Parameter(Mandatory)][ValidateSet('server','mariadb')][string]$Service)
    $state = Read-SovereignStackState
    $property = $state.services.PSObject.Properties[$Service]
    $record = if ($null -eq $property) { $null } else { $property.Value }
    if ($null -eq $record -or $null -eq $record.pid) { return $false }
    $process = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        Set-SovereignServiceState -Name $Service -Value $null
        return $false
    }
    $actualPath = $null
    try { $actualPath = [IO.Path]::GetFullPath($process.Path) } catch { throw 'Prozesspfad konnte nicht verifiziert werden.' }
    $expectedPath = [IO.Path]::GetFullPath([string]$record.executable)
    if ($actualPath -ine $expectedPath) { throw 'PID wurde wiederverwendet; fremder Prozess wird nicht beendet.' }
    if ($Service -eq 'mariadb') {
        $module = Get-SovereignActiveModule -Module mariadb
        if ($null -eq $module) { throw 'MariaDB-Modul ist nicht mehr aktiviert; geordnetes Herunterfahren nicht moeglich.' }
        $admin = Get-ChildItem -LiteralPath $module.PayloadRoot -Filter 'mariadb-admin.exe' -File -Recurse |
            Select-Object -First 1
        if ($null -eq $admin) { throw 'mariadb-admin.exe fuer geordnetes Herunterfahren fehlt.' }
        Assert-WindowsX64Pe -Path $admin.FullName
        $password = Unprotect-SovereignSecret -Name 'mariadb-root-password'
        $oldPassword = [Environment]::GetEnvironmentVariable('MYSQL_PWD', 'Process')
        $portProperty = $record.PSObject.Properties['port']
        $port = if ($null -ne $portProperty) { [int]$portProperty.Value } else { $script:MariaDbPort }
        try {
            [Environment]::SetEnvironmentVariable('MYSQL_PWD', $password, 'Process')
            $stdout = Join-Path $script:RuntimeRoot 'logs\mariadb-shutdown.stdout.log'
            $stderr = Join-Path $script:RuntimeRoot 'logs\mariadb-shutdown.stderr.log'
            $shutdown = Start-Process -FilePath $admin.FullName -ArgumentList @(
                '--protocol=tcp','--host=127.0.0.1',"--port=$port",'--user=root','shutdown'
            ) -WorkingDirectory $module.PayloadRoot -PassThru -Wait -WindowStyle Hidden `
              -RedirectStandardOutput $stdout -RedirectStandardError $stderr
            if ($shutdown.ExitCode -ne 0) {
                throw "Geordnetes MariaDB-Herunterfahren fehlgeschlagen (Exit $($shutdown.ExitCode)); der Server wurde nicht hart beendet."
            }
        }
        finally {
            [Environment]::SetEnvironmentVariable('MYSQL_PWD', $oldPassword, 'Process')
            $password = $null
        }
    }
    else {
        Stop-Process -Id $process.Id
    }
    if (-not $process.WaitForExit(10000)) {
        if ($Service -ne 'server') { throw 'Dienst reagierte nicht innerhalb von zehn Sekunden.' }
        $current = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
        if ($null -ne $current) {
            $currentPath = $null
            try { $currentPath = [IO.Path]::GetFullPath($current.Path) }
            catch { throw 'Serverprozesspfad konnte vor dem erzwungenen Beenden nicht verifiziert werden.' }
            if ($currentPath -ine $expectedPath) { throw 'PID wurde vor dem erzwungenen Beenden wiederverwendet.' }
            Stop-Process -Id $current.Id -Force
            if (-not $current.WaitForExit(5000)) { throw 'Serverprozess liess sich auch erzwungen nicht beenden.' }
        }
    }
    Set-SovereignServiceState -Name $Service -Value $null
    return $true
}

function Start-SovereignKrServer {
    [CmdletBinding()]
    param(
        [ValidateRange(1,65535)][int]$Port = 8085,
        [ValidateRange(1,256)][int]$Workers = 8
    )

    Initialize-SovereignStackLayout
    $existing = Get-SovereignServiceStatus | Where-Object Service -eq 'server'
    if ($existing.Running) { throw 'KR-Server laeuft bereits.' }
    $exe = Get-ChildItem -LiteralPath (Join-Path $script:ProjectRoot 'KR_BUILD') -Filter 'kr-sovereign-server-*.exe' -File |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($null -eq $exe) { throw 'Keine gebaute KR-Server-EXE gefunden.' }
    $newestSource = Get-ChildItem -LiteralPath $script:ProjectRoot -Filter '*.kr' -File -Recurse |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($null -ne $newestSource -and $exe.LastWriteTimeUtc -lt $newestSource.LastWriteTimeUtc) {
        throw 'Die KR-Server-EXE ist aelter als der Quellcode und muss neu gebaut werden.'
    }

    foreach ($secretName in @('jwt-secret','bootstrap-token')) {
        $secretPath = Join-Path $script:SecretsRoot ($secretName + '.dpapi')
        if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) {
            Protect-SovereignSecret -Name $secretName -Value (New-SovereignRandomSecret -Bytes 48)
        }
    }
    $jwtSecret = Unprotect-SovereignSecret -Name 'jwt-secret'
    $bootstrapToken = Unprotect-SovereignSecret -Name 'bootstrap-token'
    if ($jwtSecret -ceq $bootstrapToken) { throw 'JWT- und Bootstrap-Secret duerfen nicht identisch sein.' }

    $oldJwt = [Environment]::GetEnvironmentVariable('SOVEREIGN_JWT_SECRET','Process')
    $oldBootstrap = [Environment]::GetEnvironmentVariable('SOVEREIGN_BOOTSTRAP_TOKEN','Process')
    $oldStack = [Environment]::GetEnvironmentVariable('SOVEREIGN_STACK_ROOT','Process')
    $phpModule = Get-SovereignActiveModule -Module php
    $cmsPasswordPath = Join-Path $script:SecretsRoot 'cms-database-password.dpapi'
    $cmsDatabasePassword = if ($null -ne $phpModule -and (Test-Path -LiteralPath $cmsPasswordPath -PathType Leaf)) {
        Unprotect-SovereignSecret -Name 'cms-database-password'
    } else { $null }
    $phpEnvironment = [ordered]@{
        SOVEREIGN_PHP_ENABLED = if ($null -eq $phpModule) { '0' } else { '1' }
        SOVEREIGN_PHP_CGI = if ($null -eq $phpModule) { $null } else { $phpModule.EntryPoint }
        SOVEREIGN_DOCUMENT_ROOT = if ($null -eq $phpModule) { $null } else { $script:WebRoot }
        SOVEREIGN_PHP_INI = if ($null -eq $phpModule) { $null } else { Join-Path $phpModule.PayloadRoot 'php.ini' }
        SOVEREIGN_RUNTIME_TEMP = if ($null -eq $phpModule) { $null } else { Join-Path $script:RuntimeRoot 'tmp' }
        SOVEREIGN_PHP_CGI_LOG = if ($null -eq $phpModule) { $null } else { Join-Path $script:RuntimeRoot 'logs\php-cgi.log' }
        SOVEREIGN_PHP_MAX_PROCESSES = if ($null -eq $phpModule) { $null } else { [string][Math]::Min(8, $Workers) }
        SOVEREIGN_CMS_DB_HOST = if ($null -eq $phpModule -or $null -eq $cmsDatabasePassword) { $null } else { '127.0.0.1' }
        SOVEREIGN_CMS_DB_PORT = if ($null -eq $phpModule -or $null -eq $cmsDatabasePassword) { $null } else { [string]$script:MariaDbPort }
        SOVEREIGN_CMS_DB_NAME = if ($null -eq $phpModule -or $null -eq $cmsDatabasePassword) { $null } else { 'sovereign_cms' }
        SOVEREIGN_CMS_DB_USER = if ($null -eq $phpModule -or $null -eq $cmsDatabasePassword) { $null } else { 'sovereign_cms' }
        SOVEREIGN_CMS_DB_PASSWORD = if ($null -eq $phpModule) { $null } else { $cmsDatabasePassword }
        SOVEREIGN_SERVER_PORT = [string]$Port
        TEMP = Join-Path $script:RuntimeRoot 'tmp'
        TMP = Join-Path $script:RuntimeRoot 'tmp'
    }
    if ($null -ne $phpModule -and -not (Test-Path -LiteralPath $phpEnvironment.SOVEREIGN_PHP_INI -PathType Leaf)) {
        throw 'php.ini fehlt im aktiven PHP-Modul.'
    }
    $oldPhpEnvironment = @{}
    foreach ($name in $phpEnvironment.Keys) {
        $oldPhpEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    try {
        [Environment]::SetEnvironmentVariable('SOVEREIGN_JWT_SECRET',$jwtSecret,'Process')
        [Environment]::SetEnvironmentVariable('SOVEREIGN_BOOTSTRAP_TOKEN',$bootstrapToken,'Process')
        [Environment]::SetEnvironmentVariable('SOVEREIGN_STACK_ROOT',$script:StackRoot,'Process')
        foreach ($name in $phpEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $phpEnvironment[$name], 'Process')
        }
        $stdout = Join-Path $script:RuntimeRoot 'logs\server.stdout.log'
        $stderr = Join-Path $script:RuntimeRoot 'logs\server.stderr.log'
        $process = Start-Process -FilePath $exe.FullName -ArgumentList @('--host','127.0.0.1','--port',"$Port",'--workers',"$Workers") `
            -WorkingDirectory $script:ProjectRoot -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    }
    finally {
        [Environment]::SetEnvironmentVariable('SOVEREIGN_JWT_SECRET',$oldJwt,'Process')
        [Environment]::SetEnvironmentVariable('SOVEREIGN_BOOTSTRAP_TOKEN',$oldBootstrap,'Process')
        [Environment]::SetEnvironmentVariable('SOVEREIGN_STACK_ROOT',$oldStack,'Process')
        foreach ($name in $oldPhpEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $oldPhpEnvironment[$name], 'Process')
        }
        $jwtSecret = $null
        $cmsDatabasePassword = $null
    }
    Start-Sleep -Milliseconds 500
    if ($process.HasExited) { throw "KR-Server beendete sich sofort (Exit $($process.ExitCode))." }
    Set-SovereignServiceState -Name 'server' -Value ([pscustomobject]@{
        pid=$process.Id; executable=$exe.FullName; startedUtc=[DateTime]::UtcNow.ToString('o'); port=$Port
    })
    return [pscustomobject]@{ Process=$process; BootstrapToken=$bootstrapToken; Url="http://127.0.0.1:$Port/" }
}

function Get-SovereignBootstrapToken {
    $path = Join-Path $script:SecretsRoot 'bootstrap-token.dpapi'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Protect-SovereignSecret -Name 'bootstrap-token' -Value (New-SovereignRandomSecret -Bytes 48)
    }
    return Unprotect-SovereignSecret -Name 'bootstrap-token'
}

Export-ModuleMember -Function @(
    'Initialize-SovereignStackLayout',
    'Read-SovereignStackState',
    'Install-SovereignModulePackage',
    'Enable-SovereignModule',
    'Disable-SovereignModule',
    'Get-SovereignActiveModule',
    'Protect-SovereignSecret',
    'Unprotect-SovereignSecret',
    'New-SovereignRandomSecret',
    'Get-SovereignServiceStatus',
    'Initialize-SovereignMariaDb',
    'Start-SovereignMariaDb',
    'New-SovereignCmsDatabase',
    'Stop-SovereignManagedService',
    'Start-SovereignKrServer',
    'Get-SovereignBootstrapToken'
)
