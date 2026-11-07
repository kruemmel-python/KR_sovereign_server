[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = $PSScriptRoot
$stackRoot = Join-Path $projectRoot 'stack'
$runtimeRoot = Join-Path $stackRoot 'runtime'
$taskTemp = Join-Path $runtimeRoot 'tmp'
New-Item -ItemType Directory -Path $taskTemp -Force | Out-Null
$env:TEMP = $taskTemp
$env:TMP = $taskTemp

Import-Module (Join-Path $stackRoot 'SovereignStack.psm1') -Force
Initialize-SovereignStackLayout

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Sovereign Stack Control Center" Height="720" Width="1040"
        MinHeight="620" MinWidth="900" WindowStartupLocation="CenterScreen"
        Background="#0f172a" Foreground="#e2e8f0">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Margin" Value="4"/><Setter Property="Padding" Value="12,7"/>
      <Setter Property="Background" Value="#0369a1"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderBrush" Value="#38bdf8"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Margin" Value="4"/><Setter Property="Padding" Value="6"/>
      <Setter Property="Background" Value="#1e293b"/><Setter Property="Foreground" Value="#f8fafc"/>
      <Setter Property="BorderBrush" Value="#475569"/>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Margin" Value="4"/><Setter Property="Padding" Value="6"/>
    </Style>
    <Style TargetType="GroupBox">
      <Setter Property="Margin" Value="8"/><Setter Property="Padding" Value="8"/>
      <Setter Property="BorderBrush" Value="#334155"/><Setter Property="Foreground" Value="#cbd5e1"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#334155"/><Setter Property="Foreground" Value="#f8fafc"/>
      <Setter Property="BorderBrush" Value="#475569"/><Setter Property="Padding" Value="7,5"/>
    </Style>
    <Style TargetType="DataGridRow">
      <Setter Property="Background" Value="#1e293b"/><Setter Property="Foreground" Value="#f8fafc"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="Background" Value="Transparent"/><Setter Property="Foreground" Value="#f8fafc"/>
      <Setter Property="BorderBrush" Value="#334155"/><Setter Property="Padding" Value="6,3"/>
    </Style>
  </Window.Resources>
  <Grid Margin="12">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <StackPanel Grid.Row="0" Margin="6">
      <TextBlock Text="Sovereign Stack Control Center" FontSize="27" FontWeight="Bold" Foreground="#38bdf8"/>
      <TextBlock Text="Lokale, modulare Verwaltung fuer KR Server, PHP und MariaDB" Foreground="#94a3b8"/>
    </StackPanel>
    <TabControl Grid.Row="1" Margin="4" Background="#111827" Foreground="#e2e8f0">
      <TabItem Header="Uebersicht">
        <Grid Margin="12">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <GroupBox Header="KR Server" Grid.Row="0">
            <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
              <StackPanel><TextBlock x:Name="ServerStatus" FontSize="16"/><TextBlock x:Name="ServerUrl" Foreground="#94a3b8"/></StackPanel>
              <WrapPanel Grid.Column="1">
                <Button x:Name="StartServer" Content="Server starten"/>
                <Button x:Name="StopServer" Content="Server stoppen" Background="#9f1239"/>
                <Button x:Name="OpenBrowser" Content="Im Browser oeffnen"/>
                <Button x:Name="ShowToken" Content="Bootstrap-Token anzeigen"/>
              </WrapPanel>
            </Grid>
          </GroupBox>
          <GroupBox Header="MariaDB" Grid.Row="1">
            <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
              <StackPanel><TextBlock x:Name="DatabaseStatus" FontSize="16"/><TextBlock Text="Loopback 127.0.0.1:3308" Foreground="#94a3b8"/></StackPanel>
              <WrapPanel Grid.Column="1">
                <Button x:Name="InitDatabase" Content="Datenbank initialisieren"/>
                <Button x:Name="StartDatabase" Content="MariaDB starten"/>
                <Button x:Name="CreateCmsDatabase" Content="CMS-Datenbank anlegen"/>
                <Button x:Name="StopDatabase" Content="MariaDB stoppen" Background="#9f1239"/>
              </WrapPanel>
            </Grid>
          </GroupBox>
          <GroupBox Header="Installierte Module" Grid.Row="2">
            <DataGrid x:Name="ModuleGrid" AutoGenerateColumns="False" IsReadOnly="True"
                      Background="#1e293b" Foreground="#f8fafc" RowBackground="#1e293b"
                      AlternatingRowBackground="#172033" GridLinesVisibility="Horizontal"
                      HorizontalGridLinesBrush="#334155" AlternationCount="2">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Modul" Binding="{Binding module}" Width="*"/>
                <DataGridTextColumn Header="Version" Binding="{Binding version}" Width="*"/>
                <DataGridTextColumn Header="Aktiv" Binding="{Binding active}" Width="100"/>
                <DataGridTextColumn Header="SHA-256" Binding="{Binding sha256}" Width="3*"/>
              </DataGrid.Columns>
            </DataGrid>
          </GroupBox>
        </Grid>
      </TabItem>
      <TabItem Header="Modul installieren">
        <Grid Margin="18">
          <Grid.ColumnDefinitions><ColumnDefinition Width="180"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Text="Modultyp" VerticalAlignment="Center"/><ComboBox x:Name="InstallModule" Grid.Row="0" Grid.Column="1"><ComboBoxItem Content="php" IsSelected="True"/><ComboBoxItem Content="mariadb"/></ComboBox>
          <TextBlock Grid.Row="1" Text="Version" VerticalAlignment="Center"/><TextBox x:Name="InstallVersion" Grid.Row="1" Grid.Column="1"/>
          <TextBlock Grid.Row="2" Text="ZIP-Paket" VerticalAlignment="Center"/><TextBox x:Name="InstallPackage" Grid.Row="2" Grid.Column="1"/><Button x:Name="BrowsePackage" Grid.Row="2" Grid.Column="2" Content="Durchsuchen"/>
          <TextBlock Grid.Row="3" Text="Erwarteter SHA-256" VerticalAlignment="Center"/><TextBox x:Name="InstallHash" Grid.Row="3" Grid.Column="1"/>
          <WrapPanel Grid.Row="4" Grid.Column="1"><Button x:Name="InstallPackageButton" Content="Pruefen und installieren"/><Button x:Name="EnablePackageButton" Content="Version aktivieren"/><Button x:Name="DisablePackageButton" Content="Modul deaktivieren" Background="#9f1239"/></WrapPanel>
          <TextBlock Grid.Row="5" Grid.ColumnSpan="3" Margin="4,20" TextWrapping="Wrap" Foreground="#94a3b8"
                     Text="Nur Windows-x64-ZIP-Pakete aus vertrauenswuerdiger Quelle verwenden. Der SHA-256-Wert ist Pflicht. Archive werden vor dem Entpacken auf Pfadmanipulation, Groessenlimits und gueltige x64-Einstiegspunkte geprueft."/>
        </Grid>
      </TabItem>
      <TabItem Header="Logs">
        <Grid Margin="12"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <WrapPanel><ComboBox x:Name="LogSelector" Width="300"/><Button x:Name="RefreshLog" Content="Log aktualisieren"/></WrapPanel>
          <TextBox x:Name="LogText" Grid.Row="1" FontFamily="Consolas" IsReadOnly="True" AcceptsReturn="True" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
        </Grid>
      </TabItem>
    </TabControl>
    <DockPanel Grid.Row="2" Margin="6"><TextBlock x:Name="FooterStatus" Text="Bereit" Foreground="#94a3b8"/><Button x:Name="RefreshAll" Content="Status aktualisieren" DockPanel.Dock="Right"/></DockPanel>
  </Grid>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

function Get-Control([string]$Name) { return $window.FindName($Name) }
$serverStatus = Get-Control 'ServerStatus'
$serverUrl = Get-Control 'ServerUrl'
$databaseStatus = Get-Control 'DatabaseStatus'
$moduleGrid = Get-Control 'ModuleGrid'
$footerStatus = Get-Control 'FooterStatus'
$logSelector = Get-Control 'LogSelector'
$logText = Get-Control 'LogText'

function Write-UiStatus([string]$Message) {
    $footerStatus.Text = $Message
}

function Invoke-UiAction([scriptblock]$Action) {
    try {
        $window.Cursor = [Windows.Input.Cursors]::Wait
        & $Action
    }
    catch {
        [Windows.MessageBox]::Show($_.Exception.Message, 'Sovereign Stack', 'OK', 'Error') | Out-Null
        Write-UiStatus ('Fehler: ' + $_.Exception.Message)
    }
    finally {
        $window.Cursor = [Windows.Input.Cursors]::Arrow
    }
}

function Refresh-StackView {
    $state = Read-SovereignStackState
    $services = @(Get-SovereignServiceStatus)
    $server = $services | Where-Object Service -eq 'server'
    $database = $services | Where-Object Service -eq 'mariadb'
    $serverStatus.Text = if ($server.Running) { "Laeuft (PID $($server.ProcessId))" } else { 'Gestoppt' }
    $serverStatus.Foreground = if ($server.Running) { '#4ade80' } else { '#f87171' }
    $serverProperty = $state.services.PSObject.Properties['server']
    $serverPort = if ($null -ne $serverProperty -and $null -ne $serverProperty.Value -and
        $null -ne $serverProperty.Value.port) { $serverProperty.Value.port } else { 8085 }
    $serverUrl.Text = "http://127.0.0.1:$serverPort/"
    $databaseStatus.Text = if ($database.Running) { "Laeuft (PID $($database.ProcessId))" } else { 'Gestoppt' }
    $databaseStatus.Foreground = if ($database.Running) { '#4ade80' } else { '#f87171' }
    $rows = foreach ($item in @($state.installed)) {
        [pscustomobject]@{ module=$item.module; version=$item.version; active=($state.active.($item.module) -eq $item.version); sha256=$item.sha256 }
    }
    $moduleGrid.ItemsSource = @($rows)
    $logSelector.Items.Clear()
    $logDirectory = Join-Path $runtimeRoot 'logs'
    foreach ($file in @(Get-ChildItem -LiteralPath $logDirectory -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        [void]$logSelector.Items.Add($file.FullName)
    }
    if ($logSelector.Items.Count -gt 0 -and $logSelector.SelectedIndex -lt 0) { $logSelector.SelectedIndex = 0 }
    Write-UiStatus 'Status aktualisiert.'
}

(Get-Control 'RefreshAll').Add_Click({ Invoke-UiAction { Refresh-StackView } })
(Get-Control 'StartServer').Add_Click({ Invoke-UiAction {
    $result = Start-SovereignKrServer
    $script:lastBootstrapToken = $result.BootstrapToken
    Write-UiStatus "Server gestartet: $($result.Url)"
    Refresh-StackView
} })
(Get-Control 'StopServer').Add_Click({ Invoke-UiAction {
    [void](Stop-SovereignManagedService -Service server)
    Write-UiStatus 'Server gestoppt.'
    Refresh-StackView
} })
(Get-Control 'OpenBrowser').Add_Click({ Invoke-UiAction {
    Start-Process $serverUrl.Text
} })
(Get-Control 'ShowToken').Add_Click({ Invoke-UiAction {
    $token = Get-SovereignBootstrapToken
    [Windows.MessageBox]::Show("Bootstrap-Token:`n`n$token`n`nNicht in Logs oder Quellcode speichern.", 'Vertrauliches Token', 'OK', 'Warning') | Out-Null
    $token = $null
} })
(Get-Control 'InitDatabase').Add_Click({ Invoke-UiAction {
    $answer = [Windows.MessageBox]::Show('MariaDB-Datenverzeichnis jetzt initialisieren? Das Root-Passwort wird danach genau einmal angezeigt.', 'MariaDB initialisieren', 'YesNo', 'Question')
    if ($answer -eq 'Yes') {
        $result = Initialize-SovereignMariaDb
        [Windows.MessageBox]::Show("MariaDB wurde initialisiert.`n`nRoot-Passwort:`n$($result.RootPassword)`n`nJetzt sicher verwahren. Im Stack wird es nur DPAPI-geschuetzt gespeichert.", 'MariaDB bereit', 'OK', 'Warning') | Out-Null
        $result = $null
        Refresh-StackView
    }
} })
(Get-Control 'StartDatabase').Add_Click({ Invoke-UiAction {
    [void](Start-SovereignMariaDb)
    Write-UiStatus 'MariaDB gestartet.'
    Refresh-StackView
} })
(Get-Control 'CreateCmsDatabase').Add_Click({ Invoke-UiAction {
    $result = New-SovereignCmsDatabase
    [Windows.MessageBox]::Show(
        "CMS-Datenbank wurde angelegt.`n`nHost: $($result.Host)`nPort: $($result.Port)`nDatenbank: $($result.Database)`nBenutzer: $($result.User)`nPasswort: $($result.Password)`n`nDas Passwort wird im Stack nur DPAPI-geschuetzt gespeichert.",
        'CMS-Datenbank bereit', 'OK', 'Information') | Out-Null
    Write-UiStatus 'CMS-Datenbank und eingeschraenkter Benutzer sind bereit.'
} })
(Get-Control 'StopDatabase').Add_Click({ Invoke-UiAction {
    [void](Stop-SovereignManagedService -Service mariadb)
    Write-UiStatus 'MariaDB gestoppt.'
    Refresh-StackView
} })
(Get-Control 'BrowsePackage').Add_Click({
    $dialog = New-Object Windows.Forms.OpenFileDialog
    $dialog.Filter = 'ZIP-Pakete (*.zip)|*.zip'
    $dialog.InitialDirectory = Join-Path $stackRoot 'packages'
    if ($dialog.ShowDialog() -eq 'OK') { (Get-Control 'InstallPackage').Text = $dialog.FileName }
})
(Get-Control 'InstallPackageButton').Add_Click({ Invoke-UiAction {
    $module = [string]((Get-Control 'InstallModule').SelectedItem.Content)
    $version = (Get-Control 'InstallVersion').Text.Trim()
    $package = (Get-Control 'InstallPackage').Text.Trim()
    $hash = (Get-Control 'InstallHash').Text.Trim()
    [void](Install-SovereignModulePackage -Module $module -Version $version -PackagePath $package -ExpectedSha256 $hash)
    Write-UiStatus "$module $version wurde installiert."
    Refresh-StackView
} })
(Get-Control 'EnablePackageButton').Add_Click({ Invoke-UiAction {
    $module = [string]((Get-Control 'InstallModule').SelectedItem.Content)
    $version = (Get-Control 'InstallVersion').Text.Trim()
    Enable-SovereignModule -Module $module -Version $version
    Write-UiStatus "$module $version wurde aktiviert."
    Refresh-StackView
} })
(Get-Control 'DisablePackageButton').Add_Click({ Invoke-UiAction {
    $module = [string]((Get-Control 'InstallModule').SelectedItem.Content)
    $services = @(Get-SovereignServiceStatus)
    $dependentService = if ($module -eq 'php') { 'server' } else { 'mariadb' }
    if (($services | Where-Object Service -eq $dependentService).Running) {
        throw "Vor dem Deaktivieren von $module muss der Dienst $dependentService gestoppt werden."
    }
    Disable-SovereignModule -Module $module
    Write-UiStatus "$module wurde deaktiviert."
    Refresh-StackView
} })
(Get-Control 'RefreshLog').Add_Click({ Invoke-UiAction {
    if ($null -ne $logSelector.SelectedItem) {
        $path = [string]$logSelector.SelectedItem
        $lines = @(Get-Content -LiteralPath $path -Tail 2000 -ErrorAction Stop)
        $logText.Text = $lines -join [Environment]::NewLine
        $logText.ScrollToEnd()
    }
} })

Refresh-StackView
[void]$window.ShowDialog()
