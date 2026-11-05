#Requires -Version 5.1
<#
  VpnGuard — сторож для MeduzaVPN / AmneziaVPN, WireGuard-сервера wg_server, раздачи и zapret.

  Основной цикл ведёт агент на C# (модули agent\*.cs → bin\VpnGuardAgent.exe).
  Этот файл — часть PowerShell: запуск агента, обновления VpnGuard и MeduzaVPN, компоненты,
  веб-сервер, подбор стратегии zapret, диагностика, клиенты WireGuard, задачи планировщика.

  Запуск:
    VpnGuard.ps1               — собрать и запустить агент на C# (так запускает планировщик)
    VpnGuard.ps1 -Status       — показать состояние
    VpnGuard.ps1 -CheckUpdate  — проверить обновление MeduzaVPN прямо сейчас
    VpnGuard.ps1 -Diag [-TryFix] — диагностика
#>
[CmdletBinding()]
param(
    [switch]$Status,
    [switch]$CheckUpdate,
    [switch]$InstallCli,
    [switch]$Diag,
    [switch]$TryFix,
    [switch]$Restarted,
    [switch]$ZapretTest,
    [switch]$PsPart,
    [string]$WebTask = '',
    [string]$WebArg = '',
    [ValidateSet('agent', 'remove-agent', 'monitor', 'monitor-logon', 'remove-monitor')]
    [string]$SetupTask,
    [string]$ConfigPath = ''
)

$AgentVersion = '3.37.0'
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigPath) { $ConfigPath = Join-Path $Root 'config.json' }
$DataDir   = Join-Path $Root 'data'
$LogDir    = Join-Path $DataDir 'logs'
$DlDir     = Join-Path $DataDir 'downloads'
$BinDir    = Join-Path $Root 'bin'
$StatePath = Join-Path $DataDir 'state.json'
$StatusPath = Join-Path $DataDir 'status.json'
$CmdDir    = Join-Path $DataDir 'cmd'
foreach ($d in $DataDir, $LogDir, $DlDir, $BinDir, $CmdDir) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# ---------------------------------------------------------------- config

# умолчания настроек — из единой схемы config-schema.txt (её же читают агент и веб-сервер): «a.b.c» → вложенные таблицы
function Get-DefaultConfig {
    $c = @{}
    $f = Join-Path $Root 'config-schema.txt'
    if (-not (Test-Path $f)) { return $c }
    foreach ($e in @((Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json).settings)) {
        $parts = "$($e.key)".Split('.'); $cur = $c
        for ($i = 0; $i -lt $parts.Count - 1; $i++) { if (-not $cur.ContainsKey($parts[$i])) { $cur[$parts[$i]] = @{} }; $cur = $cur[$parts[$i]] }
        if ($e.default -is [array]) { $cur[$parts[-1]] = @($e.default) } else { $cur[$parts[-1]] = $e.default }
    }
    return $c
}

function Merge-Config($base, $over) {
    if ($null -eq $over) { return $base }
    foreach ($p in $over.PSObject.Properties) {
        if ($base.ContainsKey($p.Name) -and $base[$p.Name] -is [hashtable] -and $p.Value -is [psobject]) {
            $base[$p.Name] = Merge-Config $base[$p.Name] $p.Value
        } else {
            $base[$p.Name] = $p.Value
        }
    }
    return $base
}

$script:CfgStamp = $null
function Import-Config {
    $c = Get-DefaultConfig
    $stamp = $null
    if (Test-Path $ConfigPath) {
        $stamp = (Get-Item $ConfigPath).LastWriteTimeUtc
        $c = Merge-Config $c (Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    $script:Cfg = $c
    $script:M   = $c.meduza
    $script:W   = $c.ws4w
    $script:CfgStamp = $stamp
    $script:MzAdapterCfg = $c.meduza.adapterName
}
Import-Config

# записать одно значение в config.json (например zapret.enabled) и перечитать настройки
function Set-ConfigValue([string]$Path, $Value) {
    # config.json пишут три программы (агент, веб-сервер, PowerShell) — под общей блокировкой, временный файл — свой
    $mx = New-Object System.Threading.Mutex($false, 'Global\VpnGuardConfig'); $got = $false
    try { $got = $mx.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $got = $true }
    try { Set-ConfigValueCore $Path $Value } finally { if ($got) { try { $mx.ReleaseMutex() } catch { } }; $mx.Dispose() }
    Import-Config
}
function Set-ConfigValueCore([string]$Path, $Value) {
    $o = [pscustomobject]@{}
    if (Test-Path $ConfigPath) { $o = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    $parts = $Path.Split('.')
    $cur = $o
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        if (-not $cur.PSObject.Properties[$parts[$i]]) { $cur | Add-Member -NotePropertyName $parts[$i] -NotePropertyValue ([pscustomobject]@{}) }
        $cur = $cur.($parts[$i])
    }
    $cur | Add-Member -NotePropertyName $parts[-1] -NotePropertyValue $Value -Force
    $tmp = "$ConfigPath.$PID.tmp"
    $o | ConvertTo-Json -Depth 6 | Set-Content $tmp -Encoding UTF8
    Move-Item $tmp $ConfigPath -Force
}


# ---------------------------------------------------------------- state / log

$State = @{
    lastUpdateCheck   = [datetime]::MinValue
    cliSha256         = ''
    wgConfPath        = ''
    meduzaStartedAt   = [datetime]::MinValue
    probeFailures     = 0
    notResponding     = 0
    downTicks         = 0
    restarts          = New-Object System.Collections.ArrayList
    lastIcsApply      = [datetime]::MinValue
    lastIpFix         = [datetime]::MinValue
    updating          = $false
    # для монитора
    lastTraffic       = $null
    lastTrafficAt     = [datetime]::MinValue
    lastRestart       = [datetime]::MinValue
    lastRestartReason = ''
    lastIcsFix        = [datetime]::MinValue
    forceIcs          = $false
    remoteVersion     = $null
    history           = New-Object System.Collections.ArrayList
    activity          = ''
    activitySince     = [datetime]::MinValue
    lastSnapshot      = [datetime]::MinValue
    # счётчики с запуска агента (для статистики в окне)
    restartCount      = 0
    reconnectCount    = 0
    icsFixCount       = 0
    ultraUpSince      = [datetime]::MinValue
    wgUpSince         = [datetime]::MinValue
    wgMissingTicks    = 0
    # MeduzaVPN: список VPN (стран) и протоколов, тест протоколов
    catalog           = $null
    catalogAt         = [datetime]::MinValue
    protoTest         = $null
    awgTest           = $null
    software          = $null
    softwareCheckedAt = $null
    # MeduzaVPN: запасной протокол, если выбранный перестал работать
    mzProtoOverride   = ''
    mzProtoSince      = [datetime]::MinValue
    mzFallbackAt      = [datetime]::MinValue
    mzReturnAt        = [datetime]::MinValue
    # AmneziaVPN — свои счётчики (в режиме «два туннеля» работает вместе с MeduzaVPN)
    awgTraffic        = $null
    awgTrafficAt      = [datetime]::MinValue
    awgProbeFailures  = 0
    awgDownTicks      = 0
    awgRestarts       = New-Object System.Collections.ArrayList
    awgLastRestart    = [datetime]::MinValue
    awgLastReason     = ''
    awgUpSince        = [datetime]::MinValue
    # режим «два туннеля»
}
if (Test-Path $StatePath) {
    try {
        $s = Get-Content $StatePath -Raw | ConvertFrom-Json
        if ($s.lastUpdateCheck) { $State.lastUpdateCheck = [datetime]$s.lastUpdateCheck }
        if ($s.cliSha256)       { $State.cliSha256 = $s.cliSha256 }
        if ($s.wgConfPath)      { $State.wgConfPath = $s.wgConfPath }
    } catch { }
}
function Save-State {
    @{ lastUpdateCheck = $State.lastUpdateCheck.ToString('o'); cliSha256 = $State.cliSha256; wgConfPath = $State.wgConfPath } |
        ConvertTo-Json | Set-Content $StatePath -Encoding UTF8
}

function Write-Log([string]$Message, [string]$Level = 'INFO') {
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $file = Join-Path $LogDir ('vpnguard-{0}.log' -f (Get-Date -Format 'yyyyMMdd'))
    try { Add-Content -Path $file -Value $line -Encoding UTF8 } catch { }
    if (-not $Status) { Write-Host $line }
}


# ---------------------------------------------------------------- helpers

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-UpAdapter([string]$Name) {
    $a = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
    if ($a -and $a.Status -eq 'Up') { return $a }
    return $null
}

function Get-AdapterIPv4([string]$Name) {
    $ip = Get-NetIPAddress -InterfaceAlias $Name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
    if ($ip) { return $ip.IPAddress }
    return $null
}

function Test-TcpVia([string]$SourceIp, [string]$HostPort, [int]$TimeoutMs = 4000) {
    $parts = $HostPort.Split(':')
    $sock = New-Object System.Net.Sockets.Socket ([Net.Sockets.AddressFamily]::InterNetwork), ([Net.Sockets.SocketType]::Stream), ([Net.Sockets.ProtocolType]::Tcp)
    try {
        if ($SourceIp) { $sock.Bind((New-Object Net.IPEndPoint ([Net.IPAddress]::Parse($SourceIp)), 0)) }
        $ar = $sock.BeginConnect($parts[0], [int]$parts[1], $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $sock.EndConnect($ar); return $true }
        return $false
    } catch { return $false } finally { $sock.Close() }
}

function ConvertTo-Ver([string]$s) {
    $mt = [regex]::Match("$s", '\d+(\.\d+){1,3}')
    if ($mt.Success) { return [version]$mt.Value }
    return [version]'0.0'
}

function Invoke-Exe([string]$Exe, [string]$Arguments, [int]$TimeoutSec = 60) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        return [pscustomobject]@{ Code = -1; Out = ''; Err = "таймаут $TimeoutSec с" }
    }
    [pscustomobject]@{ Code = $p.ExitCode; Out = $o.Result.Trim(); Err = $e.Result.Trim() }
}

function Test-Signature([string]$Path) {
    $sig = Get-AuthenticodeSignature $Path
    return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match [regex]::Escape($M.signer))
}

# ---------------------------------------------------------------- WS4W / wg_server

# Find-WgConf, клиенты WireGuard, создание сервера — в модуле Wg.ps1
$WgModule = Join-Path $Root 'Wg.ps1'
if (Test-Path $WgModule) { . $WgModule }
else {
    function Find-WgConf {
        $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $W.serviceName
        if (Test-Path -LiteralPath $svcKey) {
            $mt = [regex]::Match("$((Get-ItemProperty -LiteralPath $svcKey).ImagePath)", '/tunnelservice\s+"?([^"]+?\.conf(\.dpapi)?)"?\s*$')
            if ($mt.Success -and (Test-Path $mt.Groups[1].Value)) { return $mt.Groups[1].Value }
        }
        if ($State.wgConfPath -and (Test-Path $State.wgConfPath)) { return $State.wgConfPath }
        return $W.configPath
    }
    function Initialize-WgServer { throw 'нет модуля Wg.ps1 рядом с VpnGuard.ps1' }
}

function Get-WgServerAddress {
    if ($W.serverAddress) { return $W.serverAddress }
    $conf = Find-WgConf
    if ($conf -and $conf -like '*.conf') {
        $mt = Select-String -Path $conf -Pattern '^\s*Address\s*=\s*([\d\.]+)' | Select-Object -First 1
        if ($mt) { return $mt.Matches[0].Groups[1].Value }
    }
    $ip = Get-AdapterIPv4 $W.interfaceName
    if ($ip -and $ip -notlike '192.168.137.*') { return $ip }
    return $null
}


# ---------------------------------------------------------------- снимок для монитора

function Format-When([datetime]$d) {
    if ($d -eq [datetime]::MinValue) { return 'не было' }
    if ($d.Date -eq (Get-Date).Date) { return $d.ToString('HH:mm:ss') }
    return $d.ToString('dd.MM HH:mm')
}

# имена клиентов: комментарий в блоке [Peer] конфига сервера или имя файла клиентского
# конфига WS4W (по его адресу), иначе — разрешённый IP
$script:PeerNames = @{ Stamp = ''; ByKey = @{}; ByIp = @{} }
function Get-WgPeerNames {
    $conf = Find-WgConf
    if (-not $conf -or $conf -notlike '*.conf') { return $script:PeerNames }
    $base = Split-Path (Split-Path $conf)
    $files = @(Get-ChildItem $base -Recurse -Depth 2 -Filter '*.conf' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $conf } | Select-Object -First 200)
    $stamp = ((@(Get-Item $conf) + $files) | ForEach-Object { $_.LastWriteTimeUtc.Ticks }) -join '|'
    if ($stamp -eq $script:PeerNames.Stamp) { return $script:PeerNames }
    $byKey = @{}; $byIp = @{}
    # имя клиента: «# Name = …» внутри блока [Peer] (так пишет VpnGuard) → комментарий над [Peer] (так пишет WS4W: «# 1», «[Peer]»)
    # → первый свой комментарий в блоке (не «VpnGuard: …») → имя файла клиента с тем же адресом (ByIp).
    # Комментарии после последнего ключа блока относятся к следующему блоку.
    $inPeer = $false; $key = $null; $nmName = $null; $nmFirst = $null; $above = $null; $pending = New-Object Collections.ArrayList
    $absorb = { foreach ($c in $pending) { if ($c -match '^(?:Name|Client|Имя)\s*[=:]\s*(.{1,60})$') { if (-not $nmName) { $nmName = $Matches[1].Trim() } } elseif ($c -and $c.Length -le 60 -and $c -notmatch '^VpnGuard' -and -not $nmFirst) { $nmFirst = $c } }; $pending.Clear() }
    $flush = { $n = $(if ($nmName) { $nmName } elseif ($above) { $above } else { $nmFirst }); if ($inPeer -and $key -and $n) { $byKey[$key] = $n } }
    foreach ($l in @(Get-Content $conf -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        if ($l -match '^\s*\[(\w+)\]') {
            $hdr = $Matches[1]; $up = $null
            foreach ($c in $pending) { if ($c -match '^(?:Name|Client|Имя)\s*[=:]\s*(.{1,60})$') { $up = $Matches[1].Trim() } elseif ($c -and $c.Length -le 60 -and $c -notmatch '^VpnGuard') { $up = $c } }
            $pending.Clear(); . $flush
            $inPeer = $hdr -eq 'Peer'; $key = $null; $nmName = $null; $nmFirst = $null; $above = $(if ($inPeer) { $up } else { $null })
            continue
        }
        if ($l -match '^\s*[#;]\s*(.*?)\s*$') { [void]$pending.Add($Matches[1]); continue }
        if (-not $l.Trim()) { continue }
        . $absorb
        if ($inPeer -and $l -match '^\s*PublicKey\s*=\s*(\S+)') { $key = $Matches[1] }
    }
    . $absorb; . $flush
    foreach ($f in $files) {
        $a = Select-String -Path $f.FullName -Pattern '^\s*Address\s*=\s*([\d\.]+)' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($a) { $byIp[$a.Matches[0].Groups[1].Value] = $f.BaseName }
    }
    $script:PeerNames = @{ Stamp = $stamp; ByKey = $byKey; ByIp = $byIp }
    return $script:PeerNames
}

function Get-WgPeers {
    $wgExe = Join-Path (Split-Path $W.wireguardExe) 'wg.exe'
    if (-not (Test-Path $wgExe)) { return $null }
    $r = Invoke-Exe $wgExe ('show {0} dump' -f $W.interfaceName) 5
    if ($r.Code -ne 0) { return $null }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $lines = @($r.Out -split "`r?`n" | Where-Object { $_ -match '\S' })
    if ($lines.Count -eq 0) { return $null }
    $port = (($lines[0] -split "`t")[2])
    $names = $null; try { $names = Get-WgPeerNames } catch { }
    $list = foreach ($l in ($lines | Select-Object -Skip 1)) {
        $p = $l -split "`t"
        if ($p.Count -lt 7) { continue }
        $ip = (($p[3] -split ',')[0] -replace '/\d+$', '')
        $hs = [long]$p[4]
        $name = $null
        if ($names) { $name = $names.ByKey[$p[0]]; if (-not $name) { $name = $names.ByIp[$ip] } }
        [ordered]@{
            name     = $(if ($name) { "$name" } else { $ip })
            key      = $p[0].Substring(0, [Math]::Min(8, $p[0].Length))
            ip       = $ip
            endpoint = $(if ($p[2] -eq '(none)') { '' } else { $p[2] })
            hsAgo    = $(if ($hs -gt 0) { [long]($now - $hs) } else { -1 })
            active   = [bool]($hs -gt 0 -and ($now - $hs) -lt 180)
            rx       = [long]$p[5]
            tx       = [long]$p[6]
        }
    }
    $list = @($list)
    return [pscustomobject]@{ Total = $list.Count; Active = @($list | Where-Object { $_.active }).Count; Port = $port; List = $list }
}

# ---------------------------------------------------------------- физический выход в интернет
$script:Phys = @{ At = [datetime]::MinValue; Alias = '' }

function Get-PhysAlias {
    if (((Get-Date) - $script:Phys.At).TotalSeconds -lt 60) { return $script:Phys.Alias }
    $a = ''
    try {
        $r = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-TunnelAlias $_.InterfaceAlias) -and $_.NextHop -ne '0.0.0.0' } |
            Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric } | Select-Object -First 1)
        if ($r.Count) { $a = $r[0].InterfaceAlias }
    } catch { }
    $script:Phys = @{ At = Get-Date; Alias = $a }
    return $a
}


# отметить, чем агент сейчас занят (видно в окне), и сразу отправить состояние
function Set-Activity([string]$Text) {
    $State.activity = $Text
    $State.activitySince = Get-Date
    try { Write-PsStatus } catch { }
}


# ---------------------------------------------------------------- команды для части PowerShell
# Основной цикл ведёт агент на C#; сюда он передаёт только то, что осталось на PowerShell: обновления, компоненты, создание сервера.

function Invoke-Commands {
    $files = @(Get-ChildItem $CmdDir -Filter '*.cmd' -ErrorAction SilentlyContinue | Sort-Object Name)
    foreach ($f in $files) {
        $a = ''
        try { $a = (Get-Content $f.FullName -Raw).Trim() } catch { }
        Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
        Write-Log "Команда из монитора: $a"
        switch ($a) {
            'app-check'      { Invoke-AppUpdateCheck }
            'app-update'     { Invoke-AppUpdateCheck -Install }
            'check-update'   { Invoke-MeduzaUpdate -Force }
            'check-now'      { }
            'wg-create'      {
                if (-not (Get-Service -Name $W.serviceName -ErrorAction SilentlyContinue) -and -not (Find-WgConf)) {
                    try { $c = Initialize-WgServer; $State.wgConfPath = $c; Save-State; Write-Log "wg_server: создан новый сервер ($c, адрес $($W.newServerAddress), порт UDP $($W.newServerPort)). Пробросьте этот порт на роутере и добавьте клиентов." 'WARN' }
                    catch { Write-Log "wg_server: не удалось создать сервер: $($_.Exception.Message)" 'ERROR' }
                }
            }
            'software-check' { Invoke-SoftwareCheck -Force }
            'install-missing' { Install-MissingSoftware; Invoke-SoftwareCheck -Force }
            default {
                if ($a -match '^install ([a-z]+)$') { Install-Software $Matches[1]; Invoke-SoftwareCheck -Force }
                else { Write-Log "Неизвестная команда: $a" 'WARN' }
            }
        }
    }
    # окно сразу видит результат команды
    if ($files.Count -gt 0) { try { Write-PsStatus } catch { } }
}

# ---------------------------------------------------------------- модуль zapret

$ZapretModule = Join-Path $Root 'Zapret.ps1'
if (Test-Path $ZapretModule) { . $ZapretModule }
else {
    function Invoke-ZapretWatch { }
    function Get-ZapretSnapshot { [ordered]@{ level = -1; state = 'Модуль Zapret.ps1 не найден'; details = @(); enabled = $false; strategies = @(); testing = $false; results = @() } }
    function Write-ZapretDiag { Write-Host '!! Zapret.ps1 не найден рядом с VpnGuard.ps1' }
    function Invoke-ZapretReload { }
}

# ---------------------------------------------------------------- модули AmneziaVPN и «Компоненты»

$AmneziaModule = Join-Path $Root 'Amnezia.ps1'
if (Test-Path $AmneziaModule) { . $AmneziaModule }
else {
    function Invoke-AmneziaWatch { Write-Log 'AmneziaVPN: нет модуля Amnezia.ps1 рядом с VpnGuard.ps1' 'ERROR' }
    function Get-AmneziaActive { '' }
    function Stop-AmneziaTunnels([string]$Except = '', [switch]$Close) { }
    function Invoke-AmneziaConfigTest { }
    function Get-AmneziaSnapshot { [ordered]@{ installed = $false; active = ''; configs = @(); test = $null } }
    function Get-AwgExe { '' }
    function Get-AvpnProc { $null }
    function Get-AvpnAdapter { $null }
    function Test-AmneziaAlias([string]$Alias) { $false }
    function Restart-AmneziaTunnel([string]$Name, [string]$Reason) { }
    function Get-AmneziaConfigs { @() }
}
$UpdateModule = Join-Path $Root 'Update.ps1'
if (Test-Path $UpdateModule) { . $UpdateModule }
else {
    function Invoke-AppUpdateWatch { }
    function Invoke-AppUpdateCheck([switch]$Install, [switch]$Force) { Write-Log 'Обновление VpnGuard: нет модуля Update.ps1' 'ERROR' }
    function Get-AppSnapshot { $null }
}
$RemoteModule = Join-Path $Root 'Remote.ps1'
if (Test-Path $RemoteModule) { . $RemoteModule }
else {
    function Invoke-RemoteWatch { }
    function Invoke-TrayWatch { }
    function Get-RemoteSnapshot { $null }
    function Invoke-RemoteServer { }
}
$SoftwareModule = Join-Path $Root 'Software.ps1'
if (Test-Path $SoftwareModule) { . $SoftwareModule }
else {
    function Invoke-SoftwareCheck([switch]$Force) { }
    function Install-Software([string]$Id) { Write-Log 'Компоненты: нет модуля Software.ps1' 'ERROR' }
    function Install-MissingSoftware { }
    function Get-SoftwareSnapshot { @() }
}

# ---------------------------------------------------------------- модули: MeduzaVPN, диагностика, задачи планировщика

foreach ($PsMod in 'Meduza.ps1', 'Diag.ps1', 'Setup.ps1') {
    $PsModPath = Join-Path $Root $PsMod
    if (Test-Path $PsModPath) { . $PsModPath } else { Write-Log "VpnGuard: нет модуля $PsMod рядом с VpnGuard.ps1" 'ERROR' }
}

# ---------------------------------------------------------------- режим: MeduzaVPN / AmneziaVPN / без VPN (только zapret)

function Get-VpnMode {
    $mt = $(if ($Cfg.vpn) { "$($Cfg.vpn.mode)" } else { '' })
    if ($mt -in 'meduza', 'amnezia', 'dual', 'zapret') { return $mt }
    return 'meduza'
}
$ModeNames = @{ meduza = 'MeduzaVPN'; amnezia = 'AmneziaVPN'; dual = 'два туннеля (MeduzaVPN + AmneziaVPN)'; zapret = 'без VPN (только zapret)' }

# режим «два туннеля»: какой основной и через какой сейчас идёт трафик
function Get-DualPrimary { $p = $(if ($Cfg.vpn) { "$($Cfg.vpn.primary)" } else { '' }); if ($p -in 'meduza', 'amnezia') { return $p }; return 'meduza' }
function Get-DualActive { try { $k = "$(([IO.File]::ReadAllText($StatusPath) | ConvertFrom-Json).vpn.kind)"; if ($k -in 'meduza', 'amnezia') { return $k } } catch { }; return (Get-DualPrimary) }
# какой VPN несёт трафик сейчас: meduza | amnezia | '' (без VPN)
function Get-TunnelKind {
    switch (Get-VpnMode) { 'meduza' { return 'meduza' } 'amnezia' { return 'amnezia' } 'dual' { return (Get-DualActive) } }
    return ''
}
function Get-KindAdapter([string]$Kind) { if ($Kind -eq 'meduza') { return "$($M.adapterName)" } elseif ($Kind -eq 'amnezia') { return "$(Get-AmneziaActive)" }; return '' }
# адаптер туннеля, через который сейчас идёт трафик
function Get-ActiveTunnel { Get-KindAdapter (Get-TunnelKind) }

# адаптер, через который этот ПК (и клиенты wg_server) выходят в интернет
function Get-UplinkName {
    if ((Get-VpnMode) -eq 'zapret') { return (Get-PhysAlias) }
    return (Get-ActiveTunnel)
}
# адаптеры туннелей — не «физический выход»
function Test-TunnelAlias([string]$Alias) {
    if (-not $Alias) { return $false }
    if ($Alias -like 'MeduzaVPN*' -or $Alias -eq $M.adapterName -or $Alias -eq $W.interfaceName) { return $true }
    try { if (Test-AmneziaAlias $Alias) { return $true } } catch { }
    return $false
}

# --- «два туннеля»: оба подняты, трафик (и раздача) — через активный; упал — сразу на другой

# быстрая проверка туннеля: адаптер поднят и через него открываются узлы проверки
function Test-KindOk([string]$Kind) {
    $n = Get-KindAdapter $Kind
    if (-not $n -or -not (Get-UpAdapter $n)) { return $false }
    $ip = Get-AdapterIPv4 $n
    if (-not $ip) { return $false }
    foreach ($h in $M.probeHosts) { if (Test-TcpVia $ip $h 3000) { return $true } }
    return $false
}


# ---------------------------------------------------------------- агент на C#
# Основной цикл (MeduzaVPN, AmneziaVPN, два туннеля, wg_server, раздача, zapret, трафик, состояние) ведёт bin\VpnGuardAgent.exe
# из модулей agent\*.cs. Он раз в 30 мин (или сразу по команде) запускает этот файл с -PsPart: обновления,
# компоненты, веб-сервер, значок. Подбор стратегии zapret — отдельным процессом -ZapretTest.

$CsAgentExe  = Join-Path $BinDir 'VpnGuardAgent.exe'
$PsStatusPath = Join-Path $DataDir 'status-ps.json'
$PsPartStatePath = Join-Path $DataDir 'pspart-state.xml'
# исходники агента — все модули agent\*.cs (новый модуль подхватывается сам)
$CsAgentSources = @(Get-ChildItem (Join-Path $Root 'agent') -Filter '*.cs' -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { "agent\$($_.Name)" })
$CsAgentRefs = @('System.Web.Extensions.dll', 'System.ServiceProcess.dll', 'System.Management.dll', 'System.Core.dll', 'Microsoft.CSharp.dll', 'System.IO.Compression.dll', 'System.IO.Compression.FileSystem.dll')

# собрать (если исходники изменились) и запустить; новая версия не собралась — работает прежняя сборка
function Start-CsAgent {
    if (Get-Process VpnGuardAgent -ErrorAction SilentlyContinue) { return $true }
    if (-not (Build-CsExe $CsAgentExe $CsAgentSources 'winexe' $CsAgentRefs)) {
        if (-not (Test-Path $CsAgentExe)) { Write-Log 'Агент на C# не собрался, прежней сборки нет — VpnGuard не работает до исправления Agent.cs' 'ERROR'; return $false }
        Write-Log 'Агент на C# не собрался — запускаю прежнюю сборку' 'ERROR'
    }
    $a = "`"$Root`""
    if ($ConfigPath -ne (Join-Path $Root 'config.json')) { $a += " `"$ConfigPath`"" }
    Start-Process -FilePath $CsAgentExe -ArgumentList $a -WorkingDirectory $Root | Out-Null
    Write-Log 'Запущен агент на C#'
    return $true
}

# часть PowerShell при агенте на C#: состояние zapret/обновлений/компонентов/веба — в data\status-ps.json (агент C# вставляет его в status.json)
function Write-PsStatus {
    $o = [ordered]@{
        updated  = (Get-Date).ToString('o'); pid = $PID; activity = "$($State.activity)"
        software = $(try { @(Get-SoftwareSnapshot) } catch { @() })
        remote   = $(try { Get-RemoteSnapshot } catch { $null })
        app      = $(try { Get-AppSnapshot } catch { $null })
        meduzaRemoteVersion = "$($State.remoteVersion)"
        meduzaLastCheck     = Format-When $State.lastUpdateCheck
    }
    $tmp = "$PsStatusPath.tmp"
    $o | ConvertTo-Json -Depth 8 -Compress | Set-Content $tmp -Encoding UTF8
    Move-Item $tmp $PsStatusPath -Force
    $State.lastSnapshot = Get-Date
}

function Remove-ObsoleteFiles {
    foreach ($n in 'Agent.cs', 'Zapret.cs', 'ClientZapret.cs', 'VpnGuardMonitor.ps1', 'VpnGuardMonitor.cmd') {
        $f = Join-Path $Root $n
        if (-not (Test-Path $f)) { continue }
        if ($n -like '*.cs' -and -not ("$(Get-Content $f -TotalCount 1 -ErrorAction SilentlyContinue)" -match 'Перенесено в agent')) { continue }   # только заглушки
        try { Remove-Item $f -Force -ErrorAction Stop; Write-Log "Удалён устаревший файл $n" } catch { }
    }
}
function Invoke-PsPart {
    $mx = New-Object System.Threading.Mutex($false, 'Global\VpnGuardPs')
    $got = $false
    try { $got = $mx.WaitOne(2000) } catch [Threading.AbandonedMutexException] { $got = $true }
    if (-not $got) { return }                          # предыдущая часть ещё работает
    # между запусками помнить то, что агент PowerShell держал в памяти
    if (Test-Path $PsPartStatePath) {
        try { $p = Import-Clixml $PsPartStatePath; foreach ($k in 'software', 'softwareCheckedAt', 'remoteVersion') { if ($null -ne $p[$k]) { $State[$k] = $p[$k] } } } catch { }
    }
    $script:CmdDir = Join-Path $DataDir 'cmd-ps'      # команды, которые агент C# передал сюда
    if (-not (Test-Path $CmdDir)) { New-Item -ItemType Directory $CmdDir -Force | Out-Null }
    try {
        # zapret ведёт сам агент на C# (Zapret.cs)
        foreach ($step in 'Remove-ObsoleteFiles', 'Invoke-Commands', 'Invoke-MeduzaUpdate', 'Invoke-SoftwareCheck', 'Invoke-RemoteWatch', 'Invoke-AppUpdateWatch', 'Invoke-TrayWatch') {
            try { & $step } catch { Write-Log "$step : $($_.Exception.Message)" 'ERROR' }
            if (((Get-Date) - $State.lastSnapshot).TotalSeconds -ge 10) { try { Write-PsStatus } catch { } }
        }
        $State.activity = ''
        try { Write-PsStatus } catch { Write-Log "Write-PsStatus : $($_.Exception.Message)" 'ERROR' }
    } finally {
        try { @{ software = $State.software; softwareCheckedAt = $State.softwareCheckedAt; remoteVersion = $State.remoteVersion } | Export-Clixml $PsPartStatePath } catch { }
        try { $mx.ReleaseMutex() } catch { }
        $mx.Dispose()
    }
}

# ---------------------------------------------------------------- main
# Основной цикл ведёт агент на C# (bin\VpnGuardAgent.exe). Задача «VpnGuard» запускает этот файл при входе и раз в 5 мин:
# он собирает агент (если изменился Agent.cs) и запускает его, если тот не работает.

if ($Status) { Show-Status; return }

if (-not (Test-Admin)) {
    Write-Log 'Нужны права администратора' 'ERROR'
    exit 1
}

if ($SetupTask) { Invoke-SetupTask $SetupTask; return }
if ($Diag)      { try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch { }; Invoke-Diag -TryFix:$TryFix; return }
if ($ZapretTest) { Invoke-ZapretTestRun; return }
if ($WebTask) { Invoke-WebTask $WebTask $WebArg; return }
if ($CheckUpdate) { Invoke-MeduzaUpdate -Force; return }
if ($InstallCli)  { Update-MeduzaCli (Get-Release); return }
if ($PsPart)      { Invoke-PsPart; return }
if (-not (Start-CsAgent)) { exit 1 }
