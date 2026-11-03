#Requires -Version 5.1
<#
  VpnGuard — сторож для MeduzaVPN (ULTRA) и WS4W (WireGuard-сервер wg_server).

  Что делает в цикле:
    1. Проверяет обновления MeduzaVPN (release.json), скачивает, сверяет sha256
       и цифровую подпись, ставит тихо и поднимает VPN обратно.
    2. Следит за туннелем wg_server (служба WireGuardTunnel$wg_server):
       запускает/перезапускает/переустанавливает.
    3. Следит за MeduzaVPN: процесс, адаптер "MeduzaVPN ULTRA", реальный трафик
       через туннель. Переподключает через CLI, при неудаче перезапускает приложение.
    4. Держит общий доступ (ICS): MeduzaVPN ULTRA -> wg_server. Восстанавливает
       после каждого переподключения/перезапуска/перезагрузки.

  Запуск:
    VpnGuard.ps1               — бесконечный цикл (так запускает планировщик)
    VpnGuard.ps1 -Once         — один проход проверок
    VpnGuard.ps1 -Status       — показать состояние
    VpnGuard.ps1 -CheckUpdate  — проверить обновление MeduzaVPN прямо сейчас
#>
[CmdletBinding()]
param(
    [switch]$Once,
    [switch]$Status,
    [switch]$CheckUpdate,
    [switch]$InstallCli,
    [switch]$Diag,
    [switch]$TryFix,
    [switch]$Restarted,
    [switch]$ZapretTest,
    [switch]$RemoteServer,
    [switch]$PsPart,
    [string]$WebTask = '',
    [string]$WebArg = '',
    [ValidateSet('agent', 'remove-agent', 'monitor', 'monitor-logon', 'remove-monitor')]
    [string]$SetupTask,
    [string]$ConfigPath = ''
)

$AgentVersion = '3.4.1'
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

function Get-DefaultConfig { @{
    checkIntervalSec = 30
    logRetentionDays = 14
    meduza = @{
        exePath                      = ''          # пусто = из реестра
        processName                  = 'medusa_vpn'
        adapterName                  = 'MeduzaVPN ULTRA'
        pipeName                     = 'MeduzaVPN'
        cliPath                      = ''          # пусто = bin\meduzavpn.exe
        serviceId                    = ''          # id/имя VPN из `meduzavpn list --services`; пусто = единственный
        protocol                     = 'ultra'
        autoProtocol                 = $true       # связь пропала и переподключение не помогло — пробовать другие протоколы
        protocolReturnMin            = 60          # работаем на запасном протоколе — раз в N мин пробовать вернуть выбранный (0 = нет)
        connectTimeoutSec            = 90
        startupGraceSec              = 60          # сколько ждать автоподключения приложения после старта
        probeHosts                   = @('1.1.1.1:443', '8.8.8.8:443', '9.9.9.9:443')
        probeFailuresBeforeReconnect = 3
        maxRestartsPer30Min          = 5
        autoUpdate                   = $true
        updateCheckHours             = 6
        releaseUrl                   = 'https://meduzavpn-builds.fra1.digitaloceanspaces.com/latest/release.json'
        signer                       = 'IPFB LLC'
        installerArgs                = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /NOCANCEL /SP-'
    }
    ws4w = @{
        interfaceName = 'wg_server'
        serviceName   = 'WireGuardTunnel$wg_server'
        configPath    = ''                         # пусто = найти автоматически
        wireguardExe  = 'C:\Program Files\WireGuard\wireguard.exe'
        serverAddress = ''                         # пусто = из конфига wg_server
        endpoint      = ''                         # адрес для клиентов (IP или имя[:порт]); пусто = из клиентов WS4W или внешний IP
        clientDns     = ''                         # DNS в конфиге клиента; пусто = как у клиентов WS4W или адрес сервера
        autoCreateServer = $true                   # нет ни конфига, ни службы wg_server — создать сервер самому
        newServerAddress = '10.253.0.1/24'
        newServerPort    = 51820
    }
    sharing = @{
        enabled = $true
    }
    vpn = @{
        mode         = 'meduza'      # meduza | amnezia | dual (оба, с переключением) | zapret (без VPN: напрямую, YouTube/Discord через zapret)
        stopInactive = $true         # при смене режима закрыть неиспользуемый VPN (чтобы не было двух туннелей)
        primary      = 'meduza'      # режим dual: основной туннель (meduza | amnezia)
        dualHot      = $true         # режим dual: резервный туннель поднят всегда (иначе поднимается только при сбое)
        failoverChecks = 2           # режим dual: сколько проверок подряд без трафика до переключения
        failbackMin  = 5             # режим dual: основной снова работает N мин — вернуть трафик на него (0 = не возвращать)
    }
    amnezia = @{                   # приложение AmneziaVPN (сервер и протокол выбираются в нём самом)
        exe            = ''          # пусто = из записи установщика или C:\Program Files\AmneziaVPN\AmneziaVPN.exe
        serviceName    = 'AmneziaVPN-service'
        adapterPattern = 'amnezia|tun2socks|TAP-Windows Adapter V9'   # имя или описание адаптера туннеля (зависит от протокола)
    }
    software = @{
        checkHours = 12
    }
    update = @{
        repo       = 'Fogiku/vpnguard'   # владелец/репозиторий на GitHub, откуда обновлять само приложение
        branch     = 'main'
        auto       = $true       # ставить обновления самому
        checkHours = 3
        token      = ''          # только для закрытого репозитория
    }
    agent = @{
        engine = 'powershell'    # csharp — основной цикл ведёт bin\VpnGuardAgent.exe (Agent.cs); zapret, обновления и веб — по-прежнему PowerShell
    }
    ui = @{
        tray = $true             # значок у часов вместо окна (ярлык VpnGuard открывает его; окно — в меню значка)
    }
    web = @{
        engine  = 'auto'         # auto — сервер на C# (bin\VpnGuardWeb.exe, собирается сам), powershell — прежний
        enabled = $true          # веб-интерфейс: http://localhost:8765/ (с других устройств сети и wg_server — по паролю token)
        port    = 8765
        token   = ''             # пароль для входа с других устройств; создаётся сам
    }
    remote = @{
        enabled      = $false        # удалённая диагностика: включается из окна на N часов
        until        = ''            # до какого времени (ISO); потом выключается сама
        token        = ''            # новый при каждом включении
        port         = 8765
        allowFrom    = 'any'         # any | local (только локальная сеть и клиенты wg_server)
        allowActions = $false        # разрешить удалённо команды, которые прерывают интернет (тесты, переподключение)
    }
    zapret = @{
        enabled           = $false      # включается кнопкой в окне
        dir               = ''          # пусто = <папка VpnGuard>\zapret
        autoUpdate        = $true
        updateCheckHours  = 12
        version           = ''          # пусто = последняя; иначе конкретная версия (например 1.10.2) — ставится и не обновляется
        strategy          = ''          # пусто = подбирать автоматически; иначе имя .bat без расширения
        retestHours       = 24          # переподбирать раз в N часов
        healthCheckMin    = 10          # проверять, что сайты открываются, раз в N минут
        gameFilter        = 'disabled'  # disabled | all | tcp | udp
        curlTimeoutSec    = 5
        videoCheck        = $true       # проверять ещё и видеосервер YouTube (googlevideo) и загрузку страницы целиком
        testTargets       = @('https://www.youtube.com', 'https://i.ytimg.com', 'https://redirector.googlevideo.com',
                              'https://discord.com', 'https://gateway.discord.gg', 'https://cdn.discordapp.com')
        routeGoogleRanges = $true       # официальные диапазоны Google (YouTube) — мимо VPN
        routeIspVideo     = $true       # и видеосерверы YouTube у провайдера (кэш Google в сети провайдера) — иначе видео уходит в VPN и не грузится
        routeDomainLists  = @('list-google.txt')
        routeDomains      = @('discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net', 'discord.media', 'discordcdn.com',
                              'gateway.discord.gg', 'cdn.discordapp.com', 'media.discordapp.net', 'updates.discord.com', 'dis.gd',
                              'discord-attachments-uploads-prd.storage.googleapis.com')
        maxRoutes         = 1500
    }
} }

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
    $o = [pscustomobject]@{}
    if (Test-Path $ConfigPath) { $o = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    $parts = $Path.Split('.')
    $cur = $o
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        if (-not $cur.PSObject.Properties[$parts[$i]]) { $cur | Add-Member -NotePropertyName $parts[$i] -NotePropertyValue ([pscustomobject]@{}) }
        $cur = $cur.($parts[$i])
    }
    $cur | Add-Member -NotePropertyName $parts[-1] -NotePropertyValue $Value -Force
    $tmp = "$ConfigPath.tmp"
    $o | ConvertTo-Json -Depth 6 | Set-Content $tmp -Encoding UTF8
    Move-Item $tmp $ConfigPath -Force
    Import-Config
}

# перечитать config.json, если его изменили (например, из окна монитора)
function Sync-Config {
    if (-not (Test-Path $ConfigPath)) { return }
    if ((Get-Item $ConfigPath).LastWriteTimeUtc -eq $script:CfgStamp) { return }
    $old = "$($M.serviceId)|$($M.protocol)"
    try {
        Import-Config; Write-Log 'Настройки перечитаны из config.json'
        # сменили VPN (страну) или протокол — переподключиться
        if ("$($M.serviceId)|$($M.protocol)" -ne $old) { $State.mzProtoOverride = '' }
        if ("$($M.serviceId)|$($M.protocol)" -ne $old -and $script:IsAgentLoop -and (Get-VpnMode) -in 'meduza', 'dual' -and (Test-MeduzaPipe)) {
            Write-Log "MeduzaVPN: выбраны VPN «$(if ($M.serviceId) { $M.serviceId } else { 'по умолчанию' })», протокол $($M.protocol) — переподключаю"
            Disconnect-Meduza; Start-Sleep -Seconds 2
            if (Connect-Meduza) { $State.forceIcs = $true }
        }
    }
    catch { Write-Log "config.json с ошибкой, оставляю прежние настройки: $($_.Exception.Message)" 'ERROR'; $script:CfgStamp = (Get-Item $ConfigPath).LastWriteTimeUtc }
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
    dualActive        = ''
    dualSwitches      = 0
    dualSwitchAt      = [datetime]::MinValue
    dualReason        = ''
}
$script:AgentStartedAt = Get-Date
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

function Remove-OldLogs {
    Get-ChildItem $LogDir -Filter 'vpnguard-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-[int]$Cfg.logRetentionDays) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
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

# ---------------------------------------------------------------- MeduzaVPN

function Get-MeduzaUninstallEntry {
    $keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like 'MeduzaVPN*' } |
        Select-Object -First 1
}

function Get-MeduzaExe {
    if ($M.exePath) { return $M.exePath }
    $e = Get-MeduzaUninstallEntry
    if ($e -and $e.InstallLocation) { return (Join-Path $e.InstallLocation 'medusa_vpn.exe') }
    return 'C:\Program Files\MeduzaVPN\medusa_vpn.exe'
}

function Get-MeduzaVersion {
    $e = Get-MeduzaUninstallEntry
    if ($e -and $e.DisplayVersion) { return (ConvertTo-Ver $e.DisplayVersion) }
    $exe = Get-MeduzaExe
    if (Test-Path $exe) { return (ConvertTo-Ver (Get-Item $exe).VersionInfo.ProductVersion) }
    return [version]'0.0'
}

function Get-CliPath {
    if ($M.cliPath) { return $M.cliPath }
    return (Join-Path $BinDir 'meduzavpn.exe')
}

function Test-MeduzaPipe {
    try {
        $want = '\\.\pipe\' + $M.pipeName
        return [bool]([IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -ieq $want })
    } catch { return $false }
}

function Invoke-MeduzaCli([string]$Arguments, [int]$TimeoutSec = 30) {
    $cli = Get-CliPath
    if (-not (Test-Path $cli)) { return [pscustomobject]@{ Code = -2; Out = ''; Err = 'CLI не найден' } }
    Invoke-Exe $cli $Arguments $TimeoutSec
}

# протокол, которым подключаться сейчас: выбранный или запасной (если выбранный перестал работать)
function Get-MzProtocol { if ($State.mzProtoOverride) { return "$($State.mzProtoOverride)" }; return "$($M.protocol)" }

function Connect-Meduza([int]$TimeoutSec = 0) {
    if (-not (Test-MeduzaPipe)) {
        Write-Log 'Канал управления MeduzaVPN недоступен (включите "Управление из командной строки" в настройках приложения) — жду автоподключения самого приложения' 'WARN'
        return $false
    }
    $proto = Get-MzProtocol
    $a = 'connect'
    if ($M.serviceId) { $a += ' "' + $M.serviceId + '"' }
    if ($proto)       { $a += ' --protocol ' + $proto }
    $a += ' --wait'
    Set-Activity "подключаю MeduzaVPN ($proto)"
    $State.reconnectCount++
    Write-Log "MeduzaVPN: meduzavpn $a"
    $r = Invoke-MeduzaCli $a $(if ($TimeoutSec) { $TimeoutSec } else { [int]$M.connectTimeoutSec + 30 })
    if ($r.Code -ne 0) {
        Write-Log ("MeduzaVPN: connect завершился с кодом {0}: {1} {2}" -f $r.Code, $r.Out, $r.Err) 'WARN'
    }
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if (Get-UpAdapter $M.adapterName) { Write-Log "MeduzaVPN: туннель подключён ($proto)"; return $true }
        # другой протокол — адаптер может называться иначе
        $alt = @(Get-NetAdapter -Name 'MeduzaVPN*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }) | Select-Object -First 1
        if ($alt) { $M.adapterName = $alt.Name; Write-Log "MeduzaVPN: подключён, адаптер «$($alt.Name)» ($proto)"; return $true }
        Start-Sleep -Seconds 2
    }
    return [bool](Get-UpAdapter $M.adapterName)
}

# связь пропала, переподключение тем же протоколом не помогло — попробовать остальные протоколы
function Invoke-MeduzaProtoFallback([string]$Reason) {
    if ($M.autoProtocol -eq $false -or -not (Test-MeduzaPipe)) { return $false }
    if (((Get-Date) - $State.mzFallbackAt).TotalMinutes -lt 15) { return $false }   # не чаще раза в 15 мин
    $State.mzFallbackAt = Get-Date
    $cur = Get-MzProtocol
    try { Update-MeduzaCatalog } catch { }
    $all = @(if ($State.catalog) { @($State.catalog.protocols) | ForEach-Object { "$($_.id)" } })
    # сначала те, что работали в последнем тесте (по отклику)
    $tested = @(if ($State.protoTest) { @($State.protoTest.results) | Where-Object { $_ -and $_.ok } | Sort-Object { [int]$_.pingMs } | ForEach-Object { "$($_.protocol)" } })
    # «ultra» в настройках и «meduza-ultra» в списке CLI — один и тот же протокол
    $same = @($cur, "meduza-$cur", ($cur -replace '^meduza-', ''))
    $order = @(@($tested) + @($all) + @("$($M.protocol)") | Where-Object { $_ -and $same -notcontains $_ } | Select-Object -Unique)
    if (-not $order.Count) { Write-Log "MeduzaVPN: $Reason — других протоколов нет (список не получен), пробовать нечего" 'WARN'; return $false }
    Write-Log "MeduzaVPN: $Reason, протокол $cur — пробую другие: $($order -join ', ')" 'WARN'
    $prev = $State.mzProtoOverride
    foreach ($p in $order) {
        Set-Activity "MeduzaVPN: пробую протокол $p"
        Disconnect-Meduza; Start-Sleep -Seconds 2
        $State.mzProtoOverride = $(if ($p -eq "$($M.protocol)") { '' } else { $p })
        if ((Connect-Meduza 60) -and (Test-MeduzaTraffic)) {
            $State.mzProtoSince = Get-Date; $State.mzReturnAt = Get-Date; $State.probeFailures = 0; $State.downTicks = 0
            $State.forceIcs = $true
            if ($State.mzProtoOverride) { Write-Log "MeduzaVPN: протокол $cur не работает — переключился на $p (выбран в настройках: $($M.protocol); агент будет пробовать вернуть его)" 'WARN' }
            else { Write-Log "MeduzaVPN: снова работает выбранный протокол $p" }
            return $true
        }
        Write-Log "MeduzaVPN: протокол $p тоже не работает" 'WARN'
    }
    $State.mzProtoOverride = $prev
    Write-Log 'MeduzaVPN: ни один протокол не заработал' 'WARN'
    return $false
}

# работаем на запасном протоколе — время от времени пробуем вернуть выбранный
function Invoke-MeduzaProtoReturn {
    if (-not $State.mzProtoOverride -or [int]$M.protocolReturnMin -le 0) { return }
    if (((Get-Date) - $State.mzReturnAt).TotalMinutes -lt [int]$M.protocolReturnMin) { return }
    $State.mzReturnAt = Get-Date
    $alt = $State.mzProtoOverride
    Write-Log "MeduzaVPN: пробую вернуть выбранный протокол $($M.protocol) (сейчас работает $alt)"
    Disconnect-Meduza; Start-Sleep -Seconds 2
    $State.mzProtoOverride = ''
    if ((Connect-Meduza 60) -and (Test-MeduzaTraffic)) { Write-Log "MeduzaVPN: выбранный протокол $($M.protocol) снова работает"; $State.forceIcs = $true; return }
    Write-Log "MeduzaVPN: $($M.protocol) по-прежнему не работает — остаюсь на $alt" 'WARN'
    $State.mzProtoOverride = $alt
    Disconnect-Meduza; Start-Sleep -Seconds 2
    [void](Connect-Meduza); $State.forceIcs = $true
}

function Disconnect-Meduza {
    if (Test-MeduzaPipe) {
        $r = Invoke-MeduzaCli 'disconnect' 30
        Write-Log ("MeduzaVPN: disconnect (код {0})" -f $r.Code)
    }
}

function Start-Meduza {
    $exe = Get-MeduzaExe
    if (-not (Test-Path $exe)) { Write-Log "MeduzaVPN не найден: $exe" 'ERROR'; return }
    Write-Log "MeduzaVPN: запуск $exe"
    Set-Activity 'запускаю MeduzaVPN'
    Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) | Out-Null
    $State.meduzaStartedAt = Get-Date
    $State.probeFailures = 0
    $State.notResponding = 0
    $State.downTicks = 0
    # ждём канал управления, затем сразу подключаем ULTRA
    $deadline = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $deadline -and -not (Test-MeduzaPipe)) { Start-Sleep -Seconds 2 }
    Start-Sleep -Seconds 3
    if (-not (Get-UpAdapter $M.adapterName) -and (Test-MeduzaPipe)) { [void](Connect-Meduza) }
}

function Stop-Meduza {
    Disconnect-Meduza
    $procs = Get-Process -Name $M.processName -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Log 'MeduzaVPN: остановка процесса'
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        $procs | ForEach-Object { try { $_.WaitForExit(15000) | Out-Null } catch { } }
    }
}

function Restart-Meduza([string]$Reason) {
    $now = Get-Date
    while ($State.restarts.Count -gt 0 -and $State.restarts[0] -lt $now.AddMinutes(-30)) { $State.restarts.RemoveAt(0) }
    if ($State.restarts.Count -ge [int]$M.maxRestartsPer30Min) {
        Write-Log "MeduzaVPN: слишком много перезапусков за 30 мин, пауза (причина: $Reason)" 'WARN'
        return
    }
    [void]$State.restarts.Add($now)
    $State.lastRestart = $now
    $State.lastRestartReason = $Reason
    $State.restartCount++
    Write-Log "MeduzaVPN: ПЕРЕЗАПУСК — $Reason" 'WARN'
    Set-Activity 'перезапускаю MeduzaVPN'
    Stop-Meduza
    Start-Sleep -Seconds 3
    Start-Meduza
}

function Test-MeduzaTraffic {
    $ip = Get-AdapterIPv4 $M.adapterName
    $ok = $false
    if ($ip) { foreach ($h in $M.probeHosts) { if (Test-TcpVia $ip $h) { $ok = $true; break } } }
    $State.lastTraffic = $ok
    $State.lastTrafficAt = Get-Date
    return $ok
}

# Адаптер туннеля: у другого протокола он может называться иначе (не «MeduzaVPN ULTRA»).
# Если адаптера из настроек нет, а другой «MeduzaVPN …» поднят — работаем с ним (раздача тоже).
function Resolve-MeduzaAdapter {
    $want = $script:MzAdapterCfg
    if (-not $want) { return }
    if (Get-NetAdapter -Name $want -ErrorAction SilentlyContinue) { $M.adapterName = $want; return }
    $alt = @(Get-NetAdapter -Name 'MeduzaVPN*' -ErrorAction SilentlyContinue | Sort-Object { $_.Status -ne 'Up' }) | Select-Object -First 1
    if ($alt -and $alt.Name -ne $M.adapterName) {
        Write-Log "MeduzaVPN: адаптер туннеля сейчас называется «$($alt.Name)» (протокол $($M.protocol)) — использую его"
        $M.adapterName = $alt.Name
    }
}
function Wait-MeduzaAdapter([int]$Sec = 15) {
    $deadline = (Get-Date).AddSeconds($Sec)
    do {
        $a = @(Get-NetAdapter -Name 'MeduzaVPN*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }) | Select-Object -First 1
        if ($a) { return $a.Name }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    return $null
}

# список VPN (стран/локаций) и протоколов аккаунта — для настроек в окне
function ConvertFrom-MzJson([string]$Text, [string]$Kind) {
    $o = $null; try { $o = $Text | ConvertFrom-Json } catch { return @() }
    $arr = $null
    if ($o -is [array]) { $arr = $o }
    else {
        foreach ($p in $o.PSObject.Properties) {
            if ($p.Value -is [array] -and (-not $arr -or $p.Name -match $Kind)) { $arr = $p.Value; if ($p.Name -match $Kind) { break } }
        }
    }
    $pick = { param($x, [string[]]$names) foreach ($n in $names) { if ($x.PSObject.Properties[$n] -and "$($x.$n)") { return "$($x.$n)" } }; '' }
    @(foreach ($x in @($arr)) {
        if ($null -eq $x) { continue }
        if ($x -is [string] -or $x -is [ValueType]) { [ordered]@{ id = "$x"; name = "$x"; info = '' }; continue }
        # протоколы, для которых в сборке для Windows нет движка, не предлагать
        if ($x.PSObject.Properties['available'] -and $x.available -eq $false) { continue }
        $id = & $pick $x @('id', 'service_id', 'serviceId', 'slug', 'key', 'name', 'protocol')
        $nm = & $pick $x @('title', 'display_name', 'displayName', 'name', 'location', 'city', 'country', 'protocol', 'id')
        $inf = @(foreach ($k in 'country', 'location', 'city', 'region', 'status', 'type', 'engine') { $v = & $pick $x @($k); if ($v -and $v -ne $nm) { $v } }) -join ', '
        [ordered]@{ id = $id; name = $nm; info = $inf }
    })
}
function Update-MeduzaCatalog([switch]$Force) {
    if (-not $Force -and $State.catalog -and ((Get-Date) - $State.catalogAt).TotalMinutes -lt 60) { return }
    if (-not (Test-MeduzaPipe) -and -not $Force) { return }
    $State.catalogAt = Get-Date
    $sv = Invoke-MeduzaCli 'list --services --json' 30
    $pr = Invoke-MeduzaCli 'list --protocols --json' 30
    $cat = [ordered]@{
        services  = @(ConvertFrom-MzJson $sv.Out 'service|vpn|location|server')
        protocols = @(ConvertFrom-MzJson $pr.Out 'protocol')
        at        = (Get-Date).ToString('HH:mm')
        error     = $(if ($sv.Code -ne 0) { "list --services: код $($sv.Code) $($sv.Err)".Trim() } elseif ($pr.Code -ne 0) { "list --protocols: код $($pr.Code) $($pr.Err)".Trim() } else { '' })
    }
    $State.catalog = $cat
    Write-Log ("MeduzaVPN: список VPN — {0}, протоколов — {1}{2}" -f $cat.services.Count, $cat.protocols.Count, $(if ($cat.error) { " ($($cat.error))" } else { '' }))
}

# тест протоколов: по очереди подключиться каждым и проверить трафик через туннель
function Invoke-MeduzaProtoTest {
    if (-not (Test-MeduzaPipe)) { Write-Log 'MeduzaVPN: тест протоколов невозможен — канал CLI недоступен' 'WARN'; return }
    Update-MeduzaCatalog -Force
    # два туннеля: на время теста трафик — через AmneziaVPN
    if ((Get-VpnMode) -eq 'dual' -and (Get-DualActive) -eq 'meduza' -and (Test-KindOk 'amnezia')) { Switch-DualActive 'amnezia' 'тест протоколов MeduzaVPN' }
    $protos = @($State.catalog.protocols | ForEach-Object { $_.id } | Where-Object { $_ })
    if (-not $protos.Count) { $protos = @($M.protocol) }
    $res = New-Object Collections.ArrayList
    $State.protoTest = [ordered]@{ running = $true; index = 0; total = $protos.Count; current = ''; results = $res; at = '' }
    Write-Log "MeduzaVPN: тест протоколов: $($protos -join ', ') (клиенты wg_server на время теста могут терять интернет)" 'WARN'
    $i = 0
    foreach ($p in $protos) {
        $i++
        $State.protoTest.index = $i; $State.protoTest.current = $p
        Set-Activity "тест протокола $p ($i/$($protos.Count))"
        Disconnect-Meduza; Start-Sleep -Seconds 2
        $a = 'connect'
        if ($M.serviceId) { $a += ' "' + $M.serviceId + '"' }
        $a += " --protocol $p --wait"
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-MeduzaCli $a ([int]$M.connectTimeoutSec + 30)
        $ad = Wait-MeduzaAdapter 15
        $conn = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        $okN = 0; $ms = New-Object Collections.ArrayList
        if ($ad) {
            Start-Sleep -Seconds 2
            $ip = Get-AdapterIPv4 $ad
            foreach ($h in $M.probeHosts) {
                $t = [Diagnostics.Stopwatch]::StartNew()
                if ($ip -and (Test-TcpVia $ip $h 3000)) { $okN++; [void]$ms.Add($t.ElapsedMilliseconds) }
            }
        }
        $err = ''
        if ($r.Code -ne 0) { $err = (("$($r.Err) $($r.Out)" -replace '\s+', ' ').Trim()); if ($err.Length -gt 120) { $err = $err.Substring(0, 120) + '…' } }
        [void]$res.Add([ordered]@{
            protocol = $p; ok = ($okN -gt 0); probes = "$okN/$(@($M.probeHosts).Count)"
            connectSec = $conn; pingMs = $(if ($ms.Count) { [int](($ms | Measure-Object -Average).Average) } else { -1 })
            adapter = "$ad"; error = $(if (-not $ad -and -not $err) { 'туннель не поднялся' } else { $err })
        })
        Write-Log ("MeduzaVPN: тест {0}: {1}, подключение {2} с, {3}" -f $p, $(if ($okN) { "работает ($okN/$(@($M.probeHosts).Count))" } else { 'НЕ работает' }), $conn,
            $(if ($ms.Count) { "отклик $([int](($ms | Measure-Object -Average).Average)) мс" } else { $err }))
        try { Write-StatusSnapshot } catch { }
    }
    $State.protoTest.running = $false; $State.protoTest.current = ''; $State.protoTest.at = (Get-Date).ToString('dd.MM HH:mm')
    Set-Activity "возвращаю протокол $(Get-MzProtocol)"
    Disconnect-Meduza; Start-Sleep -Seconds 2
    [void](Connect-Meduza)
    Resolve-MeduzaAdapter
    $State.forceIcs = $true
    $best = @($res | Where-Object { $_.ok } | Sort-Object { $_.pingMs })
    Write-Log ('MeduzaVPN: тест протоколов завершён — работают: ' + $(if ($best.Count) { ($best | ForEach-Object { "$($_.protocol) ($($_.pingMs) мс)" }) -join ', ' } else { 'ни один' }))
}

function Invoke-MeduzaWatch {
    if ($State.updating) { return }
    Resolve-MeduzaAdapter
    try { Update-MeduzaCatalog } catch { }
    $proc = Get-Process -Name $M.processName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) {
        Write-Log 'MeduzaVPN: процесс не запущен' 'WARN'
        Start-Meduza
        return
    }

    if (-not $proc.Responding) {
        $State.notResponding++
        if ($State.notResponding -ge 4) { Restart-Meduza 'приложение не отвечает'; return }
    } else { $State.notResponding = 0 }

    if (Get-UpAdapter $M.adapterName) {
        $State.downTicks = 0
        if (Test-MeduzaTraffic) { $State.probeFailures = 0; Invoke-MeduzaProtoReturn; return }
        $State.probeFailures++
        Write-Log ("MeduzaVPN: нет трафика через туннель ({0}/{1})" -f $State.probeFailures, $M.probeFailuresBeforeReconnect) 'WARN'
        if ($State.probeFailures -ge [int]$M.probeFailuresBeforeReconnect) {
            $State.probeFailures = 0
            if (Test-MeduzaPipe) {
                Disconnect-Meduza
                Start-Sleep -Seconds 3
                if ((Connect-Meduza) -and (Test-MeduzaTraffic)) { return }
                # тот же протокол не помог — может, работает другой
                if (Invoke-MeduzaProtoFallback 'нет трафика через туннель') { return }
            }
            Restart-Meduza 'туннель не пропускает трафик'
        }
        return
    }

    # адаптера нет
    $State.lastTraffic = $null
    if (((Get-Date) - $State.meduzaStartedAt).TotalSeconds -lt [int]$M.startupGraceSec) { return }
    $State.downTicks++
    Write-Log "MeduzaVPN: адаптер '$($M.adapterName)' не поднят" 'WARN'
    if (Connect-Meduza) { $State.downTicks = 0; return }
    if ($State.downTicks -ge 2 -and (Invoke-MeduzaProtoFallback 'туннель не подключается')) { $State.downTicks = 0; return }
    if ($State.downTicks -ge 3) { $State.downTicks = 0; Restart-Meduza 'туннель не подключается' }
}

# ---------------------------------------------------------------- MeduzaVPN update

function Get-Release {
    Invoke-RestMethod -Uri ($M.releaseUrl + '?t=' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -TimeoutSec 30 -UseBasicParsing
}

function Get-VerifiedDownload($File, [string]$Target) {
    $urls = @($File.versioned_url, $File.url) | Where-Object { $_ }
    foreach ($u in $urls) {
        try {
            Write-Log "Загрузка $u"
            Set-Activity ('скачиваю ' + [IO.Path]::GetFileName($u))
            Invoke-WebRequest -Uri $u -OutFile $Target -UseBasicParsing -TimeoutSec 900
            $hash = (Get-FileHash $Target -Algorithm SHA256).Hash
            if ($File.sha256 -and $hash -ne $File.sha256.ToUpper()) { throw "sha256 не совпал ($hash)" }
            return $true
        } catch {
            Write-Log "Загрузка не удалась: $($_.Exception.Message)" 'WARN'
            Remove-Item $Target -Force -ErrorAction SilentlyContinue
        }
    }
    return $false
}

function Update-MeduzaCli($Release) {
    $f = $Release.files | Where-Object { $_.key -eq 'meduzavpn-windows.zip' } | Select-Object -First 1
    if (-not $f) { return }
    $cli = Get-CliPath
    if ((Test-Path $cli) -and $State.cliSha256 -eq $f.sha256) { return }
    $zip = Join-Path $DlDir 'meduzavpn-windows.zip'
    if (-not (Get-VerifiedDownload $f $zip)) { return }
    $tmp = Join-Path $DlDir 'cli_x'
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive $zip $tmp -Force
    $new = Get-ChildItem $tmp -Recurse -Filter 'meduzavpn.exe' | Select-Object -First 1
    if ($new -and (Test-Signature $new.FullName)) {
        Copy-Item $new.FullName $cli -Force
        $State.cliSha256 = $f.sha256
        Save-State
        Write-Log "CLI meduzavpn обновлён до $($f.version)"
    } else {
        Write-Log 'CLI meduzavpn: подпись не прошла проверку, не устанавливаю' 'ERROR'
    }
    Remove-Item $tmp, $zip -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-MeduzaUpdate([switch]$Force) {
    if (-not $M.autoUpdate -and -not $Force) { return }
    if (-not $Force -and (Get-VpnMode) -ne 'meduza') { return }   # в других режимах — только по кнопке
    if (-not $Force -and ((Get-Date) - $State.lastUpdateCheck).TotalHours -lt [double]$M.updateCheckHours) { return }
    $State.lastUpdateCheck = Get-Date
    Save-State

    try { $rel = Get-Release } catch { Write-Log "Не удалось получить release.json: $($_.Exception.Message)" 'WARN'; return }
    try { Update-MeduzaCli $rel } catch { Write-Log "Обновление CLI: $($_.Exception.Message)" 'WARN' }

    $f = $rel.files | Where-Object { $_.key -eq 'MeduzaVPN-Setup.exe' } | Select-Object -First 1
    if (-not $f) { Write-Log 'В release.json нет MeduzaVPN-Setup.exe' 'WARN'; return }
    $remote = ConvertTo-Ver ($f.version -split '\+')[0]
    $local  = Get-MeduzaVersion
    $State.remoteVersion = $remote
    if ($remote -le $local) { Write-Log "MeduzaVPN $local — актуальная версия"; return }

    Write-Log "MeduzaVPN: доступно обновление $local -> $remote"
    $setup = Join-Path $DlDir ("MeduzaVPN-Setup-{0}.exe" -f $remote)
    if (-not (Get-VerifiedDownload $f $setup)) { return }
    if (-not (Test-Signature $setup)) {
        Write-Log 'Установщик MeduzaVPN не прошёл проверку подписи — обновление отменено' 'ERROR'
        Remove-Item $setup -Force -ErrorAction SilentlyContinue
        return
    }

    $State.updating = $true
    $updFlag = Join-Path $DataDir 'meduza-updating.flag'
    try { Set-Content $updFlag (Get-Date).ToString('o') -Encoding ASCII } catch { }   # агент на C# не трогает MeduzaVPN, пока идёт установка
    try { Write-StatusSnapshot } catch { }
    try {
        Stop-Meduza
        Write-Log "MeduzaVPN: установка $remote"
        Set-Activity "устанавливаю MeduzaVPN $remote"
        $p = Start-Process -FilePath $setup -ArgumentList $M.installerArgs -PassThru
        if (-not $p.WaitForExit(15 * 60 * 1000)) { try { $p.Kill() } catch { }; Write-Log 'Установщик завис — прерван' 'ERROR' }
        else { Write-Log "Установщик завершился с кодом $($p.ExitCode)" }
        Start-Sleep -Seconds 5
        Write-Log "MeduzaVPN: теперь установлена версия $(Get-MeduzaVersion)"
    } catch {
        Write-Log "Ошибка обновления: $($_.Exception.Message)" 'ERROR'
    } finally {
        $State.updating = $false
        Remove-Item $setup, $updFlag -Force -ErrorAction SilentlyContinue
    }
    # установщик мог сам запустить приложение
    Start-Sleep -Seconds 5
    if ((Get-VpnMode) -ne 'meduza') { if ($Cfg.vpn.stopInactive) { Stop-Meduza } }
    elseif (-not (Get-Process -Name $M.processName -ErrorAction SilentlyContinue)) { Start-Meduza }
    else { $State.meduzaStartedAt = Get-Date }
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

function Invoke-WgWatch {
    $svc = Get-Service -Name $W.serviceName -ErrorAction SilentlyContinue
    $conf = Find-WgConf
    if ($conf -and $State.wgConfPath -ne $conf) { $State.wgConfPath = $conf; Save-State }

    if (-not $svc) {
        if ($conf -and (Test-Path $W.wireguardExe)) {
            Write-Log "wg_server: служба туннеля отсутствует — устанавливаю из $conf" 'WARN'
            $r = Invoke-Exe $W.wireguardExe ('/installtunnelservice "{0}"' -f $conf) 60
            Write-Log "wg_server: installtunnelservice код $($r.Code) $($r.Err)"
            Start-Sleep -Seconds 5
        } elseif ($W.autoCreateServer) {
            # не создаём с первого раза: профиль/реестр могут быть ещё недоступны сразу после входа
            $State.wgMissingTicks++
            if ($State.wgMissingTicks -lt 3) {
                Write-Log "wg_server: нет ни службы, ни конфига ($($State.wgMissingTicks)/3) — если так останется, создам сервер сам" 'WARN'
            } else {
                $State.wgMissingTicks = 0
                Set-Activity 'создаю сервер wg_server'
                try {
                    $c = Initialize-WgServer
                    $State.wgConfPath = $c; Save-State
                    Write-Log "wg_server: создан новый сервер ($c, адрес $($W.newServerAddress), порт UDP $($W.newServerPort)). Пробросьте этот порт на роутере и добавьте клиентов в окне VpnGuard." 'WARN'
                    $State.forceIcs = $true
                } catch { Write-Log "wg_server: не удалось создать сервер: $($_.Exception.Message)" 'ERROR' }
            }
        } else {
            Write-Log "wg_server: служба '$($W.serviceName)' не найдена и конфиг не найден — настройте туннель в WS4W" 'ERROR'
        }
        return
    }

    if ($svc.StartType -ne 'Automatic') {
        Set-Service -Name $W.serviceName -StartupType Automatic
        Write-Log 'wg_server: тип запуска службы -> Автоматически'
    }

    if ($svc.Status -ne 'Running') {
        Write-Log "wg_server: служба в состоянии $($svc.Status) — запускаю" 'WARN'
        try {
            if ($svc.Status -ne 'Stopped') { Stop-Service -Name $W.serviceName -Force -ErrorAction SilentlyContinue }
            Start-Service -Name $W.serviceName
            (Get-Service -Name $W.serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            Write-Log 'wg_server: служба запущена'
        } catch { Write-Log "wg_server: не удалось запустить: $($_.Exception.Message)" 'ERROR' }
        return
    }

    $a = Get-NetAdapter -Name $W.interfaceName -ErrorAction SilentlyContinue
    if (-not $a -or $a.Status -ne 'Up') {
        Write-Log 'wg_server: служба работает, но адаптер не поднят — перезапуск службы' 'WARN'
        try {
            Restart-Service -Name $W.serviceName -Force
            (Get-Service -Name $W.serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        } catch { Write-Log "wg_server: перезапуск не удался: $($_.Exception.Message)" 'ERROR' }
    }
}

# ---------------------------------------------------------------- ICS (общий доступ)

function Get-IcsConnections {
    $mgr = New-Object -ComObject HNetCfg.HNetShare
    foreach ($c in $mgr.EnumEveryConnection) {
        $props = $mgr.NetConnectionProps.Invoke($c)
        $conf  = $mgr.INetSharingConfigurationForINetConnection.Invoke($c)
        [pscustomobject]@{
            Name    = $props.Name
            Device  = $props.DeviceName
            Guid    = $props.Guid
            Enabled = [bool]$conf.SharingEnabled
            Type    = [int]$conf.SharingConnectionType   # 0 = публичный (интернет), 1 = частный
            Config  = $conf
        }
    }
}

function Get-IcsStatus {
    $up   = Get-UplinkName
    $all  = @(Get-IcsConnections)
    $pub  = $all | Where-Object { $_.Name -eq $up } | Select-Object -First 1
    $priv = $all | Where-Object { $_.Name -eq $W.interfaceName } | Select-Object -First 1
    $others = @($all | Where-Object { $_.Enabled -and $_.Name -ne $up -and $_.Name -ne $W.interfaceName })
    [pscustomobject]@{
        All     = $all
        Public  = $pub
        Private = $priv
        Ok      = ($pub -and $pub.Enabled -and $pub.Type -eq 0 -and $priv -and $priv.Enabled -and $priv.Type -eq 1 -and $others.Count -eq 0)
    }
}

function Set-IcsScope([string]$Address) {
    if (-not $Address) { return $false }
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters'
    $cur = (Get-ItemProperty $k -ErrorAction SilentlyContinue).ScopeAddress
    if ($cur -ne $Address) {
        Set-ItemProperty $k -Name ScopeAddress       -Value $Address
        Set-ItemProperty $k -Name ScopeAddressBackup -Value $Address
        Write-Log "ICS: ScopeAddress -> $Address"
        return $true
    }
    return $false
}

function Invoke-SharingWatch {
    if (-not $Cfg.sharing.enabled) { return }
    $up = Get-UplinkName
    if (-not $up -or -not (Get-UpAdapter $up)) { return }
    if (-not (Get-UpAdapter $W.interfaceName)) { return }

    $addr = Get-WgServerAddress
    $st = Get-IcsStatus
    $wgIp = Get-AdapterIPv4 $W.interfaceName
    $ipOk = (-not $addr -or $wgIp -eq $addr -or ((Get-Date) - $State.lastIpFix).TotalMinutes -lt 10)
    if ($st.Ok -and $ipOk -and -not $State.forceIcs) { return }
    if (-not $State.forceIcs -and ((Get-Date) - $State.lastIcsApply).TotalSeconds -lt 20) { return }
    $State.forceIcs = $false
    $State.lastIcsApply = Get-Date

    Write-Log "ICS: настраиваю общий доступ '$up' -> '$($W.interfaceName)'"
    Set-Activity 'настраиваю раздачу'
    try {
        if ((Get-Service SharedAccess).StartType -ne 'Automatic') { Set-Service SharedAccess -StartupType Automatic }
        $scopeChanged = Set-IcsScope $addr
        if (-not (Wait-IcsService)) { throw 'служба SharedAccess не запускается' }
        if ($scopeChanged) {
            # новый ScopeAddress служба читает только при старте
            Write-Log 'ICS: перезапуск службы SharedAccess для нового адреса'
            Restart-Service SharedAccess -Force
            [void](Wait-IcsService)
        }

        # записи удалённых адаптеров (старый ULTRA) мешают включить раздачу на новом
        if ((Clear-StaleIcs) -gt 0) {
            Write-Log 'ICS: перезапуск службы SharedAccess после очистки старых записей'
            try { Restart-Service SharedAccess -Force } catch { }
            [void](Wait-IcsService)
        }

        # выключаем только то, что настроено неправильно — иначе служба остановится сама
        foreach ($c in @(Get-IcsConnections)) {
            if (-not $c.Enabled) { continue }
            $right = ($c.Name -eq $up -and $c.Type -eq 0) -or ($c.Name -eq $W.interfaceName -and $c.Type -eq 1)
            if (-not $right) {
                Write-Log "ICS: снимаю общий доступ с '$($c.Name)' (тип $($c.Type))"
                $c.Config.DisableSharing()
                Start-Sleep -Seconds 1
            }
        }

        Enable-IcsSide $up 0
        Enable-IcsSide $W.interfaceName 1
        Start-Sleep -Seconds 3

        # ICS мог сбросить адрес wg_server — вернуть его
        $wgIp = Get-AdapterIPv4 $W.interfaceName
        if ($addr -and $wgIp -ne $addr -and ((Get-Date) - $State.lastIpFix).TotalMinutes -ge 10) {
            $State.lastIpFix = Get-Date
            Write-Log "ICS: адрес wg_server стал $wgIp, ожидается $addr — перезапуск туннеля" 'WARN'
            Restart-Service -Name $W.serviceName -Force
            (Get-Service -Name $W.serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        }
        if ((Get-IcsStatus).Ok) { Write-Log 'ICS: общий доступ включён'; $State.lastIcsFix = Get-Date; $State.icsFixCount++ }
        else { Write-Log 'ICS: после настройки состояние не подтвердилось, повторю' 'WARN' }
    } catch {
        Write-Log "ICS: ошибка: $($_.Exception.Message)" 'ERROR'
        Write-IcsDiagnostics
    }
}

# Записи раздачи в хранилище Windows (WMI root\Microsoft\HomeNet), включая записи удалённых адаптеров.
# MeduzaVPN создаёт адаптер ULTRA заново (с новым GUID) при каждом подключении; запись старого адаптера
# остаётся помеченной как «публичный ICS», и Windows отказывается включать новый (0x80040201).
function Get-HNetIcsEntries {
    $present = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object { "$($_.InterfaceGuid)".ToUpper() })
    $names = @{}
    Get-CimInstance -Namespace root\Microsoft\HomeNet -ClassName HNet_Connection -ErrorAction SilentlyContinue |
        ForEach-Object { $names["$($_.Guid)".ToUpper()] = $_.Name }
    # WMI (а не CIM): провайдер HomeNet принимает изменения только через Put()
    Get-WmiObject -Namespace root\Microsoft\HomeNet -Class HNet_ConnectionProperties -ErrorAction SilentlyContinue |
        Where-Object { $_.IsIcsPublic -or $_.IsIcsPrivate } | ForEach-Object {
            $g = ([regex]::Match("$($_.Connection)", '\{[0-9A-Fa-f\-]+\}').Value).ToUpper()
            [pscustomobject]@{
                Guid = $g; Name = $names[$g]; Public = [bool]$_.IsIcsPublic; Private = [bool]$_.IsIcsPrivate
                Present = ($present -contains $g); Instance = $_
            }
        }
}

function Clear-StaleIcs {
    $n = 0
    foreach ($e in @(Get-HNetIcsEntries | Where-Object { -not $_.Present })) {
        Write-Log ("ICS: висячая запись раздачи удалённого адаптера '{0}' {1} (публичный={2}, частный={3}) — очищаю" -f $e.Name, $e.Guid, $e.Public, $e.Private) 'WARN'
        try {
            $e.Instance.IsIcsPublic = $false
            $e.Instance.IsIcsPrivate = $false
            [void]$e.Instance.Put()
            $n++
        } catch {
            Write-Log "ICS: не удалось очистить запись $($e.Guid): $($_.Exception.Message)" 'ERROR'
        }
    }
    return $n
}

# снять общий доступ со всех подключений (чтобы начать с чистого состояния)
function Reset-AllIcs {
    foreach ($c in @(Get-IcsConnections)) {
        if ($c.Enabled) {
            Write-Log "ICS: снимаю общий доступ с '$($c.Name)' для полной перенастройки"
            try { $c.Config.DisableSharing() } catch { Write-Log "ICS: DisableSharing '$($c.Name)': $($_.Exception.Message)" 'WARN' }
        }
    }
    [void](Clear-StaleIcs)
    Start-Sleep -Seconds 1
    try { Restart-Service SharedAccess -Force } catch { }
    [void](Wait-IcsService)
}

# дождаться, пока служба ICS будет в состоянии Running (она сама останавливается, когда раздавать нечего)
function Wait-IcsService([int]$TimeoutSec = 30) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $s = Get-Service SharedAccess
        switch ("$($s.Status)") {
            'Running' { Start-Sleep -Milliseconds 500; return $true }
            'Stopped' { try { Start-Service SharedAccess } catch { } }
        }
        Start-Sleep -Seconds 1
    }
    return ((Get-Service SharedAccess).Status -eq 'Running')
}

# включить общий доступ на одном адаптере (0 = публичный, 1 = частный) с повторами
function Enable-IcsSide([string]$Name, [int]$Type) {
    $last = $null
    for ($try = 1; $try -le 3; $try++) {
        [void](Wait-IcsService)
        $c = @(Get-IcsConnections) | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if (-not $c) { throw "адаптер '$Name' не найден в списке подключений" }
        if ($c.Enabled -and $c.Type -eq $Type) { return }
        try {
            if ($c.Enabled) { $c.Config.DisableSharing(); Start-Sleep -Seconds 1; [void](Wait-IcsService) }
            $c.Config.EnableSharing($Type)
            return
        } catch {
            $last = $_.Exception
            Write-Log ("ICS: '{0}' попытка {1}/3: {2} (служба: {3})" -f $Name, $try, $last.Message, (Get-Service SharedAccess).Status) 'WARN'
            if ($try -eq 1) {
                # чаще всего мешает «застрявшая» конфигурация: сбрасываем всё и включаем заново по порядку
                Reset-AllIcs
            } else {
                Write-Log 'ICS: перезапуск службы SharedAccess'
                try { Restart-Service SharedAccess -Force } catch { }
            }
            Start-Sleep -Seconds 3
        }
    }
    throw $last
}

function Invoke-Diag([switch]$TryFix) {
    function Section([string]$Title) { Write-Host ''; Write-Host "===== $Title =====" }
    function Try-Run([scriptblock]$Block) { try { & $Block } catch { Write-Host "!! ошибка: $($_.Exception.Message)" } }
    $names = @(@($M.adapterName, (Get-UplinkName), $W.interfaceName) | Where-Object { $_ } | Select-Object -Unique)

    Section 'Система'
    Try-Run {
        $os = Get-CimInstance Win32_OperatingSystem
        Write-Host "VpnGuard $AgentVersion · отчёт $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Write-Host "$($os.Caption) $($os.Version) (сборка $($os.BuildNumber)), PowerShell $($PSVersionTable.PSVersion), админ: $(Test-Admin)"
        Write-Host "Последняя загрузка Windows: $($os.LastBootUpTime)"
    }

    Section 'MeduzaVPN'
    Try-Run {
        $exe = Get-MeduzaExe
        Write-Host "Установлена версия: $(Get-MeduzaVersion) · exe: $exe (есть: $(Test-Path $exe))"
        try {
            $f = (Get-Release).files | Where-Object { $_.key -eq 'MeduzaVPN-Setup.exe' } | Select-Object -First 1
            Write-Host "Версия на сервере: $($f.version)"
        } catch { Write-Host "Версия на сервере: не получена ($($_.Exception.Message))" }
        $proc = Get-Process -Name $M.processName -ErrorAction SilentlyContinue
        if ($proc) { foreach ($x in $proc) { Write-Host "Процесс: PID $($x.Id), отвечает: $($x.Responding), запущен $($x.StartTime)" } }
        else { Write-Host '!! процесс MeduzaVPN не запущен' }
        Write-Host "Канал управления \\.\pipe\$($M.pipeName): $(if (Test-MeduzaPipe) { 'доступен' } else { '!! НЕТ (включите управление из командной строки в настройках MeduzaVPN)' })"
        $cli = Get-CliPath
        Write-Host "CLI: $cli (есть: $(Test-Path $cli))"
        if ((Test-Path $cli) -and (Test-MeduzaPipe)) {
            $r = Invoke-MeduzaCli 'status' 15
            Write-Host "meduzavpn status (код $($r.Code)):"
            Write-Host $r.Out
            if ($r.Err) { Write-Host $r.Err }
        }
        Write-Host "Протокол в настройках: '$($M.protocol)', VPN: '$($M.serviceId)', адаптер: '$($M.adapterName)'"
        if ((Test-Path $cli) -and (Test-MeduzaPipe)) {
            # для выбора страны/протокола в окне: как CLI отдаёт списки
            foreach ($q in 'list --all', 'list --services --json', 'list --protocols --json') {
                $r = Invoke-MeduzaCli $q 20
                $o = ("$($r.Out)" -replace '"(token|key|secret|password|private[_a-z]*|uuid)"\s*:\s*"[^"]*"', '"$1":"***"')
                if ($o.Length -gt 3000) { $o = $o.Substring(0, 3000) + ' …(обрезано)' }
                Write-Host "meduzavpn $q (код $($r.Code)):"; Write-Host $o
                if ($r.Err) { Write-Host $r.Err }
            }
        }
    }

    Section 'Адаптеры'
    Try-Run {
        $all = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)
        $all | Where-Object { $_.Name -in $names -or $_.InterfaceDescription -match 'Meduza|WireGuard|Wintun|wg_' -or $_.Status -eq 'Up' } |
            Format-Table Name, Status, InterfaceDescription, ifIndex, InterfaceGuid -AutoSize | Out-String -Width 250 | Write-Host
        foreach ($n in $names) {
            if (-not ($all | Where-Object Name -eq $n)) { Write-Host "!! адаптер с именем '$n' НЕ найден" }
            else { Write-Host "IPv4 '$n': $(Get-AdapterIPv4 $n)" }
        }
    }

    Section 'Маршрут по умолчанию и трафик'
    Try-Run {
        Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Format-Table InterfaceAlias, NextHop, RouteMetric, ifIndex -AutoSize | Out-String -Width 200 | Write-Host
        $ip = $(if ((Get-VpnMode) -eq 'zapret') { $null } else { Get-AdapterIPv4 (Get-UplinkName) })
        foreach ($h in $M.probeHosts) {
            $via = if ($ip) { Test-TcpVia $ip $h } else { 'нет IP' }
            Write-Host ("{0}: через ULTRA={1}, напрямую={2}" -f $h, $via, (Test-TcpVia $null $h))
        }
    }

    Section 'WS4W / wg_server'
    Try-Run {
        $svc = Get-Service -Name $W.serviceName -ErrorAction SilentlyContinue
        if ($svc) { Write-Host "Служба $($W.serviceName): $($svc.Status) / $($svc.StartType)" } else { Write-Host "!! служба $($W.serviceName) не найдена" }
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $W.serviceName
        if (Test-Path -LiteralPath $key) { Write-Host "ImagePath: $((Get-ItemProperty -LiteralPath $key).ImagePath)" }
        Get-Service | Where-Object { $_.Name -like 'WireGuardTunnel*' } | ForEach-Object { Write-Host "Туннель-служба: $($_.Name) $($_.Status)" }
        Write-Host "Конфиг: $(Find-WgConf)"
        Write-Host "Адрес сервера (ожидается): $(Get-WgServerAddress) · фактический IP wg_server: $(Get-AdapterIPv4 $W.interfaceName)"
        $peers = Get-WgPeers
        if ($peers) { Write-Host "Клиенты: $($peers.Active) активных из $($peers.Total)" } else { Write-Host 'Клиенты: нет данных (wg.exe)' }
        Write-Host "wireguard.exe: $($W.wireguardExe) (есть: $(Test-Path $W.wireguardExe))"
        # устройство папки WS4W (без ключей) — для управления клиентами
        $conf = Find-WgConf
        if ($conf -and (Test-Path $conf) -and $conf -like '*.conf') {
            $base = Split-Path (Split-Path $conf)
            Write-Host "Папка WS4W: $base"
            Get-ChildItem $base -Recurse -Depth 2 -File -ErrorAction SilentlyContinue | Select-Object -First 40 |
                ForEach-Object { Write-Host ("  {0} ({1} Б)" -f $_.FullName.Substring($base.Length), $_.Length) }
            Write-Host 'Конфиг сервера (ключи скрыты):'
            Get-Content $conf -Encoding UTF8 | ForEach-Object { '  ' + ($_ -replace '^(\s*(PrivateKey|PresharedKey|PublicKey)\s*=\s*)(\S{6})\S+', '$1$3…') } | Select-Object -First 60 | ForEach-Object { Write-Host $_ }
            if (Get-Command Get-WgClients -ErrorAction SilentlyContinue) {
                try { (Get-WgClients).Clients | Format-Table Name, Ip, Source, File -AutoSize | Out-String -Width 250 | Write-Host } catch { Write-Host "Клиенты: $($_.Exception.Message)" }
            }
        }
    }

    Section 'Раздача интернета (ICS)'
    Try-Run {
        $s = Get-Service SharedAccess
        Write-Host "Служба SharedAccess: $($s.Status) / $($s.StartType)"
        $p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -ErrorAction SilentlyContinue
        Write-Host "ScopeAddress=$($p.ScopeAddress)  ScopeAddressBackup=$($p.ScopeAddressBackup)"
        $rp = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\SharedAccess' -ErrorAction SilentlyContinue
        Write-Host "EnableRebootPersistConnection=$($rp.EnableRebootPersistConnection)"
        $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -ErrorAction SilentlyContinue
        if ($pol) { Write-Host "Политики: $(($pol.PSObject.Properties | Where-Object Name -like 'NC_*' | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ')" }
        @(Get-IcsConnections) | Format-Table Name, Enabled, Type, Device -AutoSize | Out-String -Width 250 | Write-Host
        Write-Host 'Хранилище раздачи Windows (HomeNet), записи с включённой раздачей:'
        $hn = @(Get-HNetIcsEntries)
        if ($hn.Count -eq 0) { Write-Host '  (нет)' }
        foreach ($e in $hn) {
            Write-Host ("  {0} '{1}' публичный={2} частный={3} {4}" -f $e.Guid, $e.Name, $e.Public, $e.Private, $(if ($e.Present) { 'адаптер есть' } else { '!! АДАПТЕРА НЕТ (висячая запись)' }))
        }
        $st = Get-IcsStatus
        Write-Host "Итог ICS: OK=$($st.Ok) (тип 0 = раздаёт интернет, 1 = получает)"
    }

    Section 'Режим, AmneziaVPN, компоненты'
    Try-Run {
        Write-Host "Режим: $(Get-VpnMode) ($($ModeNames[(Get-VpnMode)])) · выход в интернет: $(Get-UplinkName) · физический: $(Get-PhysAlias)"
        if ((Get-VpnMode) -eq 'dual') {
            Write-Host "Два туннеля: основной $(Get-DualPrimary), активный $(Get-DualActive), резерв горячий: $($Cfg.vpn.dualHot -ne $false), переключений $($State.dualSwitches)"
            foreach ($k in 'meduza', 'amnezia') {
                $n = Get-KindAdapter $k
                $ii = $(if ($n) { Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue } else { $null })
                Write-Host ("  {0}: адаптер '{1}' метрика {2} (авто {3}) · трафик {4}" -f $k, $n, $ii.InterfaceMetric, $ii.AutomaticMetric, $(if (Test-KindOk $k) { 'OK' } else { 'НЕТ' }))
            }
        }
        Write-Host 'Маршруты по умолчанию (0.0.0.0/0, /1):'
        Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in '0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1' } |
            ForEach-Object { Write-Host ("  {0,-14} {1,-28} шлюз {2,-15} метрика {3}+{4}" -f $_.DestinationPrefix, $_.InterfaceAlias, $_.NextHop, $_.RouteMetric, $_.InterfaceMetric) }
        Write-Host "MeduzaVPN: протокол выбран $($M.protocol), сейчас $(Get-MzProtocol), автоподбор $($M.autoProtocol -ne $false)"
        $avp = Get-AvpnProc; $ava = Get-AvpnAdapter
        Write-Host "AmneziaVPN: $(Get-AwgExe) (есть: $(Test-Path (Get-AwgExe))) · процесс: $(if ($avp) { "PID $($avp.Id)" } else { 'не запущен' }) · адаптер: $(if ($ava) { "$($ava.Name) ($($ava.Description)) $($ava.OperationalStatus)" } else { 'не найден' })"
        Get-Service | Where-Object { $_.Name -like 'Amnezia*' -or $_.Name -like 'WireGuardTunnel*' -or $_.Name -like 'WireGuardManager*' } |
            ForEach-Object { Write-Host "  служба $($_.Name): $($_.Status) / $($_.StartType)" }
        foreach ($s in @(Get-SoftwareSnapshot)) { Write-Host ("Компонент {0,-24} установлен: {1,-12} последний: {2,-10} нужен: {3} {4}" -f $s.name, $(if ($s.installed) { $s.installed } else { '—' }), $s.latest, $s.needed, $s.error) }
    }

    Section 'zapret-discord-youtube'
    Try-Run { Write-ZapretDiag }

    Section 'Агент и задачи'
    Try-Run {
        $script_ = Join-Path $Root 'VpnGuard.ps1'
        $procs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
            Where-Object { $_.CommandLine -match 'VpnGuard\.ps1' -and $_.ProcessId -ne $PID -and $_.CommandLine -notmatch '-(Diag|RemoteServer|ZapretTest|PsPart|WebTask)' })
        $procs += @(Get-CimInstance Win32_Process -Filter "Name='VpnGuardAgent.exe'")
        Write-Host "Движок агента: $(if ($Cfg.agent) { $Cfg.agent.engine } else { 'powershell' })"
        if (-not $procs) { Write-Host '!! агент НЕ запущен' }
        foreach ($pr in $procs) {
            $old = $pr.CreationDate -lt (Get-Item $script_).LastWriteTime
            Write-Host ("Агент PID {0}, запущен {1}{2}" -f $pr.ProcessId, $pr.CreationDate, $(if ($old) { '  !! СТАРЫЙ КОД — перезапустите агент' } else { '' }))
        }
        foreach ($tn in $AgentTask, $MonitorTask) {
            $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
            if ($t) { $i = $t | Get-ScheduledTaskInfo; Write-Host "Задача ${tn}: $($t.State), посл. запуск $($i.LastRunTime), результат 0x$('{0:X}' -f $i.LastTaskResult)" }
            else { Write-Host "Задача ${tn}: не установлена" }
        }
        if (Test-Path $StatusPath) { Write-Host "status.json обновлён: $((Get-Item $StatusPath).LastWriteTime)" }
        Write-Host 'config.json:'
        if (Test-Path $ConfigPath) { Get-Content $ConfigPath -Encoding UTF8 | ForEach-Object { Write-Host "  $_" } }
    }

    Section 'Журнал: предупреждения и ошибки (последние 60)'
    Try-Run {
        $files = @(Get-ChildItem $LogDir -Filter 'vpnguard-*.log' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 2)
        $files | ForEach-Object { Get-Content $_.FullName -Encoding UTF8 } | Where-Object { $_ -match '\[(WARN|ERROR)\]' } |
            Select-Object -Last 60 | ForEach-Object { Write-Host $_ }
    }
    Section 'Журнал: последние 25 строк'
    Try-Run {
        $f = Get-ChildItem $LogDir -Filter 'vpnguard-*.log' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
        if ($f) { Get-Content $f.FullName -Tail 25 -Encoding UTF8 | ForEach-Object { Write-Host $_ } }
    }

    if ($TryFix) {
        Section 'Попытка включить раздачу'
        Try-Run {
            if (-not (Get-UpAdapter (Get-UplinkName))) { Write-Host "!! '$(Get-UplinkName)' не поднят — раздачу включать некуда" }
            if (-not (Get-UpAdapter $W.interfaceName)) { Write-Host "!! '$($W.interfaceName)' не поднят" }
            $State.forceIcs = $true
            Invoke-SharingWatch
            $st = Get-IcsStatus
            Write-Host ("Итог: '{0}' включён={1} тип={2}; '{3}' включён={4} тип={5}; OK={6}" -f `
                (Get-UplinkName), $st.Public.Enabled, $st.Public.Type, $W.interfaceName, $st.Private.Enabled, $st.Private.Type, $st.Ok)
        }
    }
    Section 'Конец отчёта'
}
function Write-IcsDiagnostics {
    try {
        $s = Get-Service SharedAccess
        Write-Log "ICS диагностика: служба SharedAccess $($s.Status) / $($s.StartType)" 'WARN'
        foreach ($c in @(Get-IcsConnections)) {
            if ($c.Enabled -or $c.Name -eq (Get-UplinkName) -or $c.Name -eq $W.interfaceName) {
                Write-Log ("ICS диагностика: '{0}' включён={1} тип={2}" -f $c.Name, $c.Enabled, $c.Type) 'WARN'
            }
        }
        $p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' -ErrorAction SilentlyContinue
        Write-Log "ICS диагностика: ScopeAddress=$($p.ScopeAddress) wg_server IP=$(Get-AdapterIPv4 $W.interfaceName)" 'WARN'
        foreach ($e in @(Get-HNetIcsEntries)) {
            Write-Log ("ICS диагностика: HomeNet {0} '{1}' публичный={2} частный={3} адаптер есть={4}" -f $e.Guid, $e.Name, $e.Public, $e.Private, $e.Present) 'WARN'
        }
        $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -ErrorAction SilentlyContinue
        if ($pol -and $pol.PSObject.Properties['NC_ShowSharedAccessUI'] -and $pol.NC_ShowSharedAccessUI -eq 0) {
            Write-Log 'ICS диагностика: общий доступ запрещён групповой политикой (NC_ShowSharedAccessUI=0)' 'ERROR'
        }
    } catch { }
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

# ---------------------------------------------------------------- трафик адаптеров
# Счётчики байт берутся из .NET (без WMI, доли миллисекунды). Учитываются приращения:
# адаптер ULTRA пересоздаётся при каждом подключении — его счётчик начинается с нуля.
$TrafficPath = Join-Path $DataDir 'traffic.json'
$script:TrafBase = @{}
$script:TrafPending = @{ u = @(0, 0); w = @(0, 0); p = @(0, 0) }
$script:TrafRate = @{ u = @(0, 0); w = @(0, 0); p = @(0, 0) }
$script:TrafAt = $null
$script:TrafSaved = [datetime]::MinValue
$script:Phys = @{ At = [datetime]::MinValue; Alias = '' }
$script:TrafDays = [ordered]@{}
if (Test-Path $TrafficPath) {
    try {
        $tj = Get-Content $TrafficPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($pr in $tj.days.PSObject.Properties) {
            $script:TrafDays[$pr.Name] = @{ u = @([long]$pr.Value.u[0], [long]$pr.Value.u[1]); w = @([long]$pr.Value.w[0], [long]$pr.Value.w[1]); p = @([long]$pr.Value.p[0], [long]$pr.Value.p[1]) }
        }
    } catch { }
}

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

function Update-Traffic {
    $mode = Get-VpnMode
    $names = @{ u = (Get-ActiveTunnel); w = $W.interfaceName; p = (Get-PhysAlias) }
    $cur = @{}
    foreach ($n in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        foreach ($k in 'u', 'w', 'p') {
            if ($names[$k] -and $n.Name -eq $names[$k]) {
                try { $s = $n.GetIPStatistics(); $cur[$k] = @{ id = $n.Id; rx = [long]$s.BytesReceived; tx = [long]$s.BytesSent } } catch { }
            }
        }
    }
    $now = Get-Date
    $sec = $(if ($script:TrafAt) { [Math]::Max(1, ($now - $script:TrafAt).TotalSeconds) } else { 0 })
    $day = $now.ToString('yyyy-MM-dd')
    if (-not $script:TrafDays.Contains($day)) { $script:TrafDays[$day] = @{ u = @(0, 0); w = @(0, 0); p = @(0, 0) } }
    $today = $script:TrafDays[$day]
    foreach ($k in 'u', 'w', 'p') {
        $c = $cur[$k]; $b = $script:TrafBase[$k]
        $d = @(0, 0)
        if ($c) {
            if ($b -and $b.id -eq $c.id) { $d = @([Math]::Max(0, $c.rx - $b.rx), [Math]::Max(0, $c.tx - $b.tx)) }
            elseif ($b -and $k -ne 'p') { $d = @($c.rx, $c.tx) }   # адаптер пересоздан — счёт с нуля
            $script:TrafBase[$k] = $c
        } else { $script:TrafBase.Remove($k) }
        $script:TrafPending[$k] = @(($script:TrafPending[$k][0] + $d[0]), ($script:TrafPending[$k][1] + $d[1]))
        $today[$k] = @(([long]$today[$k][0] + $d[0]), ([long]$today[$k][1] + $d[1]))
        $script:TrafRate[$k] = $(if ($sec) { @([long]($d[0] / $sec), [long]($d[1] / $sec)) } else { @(0, 0) })
    }
    $script:TrafAt = $now
    while ($script:TrafDays.Count -gt 31) { $script:TrafDays.RemoveAt(0) }
    if (($now - $script:TrafSaved).TotalSeconds -ge 60) {
        try {
            $tmp = "$TrafficPath.tmp"
            @{ days = $script:TrafDays } | ConvertTo-Json -Depth 5 -Compress | Set-Content $tmp -Encoding UTF8
            Move-Item $tmp $TrafficPath -Force
            $script:TrafSaved = $now
        } catch { }
    }
    return $names
}

function Write-StatusSnapshot {
    # состояние пишет только работающий агент (не диагностика и не ручные команды)
    if (-not $script:IsAgentLoop) { return }
    $proc = Get-Process -Name $M.processName -ErrorAction SilentlyContinue | Select-Object -First 1
    $mode = Get-VpnMode
    $kind = Get-TunnelKind
    # туннель, через который сейчас идёт трафик (в режиме без VPN его нет)
    $tun  = Get-ActiveTunnel
    $ma   = $(if ($tun) { Get-NetAdapter -Name $tun -ErrorAction SilentlyContinue } else { $null })
    $wa   = Get-NetAdapter -Name $W.interfaceName -ErrorAction SilentlyContinue
    $wgSvc   = Get-Service -Name $W.serviceName -ErrorAction SilentlyContinue
    $ics  = $null; try { $ics = Get-IcsStatus } catch { }
    $pipe = Test-MeduzaPipe
    $ver  = Get-MeduzaVersion
    $uUp  = [bool]($ma -and $ma.Status -eq 'Up')
    $wUp  = [bool]($wgSvc -and $wgSvc.Status -eq 'Running' -and $wa -and $wa.Status -eq 'Up')
    # с какого момента туннели подняты
    if ($uUp) { if ($State.ultraUpSince -eq [datetime]::MinValue) { $State.ultraUpSince = Get-Date } } else { $State.ultraUpSince = [datetime]::MinValue }
    if ($wUp) { if ($State.wgUpSince -eq [datetime]::MinValue) { $State.wgUpSince = Get-Date } } else { $State.wgUpSince = [datetime]::MinValue }
    $adNames = $null; try { $adNames = Update-Traffic } catch { }
    $uIp = $(if ($ma) { Get-AdapterIPv4 $tun } else { $null })
    $wIp = $(if ($wa) { Get-AdapterIPv4 $W.interfaceName } else { $null })

    # MeduzaVPN
    if ($State.updating)              { $mL = 1; $mS = 'Обновляется' }
    elseif (-not $proc)               { $mL = 2; $mS = 'Не запущен' }
    elseif (-not $proc.Responding)    { $mL = 1; $mS = 'Не отвечает' }
    else                              { $mL = 0; $mS = 'Работает' }
    if ($mode -notin 'meduza', 'dual' -and -not $State.updating) { $mL = -1; $mS = $(if ($proc) { 'Не используется (запущен)' } else { 'Не используется' }) }
    elseif ($mode -eq 'dual' -and $mL -eq 0) {
        $mzUp = [bool](Get-UpAdapter $M.adapterName)
        if (-not $mzUp) { $mL = 1; $mS = 'Туннель не подключён' }
        elseif ($State.lastTraffic -eq $false) { $mL = 1; $mS = 'Нет трафика' }
        else { $mS = $(if ($kind -eq 'meduza') { 'Работает · активный' } else { 'Работает · резерв' }) }
    }
    $verLine = "Версия $ver"
    if ($State.remoteVersion -and $State.remoteVersion -gt $ver) { $verLine += " (есть $($State.remoteVersion))" }
    $started = ''
    if ($proc) { try { $started = ', с ' + $proc.StartTime.ToString('dd.MM HH:mm') } catch { } }
    $mD = @(
        $verLine,
        $(if ($proc) { "PID $($proc.Id)$started" } else { 'процесс отсутствует' }),
        ('Канал CLI: ' + $(if ($pipe) { 'доступен' } else { 'нет' }) + " · протокол $(Get-MzProtocol)" + $(if ($State.mzProtoOverride) { " (запасной вместо $($M.protocol))" } else { '' })),
        "Перезапуски: $($State.restarts.Count) за 30 мин, посл. $(Format-When $State.lastRestart)"
    )

    # Туннель (через который сейчас идёт трафик)
    $tTr   = $(if ($kind -eq 'amnezia') { $State.awgTraffic } else { $State.lastTraffic })
    $tTrAt = $(if ($kind -eq 'amnezia') { $State.awgTrafficAt } else { $State.lastTrafficAt })
    $tFail = $(if ($kind -eq 'amnezia') { $State.awgProbeFailures } else { $State.probeFailures })
    $tWhy  = $(if ($kind -eq 'amnezia') { $State.awgLastReason } else { $State.lastRestartReason })
    if ($mode -eq 'zapret')              { $uL = 0; $uS = 'VPN выключен — напрямую' }
    elseif ($kind -eq 'amnezia' -and -not $tun) { $uL = 2; $uS = 'AmneziaVPN не подключён' }
    elseif (-not $uUp)                   { $uL = 2; $uS = 'Отключён' }
    elseif ($tTr -eq $false)             { $uL = 1; $uS = 'Нет трафика' }
    else                                 { $uL = 0; $uS = 'Подключён' }
    $kindTitle = $(if ($kind -eq 'amnezia') { 'AmneziaVPN' } else { "MeduzaVPN · $(Get-MzProtocol)" })
    $uTitle = $(if ($mode -eq 'zapret') { 'Без VPN (только zapret)' } else { "Туннель: $kindTitle" })
    $sb = $null
    if ($mode -eq 'dual') {
        $oth = Get-OtherKind $kind
        $othUp = [bool](Get-UpAdapter (Get-KindAdapter $oth))
        $othTr = $(if ($oth -eq 'amnezia') { $State.awgTraffic } else { $State.lastTraffic })
        $sb = [ordered]@{ kind = $oth; name = $ModeNames[$oth]; up = $othUp; ok = ($othUp -and $othTr -eq $true)
                          state = $(if (-not $othUp) { 'не подключён' } elseif ($othTr -eq $true) { 'готов' } elseif ($othTr -eq $false) { 'нет трафика' } else { 'проверяется' }) }
        if ($uL -eq 0 -and -not $sb.ok) { $uS = 'Подключён · резерв не готов' }
        elseif ($uL -eq 0) { $uS = 'Подключён · резерв готов' }
    }
    $uD = @(
        $(if ($mode -eq 'zapret') { "Выход: $(Get-PhysAlias) · YouTube/Discord — через zapret" } else { '' }),
        $(if ($sb) { "Резерв: $($sb.name) — $($sb.state) · переключений: $($State.dualSwitches)" } else { '' }),
        ('Адаптер: ' + $(if ($ma) { "$tun · $($ma.Status), IP $uIp" } elseif ($mode -eq 'zapret') { 'не нужен' } else { 'отсутствует' })),
        ('Трафик: ' + $(if ($tTr -eq $true) { 'OK' } elseif ($tTr -eq $false) { 'НЕТ' } else { '—' }) + ", проверка $(Format-When $tTrAt)"),
        "Сбоев проверки подряд: $tFail",
        $(if ($tWhy) { "Последняя причина: $tWhy" } else { '' })
    )

    # wg_server
    if (-not $wgSvc)                      { $wL = 2; $wS = 'Служба не найдена' }
    elseif ($wgSvc.Status -ne 'Running')  { $wL = 2; $wS = "Служба: $($wgSvc.Status)" }
    elseif (-not $wUp)                 { $wL = 1; $wS = 'Адаптер не поднят' }
    else                               { $wL = 0; $wS = 'Работает' }
    $peers = $null; if ($wUp) { try { $peers = Get-WgPeers } catch { } }
    $addr = Get-WgServerAddress
    $wD = @(
        ('Служба: ' + $(if ($wgSvc) { "$($wgSvc.Status) / $($wgSvc.StartType)" } else { 'нет' })),
        ('IP: ' + $(if ($wIp) { $wIp } else { '—' }) + $(if ($addr) { " (нужен $addr)" } else { '' })),
        $(if ($peers) { "Клиенты: $($peers.Active) активных из $($peers.Total)" } else { 'Клиенты: —' })
    )

    # ICS
    $icsSvc = Get-Service SharedAccess -ErrorAction SilentlyContinue
    if (-not $Cfg.sharing.enabled)      { $iL = 1; $iS = 'Отключено в config' }
    elseif (-not $ics)                  { $iL = 1; $iS = 'Нет данных' }
    elseif ($ics.Ok)                    { $iL = 0; $iS = 'Включена' }
    elseif ((-not $uUp -and $mode -ne 'zapret') -or -not $wUp) { $iL = 1; $iS = 'Ждёт адаптеры' }
    else                                { $iL = 2; $iS = 'Не настроена' }
    $iD = @(
        "$(Get-UplinkName) → $($W.interfaceName)",
        ('Служба ICS: ' + $(if ($icsSvc) { "$($icsSvc.Status)" } else { 'нет' })),
        "Восстановлена: $(Format-When $State.lastIcsFix)"
    )

    # AmneziaVPN
    $awgS = $null
    try { $awgS = Get-AmneziaSnapshot } catch { $awgS = [ordered]@{ level = 2; state = 'Ошибка модуля'; details = @("$($_.Exception.Message)"); kv = @(); installed = $false; active = ''; configs = @(); test = $null } }

    # zapret
    $zs = $null
    try { $zs = Get-ZapretSnapshot } catch { $zs = [ordered]@{ level = 2; state = 'Ошибка модуля'; details = @("$($_.Exception.Message)"); enabled = $false; strategies = @(); testing = $false; results = @() } }

    # история — не чаще одной точки за интервал проверки (снимков теперь больше, чем проверок)
    $nowTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $lastTs = $(if ($State.history.Count) { [long]$State.history[$State.history.Count - 1].t } else { 0 })
    if ($nowTs - $lastTs -ge [Math]::Max(10, [int]$Cfg.checkIntervalSec - 2)) {
        # tr — байты за интервал: ULTRA ↓↑, wg_server ↓↑, физический адаптер ↓↑
        $tp = $script:TrafPending
        [void]$State.history.Add(@{ t = $nowTs; m = $mL; u = $uL; w = $wL; i = $iL; z = [int]$zs.level; a = [int]$awgS.level
            tr = @($tp.u[0], $tp.u[1], $tp.w[0], $tp.w[1], $tp.p[0], $tp.p[1]); zc = [int]$zs.conns })
        $script:TrafPending = @{ u = @(0, 0); w = @(0, 0); p = @(0, 0) }
        while ($State.history.Count -gt 240) { $State.history.RemoveAt(0) }
    }

    # подробности для вкладок окна: пары «название — значение»
    $fmtSince = { param($d) if ($d -eq [datetime]::MinValue) { '—' } else { Format-When $d } }
    $mK = @(
        @('Версия', "$ver"),
        @('Доступная версия', $(if ($State.remoteVersion) { "$($State.remoteVersion)" } else { '—' })),
        @('Последняя проверка обновлений', (Format-When $State.lastUpdateCheck)),
        @('Автообновление', $(if ($M.autoUpdate) { "включено, каждые $($M.updateCheckHours) ч" } else { 'выключено' })),
        @('Процесс', $(if ($proc) { "PID $($proc.Id)" + $(if ($proc.Responding) { '' } else { ' (не отвечает)' }) } else { 'не запущен' })),
        @('Запущен', $(if ($proc) { try { $proc.StartTime.ToString('dd.MM HH:mm:ss') } catch { '—' } } else { '—' })),
        @('Память', $(if ($proc) { '{0:N0} МБ' -f ($proc.WorkingSet64 / 1MB) } else { '—' })),
        @('Канал CLI', $(if ($pipe) { 'доступен' } else { 'нет — включите управление из командной строки' })),
        @('VPN (страна)', $(if ($M.serviceId) { "$($M.serviceId)" } else { 'по умолчанию (единственный на аккаунте)' })),
        @('Протокол', ("$(Get-MzProtocol)" + $(if ($State.mzProtoOverride) { " — запасной, выбранный $($M.protocol) не работал (с $(Format-When $State.mzProtoSince))" } else { '' }) + " · адаптер «$($M.adapterName)»")),
        @('Автоподбор протокола', $(if ($M.autoProtocol -eq $false) { 'выключен' } else { 'включён — при потере связи пробует другие протоколы' + $(if ([int]$M.protocolReturnMin -gt 0) { ", возврат к выбранному раз в $($M.protocolReturnMin) мин" } else { '' }) })),
        @('Перезапусков за 30 мин', "$($State.restarts.Count) из $($M.maxRestartsPer30Min) допустимых"),
        @('Перезапусков с запуска агента', "$($State.restartCount)"),
        @('Последний перезапуск', (Format-When $State.lastRestart)),
        @('Причина', $(if ($State.lastRestartReason) { $State.lastRestartReason } else { '—' }))
    )
    $uK = @(
        @('Режим', "$($ModeNames[$mode])"),
        $(if ($mode -eq 'dual') { , @('Трафик идёт через', ("$($ModeNames[$kind])" + $(if ($kind -eq (Get-DualPrimary)) { ' (основной)' } else { ' (резервный)' }))) }),
        $(if ($sb) { , @('Резервный туннель', "$($sb.name) — $($sb.state)") }),
        $(if ($mode -eq 'dual') { , @('Переключений', ("$($State.dualSwitches)" + $(if ($State.dualSwitches) { " · последнее $(Format-When $State.dualSwitchAt): $($State.dualReason)" } else { '' }))) }),
        $(if ($mode -eq 'dual') { , @('Резерв', ($(if ($Cfg.vpn.dualHot -ne $false) { 'горячий — оба туннеля подняты' } else { 'холодный — поднимается при сбое' }) + $(if ([int]$Cfg.vpn.failbackMin -gt 0) { ", возврат на основной через $($Cfg.vpn.failbackMin) мин" } else { '' }))) }),
        $(if ($mode -eq 'zapret') { , @('Выход в интернет', "$(Get-PhysAlias) напрямую, YouTube/Discord — через zapret") }),
        @('Адаптер', $(if ($ma) { "$($tun) · $($ma.Status) · $($ma.InterfaceDescription)" } else { 'отсутствует' })),
        @('IP', $(if ($uIp) { $uIp } else { '—' })),
        @('Скорость канала', $(if ($ma) { "$($ma.LinkSpeed)" } else { '—' })),
        @('Подключён с', (& $fmtSince $State.ultraUpSince)),
        @('Протокол', $(if ($kind -eq 'meduza') { "$(Get-MzProtocol)" } elseif ($kind -eq 'amnezia') { 'выбран в AmneziaVPN' } else { '—' })),
        @('Проверка трафика', ($(if ($tTr -eq $true) { 'OK' } elseif ($tTr -eq $false) { 'НЕТ' } else { '—' }) + " · $(Format-When $tTrAt)")),
        @('Узлы проверки', (@($M.probeHosts) -join ', ')),
        @('Сбоев проверки подряд', "$tFail (переподключение после $($M.probeFailuresBeforeReconnect))"),
        @('Переподключений с запуска агента', "$($State.reconnectCount)")
    )
    $wK = @(
        @('Служба', $(if ($wgSvc) { "$($W.serviceName) · $($wgSvc.Status) / $($wgSvc.StartType)" } else { 'не найдена' })),
        @('Адаптер', $(if ($wa) { "$($wa.Status)" } else { 'отсутствует' })),
        @('IP', ($(if ($wIp) { $wIp } else { '—' }) + $(if ($addr -and $addr -ne $wIp) { " (нужен $addr)" } else { '' }))),
        @('Порт', $(if ($peers -and $peers.Port) { "$($peers.Port) UDP" } else { '—' })),
        @('Работает с', (& $fmtSince $State.wgUpSince)),
        @('Клиенты', $(if ($peers) { "$($peers.Active) активных из $($peers.Total)" } else { '—' })),
        @('Конфиг', $(if ($State.wgConfPath) { $State.wgConfPath } else { "$(Find-WgConf)" }))
    )
    $fmtIcs = { param($c, [int]$want) if (-not $c) { 'не найдено' } elseif (-not $c.Enabled) { "$($c.Name): общий доступ выключен" } elseif ($c.Type -ne $want) { "$($c.Name): НЕВЕРНАЯ роль" } else { "$($c.Name): OK" } }
    $icsP = $(if ($ics) { & $fmtIcs $ics.Public 0 } else { '—' }); $icsQ = $(if ($ics) { & $fmtIcs $ics.Private 1 } else { '—' })
    $upN = Get-UplinkName
    $icsOther = $(if ($ics) { @($ics.All | Where-Object { $_.Enabled -and $_.Name -ne $upN -and $_.Name -ne $W.interfaceName } | ForEach-Object { $_.Name }) } else { @() })
    $iK = @(
        @('Схема', "$(Get-UplinkName) (публичный) → $($W.interfaceName) (домашняя сеть)"),
        @('Управление раздачей', $(if ($Cfg.sharing.enabled) { 'включено' } else { 'выключено в настройках' })),
        @('Служба ICS (SharedAccess)', $(if ($icsSvc) { "$($icsSvc.Status) / $($icsSvc.StartType)" } else { 'нет' })),
        @('Публичное подключение', $icsP),
        @('Частное подключение', $icsQ),
        @('Лишние подключения с ICS', $(if ($icsOther.Count) { $icsOther -join ', ' } else { 'нет' })),
        @('Восстановлена', (Format-When $State.lastIcsFix)),
        @('Восстановлений с запуска агента', "$($State.icsFixCount)")
    )
    $tdays = @($script:TrafDays.Keys | Select-Object -Last 14 | ForEach-Object { $d = $script:TrafDays[$_]; [ordered]@{ d = $_; u = $d.u; w = $d.w; p = $d.p } })
    $traffic = [ordered]@{
        names = $(if ($adNames) { $adNames } else { @{ u = $M.adapterName; w = $W.interfaceName; p = '' } })
        rate  = $script:TrafRate
        days  = $tdays
    }

    $busy = [bool]$State.activity
    $snap = [ordered]@{
        updated         = (Get-Date).ToString('o')
        # пока агент занят долгим действием, данные считаются актуальными дольше
        staleAfterSec   = $(if ($State.updating) { 1800 } elseif ($busy) { 900 } else { [int]$Cfg.checkIntervalSec + 120 })
        activity        = $State.activity
        activitySince   = $(if ($busy) { $State.activitySince.ToString('o') } else { '' })
        agentStarted    = $script:AgentStartedAt.ToString('o')
        agentPid        = $PID
        agentVersion    = $AgentVersion
        intervalSec     = [int]$Cfg.checkIntervalSec
        lastUpdateCheck = Format-When $State.lastUpdateCheck
        meduza = [ordered]@{ level = $mL; state = $mS; details = @($mD | Where-Object { $_ }); kv = $mK
                             serviceId = "$($M.serviceId)"; protocol = "$($M.protocol)"; adapter = "$($M.adapterName)"
                             protocolNow = "$(Get-MzProtocol)"; protocolOverride = "$($State.mzProtoOverride)"
                             catalog = $State.catalog; protoTest = $State.protoTest }
        ultra  = [ordered]@{ level = $uL; state = $uS; details = @($uD | Where-Object { $_ }); kv = @(foreach ($r in $uK) { if ($null -ne $r) { , $r } }); title = $uTitle
                             kind = $kind; standby = $sb; switches = $State.dualSwitches }
        wg     = [ordered]@{ level = $wL; state = $wS; details = @($wD | Where-Object { $_ }); kv = $wK
                             peers = $(if ($peers) { @($peers.List) } else { @() }) }
        ics    = [ordered]@{ level = $iL; state = $iS; details = @($iD | Where-Object { $_ }); kv = $iK }
        zapret = $zs
        traffic = $traffic
        counters = [ordered]@{ restarts = $State.restartCount; reconnects = $State.reconnectCount; icsFixes = $State.icsFixCount }
        vpn      = [ordered]@{ mode = $mode; name = $ModeNames[$mode]; uplink = "$(Get-UplinkName)"; kind = $kind; primary = (Get-DualPrimary) }
        amnezia  = $awgS
        software = $(try { @(Get-SoftwareSnapshot) } catch { @() })
        remote   = $(try { Get-RemoteSnapshot } catch { $null })
        app      = $(try { Get-AppSnapshot } catch { $null })
        history = @($State.history)
    }
    $tmp = $StatusPath + '.tmp'
    $snap | ConvertTo-Json -Depth 6 -Compress | Set-Content $tmp -Encoding UTF8
    Move-Item $tmp $StatusPath -Force
    $State.lastSnapshot = Get-Date
}

# отметить, чем агент сейчас занят (видно в окне), и сразу отправить состояние
function Set-Activity([string]$Text) {
    $State.activity = $Text
    $State.activitySince = Get-Date
    try { Write-StatusSnapshot } catch { }
}

# «пульс»: если снимок давно не писался — написать (вызывается между шагами проверки)
function Invoke-Heartbeat {
    if (((Get-Date) - $State.lastSnapshot).TotalSeconds -ge 10) { try { Write-StatusSnapshot } catch { } }
}

# ---------------------------------------------------------------- команды из монитора

function Invoke-Commands {
    $files = @(Get-ChildItem $CmdDir -Filter '*.cmd' -ErrorAction SilentlyContinue | Sort-Object Name)
    foreach ($f in $files) {
        $a = ''
        try { $a = (Get-Content $f.FullName -Raw).Trim() } catch { }
        Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
        Write-Log "Команда из монитора: $a"
        switch ($a) {
            'reconnect'      {
                if ((Get-TunnelKind) -eq 'amnezia') { $n = Get-AmneziaActive; if ($n) { $State.awgRestarts.Clear(); Restart-AmneziaTunnel $n 'по команде из окна' } }
                elseif ((Get-TunnelKind) -eq 'meduza') { Disconnect-Meduza; Start-Sleep -Seconds 3; if (-not (Connect-Meduza)) { Restart-Meduza 'переподключение из монитора не удалось' } }
            }
            'reconnect-meduza' { Disconnect-Meduza; Start-Sleep -Seconds 3; if (-not (Connect-Meduza)) { Restart-Meduza 'переподключение из монитора не удалось' } }
            'reconnect-awg'  { $n = Get-AmneziaActive; if ($n) { $State.awgRestarts.Clear(); Restart-AmneziaTunnel $n 'по команде из окна' } }
            'dual-switch'    { if ((Get-VpnMode) -eq 'dual') { $to = Get-OtherKind (Get-DualActive); if (Test-KindOk $to) { Switch-DualActive $to 'вручную из окна' } else { Write-Log "Два туннеля: $($ModeNames[$to]) сейчас не пропускает трафик — не переключаю" 'WARN' } } }
            'meduza-proto-reset' { if ($State.mzProtoOverride) { $State.mzReturnAt = [datetime]::MinValue; Invoke-MeduzaProtoReturn } }
            'zapret-check'   { $ZState.healthAt = [datetime]::MinValue }
            'zapret-releases' { [void](Get-ZapretReleases -Force) }
            'app-check'      { Invoke-AppUpdateCheck }
            'app-update'     { Invoke-AppUpdateCheck -Install }
            'restart-meduza' { $State.restarts.Clear(); Restart-Meduza 'по команде из монитора' }
            'restart-wg'     { try { Restart-Service -Name $W.serviceName -Force; $State.forceIcs = $true } catch { Write-Log "wg_server: $($_.Exception.Message)" 'ERROR' } }
            'reapply-ics'    { $State.forceIcs = $true }
            'check-update'   { Invoke-MeduzaUpdate -Force }
            'check-now'      { }
            'wg-create'      {
                if (-not (Get-Service -Name $W.serviceName -ErrorAction SilentlyContinue) -and -not (Find-WgConf)) {
                    try { $c = Initialize-WgServer; $State.wgConfPath = $c; Save-State; Write-Log "wg_server: создан новый сервер ($c, адрес $($W.newServerAddress), порт UDP $($W.newServerPort)). Пробросьте этот порт на роутере и добавьте клиентов." 'WARN' }
                    catch { Write-Log "wg_server: не удалось создать сервер: $($_.Exception.Message)" 'ERROR' }
                }
            }
            'zapret-on'      { Set-ZapretEnabled $true }
            'zapret-off'     { Set-ZapretEnabled $false }
            'zapret-test'    { if ($Cfg.zapret.enabled) { Disable-ZapretNow }; Start-ZapretTest 'по команде из окна' }
            'zapret-update'  { Invoke-ZapretUpdate -Force }
            'zapret-reload'  { Invoke-ZapretReload }
            'meduza-test'    { Invoke-MeduzaProtoTest }
            'meduza-catalog' { Update-MeduzaCatalog -Force }
            'software-check' { Invoke-SoftwareCheck -Force }
            'install-missing' { Install-MissingSoftware; Invoke-SoftwareCheck -Force }
            default {
                if ($a -match '^install ([a-z]+)$') { Install-Software $Matches[1]; Invoke-SoftwareCheck -Force }
                else { Write-Log "Неизвестная команда: $a" 'WARN' }
            }
        }
    }
    # окно сразу видит результат команды, не дожидаясь конца полной проверки
    if ($files.Count -gt 0) { try { Write-StatusSnapshot } catch { } }
}

# ---------------------------------------------------------------- задачи планировщика

$AgentTask   = 'VpnGuard'
$MonitorTask = 'VpnGuardMonitor'

function New-HiddenPsAction([string]$File) {
    New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory $Root `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$File`""
}

function Set-MonitorShortcuts([bool]$Create) {
    $paths = @(
        (Join-Path ([Environment]::GetFolderPath('Desktop')) 'VpnGuard.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Programs')) 'VpnGuard.lnk')
    )
    foreach ($p in $paths) {
        if (-not $Create) { Remove-Item $p -Force -ErrorAction SilentlyContinue; continue }
        $sh = New-Object -ComObject WScript.Shell
        $lnk = $sh.CreateShortcut($p)
        $lnk.TargetPath = "$env:windir\System32\schtasks.exe"
        $lnk.Arguments = "/run /tn `"$MonitorTask`""
        $lnk.WindowStyle = 7
        $lnk.IconLocation = "$env:windir\System32\shell32.dll,18"
        $lnk.Description = 'VpnGuard — мониторинг и управление MeduzaVPN и WS4W'
        $lnk.Save()
    }
}

function Invoke-SetupTask([string]$What) {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    switch ($What) {
        'agent' {
            $tLogon = New-ScheduledTaskTrigger -AtLogOn -User $user
            $tLogon.Delay = 'PT20S'
            $tRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
            $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName $AgentTask -Action (New-HiddenPsAction (Join-Path $Root 'VpnGuard.ps1')) `
                -Trigger $tLogon, $tRepeat -Settings $set -Principal $principal -Force | Out-Null
            Write-Log "Задача $AgentTask зарегистрирована для $user"
        }
        'remove-agent' {
            Unregister-ScheduledTask -TaskName $AgentTask -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Задача $AgentTask удалена"
        }
        { $_ -in 'monitor', 'monitor-logon' } {
            # MultipleInstances Parallel: второй запуск просто выводит уже открытое окно на передний план
            $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel
            $tray = Join-Path $BinDir 'VpnGuardTray.exe'
            $act = $(if ((Test-Path $tray) -and -not ($Cfg.ui -and $Cfg.ui.tray -eq $false)) { New-ScheduledTaskAction -Execute $tray -Argument "`"$Root`"" -WorkingDirectory $Root } else { New-HiddenPsAction (Join-Path $Root 'VpnGuardMonitor.ps1') })
            $reg = @{ TaskName = $MonitorTask; Action = $act; Settings = $set; Principal = $principal; Force = $true }
            if ($What -eq 'monitor-logon') { $reg.Trigger = New-ScheduledTaskTrigger -AtLogOn -User $user }
            Register-ScheduledTask @reg | Out-Null
            Set-MonitorShortcuts $true
            Write-Log "Задача $MonitorTask зарегистрирована (при входе: $($What -eq 'monitor-logon'))"
        }
        'remove-monitor' {
            Unregister-ScheduledTask -TaskName $MonitorTask -Confirm:$false -ErrorAction SilentlyContinue
            Set-MonitorShortcuts $false
        }
    }
}

# ---------------------------------------------------------------- status

function Show-Status {
    $proc = Get-Process -Name $M.processName -ErrorAction SilentlyContinue | Select-Object -First 1
    $ma = Get-NetAdapter -Name $M.adapterName -ErrorAction SilentlyContinue
    $wa = Get-NetAdapter -Name $W.interfaceName -ErrorAction SilentlyContinue
    $ws = Get-Service -Name $W.serviceName -ErrorAction SilentlyContinue
    $ics = try { Get-IcsStatus } catch { $null }
    $task = Get-ScheduledTask -TaskName 'VpnGuard' -ErrorAction SilentlyContinue
    $rows = [ordered]@{
        'MeduzaVPN версия'         = Get-MeduzaVersion
        'MeduzaVPN процесс'        = $(if ($proc) { "запущен (PID $($proc.Id))" } else { 'НЕ запущен' })
        'Канал управления (CLI)'   = $(if (Test-MeduzaPipe) { 'доступен' } else { 'нет' })
        'CLI meduzavpn'            = $(if (Test-Path (Get-CliPath)) { Get-CliPath } else { 'не установлен' })
        "Адаптер $($M.adapterName)" = $(if ($ma) { "$($ma.Status) $(Get-AdapterIPv4 $M.adapterName)" } else { 'нет' })
        'Трафик через ULTRA'       = $(if ($ma -and $ma.Status -eq 'Up') { if (Test-MeduzaTraffic) { 'OK' } else { 'НЕТ' } } else { '-' })
        "Служба $($W.serviceName)" = $(if ($ws) { "$($ws.Status) / $($ws.StartType)" } else { 'нет' })
        "Адаптер $($W.interfaceName)" = $(if ($wa) { "$($wa.Status) $(Get-AdapterIPv4 $W.interfaceName)" } else { 'нет' })
        'Конфиг wg_server'         = Find-WgConf
        'Адрес сервера (ожид.)'    = Get-WgServerAddress
        'Общий доступ (ICS)'       = $(if ($ics) { if ($ics.Ok) { 'OK' } else { 'НЕ настроен' } } else { 'ошибка чтения' })
        'Задача VpnGuard'          = $(if ($task) { $task.State } else { 'не установлена' })
        'Последняя проверка обнов.' = $State.lastUpdateCheck
    }
    $rows.GetEnumerator() | ForEach-Object { '{0,-28} {1}' -f $_.Key, $_.Value }
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

# ---------------------------------------------------------------- режим: MeduzaVPN / AmneziaVPN / без VPN (только zapret)

function Get-VpnMode {
    $mt = $(if ($Cfg.vpn) { "$($Cfg.vpn.mode)" } else { '' })
    if ($mt -in 'meduza', 'amnezia', 'dual', 'zapret') { return $mt }
    return 'meduza'
}
$ModeNames = @{ meduza = 'MeduzaVPN'; amnezia = 'AmneziaVPN'; dual = 'два туннеля (MeduzaVPN + AmneziaVPN)'; zapret = 'без VPN (только zapret)' }

# режим «два туннеля»: какой основной и через какой сейчас идёт трафик
function Get-DualPrimary { $p = $(if ($Cfg.vpn) { "$($Cfg.vpn.primary)" } else { '' }); if ($p -in 'meduza', 'amnezia') { return $p }; return 'meduza' }
function Get-DualActive { if ($State.dualActive -in 'meduza', 'amnezia') { return "$($State.dualActive)" }; return (Get-DualPrimary) }
function Get-OtherKind([string]$Kind) { if ($Kind -eq 'meduza') { return 'amnezia' }; return 'meduza' }
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
function Invoke-KindWatch([string]$Kind) { if ($Kind -eq 'meduza') { Invoke-MeduzaWatch } else { Invoke-AmneziaWatch } }
function Stop-Kind([string]$Kind) {
    if ($Kind -eq 'meduza') { if (Get-UpAdapter $M.adapterName) { Write-Log 'MeduzaVPN: отключаю (резерв поднимается только при сбое)'; Disconnect-Meduza } }
    else { Stop-AmneziaTunnels '' }
}

function Switch-DualActive([string]$Kind, [string]$Reason) {
    if ((Get-DualActive) -eq $Kind) { return }
    $from = Get-DualActive
    $State.dualActive = $Kind; $State.dualSwitchAt = Get-Date; $State.dualSwitches++; $State.dualReason = $Reason
    $script:DualFails = 0; $script:DualOkSince = [datetime]::MinValue
    Write-Log "Два туннеля: трафик переключён $($ModeNames[$from]) → $($ModeNames[$Kind]) — $Reason" 'WARN'
    try { Sync-DualRoutes } catch { Write-Log "Два туннеля: маршруты: $($_.Exception.Message)" 'ERROR' }
    $State.forceIcs = $true
    $State.probeFailures = 0
}

# приоритет маршрутов: у активного — половинки 0.0.0.0/1 + 128.0.0.0/1 (сильнее любого 0.0.0.0/0)
# и метрика выше физического выхода (чтобы WireGuard-клиенты не уходили в него); резервному — метрика 5000
$script:DualRoutes = New-Object System.Collections.ArrayList
function Set-IfMetric([string]$Alias, [int]$Metric) {
    $i = Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($i -and [int]$i.InterfaceMetric -ne $Metric) { Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -InterfaceMetric $Metric -ErrorAction SilentlyContinue }
}
function Sync-DualRoutes {
    $act = Get-DualActive
    $physM = 25
    $pr = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { -not (Test-TunnelAlias $_.InterfaceAlias) -and $_.NextHop -ne '0.0.0.0' })
    if ($pr.Count) { $physM = [int](@($pr | ForEach-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric }) | Measure-Object -Minimum).Minimum }
    foreach ($k in 'meduza', 'amnezia') {
        $n = Get-KindAdapter $k
        if (-not $n) { continue }
        $ad = Get-UpAdapter $n
        if (-not $ad) { continue }
        if ($k -ne $act) { Set-IfMetric $n 5000; continue }
        $own0 = @(Get-NetRoute -InterfaceAlias $n -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
        $mt = $(if ($own0.Count) { [Math]::Max(1, $physM - [int](@($own0 | ForEach-Object { $_.RouteMetric }) | Measure-Object -Minimum).Minimum + 10) } else { 0 })
        if ($mt -gt 0) { Set-IfMetric $n ([Math]::Min(4000, $mt)) }
        else { $i = Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue; if ($i -and [int]$i.InterfaceMetric -ge 5000) { Set-IfMetric $n 5 } }
        foreach ($pfx in '0.0.0.0/1', '128.0.0.0/1') {
            if (Get-NetRoute -InterfaceAlias $n -DestinationPrefix $pfx -ErrorAction SilentlyContinue) { continue }
            try {
                New-NetRoute -InterfaceIndex $ad.ifIndex -DestinationPrefix $pfx -NextHop '0.0.0.0' -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
                [void]$script:DualRoutes.Add(@{ i = $ad.ifIndex; p = $pfx })
                Write-Log "Два туннеля: добавлен маршрут $pfx через $n"
            } catch { Write-Log "Два туннеля: не удалось добавить маршрут $pfx через $n : $($_.Exception.Message)" 'WARN' }
        }
    }
}
# выход из режима: вернуть автоматические метрики и убрать наши маршруты
function Reset-DualRoutes {
    foreach ($r in @($script:DualRoutes)) { Remove-NetRoute -InterfaceIndex $r.i -DestinationPrefix $r.p -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue }
    $script:DualRoutes.Clear()
    foreach ($k in 'meduza', 'amnezia') {
        $n = Get-KindAdapter $k
        if ($n -and (Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue)) { Set-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -AutomaticMetric Enabled -ErrorAction SilentlyContinue }
    }
}

$script:DualFails = 0
$script:DualOkSince = [datetime]::MinValue
function Invoke-DualWatch {
    $hot = ($Cfg.vpn.dualHot -ne $false)
    $act = Get-DualActive; $oth = Get-OtherKind $act
    # 1. быстрая проверка активного — до долгого восстановления, чтобы клиенты не ждали
    $actUp = [bool](Get-UpAdapter (Get-KindAdapter $act))
    $actOk = $actUp -and (Test-KindOk $act)
    $grace = ($act -eq 'meduza' -and ((Get-Date) - $State.meduzaStartedAt).TotalSeconds -lt [int]$M.startupGraceSec)
    if ($actOk -or $grace) { $script:DualFails = 0 } else { $script:DualFails++ }
    $need = [Math]::Max(1, [int]$Cfg.vpn.failoverChecks)
    if (-not $actOk -and -not $grace -and ($script:DualFails -ge $need -or -not $actUp)) {
        if ($hot) {
            if (Test-KindOk $oth) { Switch-DualActive $oth $(if ($actUp) { "$($ModeNames[$act]) не пропускает трафик" } else { "$($ModeNames[$act]) отключился" }) }
            elseif ($script:DualFails -eq $need) { Write-Log "Два туннеля: $($ModeNames[$act]) не работает, резерв $($ModeNames[$oth]) тоже — восстанавливаю" 'WARN' }
        } else {
            Write-Log "Два туннеля: $($ModeNames[$act]) не работает — поднимаю резерв $($ModeNames[$oth])" 'WARN'
            Invoke-KindWatch $oth
            $deadline = (Get-Date).AddSeconds(30)
            while ((Get-Date) -lt $deadline -and -not (Test-KindOk $oth)) { Start-Sleep -Seconds 3 }
            if (Test-KindOk $oth) { Switch-DualActive $oth "$($ModeNames[$act]) не работает"; Stop-Kind $act }
        }
    }
    Invoke-Heartbeat
    # 2. наблюдение и восстановление: оба (горячий резерв) или только активный
    $act = Get-DualActive
    try { Sync-DualRoutes } catch { }
    if ($hot) { foreach ($k in @($act, (Get-OtherKind $act))) { try { Invoke-KindWatch $k } catch { Write-Log "$k : $($_.Exception.Message)" 'ERROR' }; Invoke-Heartbeat } }
    else { Invoke-KindWatch $act; Stop-Kind (Get-OtherKind $act) }
    # 3. основной снова работает N минут — вернуть трафик на него
    $prim = Get-DualPrimary
    if ($hot -and (Get-DualActive) -ne $prim -and [int]$Cfg.vpn.failbackMin -gt 0) {
        $pOk = $(if ($prim -eq 'meduza') { $State.lastTraffic -eq $true -and (Get-UpAdapter $M.adapterName) } else { $State.awgTraffic -eq $true -and (Get-UpAdapter (Get-AmneziaActive)) })
        if (-not $pOk) { $script:DualOkSince = [datetime]::MinValue }
        elseif ($script:DualOkSince -eq [datetime]::MinValue) { $script:DualOkSince = Get-Date }
        elseif (((Get-Date) - $script:DualOkSince).TotalMinutes -ge [int]$Cfg.vpn.failbackMin) { Switch-DualActive $prim "основной туннель работает уже $($Cfg.vpn.failbackMin) мин" }
    }
    try { Sync-DualRoutes } catch { }
}

$script:LastMode = $null
function Invoke-VpnWatch {
    $mode = Get-VpnMode
    if ($mode -ne $script:LastMode) {
        if ($script:LastMode) { Write-Log "Режим: $($ModeNames[$script:LastMode]) → $($ModeNames[$mode])" 'WARN' }
        Set-Activity "переключаю режим: $($ModeNames[$mode])"
        if ($script:LastMode -eq 'dual') { try { Reset-DualRoutes } catch { } }
        # закрыть неиспользуемый VPN, чтобы не было двух туннелей
        if ($mode -notin 'meduza', 'dual' -and $Cfg.vpn.stopInactive -and (Get-Process -Name $M.processName -ErrorAction SilentlyContinue)) {
            Write-Log 'MeduzaVPN: отключаю и закрываю (выбран другой режим)'
            Stop-Meduza
        }
        if ($mode -notin 'amnezia', 'dual') { Stop-AmneziaTunnels '' -Close:($Cfg.vpn.stopInactive -ne $false) }
        if ($mode -in 'meduza', 'dual') { $State.meduzaStartedAt = Get-Date }
        if ($mode -eq 'dual') { $State.dualActive = Get-DualPrimary; $script:DualFails = 0; $script:DualOkSince = [datetime]::MinValue }
        $State.probeFailures = 0; $State.downTicks = 0; $State.lastTraffic = $null
        $State.awgProbeFailures = 0; $State.awgDownTicks = 0; $State.awgTraffic = $null
        $State.forceIcs = $true
        $script:LastMode = $mode
    }
    switch ($mode) {
        'meduza'  { Invoke-MeduzaWatch }
        'amnezia' {
            # MeduzaVPN запустили вручную и он подключился — отключить туннель (приложение не трогаем)
            if (Get-UpAdapter $M.adapterName) { Write-Log 'MeduzaVPN: подключён, но выбран режим AmneziaVPN — отключаю' 'WARN'; Disconnect-Meduza }
            Invoke-AmneziaWatch
        }
        'dual'    { Invoke-DualWatch }
        'zapret'  {
            if (Get-UpAdapter $M.adapterName) { Write-Log 'MeduzaVPN: подключён, но выбран режим без VPN — отключаю' 'WARN'; Disconnect-Meduza }
            Stop-AmneziaTunnels ''
            $State.lastTraffic = $null; $State.awgTraffic = $null
        }
    }
}

# ---------------------------------------------------------------- агент на C# (agent.engine = 'csharp')
# Основной цикл (MeduzaVPN, AmneziaVPN, wg_server, раздача, zapret, трафик, состояние) ведёт bin\VpnGuardAgent.exe из Agent.cs + Zapret.cs.
# Он раз в 2 мин (или сразу по команде) запускает этот файл с -PsPart: обновления, компоненты, веб-сервер, значок.
# Подбор стратегии zapret — как и раньше отдельным процессом -ZapretTest.

$CsAgentExe  = Join-Path $BinDir 'VpnGuardAgent.exe'
$CsAgentSrc  = Join-Path $Root 'Agent.cs'
$CsStatePath = Join-Path $DataDir 'agent-cs.json'
$PsStatusPath = Join-Path $DataDir 'status-ps.json'
$PsPartStatePath = Join-Path $DataDir 'pspart-state.xml'

$CsAgentSources = @('Agent.cs', 'Zapret.cs')
$CsAgentRefs = @('System.Web.Extensions.dll', 'System.ServiceProcess.dll', 'System.Management.dll', 'System.Core.dll', 'Microsoft.CSharp.dll', 'System.IO.Compression.dll', 'System.IO.Compression.FileSystem.dll')
function Get-CsSig {
    $f = @($CsAgentSources | ForEach-Object { Join-Path $Root $_ })
    if (@($f | Where-Object { -not (Test-Path $_) }).Count) { return '' }
    (@($f | ForEach-Object { (Get-FileHash $_ -Algorithm SHA256).Hash }) -join '|')
}
function Get-CsState {
    $s = $null; try { $s = Get-Content $CsStatePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
    if (-not $s) { $s = [pscustomobject]@{ sig = ''; starts = @(); fallbackSig = '' } }
    return $s
}
function Save-CsState($s) { try { $s | ConvertTo-Json -Depth 4 | Set-Content $CsStatePath -Encoding UTF8 } catch { } }

function Test-CsAgentWanted {
    if (-not $Cfg.agent -or "$($Cfg.agent.engine)" -ne 'csharp') { return $false }
    if ((Get-VpnMode) -eq 'dual') { return $false }          # «два туннеля» — пока только агент на PowerShell
    $sig = Get-CsSig
    if (-not $sig) { return $false }
    return "$((Get-CsState).fallbackSig)" -ne $sig            # этот Agent.cs уже падал — остаёмся на PowerShell
}

function Start-CsAgent {
    if (Get-Process VpnGuardAgent -ErrorAction SilentlyContinue) { return $true }
    $sig = Get-CsSig
    $st = Get-CsState
    if (-not (Build-CsExe $CsAgentExe $CsAgentSources 'winexe' $CsAgentRefs)) {
        Write-Log 'Агент на C# не собрался — работает агент на PowerShell (до обновления Agent.cs)' 'ERROR'
        $st.fallbackSig = $sig; Save-CsState $st
        return $false
    }
    $starts = @()
    if ("$($st.sig)" -eq $sig) { foreach ($t in @($st.starts)) { try { if ([datetime]$t -gt (Get-Date).AddMinutes(-30)) { $starts += "$t" } } catch { } } }
    if ($starts.Count -ge 3) {
        Write-Log 'Агент на C# трижды завершился за 30 мин — возвращаю агент на PowerShell (до обновления Agent.cs или повторного выбора движка)' 'ERROR'
        $st.fallbackSig = $sig; Save-CsState $st
        return $false
    }
    $starts += (Get-Date).ToString('o')
    Save-CsState ([pscustomobject]@{ sig = $sig; starts = $starts; fallbackSig = "$($st.fallbackSig)" })
    $a = "`"$Root`""
    if ($ConfigPath -ne (Join-Path $Root 'config.json')) { $a += " `"$ConfigPath`"" }
    Start-Process -FilePath $CsAgentExe -ArgumentList $a -WorkingDirectory $Root | Out-Null
    Write-Log "Запущен агент на C# ($(Split-Path $CsAgentExe -Leaf)) — основной цикл теперь ведёт он"
    return $true
}

# агент на PowerShell работает, а в настройках выбрали C# — передать работу
function Test-HandToCs {
    if (-not (Test-CsAgentWanted)) {
        # вернулись на PowerShell — следующий выбор C# снова попробует его, даже если он раньше падал
        if ("$($Cfg.agent.engine)" -ne 'csharp') { $st = Get-CsState; if ($st.fallbackSig) { $st.fallbackSig = ''; Save-CsState $st } }
        return $false
    }
    Write-Log 'Выбран агент на C# — передаю ему работу' 'WARN'
    $t = Get-ScheduledTask -TaskName $AgentTask -ErrorAction SilentlyContinue
    if ($t -and $t.State -ne 'Disabled') { Start-Process cmd.exe -WindowStyle Hidden -ArgumentList "/c ping -n 6 127.0.0.1 >nul & schtasks /run /tn `"$AgentTask`"" }
    else { Start-Process powershell.exe -WindowStyle Hidden -WorkingDirectory $Root -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$SelfPath`" -Restarted" }
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
    function Write-StatusSnapshot { Write-PsStatus }  # вместо общего состояния (его пишет агент C#)
    try {
        # zapret ведёт сам агент на C# (Zapret.cs)
        foreach ($step in 'Invoke-Commands', 'Invoke-MeduzaUpdate', 'Invoke-SoftwareCheck', 'Invoke-RemoteWatch', 'Invoke-AppUpdateWatch', 'Invoke-TrayWatch') {
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

if ($Status) { Show-Status; return }

if (-not (Test-Admin)) {
    Write-Log 'Нужны права администратора' 'ERROR'
    exit 1
}

if ($SetupTask) { Invoke-SetupTask $SetupTask; return }
if ($Diag)      { try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch { }; Invoke-Diag -TryFix:$TryFix; return }
if ($ZapretTest) { Invoke-ZapretTestRun; return }
if ($RemoteServer) { Invoke-RemoteServer; return }
if ($WebTask) { Invoke-WebTask $WebTask $WebArg; return }
if ($CheckUpdate) { Invoke-MeduzaUpdate -Force; return }
if ($InstallCli)  { Update-MeduzaCli (Get-Release); return }
if ($PsPart)      { Invoke-PsPart; return }
# выбран агент на C#: собрать и запустить его (или он уже работает) — этот экземпляр не нужен
if (-not $Once -and (Test-CsAgentWanted)) { if (Start-CsAgent) { return } }

$mutex = New-Object System.Threading.Mutex($false, 'Global\VpnGuard')
# после самоперезапуска ждём, пока старый экземпляр освободит мьютекс
$gotMutex = $false
try { $gotMutex = $mutex.WaitOne($(if ($Restarted) { 60000 } else { 10000 })) } catch [Threading.AbandonedMutexException] { $gotMutex = $true }
if (-not $gotMutex) { return }   # уже работает другой экземпляр — молча выходим
$script:IsAgentLoop = $true

$SelfPath  = $MyInvocation.MyCommand.Path
function Get-CodeStamp { (@($SelfPath, $ZapretModule, $WgModule, $AmneziaModule, $SoftwareModule, $RemoteModule, $UpdateModule) | Where-Object { Test-Path $_ } | ForEach-Object { (Get-Item $_).LastWriteTimeUtc.Ticks }) -join '|' }
$SelfStamp = Get-CodeStamp

function Invoke-Tick {
    foreach ($step in 'Sync-Config', 'Invoke-Commands', 'Invoke-MeduzaUpdate', 'Invoke-WgWatch', 'Invoke-VpnWatch', 'Invoke-SharingWatch', 'Invoke-ZapretWatch', 'Invoke-SoftwareCheck', 'Invoke-RemoteWatch', 'Invoke-AppUpdateWatch', 'Invoke-TrayWatch') {
        try { & $step } catch { Write-Log "$step : $($_.Exception.Message)" 'ERROR' }
        Invoke-Heartbeat
    }
    $State.activity = ''
    try { Write-StatusSnapshot } catch { Write-Log "Write-StatusSnapshot : $($_.Exception.Message)" 'ERROR' }
}

# файл агента заменили (обновление) — запустить новый экземпляр и выйти
function Test-SelfUpdated {
    try { $now = Get-CodeStamp } catch { return $false }
    if ($now -eq $SelfStamp) { return $false }
    Start-Sleep -Seconds 2   # дать файлам дописаться
    foreach ($f in @($SelfPath, $ZapretModule, $WgModule, $AmneziaModule, $SoftwareModule, $RemoteModule, $UpdateModule) | Where-Object { Test-Path $_ }) {
        $err = $null
        [void][Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$err)
        if ($err.Count) {
            Write-Log "Новый $(Split-Path $f -Leaf) содержит ошибки ($($err[0].Message)) — продолжаю на текущей версии" 'ERROR'
            $script:SelfStamp = Get-CodeStamp
            return $false
        }
    }
    Write-Log 'Код агента обновлён — перезапускаю агент на новой версии'
    Set-Activity 'перезапуск агента на новой версии'
    $t = Get-ScheduledTask -TaskName $AgentTask -ErrorAction SilentlyContinue
    if ($t -and $t.State -ne 'Disabled') {
        # через задачу планировщика (через ~5 с, когда этот экземпляр уже завершится) —
        # тогда планировщик по-прежнему видит агента и перезапускает его при сбое
        Start-Process cmd.exe -WindowStyle Hidden -ArgumentList "/c ping -n 6 127.0.0.1 >nul & schtasks /run /tn `"$AgentTask`""
    } else {
        Start-Process powershell.exe -WindowStyle Hidden -WorkingDirectory $Root `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$SelfPath`" -Restarted"
    }
    return $true
}

try {
    Write-Log "VpnGuard $AgentVersion запущен (PID $PID)"
    Remove-OldLogs
    # сразу сообщить окну, что агент жив, не дожидаясь конца первой (долгой) проверки
    Set-Activity 'первая проверка после запуска'
    if ($Once) { Invoke-Tick; return }
    $lastCleanup = Get-Date
    while ($true) {
        Invoke-Tick
        if (Test-SelfUpdated) { break }
        if (Test-HandToCs) { break }
        if (((Get-Date) - $lastCleanup).TotalHours -ge 24) { Remove-OldLogs; $lastCleanup = Get-Date }
        # спим, но сразу просыпаемся, если монитор прислал команду
        for ($i = 0; $i -lt [int]$Cfg.checkIntervalSec; $i++) {
            Start-Sleep -Seconds 1
            if (Get-ChildItem $CmdDir -Filter '*.cmd' -ErrorAction SilentlyContinue) { break }
        }
    }
} finally {
    try { $mutex.ReleaseMutex() } catch { }
    $mutex.Dispose()
}
