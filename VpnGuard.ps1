#Requires -Version 5.1
<#
  VpnGuard — сторож для MeduzaVPN / AmneziaVPN, WireGuard-сервера wg_server, раздачи и zapret.

  Основной цикл ведёт агент на C# (Agent.cs, Zapret.cs, ClientZapret.cs → bin\VpnGuardAgent.exe).
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

$AgentVersion = '3.13.0'
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
        clientZapret     = $false                  # zapret и для клиентов: их трафик к адресам zapret агент пускает через zapret ПК (только агент на C#)
        clientNoZapret   = @()                     # IP клиентов, которым zapret не нужен — весь их трафик через VPN
        clientOff        = @()                     # IP отключённых клиентов — агент убирает их из работающего туннеля (конфиг не меняется)
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
        psPartMin = 30           # как часто агент на C# запускает часть PowerShell (обновления, компоненты, веб-сервер), мин
    }
    ui = @{
        tray = $true             # значок у часов вместо окна (ярлык VpnGuard открывает его; окно — в меню значка)
    }
    web = @{
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


function Test-MeduzaTraffic {
    $ip = Get-AdapterIPv4 $M.adapterName
    $ok = $false
    if ($ip) { foreach ($h in $M.probeHosts) { if (Test-TcpVia $ip $h) { $ok = $true; break } } }
    $State.lastTraffic = $ok
    $State.lastTrafficAt = Get-Date
    return $ok
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
    try { Write-PsStatus } catch { }
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
            Write-Host "Два туннеля: основной $(Get-DualPrimary), активный $(Get-DualActive), резерв горячий: $($Cfg.vpn.dualHot -ne $false)"
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
            Where-Object { $_.CommandLine -match 'VpnGuard\.ps1' -and $_.ProcessId -ne $PID -and $_.CommandLine -notmatch '-(Diag|ZapretTest|PsPart|WebTask)' })
        $procs += @(Get-CimInstance Win32_Process -Filter "Name='VpnGuardAgent.exe'")
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
# из Agent.cs + Zapret.cs + ClientZapret.cs. Он раз в 30 мин (или сразу по команде) запускает этот файл с -PsPart: обновления,
# компоненты, веб-сервер, значок. Подбор стратегии zapret — отдельным процессом -ZapretTest.

$CsAgentExe  = Join-Path $BinDir 'VpnGuardAgent.exe'
$PsStatusPath = Join-Path $DataDir 'status-ps.json'
$PsPartStatePath = Join-Path $DataDir 'pspart-state.xml'
$CsAgentSources = @('Agent.cs', 'Zapret.cs', 'ClientZapret.cs')
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
