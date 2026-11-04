#Requires -Version 5.1
<#
  VpnGuard — окно мониторинга и управления.
  Главная: общий статус, статистика, основные действия.
  Вкладки Туннель / MeduzaVPN / AmneziaVPN / WG-Server / ICS / zapret: подробности, история, графики, управление, события.
  Трафик: скорость сейчас (по счётчикам адаптеров, раз в секунду), за 2 часа и по дням.
  -Preview <png> — отрисовать окно в картинки и выйти (для проверки, без прав администратора).
  -StatusFile <json> — только с -Preview: взять состояние из этого файла.
#>
param([string]$Preview = '', [string]$StatusFile = '', [switch]$Demo, [switch]$Restarted)

$ErrorActionPreference = 'Stop'
$Root       = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentPs1   = Join-Path $Root 'VpnGuard.ps1'
$ConfigPath = Join-Path $Root 'config.json'
$DataDir    = Join-Path $Root 'data'
$StatusPath = Join-Path $DataDir 'status.json'
$CmdDir     = Join-Path $DataDir 'cmd'
$LogDir     = Join-Path $DataDir 'logs'
$AgentTask  = 'VpnGuard'
$MonitorTask = 'VpnGuardMonitor'
if (($Preview -or $Demo) -and $StatusFile) {
    $StatusPath = $StatusFile
    $dl = Join-Path (Split-Path $StatusFile) 'logs'
    if (Test-Path $dl) { $LogDir = $dl }
}

# ---------------------------------------------------------------- права администратора
$isAdmin = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $Preview -and -not $Demo) {
    Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
    return
}

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# ---------------------------------------------------------------- один экземпляр
$showEvt = $null
if (-not $Preview -and -not $Demo) {
    $created = $false
    $script:mutex = New-Object Threading.Mutex($true, 'Global\VpnGuardMonitor', [ref]$created)
    $showEvt = New-Object Threading.EventWaitHandle($false, [Threading.EventResetMode]::AutoReset, 'Global\VpnGuardMonitorShow')
    # после самообновления новое окно ждёт, пока старое закроется
    if (-not $created -and $Restarted) { try { $created = $script:mutex.WaitOne(20000) } catch [Threading.AbandonedMutexException] { $created = $true } }
    if (-not $created) { [void]$showEvt.Set(); return }
}
foreach ($d in $DataDir, $CmdDir, $LogDir) { if (-not (Test-Path $d)) { New-Item -ItemType Directory $d -Force | Out-Null } }

[Windows.Forms.Application]::EnableVisualStyles()

# ---------------------------------------------------------------- оформление
function C([string]$h) { [Drawing.ColorTranslator]::FromHtml($h) }
$Clr = @{
    Bg = C '#14161b'; Nav = C '#1b1e24'; Card = C '#21252d'; Border = C '#30353f'; Row = C '#252a33'; Grid = C '#2e333d'
    Text = C '#e6e8eb'; Dim = C '#8f96a0'; Ok = C '#3fb950'; Warn = C '#d29922'; Bad = C '#f85149'
    None = C '#4a505a'; Accent = C '#4c8dff'; Btn = C '#2b3039'; BtnHover = C '#363c47'; Input = C '#191c22'
    Rx = C '#3987e5'; Tx = C '#d95926'; Tip = C '#2c313b'
}
$LevelColor = @{ 0 = $Clr.Ok; 1 = $Clr.Warn; 2 = $Clr.Bad; -1 = $Clr.None }
$LevelName  = @{ 0 = 'работает'; 1 = 'предупреждение'; 2 = 'сбой'; -1 = 'нет данных / выключено' }
$F = @{
    Base  = New-Object Drawing.Font('Segoe UI', 9.5)
    Small = New-Object Drawing.Font('Segoe UI', 8.5)
    Bold  = New-Object Drawing.Font('Segoe UI Semibold', 10)
    H2    = New-Object Drawing.Font('Segoe UI Semibold', 12)
    Tile  = New-Object Drawing.Font('Segoe UI Semibold', 11)
    Big   = New-Object Drawing.Font('Segoe UI Semibold', 15)
    Kpi   = New-Object Drawing.Font('Segoe UI Semibold', 14)
    Hero  = New-Object Drawing.Font('Segoe UI Semibold', 19)
    Title = New-Object Drawing.Font('Segoe UI Semibold', 16)
    Logo  = New-Object Drawing.Font('Segoe UI Semibold', 15)
    Nav   = New-Object Drawing.Font('Segoe UI', 10.5)
    Mono  = New-Object Drawing.Font('Consolas', 9.5)
}
$Brushes = @{}
foreach ($k in $LevelColor.Keys) { $Brushes[$k] = New-Object Drawing.SolidBrush $LevelColor[$k] }
$Br = @{
    Rx = New-Object Drawing.SolidBrush $Clr.Rx; Tx = New-Object Drawing.SolidBrush $Clr.Tx
    RxFill = New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(64, $Clr.Rx))
    Card = New-Object Drawing.SolidBrush $Clr.Card; Bg = New-Object Drawing.SolidBrush $Clr.Bg
    Row = New-Object Drawing.SolidBrush $Clr.Row; Tip = New-Object Drawing.SolidBrush $Clr.Tip
    Accent = New-Object Drawing.SolidBrush $Clr.Accent; Track = New-Object Drawing.SolidBrush $Clr.Btn
}
$Pens = @{
    Grid = New-Object Drawing.Pen $Clr.Grid, 1
    Rx = New-Object Drawing.Pen $Clr.Rx, 2; Tx = New-Object Drawing.Pen $Clr.Tx, 2
    Cross = New-Object Drawing.Pen $Clr.Dim, 1; Tl = New-Object Drawing.Pen $Clr.Text, 1
}
foreach ($pn in $Pens.Rx, $Pens.Tx) { $pn.LineJoin = 'Round' }

# двойная буферизация — без мерцания при обновлении
$dbProp = [Windows.Forms.Control].GetProperty('DoubleBuffered', [Reflection.BindingFlags]'NonPublic,Instance')

function New-Label([string]$Text, $Font = $F.Base, $Color = $Clr.Text) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $Text; $l.Font = $Font; $l.ForeColor = $Color; $l.AutoSize = $true; $l.BackColor = [Drawing.Color]::Transparent
    $l
}

function New-Btn([string]$Text, [scriptblock]$OnClick, [bool]$Primary = $false) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $Text; $b.Font = $F.Base; $b.FlatStyle = 'Flat'; $b.Cursor = 'Hand'
    $b.ForeColor = $Clr.Text
    $b.BackColor = $(if ($Primary) { $Clr.Accent } else { $Clr.Btn })
    $b.FlatAppearance.BorderColor = $(if ($Primary) { $Clr.Accent } else { $Clr.Border })
    $b.FlatAppearance.MouseOverBackColor = $(if ($Primary) { C '#6aa1ff' } else { $Clr.BtnHover })
    $b.AutoSize = $true; $b.AutoSizeMode = 'GrowAndShrink'; $b.Padding = '10,3,10,3'; $b.Margin = '0,0,8,0'
    $b.UseVisualStyleBackColor = $false
    # выключенная кнопка — серая, иначе синяя «основная» кнопка выглядит активной
    $b.Tag = @{ Back = $b.BackColor; Border = $b.FlatAppearance.BorderColor }
    $b.Add_EnabledChanged({
        param($s, $e)
        if ($s.Enabled) { $s.BackColor = $s.Tag.Back; $s.FlatAppearance.BorderColor = $s.Tag.Border }
        else { $s.BackColor = $Clr.Nav; $s.FlatAppearance.BorderColor = $Clr.Border }
    })
    $b.Add_Click($OnClick)
    $b
}

function New-Dot([int]$Size = 12) {
    $d = New-Object Windows.Forms.Panel
    $d.Size = New-Object Drawing.Size($Size, $Size)
    $gp = New-Object Drawing.Drawing2D.GraphicsPath
    $gp.AddEllipse(0, 0, $Size, $Size)
    $d.Region = New-Object Drawing.Region($gp)
    $d.BackColor = $Clr.None
    $d
}

function New-AppIcon {
    $bmp = New-Object Drawing.Bitmap 32, 32
    $g = [Drawing.Graphics]::FromImage($bmp); $g.SmoothingMode = 'AntiAlias'
    $g.FillEllipse((New-Object Drawing.SolidBrush $Clr.Accent), 1, 1, 30, 30)
    $pen = New-Object Drawing.Pen ([Drawing.Color]::White), 3
    $g.DrawLines($pen, [Drawing.Point[]]@((New-Object Drawing.Point 9, 16), (New-Object Drawing.Point 14, 21), (New-Object Drawing.Point 23, 11)))
    $g.Dispose()
    [Drawing.Icon]::FromHandle($bmp.GetHicon())
}

# менять свойство только при реальном изменении — иначе лишние перерисовки
function Set-Prop($Ctl, [string]$Name, $Value) { if ($Ctl.$Name -ne $Value) { $Ctl.$Name = $Value } }

# ---------------------------------------------------------------- форматирование
function Format-Bytes([double]$b) {
    if ($b -ge 1TB) { '{0:0.00} ТБ' -f ($b / 1TB) } elseif ($b -ge 1GB) { '{0:0.00} ГБ' -f ($b / 1GB) }
    elseif ($b -ge 1MB) { '{0:0.0} МБ' -f ($b / 1MB) } elseif ($b -ge 1KB) { '{0:0} КБ' -f ($b / 1KB) } else { '{0:0} Б' -f $b }
}
# скорость: байт/с на входе, на экране — биты (как у провайдеров)
function Format-Rate([double]$v) {
    $b = $v * 8
    if ($b -ge 1e9) { '{0:0.##} Гбит/с' -f ($b / 1e9) } elseif ($b -ge 1e6) { '{0:0.#} Мбит/с' -f ($b / 1e6) }
    elseif ($b -ge 1e3) { '{0:0} Кбит/с' -f ($b / 1e3) } else { '{0:0} бит/с' -f $b }
}
function Get-NiceMax([double]$v) {
    $bits = [Math]::Max(8000.0, $v * 8 * 1.08)
    $e = [Math]::Floor([Math]::Log10($bits)); $b = [Math]::Pow(10, $e); $m = $bits / $b
    $n = $(if ($m -le 1) { 1 } elseif ($m -le 2) { 2 } elseif ($m -le 5) { 5 } else { 10 })
    return $n * $b / 8
}
function Format-Ago([double]$sec) {
    if ($sec -lt 0) { return 'не было' }
    if ($sec -lt 60) { return '{0:0} с назад' -f $sec }
    if ($sec -lt 3600) { return '{0:0} мин назад' -f ($sec / 60) }
    if ($sec -lt 86400) { return '{0:0} ч назад' -f ($sec / 3600) }
    return '{0:0} дн назад' -f ($sec / 86400)
}
function Format-Span([double]$sec) {
    if ($sec -ge 3600) { $h = $sec / 3600; return $(if ($h -eq [Math]::Floor($h)) { '−{0:0} ч' -f $h } else { '−{0:0.#} ч' -f $h }) }
    return '−{0:0} мин' -f ($sec / 60)
}
function From-Unix([long]$t) { [DateTimeOffset]::FromUnixTimeSeconds($t).LocalDateTime }

# ---------------------------------------------------------------- агент: состояние и управление
# Медленные запросы (планировщик ~0.8 с, список процессов ~0.2 с) выполняются в фоне,
# чтобы окно не замирало. Результаты забираются таймером.
$script:bg = @{}
$script:taskInfo = $null
$script:lastBgPoll = [datetime]::MinValue

function Start-Bg([string]$Key, [scriptblock]$Work, [object[]]$Arguments = @()) {
    $j = $script:bg[$Key]
    if ($j -and -not $j.Handle.IsCompleted) { return $false }
    $ps = [powershell]::Create()
    [void]$ps.AddScript($Work.ToString())
    foreach ($av in $Arguments) { [void]$ps.AddArgument($av) }
    $script:bg[$Key] = @{ PS = $ps; Handle = $ps.BeginInvoke() }
    return $true
}

function Receive-Bg([string]$Key) {
    $j = $script:bg[$Key]
    if (-not $j -or -not $j.Handle.IsCompleted) { return $null }
    $script:bg.Remove($Key)
    try { $r = $j.PS.EndInvoke($j.Handle) } catch { $r = $null } finally { $j.PS.Dispose() }
    if ($r -and $r.Count -gt 0) { return $r[0] }
    return $null
}

$QueryAgent = {
    param($AgentTask, $MonitorTask)
    $at = Get-ScheduledTask -TaskName $AgentTask -ErrorAction SilentlyContinue
    $mt = Get-ScheduledTask -TaskName $MonitorTask -ErrorAction SilentlyContinue
    $pids = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'VpnGuard\.ps1' -and $_.CommandLine -notmatch '-(Status|Once|CheckUpdate|InstallCli|SetupTask|Diag|ZapretTest|RemoteServer)' } |
        ForEach-Object { [int]$_.ProcessId })
    [pscustomobject]@{
        Agent           = $(if ($at) { "$($at.State)" } else { $null })
        MonitorTriggers = $(if ($mt) { @($mt.Triggers).Count } else { -1 })
        AgentPids       = $pids
    }
}

function Request-AgentInfo { [void](Start-Bg 'agentinfo' $QueryAgent @($AgentTask, $MonitorTask)); $script:lastBgPoll = Get-Date }

function Receive-Background {
    $r = Receive-Bg 'agentinfo'
    if ($r) { $script:taskInfo = $r }
    $c = Receive-Bg 'agentctl'
    if ($c) { Set-Footer "$c"; Request-AgentInfo }
    if (((Get-Date) - $script:lastBgPoll).TotalSeconds -ge 15) { Request-AgentInfo }
}

# быстро (без WMI): процесс с PID из status.json жив, либо фоновый опрос нашёл агента
function Test-AgentAlive {
    if ($script:snap -and $script:snap.agentPid) {
        $p = Get-Process -Id ([int]$script:snap.agentPid) -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -in 'powershell', 'VpnGuardAgent') { return $true }
    }
    return [bool]($script:taskInfo -and @($script:taskInfo.AgentPids).Count -gt 0)
}

$AgentCtl = {
    param($Action, $AgentTask, $AgentPs1)
    try {
        $t = Get-ScheduledTask -TaskName $AgentTask -ErrorAction SilentlyContinue
        if ($Action -eq 'start') {
            if ($t) {
                if ($t.State -eq 'Disabled') { Enable-ScheduledTask -TaskName $AgentTask | Out-Null }
                Start-ScheduledTask -TaskName $AgentTask
            } else {
                Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AgentPs1`""
            }
            'Агент запущен'
        } else {
            if ($t) { Stop-ScheduledTask -TaskName $AgentTask -ErrorAction SilentlyContinue; Disable-ScheduledTask -TaskName $AgentTask | Out-Null }
            Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
                Where-Object { $_.CommandLine -match 'VpnGuard\.ps1' -and $_.CommandLine -notmatch '-(Status|Once|CheckUpdate|InstallCli|SetupTask|Diag)' } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            'Агент остановлен'
        }
    } catch { "Ошибка: $($_.Exception.Message)" }
}

function Start-Agent {
    if (Start-Bg 'agentctl' $AgentCtl @('start', $AgentTask, $AgentPs1)) { Set-Footer 'Агент запускается…' }
}

function Stop-Agent {
    $r = [Windows.Forms.MessageBox]::Show("Остановить агент?`n`nПока он остановлен, MeduzaVPN, wg_server и раздача не восстанавливаются автоматически, а автозапуск агента выключен до нажатия «Запустить».",
        'VpnGuard', 'YesNo', 'Warning')
    if ($r -ne 'Yes') { return }
    if (Start-Bg 'agentctl' $AgentCtl @('stop', $AgentTask, $AgentPs1)) {
        $script:snap = $null; $script:statusStamp = $null
        if ($script:taskInfo) { $script:taskInfo.AgentPids = @() }
        Set-Footer 'Агент останавливается…'
    }
}

function Send-Cmd([string]$Action, [string]$Label) {
    if ($Demo) { Set-Footer "ДЕМО: команда «$Label» не отправлена — это тестовые данные"; return }
    if (-not (Test-AgentAlive)) {
        $r = [Windows.Forms.MessageBox]::Show("Агент не запущен — команду некому выполнить.`n`nЗапустить агент?", 'VpnGuard', 'YesNo', 'Question')
        if ($r -ne 'Yes') { return }
        Start-Agent
    }
    $fp = Join-Path $CmdDir ('{0}.cmd' -f [DateTime]::UtcNow.Ticks)
    Set-Content -Path $fp -Value $Action -Encoding ASCII
    Set-Footer "Отправлено агенту: $Label"
}

function Switch-Zapret {
    $on = [bool]($script:snap -and $script:snap.zapret -and $script:snap.zapret.enabled)
    if ($on) { Send-Cmd 'zapret-off' 'выключение zapret'; return }
    $r = [Windows.Forms.MessageBox]::Show(("Включить zapret?`n`n" +
        "YouTube и Discord на этом компьютере пойдут мимо VPN — через zapret.`n`n" +
        "Важно: zapret работает только для самого компьютера. У клиентов wg_server YouTube и Discord, " +
        "пока zapret включён, могут не открываться. Выключите zapret — и всё снова пойдёт через VPN.`n`n" +
        "При первом включении zapret скачается с GitHub и подберёт рабочую стратегию (2–4 минуты)."),
        'VpnGuard — zapret', 'YesNo', 'Question')
    if ($r -eq 'Yes') { Send-Cmd 'zapret-on' 'включение zapret' }
}

# ---------------------------------------------------------------- WS4W: клиенты, конфиги, QR
$State = $null
$W = @{}
function Update-WsCfg {
    # настройки ws4w из config.json поверх значений по умолчанию (как у агента)
    $d = @{ interfaceName = 'wg_server'; serviceName = 'WireGuardTunnel$wg_server'; configPath = ''; wireguardExe = 'C:\Program Files\WireGuard\wireguard.exe'
            serverAddress = ''; endpoint = ''; clientDns = ''; autoCreateServer = $true; newServerAddress = '10.253.0.1/24'; newServerPort = 51820 }
    try {
        if (Test-Path $ConfigPath) {
            $o = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($o.PSObject.Properties['ws4w']) { foreach ($p in $o.ws4w.PSObject.Properties) { $d[$p.Name] = $p.Value } }
        }
    } catch { }
    $script:W = $d
}
Update-WsCfg
$WgModulePath = Join-Path $Root 'Wg.ps1'
if (Test-Path $WgModulePath) { . $WgModulePath }

# AmneziaVPN: настройки модуля (путь к приложению, имя службы, адаптер)
$A = @{ exe = ''; serviceName = 'AmneziaVPN-service'; adapterPattern = 'amnezia|tun2socks|TAP-Windows Adapter V9' }
function Update-ACfg {
    try {
        if (Test-Path $ConfigPath) {
            $o = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($o.PSObject.Properties['amnezia']) { foreach ($p in $o.amnezia.PSObject.Properties) { $script:A[$p.Name] = $p.Value } }
        }
    } catch { }
}
Update-ACfg
$AmneziaModulePath = Join-Path $Root 'Amnezia.ps1'
if (Test-Path $AmneziaModulePath) { . $AmneziaModulePath }

function Get-Mode { $v = Get-Snap 'vpn'; if ($v -and $v.mode) { return "$($v.mode)" }; try { $o = Read-ConfigObject; $m = Get-CfgVal $o 'vpn.mode'; if ($m) { return "$m" } } catch { }; return 'meduza' }
$ModeItems = @(@('meduza', 'MeduzaVPN'), @('amnezia', 'AmneziaVPN'), @('dual', 'Два туннеля (с переключением)'), @('zapret', 'Без VPN — только zapret'))

function Set-ModeUi([string]$Mode) {
    $cur = Get-Mode
    if ($Mode -eq $cur) { return }
    $nm = ($ModeItems | Where-Object { $_[0] -eq $Mode })[1]
    $msg = switch ($Mode) {
        'meduza'  { "Переключиться на MeduzaVPN?`n`nAmneziaVPN будет отключён, агент запустит MeduzaVPN и подключит его." }
        'dual'    { "Включить режим «два туннеля»?`n`nАгент держит поднятыми оба туннеля — MeduzaVPN и AmneziaVPN. Трафик и раздача идут через основной (настройка «Основной туннель»), а если он перестаёт пропускать трафик — сразу переключаются на второй. Когда основной снова заработает, трафик вернётся на него.`n`nНужны: MeduzaVPN с управлением из командной строки и AmneziaVPN с включённым автоподключением." }
        'amnezia' { "Переключиться на AmneziaVPN?`n`nMeduzaVPN будет отключён и закрыт, агент запустит AmneziaVPN (сервер выбирается в самом приложении).`nAmneziaVPN ставится на вкладке «Компоненты»." }
        'zapret'  { "Отключить VPN?`n`nЭтот ПК будет выходить в интернет напрямую, YouTube и Discord — через zapret (он включится сам).`n`nКлиенты WG-Server тоже получат интернет напрямую — без VPN и без zapret (zapret работает только для самого ПК)." }
    }
    $ans = [Windows.Forms.MessageBox]::Show($msg, "VpnGuard — режим: $nm", 'YesNo', 'Question')
    if ($ans -ne 'Yes') { $script:ModeSig = ''; return }
    if ($Demo) { Set-Footer "ДЕМО: режим «$nm» не сохранён"; $script:ModeSig = ''; return }
    try {
        $o = Read-ConfigObject; Set-CfgVal $o 'vpn.mode' $Mode
        $tmp = "$ConfigPath.tmp"; $o | ConvertTo-Json -Depth 6 | Set-Content $tmp -Encoding UTF8; Move-Item $tmp $ConfigPath -Force
        Set-Footer "Режим «$nm» сохранён — агент переключит его на следующей проверке"
        Send-Cmd 'check-now' 'переключение режима'
    } catch { [Windows.Forms.MessageBox]::Show("Не удалось сохранить: $($_.Exception.Message)", 'VpnGuard', 'OK', 'Error') | Out-Null }
}

$script:WgList = $null; $script:WgListErr = ''; $script:WgListAt = [datetime]::MinValue
function Update-WgList([switch]$Force) {
    if (-not $Force -and ((Get-Date) - $script:WgListAt).TotalSeconds -lt 30) { return }
    $script:WgListAt = Get-Date
    if ($Demo) { $script:WgList = $null; $script:WgListErr = ''; return }
    if (-not (Get-Command Get-WgClients -ErrorAction SilentlyContinue)) { $script:WgListErr = 'нет модуля Wg.ps1 рядом с окном'; return }
    try { Update-WsCfg; $script:WgList = Get-WgClients; $script:WgListErr = '' }
    catch { $script:WgList = $null; $script:WgListErr = $_.Exception.Message }
}

# строки таблицы клиентов: список из конфига сервера + живая статистика из снимка агента
function Get-PeerRows {
    $live = @(Get-Peers)
    if (-not $script:WgList) { return @($live | ForEach-Object { $_ | Add-Member -NotePropertyName source -NotePropertyValue '' -PassThru -Force }) }
    @(foreach ($c in $script:WgList.Clients) {
        $l = $live | Where-Object { $_.ip -eq $c.Ip } | Select-Object -First 1
        [pscustomobject]@{
            name = $c.Name; ip = $c.Ip; key = $(if ($l) { $l.key } else { $c.PublicKey.Substring(0, [Math]::Min(8, $c.PublicKey.Length)) })
            endpoint = $(if ($l) { $l.endpoint } else { '' }); hsAgo = $(if ($l) { $l.hsAgo } else { -1 }); active = [bool]($l -and $l.active)
            rx = $(if ($l) { $l.rx } else { 0 }); tx = $(if ($l) { $l.tx } else { 0 })
            source = $c.Source; file = $c.File; pub = $c.PublicKey
        }
    })
}

$script:QrLoaded = $false
function New-QrBitmap([string]$Text, [int]$Px = 6) {
    if (-not $script:QrLoaded) {
        Add-Type -TypeDefinition (Get-Content (Join-Path $Root 'Qr.cs') -Raw -Encoding UTF8)
        $script:QrLoaded = $true
    }
    $m = [VpnGuard.Qr]::Encode($Text, 1, 0, -1)   # уровень M
    $n = $m.GetLength(0); $q = 4
    $bmp = New-Object Drawing.Bitmap (($n + 2 * $q) * $Px), (($n + 2 * $q) * $Px)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.Clear([Drawing.Color]::White)
    for ($y = 0; $y -lt $n; $y++) { for ($x = 0; $x -lt $n; $x++) { if ($m[$y, $x]) { $g.FillRectangle([Drawing.Brushes]::Black, ($x + $q) * $Px, ($y + $q) * $Px, $Px, $Px) } } }
    $g.Dispose()
    $bmp
}

function Show-ClientConfig([string]$Name, [string]$Text) {
    $dlg = New-Object Windows.Forms.Form
    $dlg.Text = "Клиент WireGuard — $Name"; $dlg.StartPosition = 'CenterParent'; $dlg.Size = New-Object Drawing.Size(900, 600)
    $dlg.BackColor = $Clr.Bg; $dlg.ForeColor = $Clr.Text; $dlg.Font = $F.Base; $dlg.MinimizeBox = $false; $dlg.Icon = $form.Icon
    $pic = New-Object Windows.Forms.PictureBox
    $pic.Location = New-Object Drawing.Point(20, 20); $pic.Size = New-Object Drawing.Size(420, 420); $pic.SizeMode = 'Zoom'; $pic.BackColor = [Drawing.Color]::White
    try { $pic.Image = New-QrBitmap $Text 8 } catch { $pic.BackColor = $Clr.Card; Set-Footer "QR не построен: $($_.Exception.Message)" }
    $hint = New-Label "Сканируйте в приложении WireGuard: «+» → «Сканировать QR-код».`nВ конфиге закрытый ключ клиента — не публикуйте его." $F.Small $Clr.Dim
    $hint.Location = New-Object Drawing.Point(20, 450)
    $tb = New-Object Windows.Forms.TextBox
    $tb.Multiline = $true; $tb.ReadOnly = $true; $tb.ScrollBars = 'Both'; $tb.WordWrap = $false; $tb.Font = $F.Mono
    $tb.BackColor = $Clr.Card; $tb.ForeColor = $Clr.Text; $tb.BorderStyle = 'None'
    $tb.Location = New-Object Drawing.Point(460, 20); $tb.Size = New-Object Drawing.Size(410, 420); $tb.Anchor = 'Top,Left,Right,Bottom'
    $tb.Text = ($Text -replace "`r?`n", "`r`n")
    $bf = New-Object Windows.Forms.FlowLayoutPanel
    $bf.AutoSize = $true; $bf.Location = New-Object Drawing.Point(460, 456); $bf.BackColor = $Clr.Bg; $bf.Anchor = 'Bottom,Left'
    $safe = $Name -replace '[^\w\-\.]', '_'
    $bf.Controls.AddRange(@(
        (New-Btn 'Копировать' { [Windows.Forms.Clipboard]::SetText($tb.Text); Set-Footer 'Конфиг клиента скопирован' }),
        (New-Btn 'Сохранить .conf…' {
            $sd = New-Object Windows.Forms.SaveFileDialog
            $sd.Filter = 'WireGuard (*.conf)|*.conf'; $sd.FileName = "$safe.conf"; $sd.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            if ($sd.ShowDialog() -eq 'OK') { [IO.File]::WriteAllText($sd.FileName, $tb.Text, (New-Object Text.UTF8Encoding $false)) }
        }),
        (New-Btn 'Сохранить QR (PNG)…' {
            if (-not $pic.Image) { return }
            $sd = New-Object Windows.Forms.SaveFileDialog
            $sd.Filter = 'PNG (*.png)|*.png'; $sd.FileName = "$safe.png"; $sd.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            if ($sd.ShowDialog() -eq 'OK') { $pic.Image.Save($sd.FileName, [Drawing.Imaging.ImageFormat]::Png) }
        }),
        (New-Btn 'Закрыть' { $dlg.Close() } $true)
    ))
    $dlg.Controls.AddRange(@($pic, $hint, $tb, $bf))
    [void]$dlg.ShowDialog($form)
    if ($pic.Image) { $pic.Image.Dispose() }
}

function Read-InputBox([string]$Title, [string]$Prompt, [string]$Default = '') {
    $dlg = New-Object Windows.Forms.Form
    $dlg.Text = $Title; $dlg.StartPosition = 'CenterParent'; $dlg.Size = New-Object Drawing.Size(460, 190); $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false; $dlg.BackColor = $Clr.Bg; $dlg.ForeColor = $Clr.Text; $dlg.Font = $F.Base
    $l = New-Label $Prompt $F.Base $Clr.Text; $l.Location = New-Object Drawing.Point(18, 16)
    $tb = New-Object Windows.Forms.TextBox
    $tb.Location = New-Object Drawing.Point(20, 46); $tb.Width = 400; $tb.Text = $Default; $tb.BackColor = $Clr.Input; $tb.ForeColor = $Clr.Text; $tb.BorderStyle = 'FixedSingle'
    $ok = New-Object Windows.Forms.Button; $ok.Text = 'Создать'; $ok.DialogResult = 'OK'; $ok.Location = New-Object Drawing.Point(234, 92); $ok.Size = New-Object Drawing.Size(90, 30)
    $cn = New-Object Windows.Forms.Button; $cn.Text = 'Отмена'; $cn.DialogResult = 'Cancel'; $cn.Location = New-Object Drawing.Point(330, 92); $cn.Size = New-Object Drawing.Size(90, 30)
    foreach ($b in $ok, $cn) { $b.FlatStyle = 'Flat'; $b.BackColor = $Clr.Btn; $b.ForeColor = $Clr.Text; $b.FlatAppearance.BorderColor = $Clr.Border }
    $ok.BackColor = $Clr.Accent
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cn
    $dlg.Controls.AddRange(@($l, $tb, $ok, $cn))
    if ($dlg.ShowDialog($form) -eq 'OK') { return $tb.Text.Trim() }
    return $null
}

function New-DemoKey { $b = New-Object byte[] 32; (New-Object Random).NextBytes($b); [Convert]::ToBase64String($b) }

function Add-WgClientUi {
    $name = Read-InputBox 'Новый клиент WireGuard' 'Имя клиента (например, phone или ноутбук-папы):'
    if (-not $name) { return }
    if ($Demo) {
        $txt = "[Interface]`r`nPrivateKey = $(New-DemoKey)`r`nAddress = 192.168.15.9/32`r`nDNS = 192.168.15.1`r`n`r`n[Peer]`r`nPublicKey = $(New-DemoKey)`r`nPresharedKey = $(New-DemoKey)`r`nAllowedIPs = 0.0.0.0/0`r`nEndpoint = 203.0.113.10:51820`r`nPersistentKeepalive = 25"
        Set-Footer "ДЕМО: клиент «$name» не создан — показан пример конфига со случайными ключами"
        Show-ClientConfig "$name (демо)" $txt
        return
    }
    $form.Cursor = 'WaitCursor'
    try {
        Update-WsCfg
        $c = New-WgClient $name
        Set-Footer "Клиент «$($c.Name)» создан: $($c.Ip), подключение к $($c.Endpoint)"
        Update-WgList -Force; Invalidate-Visible
        $form.Cursor = 'Default'
        Show-ClientConfig $c.Name $c.Text
    } catch {
        $form.Cursor = 'Default'
        [Windows.Forms.MessageBox]::Show("Не удалось создать клиента:`n$($_.Exception.Message)", 'VpnGuard', 'OK', 'Error') | Out-Null
    } finally { $form.Cursor = 'Default' }
}

function Get-SelectedPeer {
    $rows = @(Get-PeerRows)
    $r = $rows | Where-Object { $_.ip -eq $script:SelPeer } | Select-Object -First 1
    if (-not $r) { [Windows.Forms.MessageBox]::Show('Выберите клиента в таблице (щелчок по строке).', 'VpnGuard') | Out-Null }
    return $r
}

function Show-WgClientUi {
    $r = Get-SelectedPeer; if (-not $r) { return }
    if ($Demo) {
        Show-ClientConfig "$($r.name) (демо)" "[Interface]`r`nPrivateKey = $(New-DemoKey)`r`nAddress = $($r.ip)/32`r`nDNS = 192.168.15.1`r`n`r`n[Peer]`r`nPublicKey = $(New-DemoKey)`r`nAllowedIPs = 0.0.0.0/0`r`nEndpoint = 203.0.113.10:51820`r`nPersistentKeepalive = 25"
        return
    }
    if (-not $r.file -or -not (Test-Path $r.file)) {
        [Windows.Forms.MessageBox]::Show("Конфиг клиента «$($r.name)» не найден на этом ПК — закрытый ключ клиента хранится только на его устройстве.`n`nМожно удалить этого клиента и создать заново.", 'VpnGuard') | Out-Null
        return
    }
    Show-ClientConfig $r.name ([IO.File]::ReadAllText($r.file))
}

function Remove-WgClientUi {
    $r = Get-SelectedPeer; if (-not $r) { return }
    $ans = [Windows.Forms.MessageBox]::Show("Удалить клиента «$($r.name)» ($($r.ip))?`n`nОн сразу перестанет подключаться. Копия конфига сервера сохранится в data\backup.", 'VpnGuard', 'YesNo', 'Warning')
    if ($ans -ne 'Yes') { return }
    if ($Demo) { Set-Footer "ДЕМО: клиент «$($r.name)» не удалён"; return }
    try {
        Update-WsCfg
        $n = Remove-WgClient $r.pub
        Set-Footer "Клиент «$n» удалён"
        $script:SelPeer = ''
        Update-WgList -Force; Invalidate-Visible
    } catch { [Windows.Forms.MessageBox]::Show("Не удалось удалить:`n$($_.Exception.Message)", 'VpnGuard', 'OK', 'Error') | Out-Null }
}

function Invalidate-Visible {
    foreach ($c in $script:Canvases) {
        $sp = $c.Tag
        if ($sp.Rows) { $h = [int](& $sp.Rows); if ($h -gt 0) { Set-Prop $c Height $h } }
        if ($c.Visible) { $c.Invalidate() }
    }
}
$script:SelPeer = ''

function Open-Ws4w {
    $cands = @("$env:ProgramFiles\WS4W\ws4w.exe", "${env:ProgramFiles(x86)}\WS4W\ws4w.exe", "$env:LOCALAPPDATA\Programs\WS4W\ws4w.exe")
    $lnk = Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs", ([Environment]::GetFolderPath('Programs')) -Recurse -Filter '*WS4W*.lnk' -ErrorAction SilentlyContinue | Select-Object -First 1
    $exe = $cands | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($exe) { Start-Process $exe } elseif ($lnk) { Start-Process $lnk.FullName }
    else { [Windows.Forms.MessageBox]::Show('WS4W не найден. Запустите его вручную.', 'VpnGuard') | Out-Null }
}

# ---------------------------------------------------------------- данные для экрана
$script:snap = $null
$script:fresh = $null
$script:statusStamp = $null
$script:Level = @{}
$CompKeys = @('meduza', 'ultra', 'wg', 'ics', 'zapret', 'amnezia')

function Get-Snap([string]$Key) {
    $s = $script:snap
    if ($s -and $s.PSObject.Properties[$Key]) { return $s.$Key }
    return $null
}

# живой трафик: счётчики байт адаптеров из .NET раз в секунду (доли миллисекунды, без WMI)
$LiveSlots = 300
$script:Live = @{ u = New-Object Collections.ArrayList; w = New-Object Collections.ArrayList; p = New-Object Collections.ArrayList; z = New-Object Collections.ArrayList }
$script:LiveBase = @{}
$script:LiveSw = [Diagnostics.Stopwatch]::StartNew()

function Get-AdapterNames {
    $n = @{ u = 'MeduzaVPN ULTRA'; w = 'wg_server'; p = '' }
    $tr = Get-Snap 'traffic'
    if ($tr -and $tr.names) { foreach ($k in 'u', 'w', 'p') { if ($tr.names.$k) { $n[$k] = "$($tr.names.$k)" } } }
    if (-not $n.p) {
        # агент старой версии: физический адаптер — работающий, со шлюзом, не туннель
        foreach ($ni in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($ni.OperationalStatus -ne 'Up' -or $ni.Name -eq $n.u -or $ni.Name -eq $n.w) { continue }
            if ("$($ni.NetworkInterfaceType)" -notmatch 'Ethernet|Wireless') { continue }
            try { if (@($ni.GetIPProperties().GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and "$($_.Address)" -ne '0.0.0.0' }).Count) { $n.p = $ni.Name; break } } catch { }
        }
    }
    return $n
}
$script:AdNames = $null; $script:AdNamesAt = [datetime]::MinValue

$script:DemoRnd = New-Object Random 3
function Update-LiveTraffic {
    if ($Demo) {
        # демо: правдоподобная скорость вместо счётчиков адаптеров
        $script:AdNames = @{ u = 'MeduzaVPN ULTRA'; w = 'wg_server'; p = 'Ethernet 2' }
        $t = $script:LiveSw.Elapsed.TotalSeconds
        $base = 700000 + 450000 * [Math]::Sin($t / 20) + $script:DemoRnd.Next(0, 350000)
        $byp = 120000 + 90000 * [Math]::Sin($t / 7) + $script:DemoRnd.Next(0, 60000)
        $vals = @{ u = @($base, ($base / 9)); w = @(($base * 0.62), ($base / 14)); p = @(($base * 1.68 + $byp), ($base / 9 + $base / 14 + $byp / 6)) }
        foreach ($k in 'u', 'w', 'p') {
            [void]$script:Live[$k].Add([double[]]$vals[$k])
            while ($script:Live[$k].Count -gt $LiveSlots) { $script:Live[$k].RemoveAt(0) }
        }
        Add-LiveBypass
        return
    }
    if (-not $script:AdNames -or ((Get-Date) - $script:AdNamesAt).TotalSeconds -ge 30) { $script:AdNames = Get-AdapterNames; $script:AdNamesAt = Get-Date }
    $names = $script:AdNames
    $t = $script:LiveSw.Elapsed.TotalSeconds
    $found = @{}
    foreach ($ni in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        foreach ($k in 'u', 'w', 'p') {
            if ($names[$k] -and $ni.Name -eq $names[$k]) {
                try { $st = $ni.GetIPStatistics(); $found[$k] = @{ id = $ni.Id; rx = [double]$st.BytesReceived; tx = [double]$st.BytesSent; t = $t } } catch { }
            }
        }
    }
    foreach ($k in 'u', 'w', 'p') {
        $c = $found[$k]; $b = $script:LiveBase[$k]; $list = $script:Live[$k]
        if ($c -and $b -and $b.id -eq $c.id -and $c.t -gt $b.t) {
            $dt = $c.t - $b.t
            [void]$list.Add([double[]]@([Math]::Max(0, ($c.rx - $b.rx) / $dt), [Math]::Max(0, ($c.tx - $b.tx) / $dt)))
        } elseif (-not $c -and $list.Count) { [void]$list.Add($null) }   # адаптера нет — разрыв на графике
        $script:LiveBase[$k] = $c
        while ($list.Count -gt $LiveSlots) { $list.RemoveAt(0) }
    }
    Add-LiveBypass
}
# трафик мимо VPN (оценка): физический адаптер минус туннель и wg_server (их зашифрованный трафик тоже идёт через него)
function Get-Bypass($p, $u, $wc) {
    if ($null -eq $p) { return $null }
    $ur = $(if ($u) { $u[0] } else { 0 }); $ut = $(if ($u) { $u[1] } else { 0 })
    $wr = $(if ($wc) { $wc[0] } else { 0 }); $wt = $(if ($wc) { $wc[1] } else { 0 })
    [double[]]@([Math]::Max(0, $p[0] - $ur - $wr), [Math]::Max(0, $p[1] - $ut - $wt))
}
function Add-LiveBypass {
    $v = Get-Bypass (Get-LiveLast 'p') (Get-LiveLast 'u') (Get-LiveLast 'w')
    $z = $script:Live.z
    if ($null -ne $v -or $z.Count) { [void]$z.Add($v) }
    while ($z.Count -gt $LiveSlots) { $z.RemoveAt(0) }
}
function Get-LiveLast([string]$k) {
    $l = $script:Live[$k]
    if ($l.Count -and $null -ne $l[$l.Count - 1]) { return $l[$l.Count - 1] }
    return $null
}

# история трафика из status.json (байты за интервал → средняя скорость), кэш до новых данных
$script:HistCache = $null
function Get-HistTraffic {
    if ($script:HistCache -and $script:HistCache.Stamp -eq $script:statusStamp) { return $script:HistCache }
    $c = @{ Stamp = $script:statusStamp; u = New-Object Collections.ArrayList; w = New-Object Collections.ArrayList; p = New-Object Collections.ArrayList; z = New-Object Collections.ArrayList; T = New-Object Collections.ArrayList }
    $hist = @(); if ($script:snap -and $script:snap.history) { $hist = @($script:snap.history) }
    $iv = 30; if ($script:snap -and $script:snap.intervalSec) { $iv = [int]$script:snap.intervalSec }
    $prev = $null; $any = $false
    foreach ($h in $hist) {
        $t = [long]$h.t
        $dt = $(if ($prev) { [Math]::Max(1, $t - $prev) } else { $iv }); $prev = $t
        $tr = $h.tr
        $ok = [bool]($tr -and @($tr).Count -ge 6 -and $dt -le (4 * $iv + 60))
        if ($ok) { $any = $true }
        $o = 0
        foreach ($k in 'u', 'w', 'p') {
            if ($ok) { [void]$c[$k].Add([double[]]@(([double]$tr[$o] / $dt), ([double]$tr[$o + 1] / $dt))) } else { [void]$c[$k].Add($null) }
            $o += 2
        }
        $last = $c.u.Count - 1
        [void]$c.z.Add($(if ($ok) { Get-Bypass $c.p[$last] $c.u[$last] $c.w[$last] } else { $null }))
        [void]$c.T.Add($t)
    }
    $c.Any = $any
    $script:HistCache = $c
    return $c
}

function Get-Availability([string]$Key) {
    $map = @{ meduza = 'm'; ultra = 'u'; wg = 'w'; ics = 'i'; zapret = 'z'; amnezia = 'a' }
    $hist = @(); if ($script:snap -and $script:snap.history) { $hist = @($script:snap.history) }
    $n = 0; $ok = 0
    foreach ($h in $hist) { $v = $h.($map[$Key]); if ($null -ne $v -and [int]$v -ge 0) { $n++; if ([int]$v -eq 0) { $ok++ } } }
    if (-not $n) { return $null }
    return 100.0 * $ok / $n
}

function Get-TodayTraffic([string]$k) {
    $tr = Get-Snap 'traffic'
    if (-not $tr -or -not $tr.days) { return $null }
    $today = (Get-Date).ToString('yyyy-MM-dd')
    $d = @($tr.days) | Where-Object { $_.d -eq $today } | Select-Object -First 1
    if ($d -and $d.$k) { return @([double]$d.$k[0], [double]$d.$k[1]) }
    return $null
}

# скорость каждого клиента wg — по разнице счётчиков между снимками агента
$script:PeerPrev = @{}; $script:PeerRate = @{}
function Update-PeerRates {
    $wg = Get-Snap 'wg'
    if (-not $wg -or -not $wg.PSObject.Properties['peers']) { return }
    $t = $null; try { $t = [datetime]$script:snap.updated } catch { return }
    foreach ($p in @($wg.peers)) {
        if (-not $p) { continue }
        $pv = $script:PeerPrev[$p.key]
        if ($pv -and $t -gt $pv.t) {
            $dt = ($t - $pv.t).TotalSeconds
            if ($dt -le 180) { $script:PeerRate[$p.key] = @([Math]::Max(0, ([double]$p.tx - $pv.tx) / $dt), [Math]::Max(0, ([double]$p.rx - $pv.rx) / $dt)) }
        }
        if (-not $pv -or $t -gt $pv.t) { $script:PeerPrev[$p.key] = @{ t = $t; rx = [double]$p.rx; tx = [double]$p.tx } }
    }
}

# предупреждения и ошибки за сегодня — дочитываем только новый хвост файла журнала
$script:LogCnt = @{ File = ''; Pos = 0; Warn = 0; Err = 0 }
function Get-LogFiles { @(Get-ChildItem $LogDir -Filter 'vpnguard-*.log' -ErrorAction SilentlyContinue | Sort-Object Name -Descending) }
function Update-LogCounts {
    $todayName = 'vpnguard-{0}.log' -f (Get-Date -Format 'yyyyMMdd')
    $fp = Join-Path $LogDir $todayName
    if (-not (Test-Path $fp)) { $script:LogCnt = @{ File = $fp; Pos = 0; Warn = 0; Err = 0 }; return }
    if ($script:LogCnt.File -ne $fp) { $script:LogCnt = @{ File = $fp; Pos = 0; Warn = 0; Err = 0 } }
    $len = (Get-Item $fp).Length
    if ($len -lt $script:LogCnt.Pos) { $script:LogCnt = @{ File = $fp; Pos = 0; Warn = 0; Err = 0 } }
    if ($len -eq $script:LogCnt.Pos) { return }
    $fs = [IO.File]::Open($fp, 'Open', 'Read', 'ReadWrite')
    try {
        $fs.Position = $script:LogCnt.Pos
        $txt = (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd()
        $script:LogCnt.Pos = $len
    } finally { $fs.Dispose() }
    $script:LogCnt.Warn += [regex]::Matches($txt, '\[WARN\]').Count
    $script:LogCnt.Err  += [regex]::Matches($txt, '\[ERROR\]').Count
}

# ---------------------------------------------------------------- рисование (графики, таблицы)
function DT($g, [string]$s, $font, $color, [int]$x, [int]$y, [int]$wc, [int]$h, [string]$flags = 'Left, VerticalCenter, SingleLine, EndEllipsis, NoPadding') {
    if ($wc -le 0) { return }
    [Windows.Forms.TextRenderer]::DrawText($g, $s, $font, (New-Object Drawing.Rectangle $x, $y, $wc, $h), $color, [Windows.Forms.TextFormatFlags]$flags)
}
function TW([string]$s, $font) { [Windows.Forms.TextRenderer]::MeasureText($s, $font).Width }

function Draw-Tip($g, [float]$x, [float]$y, [string[]]$Lines, [int]$W) {
    $tw = 0; foreach ($l in $Lines) { $tw = [Math]::Max($tw, (TW $l $F.Small)) }
    $tw += 18; $th = 18 * $Lines.Count + 8
    $bx = $(if ($x + 14 + $tw -lt $W) { $x + 14 } else { $x - 14 - $tw })
    $g.FillRectangle($Br.Tip, [float]$bx, $y, [float]$tw, [float]$th); $g.DrawRectangle($Pens.Grid, [float]$bx, $y, [float]$tw, [float]$th)
    for ($i = 0; $i -lt $Lines.Count; $i++) { DT $g $Lines[$i] $F.Small $Clr.Text ([int]$bx + 9) ([int]$y + 4 + 18 * $i) ($tw - 10) 18 }
}

# график скорости: загрузка ↓ (заливка + линия) и отдача ↑ (линия), одна ось, наведение — подсказка
function Draw-Rate($g, [int]$W, [int]$H, $sp) {
    $d = & $sp.Get
    $data = $d.Data; $n = $data.Count; $slots = [Math]::Max(2, [int]$d.Slots)
    $L = 86; $T = 36; $R = 18; $B = 24
    $pw = $W - $L - $R; $ph = $H - $T - $B
    if ($pw -lt 40 -or $ph -lt 30) { return }
    $mx = 0.0; $last = $null
    foreach ($v in $data) { if ($null -ne $v) { if ($v[0] -gt $mx) { $mx = $v[0] }; if ($v[1] -gt $mx) { $mx = $v[1] }; $last = $v } }
    $top = Get-NiceMax $mx
    for ($j = 0; $j -le 2; $j++) {
        $y = [int]($T + $ph - $ph * $j / 2)
        $g.DrawLine($Pens.Grid, $L, $y, $L + $pw, $y)
        DT $g (Format-Rate ($top * $j / 2)) $F.Small $Clr.Dim 0 ($y - 9) ($L - 10) 18 'Right, VerticalCenter, SingleLine'
    }
    $labels = @($d.Labels); $lc = $labels.Count
    for ($j = 0; $j -lt $lc; $j++) {
        $x = [int]($L + $pw * $j / [Math]::Max(1, $lc - 1))
        if ($j -eq 0) { DT $g $labels[$j] $F.Small $Clr.Dim $x ($T + $ph + 5) 120 16 'Left, Top, SingleLine' }
        elseif ($j -eq $lc - 1) { DT $g $labels[$j] $F.Small $Clr.Dim ($x - 120) ($T + $ph + 5) 120 16 'Right, Top, SingleLine' }
        else { DT $g $labels[$j] $F.Small $Clr.Dim ($x - 60) ($T + $ph + 5) 120 16 'HorizontalCenter, Top, SingleLine' }
    }
    # легенда с текущими значениями (стрелки ↓↑ — чтобы различать не только по цвету)
    $lx = $L
    foreach ($q in @(@(0, 'Загрузка ↓', $Br.Rx), @(1, 'Отдача ↑', $Br.Tx))) {
        $g.FillRectangle($q[2], $lx, 13, 10, 10)
        $txt = $q[1] + '  ' + $(if ($last) { Format-Rate $last[$q[0]] } else { '—' })
        DT $g $txt $F.Base $Clr.Text ($lx + 16) 7 260 22
        $lx += 16 + (TW $txt $F.Base) + 20
    }
    if ($d.Note) { DT $g $d.Note $F.Small $Clr.Dim $lx 7 ($W - $lx - $R) 22 'Right, VerticalCenter, SingleLine, EndEllipsis' }
    if (-not $last) { DT $g $d.Empty $F.Base $Clr.Dim $L $T $pw $ph 'HorizontalCenter, VerticalCenter, WordBreak'; return }

    $sx = $pw / ($slots - 1); $off = $slots - $n
    $base = [float]($T + $ph)
    $i = 0
    while ($i -lt $n) {
        if ($null -eq $data[$i]) { $i++; continue }
        $st = $i; while ($i -lt $n -and $null -ne $data[$i]) { $i++ }
        $cnt = $i - $st
        $prx = New-Object 'Drawing.PointF[]' $cnt; $ptx = New-Object 'Drawing.PointF[]' $cnt
        for ($k = 0; $k -lt $cnt; $k++) {
            $x = [float]($L + ($off + $st + $k) * $sx); $v = $data[$st + $k]
            $prx[$k] = New-Object Drawing.PointF $x, ([float]($base - $ph * [Math]::Min(1.0, $v[0] / $top)))
            $ptx[$k] = New-Object Drawing.PointF $x, ([float]($base - $ph * [Math]::Min(1.0, $v[1] / $top)))
        }
        if ($cnt -ge 2) {
            $poly = New-Object 'Drawing.PointF[]' ($cnt + 2)
            [Array]::Copy($prx, $poly, $cnt)
            $poly[$cnt] = New-Object Drawing.PointF $prx[$cnt - 1].X, $base
            $poly[$cnt + 1] = New-Object Drawing.PointF $prx[0].X, $base
            $g.FillPolygon($Br.RxFill, $poly)
            $g.DrawLines($Pens.Rx, $prx); $g.DrawLines($Pens.Tx, $ptx)
        } else {
            $g.FillEllipse($Br.Rx, $prx[0].X - 4, $prx[0].Y - 4, 8, 8); $g.FillEllipse($Br.Tx, $ptx[0].X - 4, $ptx[0].Y - 4, 8, 8)
        }
    }
    $hx = $sp.Hover
    if ($hx -ge $L -and $hx -le $L + $pw) {
        $idx = [int][Math]::Round(($hx - $L) / $sx) - $off
        if ($idx -ge 0 -and $idx -lt $n -and $null -ne $data[$idx]) {
            $v = $data[$idx]; $x = [float]($L + ($off + $idx) * $sx)
            $g.DrawLine($Pens.Cross, $x, [float]$T, $x, $base)
            foreach ($q in @(@(0, $Br.Rx), @(1, $Br.Tx))) {
                $y = [float]($base - $ph * [Math]::Min(1.0, $v[$q[0]] / $top))
                $g.FillEllipse($Br.Card, $x - 6, $y - 6, 12, 12); $g.FillEllipse($q[1], $x - 4, $y - 4, 8, 8)
            }
            Draw-Tip $g $x ([float]($T + 2)) @((& $d.TimeText $idx $n), ('Загрузка ↓  ' + (Format-Rate $v[0])), ('Отдача ↑  ' + (Format-Rate $v[1]))) $W
        }
    }
}

# лента состояния: цвет — уровень в момент проверки; подписи времени и подсказка при наведении
function Draw-Timeline($g, [int]$W, [int]$H, $sp) {
    $hist = @(); if ($script:snap -and $script:snap.history) { $hist = @($script:snap.history) }
    $map = @{ meduza = 'm'; ultra = 'u'; wg = 'w'; ics = 'i'; zapret = 'z'; amnezia = 'a' }
    $key = $map[$sp.Key]; $n = 240
    $barH = $(if ($sp.Mini) { $H } else { 18 })
    $g.FillRectangle($Br.Bg, 0, 0, $W, $barH)
    $bw = $W / $n; $start = $n - $hist.Count
    for ($i = 0; $i -lt $hist.Count; $i++) {
        $x0 = [int][Math]::Floor(($start + $i) * $bw); $x1 = [int][Math]::Floor(($start + $i + 1) * $bw)
        $v = $hist[$i].$key
        $lv = $(if ($null -eq $v) { -1 } else { [int]$v })
        $g.FillRectangle($Brushes[$lv], $x0, 0, [Math]::Max(1, $x1 - $x0), $barH)
    }
    if ($sp.Mini) { return }
    $iv = 30; if ($script:snap -and $script:snap.intervalSec) { $iv = [int]$script:snap.intervalSec }
    $span = $n * $iv
    for ($j = 0; $j -le 4; $j++) {
        $x = [int]($W * $j / 4)
        $txt = $(if ($j -eq 4) { 'сейчас' } else { Format-Span ($span * (4 - $j) / 4) })
        if ($j -eq 0) { DT $g $txt $F.Small $Clr.Dim 0 ($barH + 4) 100 16 'Left, Top, SingleLine' }
        elseif ($j -eq 4) { DT $g $txt $F.Small $Clr.Dim ($W - 100) ($barH + 4) 100 16 'Right, Top, SingleLine' }
        else { DT $g $txt $F.Small $Clr.Dim ($x - 50) ($barH + 4) 100 16 'HorizontalCenter, Top, SingleLine' }
    }
    $hx = $sp.Hover
    if ($hx -ge 0 -and $hist.Count) {
        $idx = [int][Math]::Floor($hx / $bw) - $start
        if ($idx -ge 0 -and $idx -lt $hist.Count) {
            $v = $hist[$idx].$key; $lv = $(if ($null -eq $v) { -1 } else { [int]$v })
            $g.DrawLine($Pens.Tl, [float]$hx, 0, [float]$hx, [float]$barH)
            $tm = (From-Unix ([long]$hist[$idx].t)).ToString('HH:mm:ss')
            Draw-Tip $g ([float]$hx) 0 @("$tm — $($LevelName[$lv])") $W
        }
    }
}

function Get-Kv([string]$Key) {
    $o = Get-Snap $Key
    if ($o -and $o.PSObject.Properties['kv']) { return @($o.kv) }
    return @()
}
function Draw-Kv($g, [int]$W, [int]$H, $sp) {
    $rows = @(Get-Kv $sp.Key)
    if (-not $rows.Count) { DT $g 'Нет данных: агент не запущен или старой версии (подробности — с агента 1.8).' $F.Base $Clr.Dim 16 0 ($W - 32) $H; return }
    $lw = [Math]::Min(300, [int]($W * 0.38))
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $y = 6 + $i * 26
        if ($i % 2 -eq 0) { $g.FillRectangle($Br.Row, 8, $y, $W - 16, 26) }
        DT $g "$($rows[$i][0])" $F.Base $Clr.Dim 20 $y ($lw - 24) 26
        DT $g "$($rows[$i][1])" $F.Base $Clr.Text $lw $y ($W - $lw - 20) 26
    }
}

function Get-Peers { $wg = Get-Snap 'wg'; if ($wg -and $wg.PSObject.Properties['peers']) { return @($wg.peers | Where-Object { $_ }) }; return @() }
function Draw-Peers($g, [int]$W, [int]$H, $sp) {
    $peers = @(Get-PeerRows)
    if (-not $peers.Count) { DT $g $(if ($script:WgListErr) { "Клиентов нет. $($script:WgListErr)" } else { 'Клиентов пока нет — нажмите «Новый клиент».' }) $F.Base $Clr.Dim 16 0 ($W - 32) $H 'Left, VerticalCenter, WordBreak'; return }
    $cols = @(@(0.0, 'Клиент'), @(0.20, 'IP в туннеле'), @(0.33, 'Откуда подключён'), @(0.52, 'Рукопожатие'), @(0.66, 'Скорость ↓ / ↑'), @(0.83, 'Всего ↓ / ↑'))
    $x0 = 30; $cw = $W - $x0 - 12
    foreach ($c in $cols) { DT $g $c[1] $F.Small $Clr.Dim ([int]($x0 + $cw * $c[0])) 4 200 22 }
    for ($i = 0; $i -lt $peers.Count; $i++) {
        $p = $peers[$i]; $y = 28 + $i * 28
        $isSel = ($script:SelPeer -and $p.ip -eq $script:SelPeer)
        if ($isSel) { $g.FillRectangle($Br.Tip, 8, $y, $W - 16, 28); $g.FillRectangle($Br.Accent, 8, $y, 3, 28) }
        elseif ($i % 2 -eq 0) { $g.FillRectangle($Br.Row, 8, $y, $W - 16, 28) }
        $g.FillEllipse($Brushes[$(if ($p.active) { 0 } else { -1 })], 14, $y + 9, 10, 10)
        $rt = $script:PeerRate[$p.key]
        $vals = @(
            ("$($p.name)" + $(if ($p.source -eq 'WS4W') { '  · WS4W' } elseif ($p.source -eq 'только на сервере') { '  · без конфига' } else { '' })),
            "$($p.ip)", $(if ($p.endpoint) { "$($p.endpoint)" } else { '—' }),
            (Format-Ago ([double]$p.hsAgo)),
            $(if ($rt) { '↓ ' + (Format-Rate $rt[0]) + '  ↑ ' + (Format-Rate $rt[1]) } else { '—' }),
            ('↓ ' + (Format-Bytes ([double]$p.tx)) + '  ↑ ' + (Format-Bytes ([double]$p.rx)))
        )
        for ($j = 0; $j -lt $cols.Count; $j++) {
            $cx = [int]($x0 + $cw * $cols[$j][0])
            $nx = $(if ($j -lt $cols.Count - 1) { [int]($x0 + $cw * $cols[$j + 1][0]) } else { $W - 10 })
            DT $g $vals[$j] $(if ($j -eq 0) { $F.Bold } else { $F.Base }) $(if ($j -eq 0 -or $p.active) { $Clr.Text } else { $Clr.Dim }) $cx $y ($nx - $cx - 8) 28
        }
    }
}

function Get-ZResults { $z = Get-Snap 'zapret'; if ($z -and $z.results) { return @($z.results | Where-Object { $_ }) }; return @() }
function Draw-ZResults($g, [int]$W, [int]$H, $sp) {
    $z = Get-Snap 'zapret'
    $res = @(Get-ZResults)
    $y = 4
    if ($z -and $z.PSObject.Properties['progress'] -and $z.progress) {
        DT $g ("Идёт подбор: стратегия $($z.progress.index) из $($z.progress.total) · сейчас: $($z.progress.current)") $F.Bold $Clr.Accent 16 $y ($W - 32) 24
        $y += 28
    }
    if (-not $res.Count) { DT $g 'Подбора ещё не было. Он запускается сам при включении zapret или кнопкой «Подобрать стратегию».' $F.Base $Clr.Dim 16 $y ($W - 32) 26; return }
    $cur = $(if ($z -and $z.PSObject.Properties['current']) { "$($z.current)" } else { '' })
    $c1 = [int]($W * 0.30); $bw = [int]($W * 0.14); $c3 = $c1 + $bw + 74
    DT $g 'Стратегия' $F.Small $Clr.Dim 20 $y 200 22; DT $g 'Открылось' $F.Small $Clr.Dim $c1 $y 200 22; DT $g 'Не прошли' $F.Small $Clr.Dim $c3 $y 300 22
    $y += 24
    $script:ZRowGeo = @($y, 24)
    $hov = -1; if ($sp.HoverY -ge $y) { $hov = [int][Math]::Floor(($sp.HoverY - $y) / 24) }
    for ($i = 0; $i -lt $res.Count; $i++) {
        $r = $res[$i]; $ry = $y + $i * 24
        $isCur = ($cur -and "$($r.name)" -eq $cur)
        if ($isCur) { $g.FillRectangle($Br.Row, 8, $ry, $W - 16, 24); $g.FillRectangle($Br.Accent, 8, $ry, 3, 24) }
        elseif ($i -eq $hov) { $g.FillRectangle($Br.Row, 8, $ry, $W - 16, 24) }
        DT $g ("$($r.name)" + $(if ($isCur) { '   ← используется' } else { '' })) $(if ($isCur) { $F.Bold } else { $F.Base }) $(if ($isCur) { $Clr.Text } else { $Clr.Dim }) 20 $ry ($c1 - 30) 24
        $tot = [Math]::Max(1, [int]$r.total); $ok = [int]$r.ok
        $g.FillRectangle($Br.Track, $c1, $ry + 8, $bw, 8)
        $lv = $(if ($ok -ge $tot) { 0 } elseif ($ok -gt 0) { 1 } else { 2 })
        if ($ok -gt 0) { $g.FillRectangle($Brushes[$lv], $c1, $ry + 8, [int]($bw * $ok / $tot), 8) }
        DT $g "$ok из $tot" $F.Base $Clr.Text ($c1 + $bw + 10) $ry 64 24
        $bad = @(@($r.checks) | Where-Object { $_ -and -not $_.ok })
        $txt = $(if ($r.PSObject.Properties['error'] -and $r.error) { "ошибка: $($r.error)" }
            elseif ($bad.Count) { ($bad | ForEach-Object { ("$($_.n)" -replace '^(YouTube|Discord): ', '$1 · ') + ' — ' + "$($_.why)" }) -join ';  ' }
            elseif (@($r.checks).Count) { 'всё открылось' } else { '' })
        DT $g $txt $F.Small $(if ($bad.Count -or ($r.PSObject.Properties['error'] -and $r.error)) { $Clr.Bad } else { $Clr.Ok }) $c3 $ry ($W - $c3 - 12) 24
    }
    # подсказка: все проверки стратегии
    if ($hov -ge 0 -and $hov -lt $res.Count -and @($res[$hov].checks).Count) {
        $lines = @("$($res[$hov].name):") + @(@($res[$hov].checks) | Where-Object { $_ } | ForEach-Object { $(if ($_.ok) { '✓ ' } else { '✗ ' }) + "$($_.n)" + $(if ($_.ok) { " — $($_.ms) мс" } else { " — $($_.why)" }) })
        $ty = [Math]::Max(0, [Math]::Min($H - (18 * $lines.Count + 10), $y + ($hov + 1) * 24))
        $tw = 0; foreach ($l in $lines) { $tw = [Math]::Max($tw, (TW $l $F.Small)) }
        $tx = [Math]::Max(6, [Math]::Min($c3 - 14, $W - $tw - 40))
        Draw-Tip $g ([float]$tx) ([float]$ty) $lines $W
    }
}

function Get-Days([string]$k) {
    $tr = Get-Snap 'traffic'
    if (-not $tr -or -not $tr.days) { return @() }
    $list = @($tr.days | Where-Object { $_ -and $_.$k })
    [array]::Reverse($list)
    return $list
}
function Draw-Days($g, [int]$W, [int]$H, $sp) {
    $k = & $sp.Src
    $days = @(Get-Days $k)
    if (-not $days.Count) { DT $g 'Пока нет данных — агент 1.8 начнёт считать трафик по дням после запуска.' $F.Base $Clr.Dim 16 0 ($W - 32) $H; return }
    $mx = 1.0; foreach ($d in $days) { $mx = [Math]::Max($mx, [double]$d.$k[0] + [double]$d.$k[1]) }
    $today = (Get-Date).ToString('yyyy-MM-dd'); $yest = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')
    $lx = 20
    foreach ($q in @(@('Загрузка ↓', $Br.Rx), @('Отдача ↑', $Br.Tx))) {
        $g.FillRectangle($q[1], $lx, 10, 10, 10); DT $g $q[0] $F.Small $Clr.Dim ($lx + 16) 4 120 22; $lx += 16 + (TW $q[0] $F.Small) + 20
    }
    $x0 = 130; $tx0 = $W - 250; $aw = [Math]::Max(40, $tx0 - $x0 - 16)
    for ($i = 0; $i -lt $days.Count; $i++) {
        $d = $days[$i]; $y = 30 + $i * 26
        if ($i % 2 -eq 0) { $g.FillRectangle($Br.Row, 8, $y, $W - 16, 26) }
        $dd = [datetime]::ParseExact("$($d.d)", 'yyyy-MM-dd', $null)
        $lbl = $(if ($d.d -eq $today) { 'сегодня' } elseif ($d.d -eq $yest) { 'вчера' } else { $dd.ToString('dd.MM ddd') })
        DT $g $lbl $(if ($d.d -eq $today) { $F.Bold } else { $F.Base }) $Clr.Text 20 $y 100 26
        $rx = [double]$d.$k[0]; $txv = [double]$d.$k[1]
        $w1 = [int]($aw * $rx / $mx); $w2 = [int]($aw * $txv / $mx)
        if ($w1 -gt 0) { $g.FillRectangle($Br.Rx, $x0, $y + 8, $w1, 10) }
        if ($w2 -gt 0) { $g.FillRectangle($Br.Tx, $x0 + $w1 + $(if ($w1 -gt 0) { 2 } else { 0 }), $y + 8, $w2, 10) }
        DT $g ('↓ ' + (Format-Bytes $rx) + '   ↑ ' + (Format-Bytes $txv)) $F.Base $Clr.Text $tx0 $y 240 26
    }
}

# холсты: панели, которые рисуют сами себя по описанию в Tag
$script:Canvases = New-Object Collections.ArrayList
$PaintHandler = {
    param($s, $e)
    try {
        $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'
        $sp = $s.Tag; $W = $s.ClientSize.Width; $H = $s.ClientSize.Height
        switch ($sp.Kind) {
            'rate'     { Draw-Rate $g $W $H $sp }
            'timeline' { Draw-Timeline $g $W $H $sp }
            'kv'       { Draw-Kv $g $W $H $sp }
            'peers'    { Draw-Peers $g $W $H $sp }
            'zres'     { Draw-ZResults $g $W $H $sp }
            'days'     { Draw-Days $g $W $H $sp }
            'ptest'    { Draw-ProtoTest $g $W $H $sp }
            'awg'      { Draw-Awg $g $W $H $sp }
            'zchk'     { Draw-ZChecks $g $W $H $sp }
        }
    } catch { }
}
function New-Canvas([int]$Height, [hashtable]$Spec, $Back = $Clr.Card) {
    $p = New-Object Windows.Forms.Panel
    $p.Height = $Height; $p.BackColor = $Back
    if (-not $Spec.ContainsKey('Hover')) { $Spec.Hover = -1 }
    $p.Tag = $Spec
    $dbProp.SetValue($p, $true, $null)
    $p.Add_Paint($PaintHandler)
    $p.Add_Resize({ $this.Invalidate() })
    if ($Spec.Kind -in 'rate', 'timeline' -and -not $Spec.Mini) {
        $p.Add_MouseMove({ param($s, $e) $s.Tag.Hover = $e.X; $s.Invalidate() })
        $p.Add_MouseLeave({ $this.Tag.Hover = -1; $this.Invalidate() })
    }
    if ($Spec.Kind -eq 'zres') {
        $p.Cursor = 'Hand'; $Spec.HoverY = -1
        $p.Add_MouseMove({ param($s, $e) if ($s.Tag.HoverY -ne $e.Y) { $s.Tag.HoverY = $e.Y; $s.Invalidate() } })
        $p.Add_MouseLeave({ $this.Tag.HoverY = -1; $this.Invalidate() })
        $p.Add_MouseClick({ param($s, $e) Select-ZRowUi $e.Y })
    }
    if ($Spec.Kind -eq 'peers') {
        $p.Cursor = 'Hand'
        $p.Add_MouseClick({
            param($s, $e)
            $rows = @(Get-PeerRows); $i = [int][Math]::Floor(($e.Y - 28) / 28)
            if ($i -ge 0 -and $i -lt $rows.Count) { $script:SelPeer = "$($rows[$i].ip)"; Set-Footer "Выбран клиент «$($rows[$i].name)»" }
            $s.Invalidate()
        })
        $p.Add_MouseDoubleClick({ param($s, $e) Show-WgClientUi })
    }
    [void]$script:Canvases.Add($p)
    $p
}

# описания графиков скорости
function New-LiveSpec([scriptblock]$Src) {
    @{ Kind = 'rate'; Live = $true; Src = $Src; Get = {
        $k = & $sp.Src
        $nm = $script:AdNames
        @{ Data = $script:Live[$k]; Slots = $LiveSlots; Labels = @('−5 мин', '−2,5 мин', 'сейчас')
           TimeText = { param($i, $n) '{0} с назад' -f ($n - 1 - $i) }
           Note = $(if ($k -eq 'z') { 'оценка: физический адаптер − туннель − wg_server' } elseif ($nm -and $nm[$k]) { "адаптер «$($nm[$k])» · раз в секунду" } else { '' })
           Empty = $(if ($nm -and -not $nm[$k]) { 'Адаптер не найден.' } else { 'Собираю данные… (адаптер не найден или ещё нет замеров)' }) }
    } }
}
function New-HistSpec([scriptblock]$Src) {
    @{ Kind = 'rate'; Src = $Src; Get = {
        $k = & $sp.Src
        $hc = Get-HistTraffic
        $iv = 30; if ($script:snap -and $script:snap.intervalSec) { $iv = [int]$script:snap.intervalSec }
        $times = $hc.T
        @{ Data = $(if ($hc.Any) { $hc[$k] } else { @() }); Slots = 240
           Labels = @((Format-Span (240 * $iv)), (Format-Span (120 * $iv)), 'сейчас')
           # замыкание: без функций скрипта (GetNewClosure видит только глобальную область)
           TimeText = { param($i, $n) [DateTimeOffset]::FromUnixTimeSeconds([long]$times[$i]).LocalDateTime.ToString('HH:mm:ss') + " · средняя за $iv с" }.GetNewClosure()
           Note = 'по данным агента, средняя за интервал проверки'
           Empty = 'Пока нет данных — агент 1.8 записывает трафик в историю каждые 30 с.' }
    } }
}

# ---------------------------------------------------------------- окно
$form = New-Object Windows.Forms.Form
$form.Text = 'VpnGuard — MeduzaVPN + WS4W'
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object Drawing.Size(1240, 920)
$form.MinimumSize = New-Object Drawing.Size(1040, 720)
$form.BackColor = $Clr.Bg
$form.ForeColor = $Clr.Text
$form.Font = $F.Base
$form.Icon = New-AppIcon

# --- боковая панель
$sidebar = New-Object Windows.Forms.Panel
$sidebar.Dock = 'Left'; $sidebar.Width = 214; $sidebar.BackColor = $Clr.Nav

$logo = New-Object Windows.Forms.Panel
$logo.Dock = 'Top'; $logo.Height = 72; $logo.BackColor = $Clr.Nav
$logoIcon = New-Object Windows.Forms.PictureBox
$logoIcon.Image = $form.Icon.ToBitmap(); $logoIcon.SizeMode = 'Zoom'; $logoIcon.Size = New-Object Drawing.Size(26, 26); $logoIcon.Location = New-Object Drawing.Point(20, 18)
$logoT = New-Label 'VpnGuard' $F.Logo; $logoT.Location = New-Object Drawing.Point(52, 12)
$logoS = New-Label 'VPN · WS4W · zapret' $F.Small $Clr.Dim; $logoS.Location = New-Object Drawing.Point(54, 40)
$logo.Controls.AddRange(@($logoIcon, $logoT, $logoS))

$navFlow = New-Object Windows.Forms.FlowLayoutPanel
$navFlow.Dock = 'Fill'; $navFlow.FlowDirection = 'TopDown'; $navFlow.WrapContents = $false; $navFlow.BackColor = $Clr.Nav; $navFlow.Padding = '0,6,0,0'
$sidebar.Controls.AddRange(@($navFlow, $logo))

# --- правая часть: шапка + страницы
$main = New-Object Windows.Forms.Panel
$main.Dock = 'Fill'; $main.BackColor = $Clr.Bg

$header = New-Object Windows.Forms.Panel
$header.Dock = 'Top'; $header.Height = 84; $header.BackColor = $Clr.Bg
$pageTitle = New-Label 'Главная' $F.Title
$pageTitle.Location = New-Object Drawing.Point(22, 10)
$agentDot = New-Dot 10
$agentDot.Location = New-Object Drawing.Point(25, 50)
$agentLbl = New-Label 'Агент: проверка…' $F.Small $Clr.Dim
$agentLbl.Location = New-Object Drawing.Point(40, 47)
$agentBusy = New-Label '' $F.Small $Clr.Accent
$agentBusy.Location = New-Object Drawing.Point(40, 64)
$hBtns = New-Object Windows.Forms.FlowLayoutPanel
$hBtns.AutoSize = $true; $hBtns.WrapContents = $false; $hBtns.BackColor = $Clr.Bg
$hBtns.Anchor = 'Top,Right'
$btnStart = New-Btn '▶ Запустить агент' { Start-Agent } $true
$btnStop  = New-Btn '■ Остановить агент' { Stop-Agent }
$btnNow   = New-Btn '⟳ Проверить сейчас' { Send-Cmd 'check-now' 'проверка' }
$hBtns.Controls.AddRange(@($btnNow, $btnStart, $btnStop))
$header.Controls.AddRange(@($pageTitle, $agentDot, $agentLbl, $agentBusy, $hBtns))
$header.Add_Resize({ $hBtns.Location = New-Object Drawing.Point(($header.ClientSize.Width - $hBtns.Width - 20), 22) })

$footer = New-Object Windows.Forms.Label
$footer.Dock = 'Bottom'; $footer.Height = 26; $footer.BackColor = $Clr.Nav; $footer.ForeColor = $Clr.Dim
$footer.Font = $F.Small; $footer.TextAlign = 'MiddleLeft'; $footer.Padding = '20,0,0,0'
function Set-Footer([string]$t) { $footer.Text = (Get-Date -Format 'HH:mm:ss') + '   ' + $t }

$content = New-Object Windows.Forms.Panel
$content.Dock = 'Fill'; $content.BackColor = $Clr.Bg
$main.Controls.AddRange(@($content, $header))

# --- страницы и навигация
$pages = @{}
$navButtons = @{}
$script:CurPage = ''
$PageTitles = @{
    home = 'Главная'; meduza = 'MeduzaVPN — приложение'; ultra = 'Туннель'; wg = 'WG-Server'
    ics = 'Раздача интернета (ICS): туннель → WG-Server'; zapret = 'zapret-discord-youtube'; traffic = 'Трафик'
    log = 'Журнал'; settings = 'Настройки'; diag = 'Диагностика'; amnezia = 'AmneziaVPN — альтернатива MeduzaVPN'; software = 'Компоненты — установка и обновление'
}

function Show-Page([string]$Name) {
    $script:CurPage = $Name
    foreach ($k in $pages.Keys) { $pages[$k].Visible = ($k -eq $Name) }
    foreach ($k in $navButtons.Keys) {
        $b = $navButtons[$k]; $sel = ($k -eq $Name)
        $b.Tag.Sel = $sel
        $b.ForeColor = $(if ($sel) { $Clr.Text } else { $Clr.Dim })
        $b.BackColor = $(if ($sel) { $Clr.Card } else { $Clr.Nav })
        $b.Invalidate()
    }
    Set-Prop $pageTitle Text $PageTitles[$Name]
    if ($Name -eq 'settings') { Import-SettingsForm }
    if ($Name -eq 'log') { Update-LogView -Force }
    if ($CompKeys -contains $Name) { $script:compSig[$Name] = '' ; Update-LogView }
    if ($Name -eq 'wg') { Update-WgList -Force; Invalidate-Visible }
    if ($Name -eq 'meduza') { Update-MzSelect }
    if ($Name -eq 'amnezia') { Update-ACfg; Update-AwgInfo; Invalidate-Visible }
    if ($Name -eq 'zapret') { $script:ZsSig = ''; Update-ZStratUi }
    if ($Name -eq 'software') { Update-SoftUi }
    if ($Name -eq 'diag') { $script:RmSig = ''; try { Update-RemoteUi } catch { }; try { Update-WebUi } catch { } }
    if ($Name -eq 'zapret' -and -not $script:ZListDirty) { if ($cbZList.SelectedIndex -lt 0) { $cbZList.SelectedIndex = 0 } else { Import-ZList } }
    # фокус на кнопку страницы — тогда колесо мыши прокручивает страницу
    try { [void]$pages[$Name].SelectNextControl($null, $true, $true, $true, $true) } catch { }
    if ($pages[$Name].AutoScroll) { $pages[$Name].AutoScrollPosition = New-Object Drawing.Point(0, 0) }
    foreach ($c in $script:Canvases) { if ($c.Visible) { $c.Invalidate() } }
}

$NavItems = @(
    @('home', 'Главная', ''), @('ultra', 'Туннель', 'ultra'), @('meduza', 'MeduzaVPN', 'meduza'), @('amnezia', 'AmneziaVPN', 'amnezia'),
    @('wg', 'WG-Server', 'wg'), @('ics', 'Раздача ICS', 'ics'), @('zapret', 'zapret', 'zapret'), @('traffic', 'Трафик', ''), @('-'),
    @('software', 'Компоненты', ''), @('log', 'Журнал', ''), @('settings', 'Настройки', ''), @('diag', 'Диагностика', '')
)
foreach ($it in $NavItems) {
    if ($it[0] -eq '-') {
        $sep = New-Object Windows.Forms.Label
        $sep.AutoSize = $false; $sep.Height = 1; $sep.Width = 178; $sep.BackColor = $Clr.Border; $sep.Margin = '18,10,18,10'
        $navFlow.Controls.Add($sep); continue
    }
    $key = $it[0]
    $b = New-Object Windows.Forms.Button
    $b.Text = $it[1]; $b.Font = $F.Nav; $b.FlatStyle = 'Flat'; $b.Height = 40; $b.Width = 214; $b.Margin = '0,0,0,2'
    $b.TextAlign = 'MiddleLeft'; $b.Padding = '20,0,0,0'
    $b.BackColor = $Clr.Nav; $b.ForeColor = $Clr.Dim; $b.Cursor = 'Hand'; $b.UseVisualStyleBackColor = $false
    $b.FlatAppearance.BorderSize = 0; $b.FlatAppearance.MouseOverBackColor = $Clr.Card
    $b.Tag = @{ Key = $key; Comp = $it[2]; Sel = $false }
    $b.Add_Paint({
        param($s, $e)
        $t = $s.Tag
        if ($t.Sel) { $e.Graphics.FillRectangle($Br.Accent, 0, 8, 3, $s.Height - 16) }
        if ($t.Comp) {
            $lv = $script:Level[$t.Comp]; if ($null -eq $lv) { $lv = -1 }
            $e.Graphics.SmoothingMode = 'AntiAlias'
            $e.Graphics.FillEllipse($Brushes[[int]$lv], $s.Width - 30, [int](($s.Height - 10) / 2), 10, 10)
        }
    })
    $b.Add_Click([scriptblock]::Create("Show-Page '$key'"))
    $navFlow.Controls.Add($b)
    $navButtons[$key] = $b
}

$tip = New-Object Windows.Forms.ToolTip

# --- помощники вёрстки
function New-Page([bool]$Scroll = $true) {
    $p = New-Object Windows.Forms.Panel
    $p.Dock = 'Fill'; $p.AutoScroll = $Scroll; $p.BackColor = $Clr.Bg; $p.Padding = '20,4,20,16'
    $p
}
# блоки сверху вниз (Dock=Top) с отступом между ними; последний — по желанию на всю высоту
function Add-Blocks($Page, [object[]]$Blocks, $FillLast = $null) {
    if ($FillLast) { $FillLast.Dock = 'Fill'; $Page.Controls.Add($FillLast) }
    for ($i = $Blocks.Count - 1; $i -ge 0; $i--) {
        $b = $Blocks[$i]; $b.Dock = 'Top'; $Page.Controls.Add($b)
        if ($i -gt 0) {
            $sp = New-Object Windows.Forms.Panel; $sp.Height = 12; $sp.Dock = 'Top'; $sp.BackColor = $Clr.Bg
            $Page.Controls.Add($sp)
        }
    }
    if ($FillLast) { $FillLast.BringToFront() }
}
function New-SectionTitle([string]$Text) {
    $l = New-Label $Text $F.Bold $Clr.Dim
    $l.AutoSize = $false; $l.Height = 22; $l.TextAlign = 'BottomLeft'
    $l
}
function New-ToolRow([object[]]$Buttons, [string]$Hint = '') {
    $fl = New-Object Windows.Forms.FlowLayoutPanel
    $fl.Height = 36; $fl.WrapContents = $false; $fl.BackColor = $Clr.Bg; $fl.Padding = '0,2,0,0'
    foreach ($b in $Buttons) { $fl.Controls.Add($b) }
    if ($Hint) { $h = New-Label $Hint $F.Small $Clr.Dim; $h.Margin = '8,8,0,0'; $fl.Controls.Add($h) }
    $fl
}
function New-Row([int]$Height, [int]$Cols) {
    $t = New-Object Windows.Forms.TableLayoutPanel
    $t.Height = $Height; $t.ColumnCount = $Cols; $t.RowCount = 1; $t.BackColor = $Clr.Bg; $t.Margin = '0,0,0,0'; $t.Padding = '0,0,0,0'
    for ($i = 0; $i -lt $Cols; $i++) { [void]$t.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Percent', (100 / $Cols)))) }
    [void]$t.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent', 100)))
    $t
}
function Add-ClickAll($Ctl, [scriptblock]$Sb) {
    $Ctl.Cursor = 'Hand'; $Ctl.Add_Click($Sb)
    foreach ($ch in $Ctl.Controls) { Add-ClickAll $ch $Sb }
}
function New-LogBox([int]$Height = 0) {
    $r = New-Object Windows.Forms.RichTextBox
    $r.ReadOnly = $true; $r.BorderStyle = 'None'; $r.BackColor = $Clr.Card
    $r.ForeColor = $Clr.Text; $r.Font = $F.Mono; $r.WordWrap = $false; $r.DetectUrls = $false
    if ($Height) { $r.Height = $Height }
    $r
}
function New-Kpi([string]$Title, [scriptblock]$OnClick = $null) {
    $p = New-Object Windows.Forms.Panel
    $p.Dock = 'Fill'; $p.Margin = '0,0,10,0'; $p.BackColor = $Clr.Card; $p.Size = New-Object Drawing.Size(180, 84)
    $t = New-Label $Title $F.Small $Clr.Dim; $t.Location = New-Object Drawing.Point(14, 10)
    $v = New-Label '—' $F.Kpi; $v.Location = New-Object Drawing.Point(12, 28)
    $s = New-Label '' $F.Small $Clr.Dim; $s.AutoSize = $false; $s.AutoEllipsis = $true
    $s.Location = New-Object Drawing.Point(14, 58); $s.Size = New-Object Drawing.Size(152, 18); $s.Anchor = 'Top,Left,Right'
    $p.Controls.AddRange(@($t, $v, $s))
    if ($OnClick) { Add-ClickAll $p $OnClick }
    [pscustomobject]@{ Panel = $p; Value = $v; Sub = $s }
}

# ================================================================ Главная
$pgHome = New-Page $true

# общий статус + основные действия
$hero = New-Object Windows.Forms.Panel
$hero.Height = 128; $hero.BackColor = $Clr.Card; $hero.Size = New-Object Drawing.Size(900, 128)
$heroDot = New-Dot 18; $heroDot.Location = New-Object Drawing.Point(22, 22)
$heroLbl = New-Label 'Нет данных' $F.Hero; $heroLbl.Location = New-Object Drawing.Point(48, 12)
$heroSub = New-Label 'Ждём состояние от агента…' $F.Base $Clr.Dim; $heroSub.AutoSize = $false; $heroSub.AutoEllipsis = $true
$heroSub.Location = New-Object Drawing.Point(51, 50); $heroSub.Size = New-Object Drawing.Size(830, 22); $heroSub.Anchor = 'Top,Left,Right'
$heroBtns = New-Object Windows.Forms.FlowLayoutPanel
$heroBtns.AutoSize = $true; $heroBtns.WrapContents = $false; $heroBtns.BackColor = $Clr.Card; $heroBtns.Location = New-Object Drawing.Point(48, 80)
$script:ZToggleBtns = New-Object Collections.ArrayList
$hzBtn = New-Btn 'Включить zapret' { Switch-Zapret }
[void]$script:ZToggleBtns.Add($hzBtn)
$heroBtns.Controls.AddRange(@(
    (New-Btn 'Переподключить туннель' { Send-Cmd 'reconnect' 'переподключение туннеля' }),
    (New-Btn 'Восстановить раздачу' { Send-Cmd 'reapply-ics' 'восстановление раздачи' }),
    (New-Btn 'Перезапустить WG-Server' { Send-Cmd 'restart-wg' 'перезапуск WG-Server' }),
    $hzBtn,
    (New-Btn 'Веб-интерфейс' { Start-Process "http://localhost:$((Get-WebCfgUi).port)/" })
))
# режим работы: MeduzaVPN / AmneziaVPN / без VPN
$modeLbl = New-Label 'Режим работы' $F.Small $Clr.Dim; $modeLbl.Anchor = 'Top,Right'
$cbMode = New-Object Windows.Forms.ComboBox
$cbMode.DropDownStyle = 'DropDownList'; $cbMode.Width = 250; $cbMode.BackColor = $Clr.Input; $cbMode.ForeColor = $Clr.Text; $cbMode.FlatStyle = 'Flat'; $cbMode.Anchor = 'Top,Right'
foreach ($mi in $ModeItems) { [void]$cbMode.Items.Add($mi[1]) }
$cbMode.Add_SelectionChangeCommitted({ Set-ModeUi $ModeItems[$cbMode.SelectedIndex][0] })
$script:ModeSig = ''
$hero.Controls.AddRange(@($heroDot, $heroLbl, $heroSub, $heroBtns, $modeLbl, $cbMode))
$hero.Add_Resize({
    $cbMode.Location = New-Object Drawing.Point(($hero.ClientSize.Width - $cbMode.Width - 18), 30)
    $modeLbl.Location = New-Object Drawing.Point(($hero.ClientSize.Width - $cbMode.Width - 18), 10)
    $heroSub.Width = [Math]::Max(200, $cbMode.Left - 70)
})
function Update-ModeUi {
    $m = Get-Mode
    if ($m -ne $script:ModeSig -and -not $cbMode.DroppedDown) {
        $script:ModeSig = $m
        $i = 0; for ($j = 0; $j -lt $ModeItems.Count; $j++) { if ($ModeItems[$j][0] -eq $m) { $i = $j } }
        $cbMode.SelectedIndex = $i
    }
    # в режиме без VPN zapret включён всегда — кнопку выключения не показываем
    foreach ($b in $script:ZToggleBtns) { Set-Prop $b Enabled ($m -ne 'zapret') }
    $tt = $(if ($m -eq 'zapret') { 'Без VPN (только zapret)' } else { 'Туннель' })
    Set-Prop $navButtons['ultra'] Text $(if ($m -eq 'zapret') { 'Без VPN' } else { 'Туннель' })
    Set-Prop $btnDualSw Visible ($m -eq 'dual')
    $u = Get-Snap 'ultra'
    $PageTitles['ultra'] = $(if ($u -and $u.PSObject.Properties['title'] -and $u.title) { "$($u.title)" } else { $tt })
    if ($script:CurPage -eq 'ultra') { Set-Prop $pageTitle Text $PageTitles['ultra'] }
    Set-Prop $script:TileTitles['ultra'] Text $tt
    Set-Prop $Kpi.avail.Panel.Controls[0] Text $(if ($m -eq 'zapret') { 'Доступность выхода · 2 ч' } else { 'Доступность VPN · 2 ч' })
}

# плитки компонентов (клик — вкладка компонента)
$Tiles = @{}
$script:TileTitles = @{}
$TileDefs = @(@('ultra', 'Туннель'), @('meduza', 'MeduzaVPN'), @('amnezia', 'AmneziaVPN'), @('wg', 'WG-Server'), @('ics', 'Раздача ICS'), @('zapret', 'zapret'))
$tileRow = New-Row 116 $TileDefs.Count
for ($i = 0; $i -lt $TileDefs.Count; $i++) {
    $key = $TileDefs[$i][0]
    $p = New-Object Windows.Forms.Panel
    $p.Dock = 'Fill'; $p.Margin = $(if ($i -lt $TileDefs.Count - 1) { '0,0,10,0' } else { '0,0,0,0' }); $p.BackColor = $Clr.Card; $p.Size = New-Object Drawing.Size(160, 116)
    $p.Padding = '12,0,12,12'
    $dot = New-Dot 10; $dot.Location = New-Object Drawing.Point(14, 16)
    $t = New-Label $TileDefs[$i][1] $F.Bold $Clr.Dim; $t.Location = New-Object Drawing.Point(30, 11)
    $st = New-Label 'нет данных' $F.Tile; $st.AutoSize = $false; $st.AutoEllipsis = $true
    $st.Location = New-Object Drawing.Point(12, 37); $st.Size = New-Object Drawing.Size(136, 24); $st.Anchor = 'Top,Left,Right'
    $sub = New-Label '' $F.Small $Clr.Dim; $sub.AutoSize = $false; $sub.AutoEllipsis = $true
    $sub.Location = New-Object Drawing.Point(14, 64); $sub.Size = New-Object Drawing.Size(134, 18); $sub.Anchor = 'Top,Left,Right'
    $tl = New-Canvas 8 @{ Kind = 'timeline'; Key = $key; Mini = $true } $Clr.Bg
    $tl.Dock = 'Bottom'
    $p.Controls.AddRange(@($dot, $t, $st, $sub, $tl))
    Add-ClickAll $p ([scriptblock]::Create("Show-Page '$key'"))
    $tileRow.Controls.Add($p, $i, 0)
    $Tiles[$key] = [pscustomobject]@{ Dot = $dot; State = $st; Sub = $sub }
    $script:TileTitles[$key] = $t
}

# статистика
$kpiRow = New-Row 84 6
$Kpi = @{
    avail   = New-Kpi 'Доступность VPN · 2 ч' { Show-Page 'ultra' }
    speed   = New-Kpi 'Скорость туннеля сейчас' { Show-Page 'traffic' }
    today   = New-Kpi 'Трафик туннеля сегодня' { Show-Page 'traffic' }
    clients = New-Kpi 'Клиенты WG-Server' { Show-Page 'wg' }
    fixes   = New-Kpi 'Автовосстановлений' { Show-Page 'log' }
    events  = New-Kpi 'События сегодня' { Show-Page 'log' }
}
$ki = 0
foreach ($k in 'avail', 'speed', 'today', 'clients', 'fixes', 'events') {
    if ($ki -eq 5) { $Kpi[$k].Panel.Margin = '0,0,0,0' }
    $kpiRow.Controls.Add($Kpi[$k].Panel, $ki, 0); $ki++
}

$homeChart = New-Canvas 210 (New-LiveSpec { 'u' })
$homeEvents = New-LogBox 170
Add-Blocks $pgHome @($hero, $tileRow, $kpiRow, (New-SectionTitle 'Трафик туннеля — последние 5 минут'), $homeChart,
    (New-SectionTitle 'Последние события'), $homeEvents)
$pages['home'] = $pgHome

# ================================================================ вкладки компонентов
$CompHdr = @{}
$CompLog = @{}
$CompAvail = @{}
$script:compSig = @{}
$LogFilter = @{
    meduza = 'MeduzaVPN|CLI meduzavpn|Установщик|release\.json|обновлен'
    ultra  = 'ULTRA|[Тт]уннел|meduzavpn connect|трафик|переподключ|Два туннеля|Режим'
    amnezia = 'AmneziaWG'
    wg     = 'wg_server|WS4W|WireGuard'
    ics    = 'ICS|раздач|SharedAccess'
    zapret = 'zapret|winws|WinDivert|стратеги'
}

function New-CompPage([string]$Key, [object[]]$Buttons, [object[]]$Extra, [string]$Hint = '', [switch]$ExtraFirst) {
    $pg = New-Page $true
    $h = New-Object Windows.Forms.Panel
    $h.Height = 86; $h.BackColor = $Clr.Card
    $dot = New-Dot 16; $dot.Location = New-Object Drawing.Point(22, 22)
    $st = New-Label 'нет данных' $F.Hero; $st.Location = New-Object Drawing.Point(46, 10)
    $sub = New-Label '' $F.Base $Clr.Dim; $sub.AutoSize = $false; $sub.AutoEllipsis = $true
    $sub.Location = New-Object Drawing.Point(49, 52); $sub.Size = New-Object Drawing.Size(500, 22)
    $bf = New-Object Windows.Forms.FlowLayoutPanel
    $bf.AutoSize = $true; $bf.WrapContents = $false; $bf.BackColor = $Clr.Card; $bf.Anchor = 'Top,Right'
    foreach ($b in $Buttons) { $bf.Controls.Add($b) }
    $h.Controls.AddRange(@($dot, $st, $sub, $bf))
    $h.Add_Resize({
        $f2 = $this.Controls[3]
        $f2.Location = New-Object Drawing.Point(($this.ClientSize.Width - $f2.Width - 18), 26)
        $this.Controls[2].Width = [Math]::Max(100, $f2.Left - 60)
    }.GetNewClosure())
    $av = New-SectionTitle 'Состояние за 2 часа'
    $tl = New-Canvas 40 @{ Kind = 'timeline'; Key = $Key } $Clr.Bg
    $kv = New-Canvas 120 @{ Kind = 'kv'; Key = $Key; Rows = { [Math]::Max(1, @(Get-Kv $sp.Key).Count) * 26 + 12 } }
    $log = New-LogBox 220
    $blocks = @($h)
    if ($Hint) { $hl = New-Label $Hint $F.Small $Clr.Dim; $hl.AutoSize = $false; $hl.Height = 20; $blocks += $hl }
    if ($ExtraFirst) { $blocks += @($Extra) + @($av, $tl, (New-SectionTitle 'Подробности'), $kv) + @((New-SectionTitle 'События сегодня'), $log) }
    else { $blocks += @($av, $tl, (New-SectionTitle 'Подробности'), $kv) + @($Extra) + @((New-SectionTitle 'События сегодня'), $log) }
    Add-Blocks $pg $blocks
    $script:CompHdr[$Key] = [pscustomobject]@{ Dot = $dot; State = $st; Sub = $sub }
    $script:CompLog[$Key] = $log
    $script:CompAvail[$Key] = $av
    $script:compSig[$Key] = ''
    $pages[$Key] = $pg
}

# --- MeduzaVPN: выбор VPN (страны) и протокола, тест протоколов
$mzBox = New-Object Windows.Forms.Panel
$mzBox.Height = 132; $mzBox.BackColor = $Clr.Card
$mzL1 = New-Label 'VPN (страна / локация)' $F.Small $Clr.Dim; $mzL1.Location = New-Object Drawing.Point(16, 10)
$cbSvc = New-Object Windows.Forms.ComboBox
$cbSvc.DropDownStyle = 'DropDownList'; $cbSvc.Width = 360; $cbSvc.Location = New-Object Drawing.Point(16, 30); $cbSvc.BackColor = $Clr.Input; $cbSvc.ForeColor = $Clr.Text; $cbSvc.FlatStyle = 'Flat'
$mzL2 = New-Label 'Протокол' $F.Small $Clr.Dim; $mzL2.Location = New-Object Drawing.Point(392, 10)
$cbProto = New-Object Windows.Forms.ComboBox
$cbProto.DropDownStyle = 'DropDownList'; $cbProto.Width = 200; $cbProto.Location = New-Object Drawing.Point(392, 30); $cbProto.BackColor = $Clr.Input; $cbProto.ForeColor = $Clr.Text; $cbProto.FlatStyle = 'Flat'
$mzBtns = New-Object Windows.Forms.FlowLayoutPanel
$mzBtns.AutoSize = $true; $mzBtns.WrapContents = $false; $mzBtns.BackColor = $Clr.Card; $mzBtns.Location = New-Object Drawing.Point(16, 62)
$mzBtns.Controls.AddRange(@(
    (New-Btn 'Применить' { Set-MzSelection } $true),
    (New-Btn 'Лучший из теста' { Select-BestProto }),
    (New-Btn 'Обновить список' { Send-Cmd 'meduza-catalog' 'обновление списка VPN и протоколов' }),
    ($script:btnMzReturn = New-Btn 'Вернуть выбранный протокол' { Send-Cmd 'meduza-proto-reset' 'возврат к выбранному протоколу' })
))
$mzInfo = New-Label '' $F.Small $Clr.Dim; $mzInfo.AutoSize = $false; $mzInfo.AutoEllipsis = $true
$mzInfo.Location = New-Object Drawing.Point(16, 102); $mzInfo.Size = New-Object Drawing.Size(900, 20); $mzInfo.Anchor = 'Top,Left,Right'
$mzBox.Controls.AddRange(@($mzL1, $cbSvc, $mzL2, $cbProto, $mzBtns, $mzInfo))
$script:MzSvcIds = @(); $script:MzProtoIds = @(); $script:MzSig = ''; $script:MzDirty = $false
$cbSvc.Add_SelectionChangeCommitted({ $script:MzDirty = $true })
$cbProto.Add_SelectionChangeCommitted({ $script:MzDirty = $true })

function Update-MzSelect {
    $mz = Get-Snap 'meduza'
    $cat = $(if ($mz -and $mz.PSObject.Properties['catalog']) { $mz.catalog } else { $null })
    $curS = $(if ($mz -and $mz.PSObject.Properties['serviceId']) { "$($mz.serviceId)" } else { '' })
    $curP = $(if ($mz -and $mz.PSObject.Properties['protocol']) { "$($mz.protocol)" } else { 'ultra' })
    $sig = "$(if ($cat) { "$($cat.at)|$(@($cat.services).Count)|$(@($cat.protocols).Count)" })|$curS|$curP"
    Set-Prop $mzInfo Text $(if (-not $mz -or -not $mz.PSObject.Properties['catalog']) { 'Список VPN и протоколов появится с агентом 1.8 (включите в MeduzaVPN управление из командной строки).' }
        elseif (-not $cat) { 'Список VPN и протоколов ещё не получен — нажмите «Обновить список».' }
        else { "С аккаунта: VPN — $(@($cat.services).Count), протоколов — $(@($cat.protocols).Count) · обновлено $($cat.at)" + $(if ($cat.error) { " · $($cat.error)" } else { '' }) + ' · после «Применить» агент сам переподключит MeduzaVPN.' })
    $ovr = $(if ($mz -and $mz.PSObject.Properties['protocolOverride']) { "$($mz.protocolOverride)" } else { '' })
    if ($ovr) { Set-Prop $mzInfo Text "Выбранный протокол $curP перестал работать — агент переключился на $ovr и будет пробовать вернуть выбранный."; Set-Prop $mzInfo ForeColor $Clr.Warn }
    else { Set-Prop $mzInfo ForeColor $Clr.Dim }
    Set-Prop $script:btnMzReturn Visible ([bool]$ovr)
    if ($sig -eq $script:MzSig -or $script:MzDirty -or $cbSvc.DroppedDown -or $cbProto.DroppedDown) { return }
    $script:MzSig = $sig
    $cbSvc.Items.Clear(); $script:MzSvcIds = @('')
    [void]$cbSvc.Items.Add('(по умолчанию — единственный на аккаунте)')
    foreach ($s in @(if ($cat) { $cat.services })) {
        if (-not $s) { continue }
        [void]$cbSvc.Items.Add(("$($s.name)" + $(if ($s.info) { " — $($s.info)" } else { '' }) + $(if ("$($s.id)" -ne "$($s.name)") { "  [$($s.id)]" } else { '' })))
        $script:MzSvcIds += "$($s.id)"
    }
    if ($curS -and $script:MzSvcIds -notcontains $curS) { [void]$cbSvc.Items.Add("$curS (из настроек)"); $script:MzSvcIds += $curS }
    $cbSvc.SelectedIndex = [Math]::Max(0, [array]::IndexOf([string[]]$script:MzSvcIds, $curS))
    $cbProto.Items.Clear(); $script:MzProtoIds = @()
    foreach ($p in @(if ($cat) { $cat.protocols })) {
        if (-not $p) { continue }
        [void]$cbProto.Items.Add(("$($p.name)" + $(if ($p.info) { " — $($p.info)" } else { '' }))); $script:MzProtoIds += "$($p.id)"
    }
    if ($script:MzProtoIds -notcontains $curP -and $script:MzProtoIds -contains "meduza-$curP") { $curP = "meduza-$curP" }
    if ($script:MzProtoIds -notcontains $curP) { [void]$cbProto.Items.Add($curP); $script:MzProtoIds += $curP }
    $cbProto.SelectedIndex = [Math]::Max(0, [array]::IndexOf([string[]]$script:MzProtoIds, $curP))
}

function Set-MzSelection {
    if ($cbSvc.SelectedIndex -lt 0 -or $cbProto.SelectedIndex -lt 0) { return }
    $sid = $script:MzSvcIds[$cbSvc.SelectedIndex]; $pid2 = $script:MzProtoIds[$cbProto.SelectedIndex]
    $ans = [Windows.Forms.MessageBox]::Show("Переподключить MeduzaVPN?`n`nVPN: $($cbSvc.SelectedItem)`nПротокол: $pid2`n`nКлиенты wg_server на несколько секунд потеряют интернет, раздача восстановится сама.", 'VpnGuard', 'YesNo', 'Question')
    if ($ans -ne 'Yes') { return }
    $script:MzDirty = $false
    if ($Demo) { Set-Footer "ДЕМО: выбор не сохранён (VPN «$sid», протокол $pid2)"; return }
    try {
        $o = Read-ConfigObject
        Set-CfgVal $o 'meduza.serviceId' $sid; Set-CfgVal $o 'meduza.protocol' $pid2
        $tmp = "$ConfigPath.tmp"; $o | ConvertTo-Json -Depth 6 | Set-Content $tmp -Encoding UTF8; Move-Item $tmp $ConfigPath -Force
        Set-Footer "Сохранено: VPN «$(if ($sid) { $sid } else { 'по умолчанию' })», протокол $pid2 — агент переподключит MeduzaVPN на следующей проверке"
        $script:MzSig = ''
    } catch { [Windows.Forms.MessageBox]::Show("Не удалось сохранить: $($_.Exception.Message)", 'VpnGuard', 'OK', 'Error') | Out-Null }
}

function Get-ProtoTest { $mz = Get-Snap 'meduza'; if ($mz -and $mz.PSObject.Properties['protoTest']) { return $mz.protoTest }; return $null }
function Select-BestProto {
    $pt = Get-ProtoTest
    $best = @($(if ($pt) { $pt.results }) | Where-Object { $_ -and $_.ok } | Sort-Object { [int]$_.pingMs }) | Select-Object -First 1
    if (-not $best) { [Windows.Forms.MessageBox]::Show('Нет результатов теста с рабочим протоколом — запустите «Тест протоколов».', 'VpnGuard') | Out-Null; return }
    $i = [array]::IndexOf([string[]]$script:MzProtoIds, "$($best.protocol)")
    if ($i -ge 0) { $cbProto.SelectedIndex = $i; $script:MzDirty = $true; Set-Footer "Выбран $($best.protocol) (отклик $($best.pingMs) мс) — нажмите «Применить»" }
}
function Start-ProtoTest {
    $ans = [Windows.Forms.MessageBox]::Show("Запустить тест протоколов?`n`nАгент по очереди подключит MeduzaVPN каждым протоколом и проверит трафик (до минуты на протокол), затем вернёт текущий.`n`nНа время теста клиенты wg_server будут терять интернет.", 'VpnGuard', 'YesNo', 'Question')
    if ($ans -eq 'Yes') { Send-Cmd 'meduza-test' 'тест протоколов MeduzaVPN' }
}

function Draw-ProtoTest($g, [int]$W, [int]$H, $sp) {
    $pt = $(if ($sp.Src) { & $sp.Src } else { Get-ProtoTest })
    $res = @($(if ($pt) { $pt.results }) | Where-Object { $_ })
    $y = 4
    if ($pt -and $pt.running) { DT $g "Идёт тест: $($pt.index) из $($pt.total) · сейчас: $($pt.current)" $F.Bold $Clr.Accent 16 $y ($W - 32) 24; $y += 28 }
    if (-not $res.Count) { DT $g $(if ($sp.Src) { 'Тест ещё не запускали. «Тест конфигов» по очереди поднимет каждый конфиг и проверит трафик через туннель.' } else { 'Тест ещё не запускали. «Тест протоколов» по очереди подключит каждый протокол и проверит трафик через туннель.' }) $F.Base $Clr.Dim 16 $y ($W - 32) 26; return }
    if ($pt.at -and -not $pt.running) { DT $g "Последний тест: $($pt.at)" $F.Small $Clr.Dim 16 $y 300 20; $y += 22 }
    $mz = Get-Snap 'meduza'; $cur = $(if ($sp.Cur) { & $sp.Cur } elseif ($mz) { "$($mz.protocol)" } else { '' })
    $cols = @(@(0.0, $(if ($sp.Src) { 'Конфиг' } else { 'Протокол' })), @(0.20, 'Результат'), @(0.36, 'Проверки'), @(0.48, 'Подключение'), @(0.62, 'Отклик'), @(0.74, 'Ошибка'))
    foreach ($c in $cols) { DT $g $c[1] $F.Small $Clr.Dim ([int](30 + ($W - 40) * $c[0])) $y 200 20 }
    $y += 22
    for ($i = 0; $i -lt $res.Count; $i++) {
        $r = $res[$i]; $ry = $y + $i * 26
        $rn = $(if ($sp.Src) { "$($r.name)" } else { "$($r.protocol)" })
        $isCur = ($cur -and ($rn -eq $cur -or $rn -eq "meduza-$cur"))
        if ($isCur) { $g.FillRectangle($Br.Row, 8, $ry, $W - 16, 26); $g.FillRectangle($Br.Accent, 8, $ry, 3, 26) } elseif ($i % 2) { $g.FillRectangle($Br.Row, 8, $ry, $W - 16, 26) }
        $g.FillEllipse($Brushes[$(if ($r.ok) { 0 } else { 2 })], 14, $ry + 8, 10, 10)
        $vals = @(("$($r.protocol)" + $(if ($isCur) { '  ← текущий' } else { '' })), $(if ($r.ok) { 'работает' } else { 'не работает' }), "$($r.probes)",
            ('{0} с' -f $r.connectSec), $(if ([int]$r.pingMs -ge 0) { "$($r.pingMs) мс" } else { '—' }), "$($r.error)")
        for ($j = 0; $j -lt $cols.Count; $j++) {
            $cx = [int](30 + ($W - 40) * $cols[$j][0]); $nx = $(if ($j -lt $cols.Count - 1) { [int](30 + ($W - 40) * $cols[$j + 1][0]) } else { $W - 10 })
            DT $g $vals[$j] $(if ($j -eq 0) { $F.Bold } else { $F.Base }) $(if ($j -eq 1) { $(if ($r.ok) { $Clr.Ok } else { $Clr.Bad }) } else { $Clr.Text }) $cx $ry ($nx - $cx - 8) 26
        }
    }
}

New-CompPage 'meduza' @(
    (New-Btn 'Перезапустить MeduzaVPN' { Send-Cmd 'restart-meduza' 'перезапуск MeduzaVPN' }),
    (New-Btn 'Тест протоколов' { Start-ProtoTest }),
    (New-Btn 'Проверить обновление' { Send-Cmd 'check-update' 'проверка обновления' })
) @(
    (New-SectionTitle 'VPN и протокол'), $mzBox,
    (New-SectionTitle 'Тест протоколов (зелёный — трафик через туннель проходит)'),
    (New-Canvas 80 @{ Kind = 'ptest'; Rows = {
        $pt = Get-ProtoTest; $n = @($(if ($pt) { $pt.results }) | Where-Object { $_ }).Count
        $(if ($pt -and $pt.running) { 28 } else { 0 }) + $(if ($n) { 22 + 22 + $n * 26 + 8 } else { 34 }) } })
) -ExtraFirst

function Switch-DualUi {
    $u = Get-Snap 'ultra'; $sb = $(if ($u -and $u.PSObject.Properties['standby']) { $u.standby } else { $null })
    if (-not $sb) { [Windows.Forms.MessageBox]::Show('Переключение — только в режиме «два туннеля».', 'VpnGuard') | Out-Null; return }
    if (-not $sb.ok -and [Windows.Forms.MessageBox]::Show("Резервный туннель $($sb.name) сейчас: $($sb.state).`nВсё равно попробовать переключить?", 'VpnGuard', 'YesNo', 'Warning') -ne 'Yes') { return }
    Send-Cmd 'dual-switch' "переключение на $($sb.name)"
}
$btnDualSw = New-Btn 'Переключить на другой' { Switch-DualUi }
New-CompPage 'ultra' @(
    (New-Btn 'Переподключить' { Send-Cmd 'reconnect' 'переподключение туннеля' }),
    $btnDualSw
) @(
    (New-SectionTitle 'Скорость — последние 5 минут'), (New-Canvas 210 (New-LiveSpec { 'u' })),
    (New-SectionTitle 'Скорость — последние 2 часа'), (New-Canvas 190 (New-HistSpec { 'u' }))
)

New-CompPage 'wg' @(
    (New-Btn 'Перезапустить туннель' { Send-Cmd 'restart-wg' 'перезапуск wg_server' }),
    (New-Btn 'Открыть WS4W' { Open-Ws4w })
) @(
    (New-SectionTitle 'Клиенты (зелёный — рукопожатие за последние 3 минуты; ↓ — клиенту, ↑ — от клиента)'),
    (New-ToolRow @(
        (New-Btn '＋ Новый клиент' { Add-WgClientUi } $true),
        (New-Btn 'Настройки и QR' { Show-WgClientUi }),
        (New-Btn 'Удалить клиента' { Remove-WgClientUi })
    ) 'Щелчок по строке — выбрать, двойной щелчок — настройки и QR.'),
    (New-Canvas 90 @{ Kind = 'peers'; Rows = { 28 + [Math]::Max(1, @(Get-PeerRows).Count) * 28 + 8 } }),
    (New-SectionTitle 'Скорость WG-Server — последние 5 минут'), (New-Canvas 200 (New-LiveSpec { 'w' }))
)

New-CompPage 'ics' @(
    (New-Btn 'Восстановить раздачу' { Send-Cmd 'reapply-ics' 'восстановление раздачи' }),
    (New-Btn 'Диагностика раздачи' { Show-Page 'diag'; Start-Diag $false })
) @() 'После каждого переподключения туннеля Windows создаёт адаптер заново и теряет общий доступ — агент включает его снова сам.'

# --- zapret: свои списки
$ZLists = @(
    @('list-general-user.txt', 'Свои домены — обрабатывать zapret и пускать мимо VPN', 'domain', 'domain.example.abc'),
    @('list-exclude-user.txt', 'Исключения — домены, которые zapret не трогает', 'domain', 'domain.example.abc'),
    @('ipset-exclude-user.txt', 'Исключения — IP-адреса и подсети (не трогать)', 'ip', '203.0.113.113/32')
)
$zlBox = New-Object Windows.Forms.Panel
$zlBox.Height = 268; $zlBox.BackColor = $Clr.Card; $zlBox.Padding = '16,12,16,12'
$cbZList = New-Object Windows.Forms.ComboBox
$cbZList.DropDownStyle = 'DropDownList'; $cbZList.Width = 440; $cbZList.Location = New-Object Drawing.Point(16, 12); $cbZList.BackColor = $Clr.Input; $cbZList.ForeColor = $Clr.Text; $cbZList.FlatStyle = 'Flat'
foreach ($zl in $ZLists) { [void]$cbZList.Items.Add($zl[1]) }
$zlHint = New-Label 'По одному на строку: youtube.com, rutracker.org … (поддомены включаются сами). Строки с # — комментарии.' $F.Small $Clr.Dim
$zlHint.Location = New-Object Drawing.Point(470, 16)
$tbZList = New-Object Windows.Forms.TextBox
$tbZList.Multiline = $true; $tbZList.ScrollBars = 'Vertical'; $tbZList.AcceptsReturn = $true; $tbZList.Font = $F.Mono
$tbZList.BackColor = $Clr.Input; $tbZList.ForeColor = $Clr.Text; $tbZList.BorderStyle = 'FixedSingle'
$tbZList.Location = New-Object Drawing.Point(16, 46); $tbZList.Size = New-Object Drawing.Size(900, 168); $tbZList.Anchor = 'Top,Left,Right'
$zlBtns = New-Object Windows.Forms.FlowLayoutPanel
$zlBtns.AutoSize = $true; $zlBtns.WrapContents = $false; $zlBtns.BackColor = $Clr.Card; $zlBtns.Location = New-Object Drawing.Point(16, 224)
$zlState = New-Label '' $F.Small $Clr.Dim; $zlState.Margin = '8,8,0,0'
$zlBtns.Controls.AddRange(@(
    (New-Btn 'Сохранить и применить' { Save-ZList } $true),
    (New-Btn 'Отменить изменения' { Import-ZList }),
    (New-Btn 'Открыть папку списков' { $d = Get-ZListsDir; if (Test-Path $d) { Start-Process explorer.exe $d } else { Set-Footer "Папки нет: $d (zapret ещё не установлен)" } }),
    $zlState
))
$zlBox.Controls.AddRange(@($cbZList, $zlHint, $tbZList, $zlBtns))
$zlBox.Add_Resize({ $tbZList.Width = [Math]::Max(200, $zlBox.ClientSize.Width - 32) })

function Get-ZListsDir {
    $z = Get-Snap 'zapret'
    if ($z -and $z.PSObject.Properties['dir'] -and $z.dir) { return (Join-Path "$($z.dir)" 'lists') }
    try { $o = Read-ConfigObject; $d = Get-CfgVal $o 'zapret.dir'; if ($d) { return (Join-Path "$d" 'lists') } } catch { }
    return (Join-Path $Root 'zapret\lists')
}
function Import-ZList {
    $i = [Math]::Max(0, $cbZList.SelectedIndex); $def = $ZLists[$i]
    $path = Join-Path (Get-ZListsDir) $def[0]
    $lines = @()
    if (Test-Path $path) { $lines = @([IO.File]::ReadAllLines($path) | Where-Object { $_.Trim() -ne $def[3] -and $_ -notmatch '^#\s*Never leave this file empty' }) }
    $tbZList.Text = ($lines -join "`r`n")
    $zlState.Text = $(if (Test-Path $path) { "$($def[0]) · записей: $(@($lines | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }).Count)" } else { "$($def[0]) — ещё нет (появится после установки zapret)" })
    $script:ZListDirty = $false
}
$cbZList.Add_SelectedIndexChanged({ Import-ZList })
$tbZList.Add_TextChanged({ $script:ZListDirty = $true })

function Save-ZList {
    $i = [Math]::Max(0, $cbZList.SelectedIndex); $def = $ZLists[$i]
    $out = New-Object Collections.ArrayList; $bad = New-Object Collections.ArrayList
    foreach ($raw in ($tbZList.Text -split "`r?`n")) {
        $l = $raw.Trim()
        if (-not $l) { continue }
        if ($l.StartsWith('#')) { [void]$out.Add($l); continue }
        if ($def[2] -eq 'domain') {
            $l = $l.ToLower() -replace '^[a-z]+://', '' -replace '[/:?#].*$', '' -replace '^\*\.', '' -replace '^www\.', ''
            # кириллические домены (.рф) — в punycode, как их видит zapret
            if ($l -match '[а-яё]') { try { $l = (New-Object Globalization.IdnMapping).GetAscii($l) } catch { } }
            if ($l -match '^([a-z0-9а-яё-]+\.)+[a-z0-9а-яё-]{2,}$') { [void]$out.Add($l) } else { [void]$bad.Add($raw.Trim()) }
        } else {
            if ($l -match '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$' -or $l -match '^[0-9a-f:]+(/\d{1,3})?$') { [void]$out.Add($l) } else { [void]$bad.Add($l) }
        }
    }
    if ($bad.Count) {
        [Windows.Forms.MessageBox]::Show("Не понял строки:`n" + (($bad | Select-Object -First 10) -join "`n") + "`n`nНужно: $(if ($def[2] -eq 'domain') { 'домен, например rutracker.org' } else { 'IP или подсеть, например 1.2.3.4 или 1.2.3.0/24' })", 'VpnGuard', 'OK', 'Warning') | Out-Null
        return
    }
    $items = @($out | Where-Object { -not $_.StartsWith('#') })
    if ($Demo) { Set-Footer "ДЕМО: список не сохранён ($($items.Count) записей)"; return }
    $dir = Get-ZListsDir
    if (-not (Test-Path $dir)) { [Windows.Forms.MessageBox]::Show("zapret ещё не установлен (нет $dir). Включите zapret — он скачается, затем добавьте списки.", 'VpnGuard') | Out-Null; return }
    # файл не должен быть пустым (так требует zapret) — оставляем заглушку
    $final = @($out | Select-Object -Unique)
    if (-not $items.Count) { $final = @('# Never leave this file empty') + @($final) + @($def[3]) }
    [IO.File]::WriteAllText((Join-Path $dir $def[0]), (($final -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding $false))
    $script:ZListDirty = $false
    Import-ZList
    Send-Cmd 'zapret-reload' "применение списка $($def[0])"
}

# выбор стратегии прямо на вкладке
$zsBox = New-Object Windows.Forms.Panel
$zsBox.Height = 96; $zsBox.BackColor = $Clr.Card
$zsL = New-Label 'Стратегия' $F.Small $Clr.Dim; $zsL.Location = New-Object Drawing.Point(16, 10)
$cbZStrat = New-Object Windows.Forms.ComboBox
$cbZStrat.DropDownStyle = 'DropDownList'; $cbZStrat.Width = 380; $cbZStrat.Location = New-Object Drawing.Point(16, 30); $cbZStrat.BackColor = $Clr.Input; $cbZStrat.ForeColor = $Clr.Text; $cbZStrat.FlatStyle = 'Flat'
$zsBtns = New-Object Windows.Forms.FlowLayoutPanel
$zsBtns.AutoSize = $true; $zsBtns.WrapContents = $false; $zsBtns.BackColor = $Clr.Card; $zsBtns.Location = New-Object Drawing.Point(408, 26)
$zsBtns.Controls.AddRange(@(
    (New-Btn 'Применить' { Set-ZStrategyUi } $true),
    (New-Btn 'Проверить сайты сейчас' { Send-Cmd 'zapret-check' 'проверка сайтов через zapret' })
))
$zsInfo = New-Label '' $F.Small $Clr.Dim; $zsInfo.AutoSize = $false; $zsInfo.AutoEllipsis = $true
$zsInfo.Location = New-Object Drawing.Point(16, 66); $zsInfo.Size = New-Object Drawing.Size(900, 20); $zsInfo.Anchor = 'Top,Left,Right'
$zsBox.Controls.AddRange(@($zsL, $cbZStrat, $zsBtns, $zsInfo))
$script:ZsNames = @(''); $script:ZsSig = ''; $script:ZsDirty = $false
$cbZStrat.Add_SelectionChangeCommitted({ $script:ZsDirty = $true })

function Update-ZStratUi {
    $z = Get-Snap 'zapret'
    $man = $(if ($z -and $z.PSObject.Properties['manual']) { "$($z.manual)" } else { try { "$(Get-CfgVal (Read-ConfigObject) 'zapret.strategy')" } catch { '' } })
    $cur = $(if ($z) { "$($z.current)" } else { '' })
    $res = @(Get-ZResults)
    $names = @(if ($z) { @($z.strategies) | Where-Object { $_ } })
    Set-Prop $zsInfo Text $(if (-not $z) { 'Нет данных от агента.' }
        elseif (-not $z.enabled) { 'zapret выключен — стратегия применится, когда он включится.' }
        elseif ($man) { "Выбрана вручную: $man. Автоподбор не меняет её. «(авто)» — снова подбирать самому." }
        elseif ($cur) { "Подобрана автоматически: $cur. Можно выбрать другую — агент перезапустит zapret и сразу проверит сайты." }
        else { 'Стратегия ещё не выбрана — идёт или будет подбор.' })
    $sig = "$($names -join '|')|$man|$(@($res).Count)"
    if ($sig -eq $script:ZsSig -or $script:ZsDirty -or $cbZStrat.DroppedDown) { return }
    $script:ZsSig = $sig
    $cbZStrat.Items.Clear(); $script:ZsNames = @('')
    [void]$cbZStrat.Items.Add('(авто) — подбирать автоматически')
    foreach ($n in $names) {
        $r = $res | Where-Object { "$($_.name)" -eq "$n" } | Select-Object -First 1
        [void]$cbZStrat.Items.Add("$n" + $(if ($r) { "   ·   $($r.ok) из $($r.total) при подборе" } else { '' })); $script:ZsNames += "$n"
    }
    if ($man -and $script:ZsNames -notcontains $man) { [void]$cbZStrat.Items.Add("$man (нет в папке zapret)"); $script:ZsNames += $man }
    $cbZStrat.SelectedIndex = [Math]::Max(0, [array]::IndexOf([string[]]$script:ZsNames, $man))
}
function Set-ZStrategyUi {
    if ($cbZStrat.SelectedIndex -lt 0) { return }
    $v = $script:ZsNames[$cbZStrat.SelectedIndex]
    $script:ZsDirty = $false
    if ($Demo) { Set-Footer "ДЕМО: стратегия «$(if ($v) { $v } else { 'авто' })» не сохранена"; return }
    try {
        $o = Read-ConfigObject; Set-CfgVal $o 'zapret.strategy' $v
        $tmp = "$ConfigPath.tmp"; $o | ConvertTo-Json -Depth 6 | Set-Content $tmp -Encoding UTF8; Move-Item $tmp $ConfigPath -Force
        $script:ZsSig = ''
        Send-Cmd 'check-now' $(if ($v) { "стратегия zapret «$v»" } else { 'автоподбор стратегии zapret' })
    } catch { [Windows.Forms.MessageBox]::Show("Не удалось сохранить: $($_.Exception.Message)", 'VpnGuard', 'OK', 'Error') | Out-Null }
}
# щелчок по строке таблицы стратегий — выбрать её в списке
function Select-ZRowUi([int]$Y) {
    $g = $script:ZRowGeo; if (-not $g) { return }
    $i = [int][Math]::Floor(($Y - $g[0]) / $g[1])
    $res = @(Get-ZResults)
    if ($i -lt 0 -or $i -ge $res.Count) { return }
    $n = "$($res[$i].name)"
    $ix = [array]::IndexOf([string[]]$script:ZsNames, $n)
    if ($ix -ge 0) { $cbZStrat.SelectedIndex = $ix; $script:ZsDirty = $true; Set-Footer "Выбрана стратегия «$n» — нажмите «Применить»" }
}

# проверка сайтов сейчас: что открывается, что нет и почему
function Get-ZChecks { $z = Get-Snap 'zapret'; if ($z -and $z.PSObject.Properties['checks']) { return @($z.checks | Where-Object { $_ }) }; return @() }
function Draw-ZChecks($g, [int]$W, [int]$H, $sp) {
    $z = Get-Snap 'zapret'; $ch = @(Get-ZChecks)
    if (-not $ch.Count) { DT $g $(if ($z -and -not $z.enabled) { 'zapret выключен.' } else { 'Проверки ещё не было (идёт раз в 10 мин или кнопкой «Проверить сайты сейчас»).' }) $F.Base $Clr.Dim 16 0 ($W - 32) $H; return }
    $cols = @(@(0.0, 'Что проверяется'), @(0.25, 'Адрес'), @(0.49, 'Результат'), @(0.93, 'Время'))
    $x0 = 30; $cw = $W - $x0 - 12
    foreach ($c in $cols) { DT $g $c[1] $F.Small $Clr.Dim ([int]($x0 + $cw * $c[0])) 4 220 20 }
    for ($i = 0; $i -lt $ch.Count; $i++) {
        $r = $ch[$i]; $y = 26 + $i * 24
        if ($i % 2 -eq 0) { $g.FillRectangle($Br.Row, 8, $y, $W - 16, 24) }
        $g.FillEllipse($Brushes[$(if ($r.ok) { 0 } else { 2 })], 14, $y + 7, 10, 10)
        $vals = @("$($r.n)", "$($r.h)", $(if ($r.ok) { 'открывается' } else { "$($r.why)" }), $(if ([int]$r.ms -ge 0) { "$($r.ms) мс" } else { '—' }))
        for ($j = 0; $j -lt $cols.Count; $j++) {
            $cx = [int]($x0 + $cw * $cols[$j][0]); $nx = $(if ($j -lt $cols.Count - 1) { [int]($x0 + $cw * $cols[$j + 1][0]) } else { $W - 10 })
            DT $g $vals[$j] $(if ($j -eq 0) { $F.Bold } else { $F.Base }) $(if ($j -eq 2) { $(if ($r.ok) { $Clr.Ok } else { $Clr.Bad }) } elseif ($j -eq 1) { $Clr.Dim } else { $Clr.Text }) $cx $y ($nx - $cx - 8) 24
        }
    }
}

$zToggle2 = New-Btn 'Включить zapret' { Switch-Zapret } $true
[void]$script:ZToggleBtns.Add($zToggle2)
New-CompPage 'zapret' @(
    $zToggle2,
    (New-Btn 'Подобрать стратегию' { Send-Cmd 'zapret-test' 'подбор стратегии zapret' }),
    (New-Btn 'Обновить zapret' { Send-Cmd 'zapret-update' 'проверка обновления zapret' })
) @(
    (New-SectionTitle 'Выбор стратегии'), $zsBox,
    (New-SectionTitle 'Проверка сайтов сейчас (через zapret, мимо VPN)'),
    (New-Canvas 60 @{ Kind = 'zchk'; Rows = { $n = @(Get-ZChecks).Count; $(if ($n) { 26 + $n * 24 + 8 } else { 34 }) } }),
    (New-SectionTitle 'Результаты подбора (щелчок — выбрать стратегию, наведение — подробности)'),
    (New-Canvas 80 @{ Kind = 'zres'; Rows = {
        $z = Get-Snap 'zapret'; $n = @(Get-ZResults).Count
        $(if ($z -and $z.PSObject.Properties['progress'] -and $z.progress) { 28 } else { 0 }) + $(if ($n) { 24 + $n * 24 + 8 } else { 34 }) } }),
    (New-SectionTitle 'Трафик мимо VPN — последние 5 минут (оценка)'), (New-Canvas 200 (New-LiveSpec { 'z' })),
    (New-SectionTitle 'Трафик мимо VPN — последние 2 часа (оценка)'), (New-Canvas 180 (New-HistSpec { 'z' })),
    (New-SectionTitle 'Свои списки'), $zlBox
) -ExtraFirst 'YouTube и Discord этого ПК идут мимо VPN. Только для самого компьютера: у клиентов WG-Server они, пока zapret включён, не открываются (zapret не умеет обрабатывать чужой трафик).'

# ================================================================ AmneziaVPN
# приложение AmneziaVPN: сервер и протокол выбираются в нём; VpnGuard следит за ним и перезапускает при сбое
function Draw-Awg($g, [int]$W, [int]$H, $sp) { }
$awgInfo = New-Label '' $F.Base $Clr.Dim; $awgInfo.AutoSize = $false; $awgInfo.Height = 120
New-CompPage 'amnezia' @(
    (New-Btn 'Перезапустить AmneziaVPN' { if ([Windows.Forms.MessageBox]::Show("Закрыть и снова открыть AmneziaVPN?`n`nТуннель переподключится сам, если в AmneziaVPN включено «Автоподключение».", 'VpnGuard', 'YesNo', 'Question') -eq 'Yes') { Send-Cmd 'reconnect-awg' 'перезапуск AmneziaVPN' } }),
    (New-Btn 'Открыть AmneziaVPN' { try { $e = Get-AwgExe; if (Test-Path $e) { Start-Process $e } else { Show-Page 'software' } } catch { } }),
    (New-Btn 'Режим AmneziaVPN' { Set-ModeUi 'amnezia' })
) @($awgInfo) -ExtraFirst
function Update-AwgInfo {
    $as = Get-Snap 'amnezia'; $m = Get-Mode
    $inst = $(if ($as) { [bool]$as.installed } else { $null })
    Set-Prop $awgInfo Text ("Режим сейчас: $(($ModeItems | Where-Object { $_[0] -eq $m })[1])" +
        $(if ($m -notin 'amnezia', 'dual') { ' — AmneziaVPN не используется (кнопка «Режим AmneziaVPN» переключит)' } elseif ($m -eq 'dual') { ' — AmneziaVPN работает вместе с MeduzaVPN' } else { '' }) + "`n" +
        $(if ($inst -eq $false) { 'AmneziaVPN не установлен — поставьте его на вкладке «Компоненты», затем добавьте сервер в самом приложении.' } else { 'Сервер и протокол выбираются в приложении AmneziaVPN. VpnGuard держит его запущенным, проверяет трафик туннеля и при сбое перезапускает приложение.' }) + "`n" +
        'Один раз включите в AmneziaVPN «Автоподключение» (Настройки → Подключение) и «Автозапуск» (Настройки → Приложение). «Kill Switch» лучше не включать — он мешает zapret и ответам клиентам WG-Server.')
}

# ================================================================ Компоненты
$pgSoft = New-Page $true
$softIntro = New-Label 'Всё, что нужно для работы: установка и обновление в один клик. Загрузка — только с официальных источников, с проверкой подписи или контрольной суммы.' $F.Base $Clr.Dim
$softIntro.AutoSize = $false; $softIntro.Height = 42
$softTools = New-ToolRow @(
    (New-Btn 'Установить всё нужное' { if ([Windows.Forms.MessageBox]::Show('Установить все компоненты, нужные для текущего режима, которых нет?', 'VpnGuard', 'YesNo', 'Question') -eq 'Yes') { Send-Cmd 'install-missing' 'установка недостающих компонентов' } } $true),
    (New-Btn 'Проверить версии' { Send-Cmd 'software-check' 'проверка версий компонентов' })
) ''
$softTable = New-Object Windows.Forms.TableLayoutPanel
$softTable.ColumnCount = 5; $softTable.AutoSize = $true; $softTable.BackColor = $Clr.Card; $softTable.Padding = '12,8,12,8'
foreach ($colW in 34, 16, 16, 18, 16) { [void]$softTable.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Percent', $colW))) }
foreach ($h in 'Компонент', 'Установлено', 'Последняя версия', 'Состояние', '') { $l = New-Label $h $F.Small $Clr.Dim; $l.Margin = '4,4,4,8'; $softTable.Controls.Add($l) }
$SoftRows = @{}
$SoftIds = @(@('meduza', 'MeduzaVPN', 'VPN (режим MeduzaVPN)'), @('meduzacli', 'MeduzaVPN CLI', 'управление MeduzaVPN из агента'), @('wireguard', 'WireGuard', 'туннель WG-Server для клиентов'),
    @('amneziavpn', 'AmneziaVPN', 'VPN (режим AmneziaVPN)'), @('ws4w', 'WS4W', 'окно настройки сервера — не обязательно'), @('zapret', 'zapret-discord-youtube', 'YouTube и Discord мимо блокировок'))
foreach ($si in $SoftIds) {
    $id = $si[0]
    $nm = New-Object Windows.Forms.Label; $nm.AutoSize = $true; $nm.Text = "$($si[1])`n$($si[2])"; $nm.Font = $F.Base; $nm.ForeColor = $Clr.Text; $nm.Margin = '4,6,4,6'
    $iv = New-Label '—' $F.Base; $iv.Margin = '4,10,4,6'
    $lv = New-Label '—' $F.Base $Clr.Dim; $lv.Margin = '4,10,4,6'
    $stl = New-Label '' $F.Base $Clr.Dim; $stl.Margin = '4,10,4,6'; $stl.MaximumSize = New-Object Drawing.Size(260, 0)
    $btn = New-Btn 'Установить' ([scriptblock]::Create("Install-SoftUi '$id'"))
    $btn.Margin = '4,6,4,6'
    $softTable.Controls.AddRange(@($nm, $iv, $lv, $stl, $btn))
    $SoftRows[$id] = [pscustomobject]@{ Name = $nm; Inst = $iv; Latest = $lv; State = $stl; Btn = $btn; Title = $si[1] }
}
$appBox = New-Object Windows.Forms.Panel
$appBox.Height = 92; $appBox.BackColor = $Clr.Card
$appT = New-Label 'VpnGuard (это приложение)' $F.Bold $Clr.Text; $appT.Location = New-Object Drawing.Point(16, 10)
$appInfo = New-Label '' $F.Base $Clr.Dim; $appInfo.AutoSize = $false; $appInfo.AutoEllipsis = $true
$appInfo.Location = New-Object Drawing.Point(16, 32); $appInfo.Size = New-Object Drawing.Size(900, 20)
$appBtns = New-Object Windows.Forms.FlowLayoutPanel
$appBtns.AutoSize = $true; $appBtns.WrapContents = $false; $appBtns.BackColor = $Clr.Card; $appBtns.Location = New-Object Drawing.Point(12, 54)
$appBtns.Controls.AddRange(@(
    (New-Btn 'Обновить сейчас' { Send-Cmd 'app-update' 'обновление VpnGuard' } $true),
    (New-Btn 'Проверить' { Send-Cmd 'app-check' 'проверка обновления VpnGuard' }),
    (New-Btn 'Где взять обновления…' { Show-Page 'settings' })
))
$appBox.Controls.AddRange(@($appT, $appInfo, $appBtns))
$appBox.Add_Resize({ $appInfo.Width = [Math]::Max(200, $appBox.ClientSize.Width - 32) })
function Update-AppUi {
    $av = Get-Snap 'app'
    Set-Prop $appInfo Text $(if (-not $av) { 'Автообновление появится с агентом 2.2.' }
        elseif (-not $av.repo) { "Версия $($av.version). Автообновление не настроено: укажите репозиторий GitHub в Настройках → «Обновление приложения»." }
        else {
            "Версия $($av.version)" + $(if ($av.build) { " (сборка $($av.build))" } else { '' }) + " · источник github.com/$($av.repo)" +
            $(if ($av.error) { " · ошибка: $($av.error)" } elseif ([int]$av.pending -gt 0) { " · доступна $($av.latestVersion) ($($av.latestBuild)), файлов: $($av.pending)" } elseif ($av.checkedAt) { ' · актуальная' } else { '' }) +
            $(if ($av.checkedAt) { " · проверено $(try { ([datetime]$av.checkedAt).ToString('dd.MM HH:mm') } catch { '' })" } else { '' }) +
            $(if ($av.auto) { " · ставится само раз в $($av.checkHours) ч" } else { ' · автоустановка выключена' })
        })
    Set-Prop $appInfo ForeColor $(if ($av -and $av.error) { $Clr.Bad } elseif ($av -and [int]$av.pending -gt 0) { $Clr.Warn } else { $Clr.Dim })
}
Add-Blocks $pgSoft @($appBox, $softIntro, $softTools, $softTable)
$pages['software'] = $pgSoft

function Install-SoftUi([string]$Id) {
    $r = $SoftRows[$Id]
    $warn = switch ($Id) {
        'wireguard' { "`n`nТуннель wg_server на несколько секунд прервётся." }
        'ws4w'      { "`n`nОткроется окно установщика WS4W — пройдите его до конца." }
        'meduza'    { "`n`nMeduzaVPN будет перезапущен." }
        default     { '' }
    }
    if ([Windows.Forms.MessageBox]::Show("$($r.Btn.Text): $($r.Title)?$warn", 'VpnGuard — компоненты', 'YesNo', 'Question') -ne 'Yes') { return }
    Send-Cmd "install $Id" "$($r.Btn.Text.ToLower()) $($r.Title)"
}
function Update-SoftUi {
    $list = @(); $s = Get-Snap 'software'; if ($s) { $list = @($s | Where-Object { $_ }) }
    foreach ($id in $SoftRows.Keys) {
        $row = $SoftRows[$id]; $x = $list | Where-Object { $_.id -eq $id } | Select-Object -First 1
        if (-not $x) { Set-Prop $row.Inst Text '—'; Set-Prop $row.Latest Text '—'; Set-Prop $row.State Text 'нет данных (агент 1.9)'; continue }
        Set-Prop $row.Inst Text $(if ($x.installed) { "$($x.installed)" } else { 'не установлен' })
        Set-Prop $row.Inst ForeColor $(if ($x.installed) { $Clr.Text } elseif ($x.needed) { $Clr.Bad } else { $Clr.Dim })
        Set-Prop $row.Latest Text $(if ($x.latest) { "$($x.latest)" } else { '—' })
        $stt = $(if ($x.status) { "$($x.status)…" } elseif ($x.error) { "ошибка: $($x.error)" } elseif (-not $x.installed) { $(if ($x.needed) { 'нужен для текущего режима' } else { 'не нужен сейчас' }) } elseif ($x.update) { 'есть обновление' } else { 'актуально' })
        Set-Prop $row.State Text $stt
        Set-Prop $row.State ForeColor $(if ($x.error) { $Clr.Bad } elseif ($x.status) { $Clr.Accent } elseif ($x.update -or (-not $x.installed -and $x.needed)) { $Clr.Warn } elseif ($x.installed) { $Clr.Ok } else { $Clr.Dim })
        Set-Prop $row.Btn Text $(if (-not $x.installed) { 'Установить' } elseif ($x.update) { 'Обновить' } else { 'Переустановить' })
        Set-Prop $row.Btn Enabled (-not $x.status)
    }
}

# ================================================================ Трафик
$pgTraffic = New-Page $true
$script:TrafSel = 'u'
$trafKpiRow = New-Row 84 3
$TrafKpi = @{
    u = New-Kpi 'Туннель' { Select-Traffic 'u' }
    w = New-Kpi 'WG-Server (клиенты)' { Select-Traffic 'w' }
    p = New-Kpi 'Физический адаптер' { Select-Traffic 'p' }
}
$TrafKpi.p.Panel.Margin = '0,0,0,0'
$trafKpiRow.Controls.Add($TrafKpi.u.Panel, 0, 0); $trafKpiRow.Controls.Add($TrafKpi.w.Panel, 1, 0); $trafKpiRow.Controls.Add($TrafKpi.p.Panel, 2, 0)

$trafBar = New-Object Windows.Forms.FlowLayoutPanel
$trafBar.Height = 34; $trafBar.WrapContents = $false; $trafBar.BackColor = $Clr.Bg
$TrafBtns = @{}
foreach ($q in @(@('u', 'Туннель'), @('w', 'WG-Server'), @('p', 'Физический адаптер'))) {
    $b = New-Btn $q[1] ([scriptblock]::Create("Select-Traffic '$($q[0])'"))
    $TrafBtns[$q[0]] = $b; $trafBar.Controls.Add($b)
}
$trafHint = New-Label '   Клик по плитке или кнопке — выбрать адаптер для графиков ниже.' $F.Small $Clr.Dim; $trafHint.Margin = '0,8,0,0'
$trafBar.Controls.Add($trafHint)

function Select-Traffic([string]$k) {
    $script:TrafSel = $k
    foreach ($q in $TrafBtns.Keys) {
        $b = $TrafBtns[$q]; $on = ($q -eq $k)
        $b.BackColor = $(if ($on) { $Clr.Accent } else { $Clr.Btn }); $b.FlatAppearance.BorderColor = $(if ($on) { $Clr.Accent } else { $Clr.Border })
        $b.Tag.Back = $b.BackColor; $b.Tag.Border = $b.FlatAppearance.BorderColor
    }
    foreach ($q in $TrafKpi.Keys) { $TrafKpi[$q].Panel.BackColor = $(if ($q -eq $k) { $Clr.Row } else { $Clr.Card }) }
    foreach ($c in $script:Canvases) { if ($c.Visible) { $c.Invalidate() } }
}
$trafLive = New-Canvas 230 (New-LiveSpec { $script:TrafSel })
$trafHist = New-Canvas 200 (New-HistSpec { $script:TrafSel })
$trafDays = New-Canvas 120 @{ Kind = 'days'; Src = { $script:TrafSel }; Rows = { 30 + [Math]::Max(1, @(Get-Days $script:TrafSel).Count) * 26 + 8 } }
Add-Blocks $pgTraffic @($trafKpiRow, $trafBar, (New-SectionTitle 'Скорость — последние 5 минут (замер раз в секунду)'), $trafLive,
    (New-SectionTitle 'Скорость — последние 2 часа'), $trafHist, (New-SectionTitle 'Трафик по дням (14 дней)'), $trafDays)
$pages['traffic'] = $pgTraffic
Select-Traffic 'u'

# ================================================================ Журнал
$pgLog = New-Object Windows.Forms.Panel
$pgLog.Dock = 'Fill'; $pgLog.Padding = '20,4,20,16'; $pgLog.BackColor = $Clr.Bg

$logBar = New-Object Windows.Forms.FlowLayoutPanel
$logBar.Dock = 'Top'; $logBar.Height = 40; $logBar.BackColor = $Clr.Bg; $logBar.WrapContents = $false

$cbDay = New-Object Windows.Forms.ComboBox
$cbDay.DropDownStyle = 'DropDownList'; $cbDay.Width = 170; $cbDay.BackColor = $Clr.Input; $cbDay.ForeColor = $Clr.Text; $cbDay.FlatStyle = 'Flat'; $cbDay.Margin = '0,4,10,0'
$cbLevel = New-Object Windows.Forms.ComboBox
$cbLevel.DropDownStyle = 'DropDownList'; $cbLevel.Width = 220; $cbLevel.BackColor = $Clr.Input; $cbLevel.ForeColor = $Clr.Text; $cbLevel.FlatStyle = 'Flat'; $cbLevel.Margin = '0,4,10,0'
[void]$cbLevel.Items.AddRange(@('Все события', 'Предупреждения и ошибки', 'Только ошибки'))
$cbLevel.SelectedIndex = 0
$cbComp = New-Object Windows.Forms.ComboBox
$cbComp.DropDownStyle = 'DropDownList'; $cbComp.Width = 170; $cbComp.BackColor = $Clr.Input; $cbComp.ForeColor = $Clr.Text; $cbComp.FlatStyle = 'Flat'; $cbComp.Margin = '0,4,10,0'
[void]$cbComp.Items.AddRange(@('Все компоненты', 'MeduzaVPN', 'Туннель', 'WG-Server', 'Раздача ICS', 'zapret', 'AmneziaVPN'))
$cbComp.SelectedIndex = 0
$tbFind = New-Object Windows.Forms.TextBox
$tbFind.Width = 180; $tbFind.BackColor = $Clr.Input; $tbFind.ForeColor = $Clr.Text; $tbFind.BorderStyle = 'FixedSingle'; $tbFind.Margin = '0,5,10,0'
$lblFind = New-Label 'Поиск:' $F.Base $Clr.Dim; $lblFind.Margin = '0,9,4,0'
$logBar.Controls.AddRange(@($cbDay, $cbLevel, $cbComp, $lblFind, $tbFind,
    (New-Btn 'Открыть папку логов' { Start-Process explorer.exe $LogDir })))

$logBox = New-LogBox
$logBox.Dock = 'Fill'
$pgLog.Controls.AddRange(@($logBar, $logBox))
$logBox.BringToFront()
$pages['log'] = $pgLog

$script:logSig = ''
function Update-DayList {
    $files = Get-LogFiles
    $names = @($files | ForEach-Object { $_.BaseName -replace '^vpnguard-(\d{4})(\d{2})(\d{2})$', '$3.$2.$1' })
    $cur = @($cbDay.Items | ForEach-Object { "$_" }) -join '|'
    if ($cur -ne ($names -join '|')) {
        $sel = $cbDay.SelectedIndex
        $cbDay.Items.Clear()
        if ($names.Count) { [void]$cbDay.Items.AddRange($names); $cbDay.SelectedIndex = [Math]::Max(0, [Math]::Min($sel, $names.Count - 1)) }
    }
}

function Write-ColoredLines($Box, [string[]]$Lines) {
    # весь текст одним присваиванием, затем раскрашиваем только строки WARN/ERROR
    $Lines = @($Lines | ForEach-Object { "$_" -replace "`r", '' })
    $Box.SuspendLayout()
    $Box.Text = ($Lines -join "`n")
    $Box.SelectAll(); $Box.SelectionColor = $Clr.Text
    $pos = 0
    foreach ($l in $Lines) {
        if ($l.Contains('[ERROR]') -or $l.Contains('[WARN]')) {
            $Box.Select($pos, $l.Length)
            $Box.SelectionColor = $(if ($l.Contains('[ERROR]')) { $Clr.Bad } else { $Clr.Warn })
        }
        $pos += $l.Length + 1
    }
    $Box.Select($Box.TextLength, 0)
    $Box.ScrollToCaret()
    $Box.ResumeLayout()
}

# хвост сегодняшнего журнала — читается только когда файл изменился, общий для всех вкладок
$script:tail = @{ Sig = ''; Lines = @() }
function Get-TodayTail($files) {
    $sig = '{0}|{1}' -f $files[0].FullName, $files[0].Length
    if ($sig -ne $script:tail.Sig) {
        $script:tail = @{ Sig = $sig; Lines = @(Get-Content $files[0].FullName -Tail 3000 -Encoding UTF8 -ErrorAction SilentlyContinue) }
    }
    return $script:tail
}

function Update-LogView([switch]$Force) {
    $page = $script:CurPage
    $isComp = $CompKeys -contains $page
    if (-not ($page -in 'log', 'home' -or $isComp -or $Force)) { return }
    $files = Get-LogFiles
    if ($files.Count -eq 0) {
        foreach ($b in @($logBox, $homeEvents) + @($CompLog.Values)) { if ($b.TextLength -eq 0) { $b.Text = 'Журнал пуст — агент ещё не запускался.' } }
        return
    }
    if ($page -eq 'home') {
        $t = Get-TodayTail $files
        if ($t.Sig -ne $script:eventsSig) { $script:eventsSig = $t.Sig; Write-ColoredLines $homeEvents @($t.Lines | Select-Object -Last 40) }
    }
    if ($isComp) {
        $t = Get-TodayTail $files
        if ($t.Sig -ne $script:compSig[$page]) {
            $script:compSig[$page] = $t.Sig
            $rx = $LogFilter[$page]
            $sel = @($t.Lines | Where-Object { $_ -match $rx } | Select-Object -Last 100)
            if ($sel.Count) { Write-ColoredLines $CompLog[$page] $sel } else { $CompLog[$page].Text = 'Сегодня событий по этому компоненту нет.' }
        }
    }
    if (-not ($page -eq 'log' -or $Force)) { return }

    Update-DayList
    $fi = $files[[Math]::Max(0, $cbDay.SelectedIndex)]
    $sig = '{0}|{1}|{2}|{3}|{4}' -f $fi.FullName, $fi.Length, $cbLevel.SelectedIndex, $cbComp.SelectedIndex, $tbFind.Text
    if (-not $Force -and $sig -eq $script:logSig) { return }
    $script:logSig = $sig
    $lines = @(Get-Content $fi.FullName -Tail 3000 -Encoding UTF8 -ErrorAction SilentlyContinue)
    switch ($cbLevel.SelectedIndex) {
        1 { $lines = @($lines | Where-Object { $_ -match '\[(WARN|ERROR)\]' }) }
        2 { $lines = @($lines | Where-Object { $_ -match '\[ERROR\]' }) }
    }
    if ($cbComp.SelectedIndex -gt 0) { $rx = $LogFilter[$CompKeys[$cbComp.SelectedIndex - 1]]; $lines = @($lines | Where-Object { $_ -match $rx }) }
    if ($tbFind.Text) { $q = $tbFind.Text; $lines = @($lines | Where-Object { $_ -like "*$q*" }) }
    Write-ColoredLines $logBox @($lines | Select-Object -Last 800)
}
$script:eventsSig = ''
$cbDay.Add_SelectedIndexChanged({ Update-LogView -Force })
$cbLevel.Add_SelectedIndexChanged({ Update-LogView -Force })
$cbComp.Add_SelectedIndexChanged({ Update-LogView -Force })
# поиск — с небольшой задержкой, чтобы не перечитывать журнал на каждую букву
$findTimer = New-Object Windows.Forms.Timer
$findTimer.Interval = 400
$findTimer.Add_Tick({ $findTimer.Stop(); Update-LogView -Force })
$tbFind.Add_TextChanged({ $findTimer.Stop(); $findTimer.Start() })

# ================================================================ Настройки
$pgSet = New-Object Windows.Forms.Panel
$pgSet.Dock = 'Fill'; $pgSet.AutoScroll = $true; $pgSet.BackColor = $Clr.Bg; $pgSet.Padding = '24,4,24,12'

$setTable = New-Object Windows.Forms.TableLayoutPanel
$setTable.ColumnCount = 3; $setTable.AutoSize = $true; $setTable.Dock = 'Top'; $setTable.BackColor = $Clr.Bg
[void]$setTable.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Absolute', 300)))
[void]$setTable.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Absolute', 330)))
[void]$setTable.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('AutoSize')))

$SetCtl = @{}
function Add-Section([string]$Text) {
    $l = New-Label $Text $F.Bold $Clr.Accent; $l.Margin = '0,16,0,6'
    $setTable.Controls.Add($l); $setTable.SetColumnSpan($l, 3)
}
function Add-Setting([string]$Key, [string]$Label, [string]$Kind, [string]$Hint = '', $Min = 0, $Max = 100000) {
    $l = New-Label $Label $F.Base $Clr.Text; $l.Margin = '0,7,10,3'
    switch ($Kind) {
        'text' { $c = New-Object Windows.Forms.TextBox; $c.Width = 310; $c.BorderStyle = 'FixedSingle' }
        'num'  { $c = New-Object Windows.Forms.NumericUpDown; $c.Width = 110; $c.Minimum = $Min; $c.Maximum = $Max; $c.BorderStyle = 'FixedSingle' }
        'bool' { $c = New-Object Windows.Forms.CheckBox; $c.Text = 'включено'; $c.AutoSize = $true; $c.ForeColor = $Clr.Text }
        'combo' { $c = New-Object Windows.Forms.ComboBox; $c.Width = 310; $c.DropDownStyle = 'DropDownList'; $c.FlatStyle = 'Flat' }
    }
    if ($Kind -ne 'bool') { $c.BackColor = $Clr.Input; $c.ForeColor = $Clr.Text }
    $c.Font = $F.Base; $c.Margin = '0,4,10,3'
    $h = New-Label $Hint $F.Small $Clr.Dim; $h.Margin = '0,8,0,3'
    $setTable.Controls.AddRange(@($l, $c, $h))
    $script:SetCtl[$Key] = $c
}

Add-Section 'Общее'
Add-Setting 'checkIntervalSec'                    'Интервал проверки, сек'            'num'  'как часто агент проверяет всё' 10 600
Add-Setting 'logRetentionDays'                    'Хранить журналы, дней'             'num'  '' 1 365
Add-Section 'MeduzaVPN'
Add-Setting 'meduza.serviceId'                    'VPN (id или часть имени)'          'text' 'пусто — единственный на аккаунте'
Add-Setting 'meduza.protocol'                     'Протокол'                          'text' 'ultra'
Add-Setting 'meduza.autoProtocol'                 'Пробовать другие протоколы'        'bool' 'если связь пропала и переподключение не помогло'
Add-Setting 'meduza.protocolReturnMin'            'Возвращать выбранный протокол, мин' 'num' 'работаем на запасном — раз в N мин пробовать выбранный (0 — нет)' 0 1440
Add-Setting 'meduza.adapterName'                  'Имя адаптера туннеля'              'text' 'MeduzaVPN ULTRA'
Add-Setting 'meduza.autoUpdate'                   'Автообновление'                    'bool' 'скачивание, проверка подписи, тихая установка'
Add-Setting 'meduza.updateCheckHours'             'Проверять обновления каждые, ч'   'num'  '' 1 168
Add-Setting 'meduza.probeHosts'                   'Проверка трафика (хост:порт, …)'   'text' 'через запятую'
Add-Setting 'meduza.probeFailuresBeforeReconnect' 'Неудачных проверок до переподключения' 'num' '' 1 50
Add-Setting 'meduza.startupGraceSec'              'Ждать автоподключения после старта, сек' 'num' '' 0 600
Add-Setting 'meduza.maxRestartsPer30Min'          'Максимум перезапусков за 30 мин'   'num'  'защита от бесконечных перезапусков' 1 100
Add-Section 'WG-Server (wg_server, WS4W)'
Add-Setting 'ws4w.interfaceName'                  'Интерфейс'                         'text' 'wg_server'
Add-Setting 'ws4w.serviceName'                    'Служба туннеля'                    'text' 'WireGuardTunnel$wg_server'
Add-Setting 'ws4w.configPath'                     'Путь к конфигу wg_server'          'text' 'пусто — найти автоматически'
Add-Setting 'ws4w.serverAddress'                  'Адрес сервера'                     'text' 'пусто — из конфига (напр. 10.253.0.1)'
Add-Setting 'ws4w.endpoint'                       'Адрес для клиентов (IP или имя[:порт])' 'text' 'пусто — как у клиентов WS4W или внешний IP'
Add-Setting 'ws4w.clientDns'                      'DNS для новых клиентов'            'text' 'пусто — как у клиентов WS4W или адрес сервера'
Add-Setting 'ws4w.autoCreateServer'               'Создавать сервер, если настроек нет' 'bool' 'нет ни конфига, ни службы wg_server'
Add-Section 'Режим и AmneziaVPN'
Add-Setting 'vpn.mode'                            'Режим работы'                      'combo' 'meduza · amnezia · dual (два туннеля) · zapret (без VPN)'
$SetCtl['vpn.mode'].Items.AddRange(@('meduza', 'amnezia', 'dual', 'zapret'))
Add-Setting 'vpn.primary'                         'Два туннеля: основной'             'combo' 'через какой идёт трафик, пока он работает'
$SetCtl['vpn.primary'].Items.AddRange(@('meduza', 'amnezia'))
Add-Setting 'vpn.dualHot'                         'Два туннеля: резерв всегда поднят' 'bool' 'выключено — резерв поднимается только при сбое (медленнее)'
Add-Setting 'vpn.failoverChecks'                  'Два туннеля: проверок до переключения' 'num' 'подряд без трафика (отключение — сразу)' 1 10
Add-Setting 'vpn.failbackMin'                     'Два туннеля: вернуться на основной через, мин' 'num' 'после того как он снова заработал (0 — не возвращать)' 0 1440
Add-Setting 'vpn.stopInactive'                    'Закрывать неиспользуемый VPN'      'bool' 'чтобы не работали два туннеля сразу'
Add-Setting 'software.checkHours'                 'Проверять версии компонентов, ч'  'num'  '' 1 168
Add-Section 'Раздача интернета'
Add-Setting 'sharing.enabled'                     'Управлять раздачей ICS'            'bool' 'туннель → wg_server'
Add-Section 'zapret-discord-youtube'
Add-Setting 'zapret.strategy'                     'Стратегия'                         'combo' '(авто) — подбирать автоматически'
Add-Setting 'zapret.version'                      'Версия zapret'                     'text' 'пусто — последняя; например 1.10.2 — поставится и не будет обновляться'
Add-Setting 'zapret.autoUpdate'                   'Автообновление zapret'             'bool' 'последний релиз с GitHub (если версия не выбрана)'
Add-Setting 'zapret.updateCheckHours'             'Проверять обновления каждые, ч'   'num'  '' 1 168
Add-Setting 'zapret.retestHours'                  'Переподбирать стратегию каждые, ч' 'num'  'и сразу — если сайты перестали открываться' 1 720
Add-Setting 'zapret.healthCheckMin'               'Проверять сайты каждые, мин'       'num'  '' 2 240
Add-Setting 'zapret.videoCheck'                   'Проверять видео YouTube'           'bool' 'видеосервер googlevideo и загрузку страницы целиком'
Add-Setting 'zapret.gameFilter'                   'Игровой фильтр'                    'combo' 'disabled — выключен (как в service.bat)'
$SetCtl['zapret.gameFilter'].Items.AddRange(@('disabled', 'all', 'tcp', 'udp'))
Add-Section 'Веб-интерфейс'
Add-Setting 'web.requirePassword'                 'Пароль с других устройств'         'bool' 'выключено — без пароля из домашней сети и от клиентов wg_server'
Add-Setting 'web.token'                           'Пароль'                            'text' 'от 6 символов; пусто — создастся сам'
Add-Section 'Обновление приложения'
Add-Setting 'update.repo'                         'Репозиторий GitHub'                'text' 'владелец/имя, например ivan/vpnguard; пусто — не обновлять'
Add-Setting 'update.branch'                       'Ветка'                             'text' 'main'
Add-Setting 'update.auto'                         'Ставить обновления само'           'bool' 'проверка sha256 и кода, копия старых файлов в data\backup'
Add-Setting 'update.checkHours'                   'Проверять каждые, ч'               'num'  '' 1 168
Add-Section 'Автозапуск'
Add-Setting 'auto.agent'                          'Агент при входе в Windows'         'bool' 'задача планировщика VpnGuard'
Add-Setting 'auto.monitor'                        'Открывать это окно при входе'      'bool' ''

$setBtns = New-Object Windows.Forms.FlowLayoutPanel
$setBtns.AutoSize = $true; $setBtns.Margin = '0,20,0,10'; $setBtns.BackColor = $Clr.Bg
$setBtns.Controls.AddRange(@(
    (New-Btn 'Сохранить' { Save-SettingsForm } $true),
    (New-Btn 'Отменить изменения' { Import-SettingsForm; Set-Footer 'Изменения отменены' }),
    (New-Btn 'Открыть config.json' { Start-Process notepad.exe $ConfigPath })
))
$setTable.Controls.Add($setBtns); $setTable.SetColumnSpan($setBtns, 3)
$pgSet.Controls.Add($setTable)
$pages['settings'] = $pgSet

function Read-ConfigObject {
    if (Test-Path $ConfigPath) { return (Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json) }
    return [pscustomobject]@{}
}
function Get-CfgVal($Obj, [string]$Path) {
    $cur = $Obj
    foreach ($p in $Path.Split('.')) {
        if ($null -eq $cur -or -not $cur.PSObject.Properties[$p]) { return $null }
        $cur = $cur.$p
    }
    $cur
}
function Set-CfgVal($Obj, [string]$Path, $Value) {
    $parts = $Path.Split('.')
    $cur = $Obj
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        if (-not $cur.PSObject.Properties[$parts[$i]]) { $cur | Add-Member -NotePropertyName $parts[$i] -NotePropertyValue ([pscustomobject]@{}) }
        $cur = $cur.($parts[$i])
    }
    $cur | Add-Member -NotePropertyName $parts[-1] -NotePropertyValue $Value -Force
}

$Fallback = @{
    'checkIntervalSec' = 30; 'logRetentionDays' = 14; 'meduza.protocol' = 'ultra'; 'meduza.adapterName' = 'MeduzaVPN ULTRA'
    'meduza.autoUpdate' = $true; 'meduza.updateCheckHours' = 6; 'meduza.probeHosts' = @('1.1.1.1:443', '8.8.8.8:443', '9.9.9.9:443')
    'meduza.probeFailuresBeforeReconnect' = 3; 'meduza.startupGraceSec' = 60; 'meduza.maxRestartsPer30Min' = 5
    'ws4w.interfaceName' = 'wg_server'; 'ws4w.serviceName' = 'WireGuardTunnel$wg_server'; 'sharing.enabled' = $true; 'ws4w.autoCreateServer' = $true; 'vpn.mode' = 'meduza'; 'vpn.stopInactive' = $true; 'vpn.primary' = 'meduza'; 'vpn.dualHot' = $true; 'vpn.failoverChecks' = 2; 'vpn.failbackMin' = 5
    'meduza.autoProtocol' = $true; 'update.repo' = 'Fogiku/vpnguard'; 'web.requirePassword' = $true; 'zapret.version' = ''; 'update.branch' = 'main'; 'update.auto' = $true; 'update.checkHours' = 3; 'meduza.protocolReturnMin' = 60; 'zapret.videoCheck' = $true; 'amnezia.splitDefaultRoute' = $true; 'software.checkHours' = 12
    'zapret.strategy' = ''; 'zapret.autoUpdate' = $true; 'zapret.updateCheckHours' = 12; 'zapret.retestHours' = 24
    'zapret.healthCheckMin' = 10; 'zapret.gameFilter' = 'disabled'
}

function Import-SettingsForm {
    try { $o = Read-ConfigObject } catch { Set-Footer "config.json не читается: $($_.Exception.Message)"; return }
    # список стратегий zapret — из состояния агента
    $sc = $SetCtl['zapret.strategy']
    $sc.Items.Clear(); [void]$sc.Items.Add('(авто)')
    if ($script:snap -and $script:snap.PSObject.Properties['zapret']) { foreach ($n in @($script:snap.zapret.strategies)) { if ($n) { [void]$sc.Items.Add("$n") } } }
    $cur = Get-CfgVal $o 'zapret.strategy'
    if ($cur -and -not $sc.Items.Contains("$cur")) { [void]$sc.Items.Add("$cur") }
    foreach ($k in $SetCtl.Keys) {
        $c = $SetCtl[$k]
        if ($k -like 'auto.*') { continue }
        $v = Get-CfgVal $o $k
        if ($null -eq $v) { $v = $Fallback[$k] }
        if ($c -is [Windows.Forms.CheckBox]) { $c.Checked = [bool]$v }
        elseif ($c -is [Windows.Forms.NumericUpDown]) { if ($null -ne $v) { $c.Value = [Math]::Min($c.Maximum, [Math]::Max($c.Minimum, [decimal]$v)) } }
        elseif ($k -eq 'zapret.strategy') { $c.SelectedItem = $(if ($v) { "$v" } else { '(авто)' }) }
        elseif ($c -is [Windows.Forms.ComboBox]) { $c.SelectedItem = "$v"; if ($c.SelectedIndex -lt 0 -and $c.Items.Count) { $c.SelectedIndex = 0 } }
        else { $c.Text = $(if ($v -is [array]) { $v -join ', ' } elseif ($null -ne $v) { "$v" } else { '' }) }
    }
    # состояние задач — из фонового опроса (без задержки окна)
    $ti = $script:taskInfo
    if ($ti) {
        $SetCtl['auto.agent'].Checked = [bool]($ti.Agent -and $ti.Agent -ne 'Disabled')
        $SetCtl['auto.monitor'].Checked = [bool]($ti.MonitorTriggers -gt 0)
    }
}

function Invoke-AgentSetup([string]$What) {
    $r = Start-Process powershell.exe -WindowStyle Hidden -Wait -PassThru `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$AgentPs1`" -SetupTask $What"
    return ($r.ExitCode -eq 0)
}

function Save-SettingsForm {
    $form.Cursor = 'WaitCursor'
    try {
        $o = Read-ConfigObject
        foreach ($k in $SetCtl.Keys) {
            if ($k -like 'auto.*') { continue }
            $c = $SetCtl[$k]
            if ($c -is [Windows.Forms.CheckBox]) { $v = $c.Checked }
            elseif ($c -is [Windows.Forms.NumericUpDown]) { $v = [int]$c.Value }
            elseif ($k -eq 'meduza.probeHosts') {
                $v = @($c.Text -split '[,;\s]+' | Where-Object { $_ })
                $bad = @($v | Where-Object { $_ -notmatch '^[\w\.\-]+:\d{1,5}$' })
                if ($bad.Count) { throw "неверный формат проверки трафика: $($bad -join ', ') (нужно хост:порт)" }
            }
            elseif ($k -eq 'zapret.strategy') { $v = $(if ("$($c.SelectedItem)" -eq '(авто)') { '' } else { "$($c.SelectedItem)" }) }
            elseif ($c -is [Windows.Forms.ComboBox]) { $v = "$($c.SelectedItem)" }
            else { $v = $c.Text.Trim() }
            Set-CfgVal $o $k $v
        }
        $tmp = "$ConfigPath.tmp"
        $o | ConvertTo-Json -Depth 6 | Set-Content $tmp -Encoding UTF8
        Move-Item $tmp $ConfigPath -Force

        # автозапуск
        $at = Get-ScheduledTask -TaskName $AgentTask -ErrorAction SilentlyContinue
        if ($SetCtl['auto.agent'].Checked) {
            if (-not $at) { [void](Invoke-AgentSetup 'agent') }
            elseif ($at.State -eq 'Disabled') { Enable-ScheduledTask -TaskName $AgentTask | Out-Null }
        } elseif ($at -and $at.State -ne 'Disabled') {
            Disable-ScheduledTask -TaskName $AgentTask | Out-Null
        }
        $mt = Get-ScheduledTask -TaskName $MonitorTask -ErrorAction SilentlyContinue
        $wantMon = $SetCtl['auto.monitor'].Checked
        $hasMon = [bool]($mt -and @($mt.Triggers).Count -gt 0)
        if ($wantMon -ne $hasMon) { [void](Invoke-AgentSetup $(if ($wantMon) { 'monitor-logon' } else { 'monitor' })) }

        Set-Footer 'Настройки сохранены — агент применит их на следующей проверке'
        Request-AgentInfo
    } catch {
        [Windows.Forms.MessageBox]::Show("Не удалось сохранить: $($_.Exception.Message)", 'VpnGuard', 'OK', 'Error') | Out-Null
    } finally {
        $form.Cursor = 'Default'
    }
}

# ================================================================ Диагностика
$pgDiag = New-Object Windows.Forms.Panel
$pgDiag.Dock = 'Fill'; $pgDiag.Padding = '20,4,20,16'; $pgDiag.BackColor = $Clr.Bg

$diagIntro = New-Label 'Соберите отчёт и отправьте его целиком (кнопка «Копировать всё» или файл). Ключей и паролей в отчёте нет.' $F.Base $Clr.Dim
$diagIntro.AutoSize = $false; $diagIntro.Dock = 'Top'; $diagIntro.Height = 26

$diagBar = New-Object Windows.Forms.FlowLayoutPanel
$diagBar.Dock = 'Top'; $diagBar.Height = 42; $diagBar.BackColor = $Clr.Bg; $diagBar.WrapContents = $false
$btnDiag    = New-Btn 'Собрать отчёт' { Start-Diag $false } $true
$btnDiagFix = New-Btn 'Собрать + попытаться включить раздачу' { Start-Diag $true }
$btnCopy    = New-Btn 'Копировать всё' { Copy-Diag }
$btnSave    = New-Btn 'Сохранить в файл…' { Save-Diag }
$diagState  = New-Label '' $F.Base $Clr.Dim; $diagState.Margin = '6,8,0,0'
$diagBar.Controls.AddRange(@($btnDiag, $btnDiagFix, $btnCopy, $btnSave, $diagState))

$diagBox = New-Object Windows.Forms.TextBox
$diagBox.Multiline = $true; $diagBox.ReadOnly = $true; $diagBox.ScrollBars = 'Both'; $diagBox.WordWrap = $false
$diagBox.Dock = 'Fill'; $diagBox.BorderStyle = 'None'; $diagBox.BackColor = $Clr.Card; $diagBox.ForeColor = $Clr.Text
$diagBox.Font = $F.Mono; $diagBox.MaxLength = 0
$diagBox.Text = 'Нажмите «Собрать отчёт».'

# --- удалённая диагностика: включить на N часов, токен, адреса для подключения
$rmBox = New-Object Windows.Forms.Panel
$rmBox.Dock = 'Top'; $rmBox.Height = 150; $rmBox.BackColor = $Clr.Card
$rmTitle = New-Label 'Удалённая диагностика' $F.Bold $Clr.Text; $rmTitle.Location = New-Object Drawing.Point(16, 10)
$rmDot = New-Dot 10; $rmDot.Location = New-Object Drawing.Point(190, 15)
$rmState = New-Label 'выключена' $F.Base $Clr.Dim; $rmState.AutoSize = $false; $rmState.AutoEllipsis = $true
$rmState.Location = New-Object Drawing.Point(206, 10); $rmState.Size = New-Object Drawing.Size(700, 22)
$rmHint = New-Label 'Можно подключиться к этому ПК по IP и собрать всё для поиска проблем: состояние, отчёт, журналы, сеть, живые проверки сайтов и туннелей. Только чтение и команды агенту из короткого списка; ключи скрыты. Доступ — по токену, выключается сама по таймеру.' $F.Small $Clr.Dim
$rmHint.AutoSize = $false; $rmHint.Location = New-Object Drawing.Point(16, 34); $rmHint.Size = New-Object Drawing.Size(900, 34)
$rmOpts = New-Object Windows.Forms.FlowLayoutPanel
$rmOpts.AutoSize = $true; $rmOpts.WrapContents = $false; $rmOpts.BackColor = $Clr.Card; $rmOpts.Location = New-Object Drawing.Point(12, 70)
$cbRmHours = New-Object Windows.Forms.ComboBox
$cbRmHours.DropDownStyle = 'DropDownList'; $cbRmHours.Width = 110; $cbRmHours.BackColor = $Clr.Input; $cbRmHours.ForeColor = $Clr.Text; $cbRmHours.FlatStyle = 'Flat'; $cbRmHours.Margin = '4,6,8,0'
$RmHours = @(2, 8, 24, 72); foreach ($hh in $RmHours) { [void]$cbRmHours.Items.Add("на $hh ч") }; $cbRmHours.SelectedIndex = 2
$cbRmFrom = New-Object Windows.Forms.ComboBox
$cbRmFrom.DropDownStyle = 'DropDownList'; $cbRmFrom.Width = 270; $cbRmFrom.BackColor = $Clr.Input; $cbRmFrom.ForeColor = $Clr.Text; $cbRmFrom.FlatStyle = 'Flat'; $cbRmFrom.Margin = '0,6,8,0'
[void]$cbRmFrom.Items.AddRange(@('откуда угодно (через интернет)', 'только локальная сеть и клиенты wg_server')); $cbRmFrom.SelectedIndex = 0
$chkRmAct = New-Object Windows.Forms.CheckBox
$chkRmAct.Text = 'разрешить тесты и переподключения (клиенты ненадолго теряют интернет)'; $chkRmAct.AutoSize = $true; $chkRmAct.ForeColor = $Clr.Text; $chkRmAct.Margin = '0,8,8,0'
$rmOpts.Controls.AddRange(@($cbRmHours, $cbRmFrom, $chkRmAct))
$rmBtns = New-Object Windows.Forms.FlowLayoutPanel
$rmBtns.AutoSize = $true; $rmBtns.WrapContents = $false; $rmBtns.BackColor = $Clr.Card; $rmBtns.Location = New-Object Drawing.Point(12, 104)
$btnRmOn = New-Btn 'Включить' { Switch-RemoteUi } $true
$btnRmCopy = New-Btn 'Скопировать данные для подключения' { Copy-RemoteUi }
$btnRmIp = New-Btn 'Узнать внешний IP' { [void](Start-Bg 'pubip' { try { (Invoke-RestMethod 'https://api.ipify.org' -TimeoutSec 8 -UseBasicParsing).ToString().Trim() } catch { 'не удалось' } }); Set-Footer 'Узнаю внешний IP…' }
$rmAddr = New-Label '' $F.Small $Clr.Dim; $rmAddr.Margin = '8,10,0,0'
$rmBtns.Controls.AddRange(@($btnRmOn, $btnRmCopy, $btnRmIp, $rmAddr))
$rmBox.Controls.AddRange(@($rmTitle, $rmDot, $rmState, $rmHint, $rmOpts, $rmBtns))
$rmBox.Add_Resize({ $rmHint.Width = [Math]::Max(200, $rmBox.ClientSize.Width - 32); $rmState.Width = [Math]::Max(100, $rmBox.ClientSize.Width - 222) })
# при крупном масштабе экрана элементы выше — раскладываем по фактическим размерам и подгоняем высоту блока
$rmBox.Add_Layout({
    $rmHint.Height = [Windows.Forms.TextRenderer]::MeasureText($rmHint.Text, $rmHint.Font, (New-Object Drawing.Size($rmHint.Width, 1000)), [Windows.Forms.TextFormatFlags]'WordBreak').Height + 4
    $rmHint.Top = $rmTitle.Bottom + 4
    foreach ($fp in $rmOpts, $rmBtns) { $ps = $fp.GetPreferredSize([Drawing.Size]::Empty); if ($fp.Height -ne $ps.Height) { $fp.Height = $ps.Height } }
    $rmOpts.Top = $rmHint.Bottom + 4
    $rmBtns.Top = $rmOpts.Bottom + 6
    $h = $rmBtns.Bottom + 12
    if ($rmBox.Height -ne $h) { $rmBox.Height = $h }
})
$rmSpacer = New-Object Windows.Forms.Panel; $rmSpacer.Dock = 'Top'; $rmSpacer.Height = 12; $rmSpacer.BackColor = $Clr.Bg
# --- веб-интерфейс: адрес и пароль для других устройств
$webBox = New-Object Windows.Forms.FlowLayoutPanel
$webBox.Dock = 'Top'; $webBox.Height = 46; $webBox.BackColor = $Clr.Card; $webBox.WrapContents = $false; $webBox.Padding = '10,6,10,6'
$webLbl = New-Label 'Веб-интерфейс' $F.Bold $Clr.Text; $webLbl.Margin = '6,8,10,0'
$webInfo = New-Label '' $F.Base $Clr.Dim; $webInfo.Margin = '0,9,12,0'
$webBox.Controls.AddRange(@($webLbl, $webInfo,
    (New-Btn 'Открыть в браузере' { Start-Process "http://localhost:$((Get-WebCfgUi).port)/" } $true),
    (New-Btn 'Скопировать адрес и пароль' { $wcf = Get-WebCfgUi; $ips = @(Get-LocalIps | ForEach-Object { "http://$($_.Ip):$($wcf.port)/  (сеть «$($_.Alias)»)" }); [Windows.Forms.Clipboard]::SetText((@('VpnGuard — веб-интерфейс') + $ips + @("Пароль: $($wcf.token)")) -join "`r`n"); Set-Footer 'Адрес и пароль веб-интерфейса скопированы' })))
$webSpacer = New-Object Windows.Forms.Panel; $webSpacer.Dock = 'Top'; $webSpacer.Height = 12; $webSpacer.BackColor = $Clr.Bg
function Get-WebCfgUi {
    $d = @{ enabled = $true; port = 8765; token = ''; requirePassword = $true }
    try { $o = Read-ConfigObject; if ($o.PSObject.Properties['web']) { foreach ($pp in $o.web.PSObject.Properties) { $d[$pp.Name] = $pp.Value } } } catch { }
    return $d
}
function Update-WebUi {
    $wcf = Get-WebCfgUi
    Set-Prop $webInfo Text $(if (-not $wcf.enabled) { 'выключен (web.enabled в config.json)' } else { "http://localhost:$($wcf.port)/ · с телефона и других устройств сети — по адресу этого ПК, $(if ($wcf.requirePassword -eq $false) { 'без пароля' } elseif ($wcf.token) { "пароль: $($wcf.token)" } else { 'пароль появится, когда агент запустит сервер' })" })
}
$script:PubIp = ''

function Get-RemoteCfgUi {
    $d = @{ enabled = $false; until = ''; token = ''; port = 8765; allowFrom = 'any'; allowActions = $false }
    try { $o = Read-ConfigObject; if ($o.PSObject.Properties['remote']) { foreach ($pp in $o.remote.PSObject.Properties) { $d[$pp.Name] = $pp.Value } } } catch { }
    return $d
}
function Get-LocalIps {
    @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.InterfaceAlias -notlike 'MeduzaVPN*' -and $_.InterfaceAlias -notlike 'awg*' } |
        ForEach-Object { [pscustomobject]@{ Ip = $_.IPAddress; Alias = $_.InterfaceAlias } })
}
function Test-RemoteOnUi($r) { $u = [datetime]::MinValue; try { if ($r.until) { $u = [datetime]$r.until } } catch { }; [bool]($r.enabled -and "$($r.token)".Length -ge 16 -and $u -gt (Get-Date)) }

function Switch-RemoteUi {
    $r = Get-RemoteCfgUi
    if ($Demo) { Set-Footer 'ДЕМО: удалённая диагностика не включается'; return }
    try {
        $o = Read-ConfigObject
        if (Test-RemoteOnUi $r) {
            Set-CfgVal $o 'remote.enabled' $false
            $tmp = "$ConfigPath.tmp"; $o | ConvertTo-Json -Depth 6 | Set-Content $tmp -Encoding UTF8; Move-Item $tmp $ConfigPath -Force
            # сразу закрыть, не дожидаясь агента
            try { $st = Get-Content (Join-Path $DataDir 'remote-state.json') -Raw -Encoding UTF8 | ConvertFrom-Json; if ($st.pid) { $pp = Get-Process -Id ([int]$st.pid) -ErrorAction SilentlyContinue; if ($pp -and ($pp.ProcessName -like 'powershell*' -or $pp.ProcessName -eq 'VpnGuardWeb')) { Stop-Process -Id $pp.Id -Force } } } catch { }
            try { Remove-NetFirewallRule -DisplayName 'VpnGuard remote diagnostics' -ErrorAction SilentlyContinue } catch { }
            Set-Footer 'Удалённая диагностика выключена'
        } else {
            $hours = $RmHours[[Math]::Max(0, $cbRmHours.SelectedIndex)]
            $msg = "Включить удалённую диагностику на $hours ч?`n`nПо адресу этого ПК и токену можно будет читать состояние, журналы, настройки сети и запускать проверки. Ключи и пароли скрыты." +
                $(if ($cbRmFrom.SelectedIndex -eq 0) { "`n`nДоступ — откуда угодно. Чтобы подключиться из интернета, на роутере нужно пробросить TCP-порт $($r.port) на этот ПК." } else { '' }) +
                $(if ($chkRmAct.Checked) { "`n`nРазрешены тесты и переподключения — клиенты wg_server могут ненадолго терять интернет." } else { '' })
            if ([Windows.Forms.MessageBox]::Show($msg, 'VpnGuard — удалённая диагностика', 'YesNo', 'Question') -ne 'Yes') { return }
            $b = New-Object byte[] 20; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
            $tok = (-join ($b | ForEach-Object { $_.ToString('x2') }))
            Set-CfgVal $o 'remote.enabled' $true
            Set-CfgVal $o 'remote.until' ((Get-Date).AddHours($hours).ToString('o'))
            Set-CfgVal $o 'remote.token' $tok
            Set-CfgVal $o 'remote.port' ([int]$r.port)
            Set-CfgVal $o 'remote.allowFrom' $(if ($cbRmFrom.SelectedIndex -eq 1) { 'local' } else { 'any' })
            Set-CfgVal $o 'remote.allowActions' ([bool]$chkRmAct.Checked)
            $tmp = "$ConfigPath.tmp"; $o | ConvertTo-Json -Depth 6 | Set-Content $tmp -Encoding UTF8; Move-Item $tmp $ConfigPath -Force
            Send-Cmd 'check-now' 'включение удалённой диагностики'
            if (-not $script:PubIp) { [void](Start-Bg 'pubip' { try { (Invoke-RestMethod 'https://api.ipify.org' -TimeoutSec 8 -UseBasicParsing).ToString().Trim() } catch { 'не удалось' } }) }
        }
    } catch { [Windows.Forms.MessageBox]::Show("Не удалось сохранить: $($_.Exception.Message)", 'VpnGuard', 'OK', 'Error') | Out-Null }
    $script:RmSig = ''; Update-RemoteUi
}

function Get-RemoteConnText {
    $r = Get-RemoteCfgUi
    $u = $(try { ([datetime]$r.until).ToString('dd.MM.yyyy HH:mm') } catch { '' })
    $lines = @("VpnGuard — удалённая диагностика (до $u)")
    if ($script:PubIp -and $script:PubIp -ne 'не удалось') { $lines += "Через интернет: http://$($script:PubIp):$($r.port)/   (нужен проброс TCP $($r.port) на роутере)" }
    foreach ($av in Get-LocalIps) { $lines += "В сети «$($av.Alias)»: http://$($av.Ip):$($r.port)/" }
    $lines += "Токен: $($r.token)"
    $lines += "Пример: curl -H `"X-Token: $($r.token)`" http://АДРЕС:$($r.port)/bundle"
    return ($lines -join "`r`n")
}
function Copy-RemoteUi {
    $r = Get-RemoteCfgUi
    if (-not (Test-RemoteOnUi $r)) { [Windows.Forms.MessageBox]::Show('Сначала включите удалённую диагностику.', 'VpnGuard') | Out-Null; return }
    [Windows.Forms.Clipboard]::SetText((Get-RemoteConnText))
    Set-Footer 'Данные для подключения скопированы — отправьте их вместе с сообщением'
}

$script:RmSig = ''
function Update-RemoteUi {
    $ip = Receive-Bg 'pubip'; if ($ip) { $script:PubIp = "$ip"; Set-Footer "Внешний IP: $ip"; $script:RmSig = '' }
    $r = Get-RemoteCfgUi
    $rs = Get-Snap 'remote'
    $on = Test-RemoteOnUi $r
    $sig = "$on|$($r.until)|$($r.token)|$($rs.running)|$($rs.requests)|$($rs.last)|$($rs.error)|$script:PubIp"
    if ($sig -eq $script:RmSig) { return }
    $script:RmSig = $sig
    $u = $(try { ([datetime]$r.until).ToString('dd.MM HH:mm') } catch { '' })
    Set-Prop $btnRmOn Text $(if ($on) { 'Выключить' } else { 'Включить' })
    foreach ($c in $cbRmHours, $cbRmFrom, $chkRmAct) { Set-Prop $c Enabled (-not $on) }
    if ($on) { $chkRmAct.Checked = [bool]$r.allowActions; $cbRmFrom.SelectedIndex = $(if ("$($r.allowFrom)" -eq 'local') { 1 } else { 0 }) }
    $lv = $(if (-not $on) { -1 } elseif ($rs -and $rs.error) { 2 } elseif ($rs -and $rs.running) { 0 } else { 1 })
    Set-Prop $rmDot BackColor $LevelColor[$lv]
    Set-Prop $rmState Text $(if (-not $on) { 'выключена' }
        elseif ($rs -and $rs.error) { "ошибка: $($rs.error)" }
        elseif ($rs -and $rs.running) { "включена до $u · порт $($r.port) · запросов: $($rs.requests)" + $(if ($rs.last) { " · последний: $($rs.last)" } else { '' }) }
        else { "включена до $u — ждём, когда агент запустит сервер (порт $($r.port))" })
    $loc = @(Get-LocalIps | ForEach-Object { $_.Ip })
    Set-Prop $rmAddr Text $(if ($on) { "адреса: $(@(@($(if ($script:PubIp) { "$($script:PubIp) (внешний)" })) + $loc | Where-Object { $_ }) -join ', ') · порт $($r.port)" } else { '' })
}
$rmTimer = New-Object Windows.Forms.Timer
$rmTimer.Interval = 1500
$rmTimer.Add_Tick({ if ($script:CurPage -eq 'diag') { try { Update-RemoteUi } catch { }; try { Update-WebUi } catch { } } })
$rmTimer.Start()

$pgDiag.Controls.AddRange(@($diagBar, $diagIntro, $rmSpacer, $rmBox, $webSpacer, $webBox, $diagBox))
$diagBox.BringToFront()
$pages['diag'] = $pgDiag

$script:diagProc = $null
$script:diagOut  = Join-Path $env:TEMP 'vpnguard-diag.out.txt'
$script:diagErr  = Join-Path $env:TEMP 'vpnguard-diag.err.txt'
$script:diagStarted = $null

function Read-Shared([string]$Path) {
    if (-not (Test-Path $Path)) { return '' }
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try { (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd() } finally { $fs.Dispose() }
    } catch { '' }
}

function Start-Diag([bool]$TryFix) {
    if ($script:diagProc -and -not $script:diagProc.HasExited) { return }
    Remove-Item $script:diagOut, $script:diagErr -Force -ErrorAction SilentlyContinue
    $av = "-NoProfile -ExecutionPolicy Bypass -File `"$AgentPs1`" -Diag" + $(if ($TryFix) { ' -TryFix' } else { '' })
    $script:diagProc = Start-Process powershell.exe -ArgumentList $av -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $script:diagOut -RedirectStandardError $script:diagErr
    $script:diagStarted = Get-Date
    $btnDiag.Enabled = $false; $btnDiagFix.Enabled = $false
    $diagBox.Text = 'Собираю отчёт…'
    $diagState.Text = 'идёт сбор…'
    $diagTimer.Start()
}

function Update-Diag {
    if (-not $script:diagProc) { $diagTimer.Stop(); return }
    $txt = (Read-Shared $script:diagOut) -replace "`r?`n", "`r`n"
    $done = $script:diagProc.HasExited
    if ($done) {
        $err = Read-Shared $script:diagErr
        if ($err.Trim()) { $txt += "`r`n===== stderr =====`r`n" + ($err -replace "`r?`n", "`r`n") }
    }
    if ($txt -and $txt -ne $diagBox.Text) { $diagBox.Text = $txt; $diagBox.SelectionStart = $diagBox.TextLength; $diagBox.ScrollToCaret() }
    $sec = [int]((Get-Date) - $script:diagStarted).TotalSeconds
    if ($done) {
        $diagTimer.Stop()
        $btnDiag.Enabled = $true; $btnDiagFix.Enabled = $true
        $diagState.Text = "готово за $sec с · $(($diagBox.Lines).Count) строк"
        $diagBox.SelectionStart = 0; $diagBox.ScrollToCaret()
        Set-Footer 'Отчёт диагностики собран'
    } else {
        $diagState.Text = "идёт сбор… $sec с"
        if ($sec -gt 180) { try { $script:diagProc.Kill() } catch { }; $diagState.Text = 'прервано по таймауту' }
    }
}

function Copy-Diag {
    if (-not $diagBox.Text.Trim()) { return }
    [Windows.Forms.Clipboard]::SetText($diagBox.Text)
    Set-Footer 'Отчёт скопирован в буфер обмена — вставьте его в сообщение'
}

function Save-Diag {
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'Текст (*.txt)|*.txt'
    $dlg.FileName = 'vpnguard-diag-{0}.txt' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
    $dlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')
    if ($dlg.ShowDialog($form) -eq 'OK') {
        [IO.File]::WriteAllText($dlg.FileName, $diagBox.Text, (New-Object Text.UTF8Encoding $true))
        Set-Footer "Отчёт сохранён: $($dlg.FileName)"
    }
}

$diagTimer = New-Object Windows.Forms.Timer
$diagTimer.Interval = 700
$diagTimer.Add_Tick({ try { Update-Diag } catch { $diagTimer.Stop() } })

# ---------------------------------------------------------------- обновление экрана
# читает status.json только когда агент его переписал
function Read-Status {
    $stamp = $null
    try { if (Test-Path $StatusPath) { $stamp = (Get-Item $StatusPath).LastWriteTimeUtc } } catch { }
    if ($stamp -eq $script:statusStamp) { return $false }
    $script:statusStamp = $stamp
    $s = $null
    if ($stamp) { try { $s = [IO.File]::ReadAllText($StatusPath, [Text.Encoding]::UTF8) | ConvertFrom-Json } catch { $script:statusStamp = $null; return $false } }
    $script:snap = $s
    return $true
}

# шапка: дешёво, обновляется каждый тик (возраст данных)
function Update-Header {
    $s = $script:snap
    $age = 1e9
    if ($s) { try { $age = ((Get-Date) - [datetime]$s.updated).TotalSeconds } catch { } }
    $fresh = [bool]($s -and $age -lt [double]$s.staleAfterSec)
    if (($Preview -or $Demo) -and $s) { $fresh = $true }
    if ($Demo) {
        Set-Prop $agentDot BackColor $Clr.Accent
        Set-Prop $agentLbl Text 'ДЕМО-РЕЖИМ: тестовые данные, кнопки ничего не делают'
        Set-Prop $btnStart Enabled $false; Set-Prop $btnStop Enabled $false
        return $fresh
    }
    $running = Test-AgentAlive
    $snapAlive = $false
    if ($s -and $s.agentPid) { $snapAlive = [bool](Get-Process -Id ([int]$s.agentPid) -ErrorAction SilentlyContinue) }
    $busy = ''
    if ($s -and $s.PSObject.Properties['activity'] -and $s.activity) {
        $sec = 0; try { $sec = [int]((Get-Date) - [datetime]$s.activitySince).TotalSeconds } catch { }
        $busy = "сейчас: $($s.activity) ($sec с)"
    }
    if ($running -and $fresh) {
        Set-Prop $agentDot BackColor $(if ($busy) { $Clr.Accent } else { $Clr.Ok })
        Set-Prop $agentLbl Text ('Агент {2} работает · данные обновлены {0} с назад · проверка каждые {1} с' -f [int]$age, $s.intervalSec, $s.agentVersion)
    } elseif ($running -and -not $snapAlive) {
        Set-Prop $agentDot BackColor $Clr.Warn
        Set-Prop $agentLbl Text 'Агент запускается… Если надпись не меняется больше минуты — работает старая версия: нажмите «Остановить», затем «Запустить».'
    } elseif ($running) {
        Set-Prop $agentDot BackColor $Clr.Warn
        Set-Prop $agentLbl Text ('Агент {0} не присылал данные {1} мин — если так останется, нажмите «Остановить» → «Запустить»' -f $s.agentVersion, [int]($age / 60))
    } else {
        $ts = $(if ($script:taskInfo) { $script:taskInfo.Agent } else { 'unknown' })
        Set-Prop $agentDot BackColor $Clr.Bad
        Set-Prop $agentLbl Text ('Агент остановлен' + $(if ($ts -eq 'Disabled') { ' (автозапуск выключен)' } elseif (-not $ts) { ' (задача не установлена)' } else { '' }))
    }
    Set-Prop $agentBusy Text $(if ($running) { $busy } else { '' })
    Set-Prop $btnStart Enabled (-not $running)
    Set-Prop $btnStop Enabled $running
    return $fresh
}

$TileSub = @{ meduza = 0; ultra = 0; wg = 2; ics = 2; zapret = 1; amnezia = 1 }

# всё, что зависит от status.json — только при новых данных или смене «свежести»
function Update-Data([bool]$Fresh) {
    $s = $script:snap
    $worst = -1
    $zOn = [bool]($s -and $s.PSObject.Properties['zapret'] -and $s.zapret.enabled)
    foreach ($b in $script:ZToggleBtns) { Set-Prop $b Text $(if ($zOn) { 'Выключить zapret' } else { 'Включить zapret' }) }
    foreach ($k in $CompKeys) {
        $o = Get-Snap $k
        if ($o) {
            $lv = $(if ($Fresh) { [int]$o.level } else { -1 })
            $stt = "$($o.state)" + $(if (-not $Fresh) { ' (устарело)' } else { '' })
            $det = @($o.details | Where-Object { $_ })
        } else {
            $lv = -1; $stt = 'нет данных'; $det = @('Агент ещё не прислал состояние.')
        }
        $script:Level[$k] = $lv
        $col = $(if ($lv -ge 0) { $LevelColor[$lv] } else { $Clr.Dim })
        foreach ($ui in @($Tiles[$k], $CompHdr[$k])) {
            Set-Prop $ui.Dot BackColor $LevelColor[$lv]; Set-Prop $ui.State Text $stt; Set-Prop $ui.State ForeColor $col
        }
        # на плитке — коротко (до « · »), полностью — во всплывающей подсказке и на вкладке
        Set-Prop $Tiles[$k].State Text ((("$stt" -split ' · ')[0]) + $(if (-not $Fresh -and $o) { ' (устарело)' } else { '' }))
        $tip.SetToolTip($Tiles[$k].State, (@("$stt") + @($det) -join "`n"))
        $ix = [Math]::Min($TileSub[$k], [Math]::Max(0, $det.Count - 1))
        Set-Prop $Tiles[$k].Sub Text $(if ($det.Count) { "$($det[$ix])" } else { '' })
        Set-Prop $CompHdr[$k].Sub Text ($det -join '   ·   ')
        $av = Get-Availability $k
        Set-Prop $CompAvail[$k] Text ('Состояние за 2 часа' + $(if ($null -ne $av) { ' · без сбоев {0:0.#} % времени' -f $av } else { '' }))
        if ($lv -gt $worst) { $worst = $lv }
    }
    # общий статус
    $heroText = switch ($worst) { 0 { 'Всё работает' } 1 { 'Есть предупреждения' } 2 { 'Есть сбои' } default { 'Нет данных' } }
    Set-Prop $heroLbl Text $heroText
    Set-Prop $heroLbl ForeColor $(if ($worst -ge 0) { $LevelColor[$worst] } else { $Clr.Dim })
    Set-Prop $heroDot BackColor $LevelColor[$worst]
    $probs = @(foreach ($k in $CompKeys) { if ($script:Level[$k] -ge 1) { ($TileDefs | Where-Object { $_[0] -eq $k })[1] + ': ' + (Get-Snap $k).state } })
    Set-Prop $heroSub Text $(if (-not $s) { 'Ждём состояние от агента…' } elseif (-not $Fresh) { 'Данные устарели — агент давно не обновлял состояние.' }
        elseif ($probs.Count) { $probs -join '   ·   ' } else { 'Туннель, WG-Server и раздача в порядке' })
    Set-Prop $form Text ('VpnGuard — ' + $(switch ($worst) { 0 { 'всё работает' } 1 { 'есть предупреждения' } 2 { 'ЕСТЬ СБОИ' } default { 'нет данных' } }))
    foreach ($b in $navButtons.Values) { if ($b.Tag.Comp) { $b.Invalidate() } }

    Update-PeerRates
    try { Update-MzSelect } catch { }
    try { Update-ModeUi } catch { }
    try { Update-AwgInfo } catch { }
    try { Update-SoftUi } catch { }
    try { Update-ZStratUi } catch { }
    try { Update-AppUi } catch { }
    # статистика
    $av = Get-Availability 'ultra'
    Set-Prop $Kpi.avail.Value Text $(if ($null -ne $av) { '{0:0.#} %' -f $av } else { '—' })
    Set-Prop $Kpi.avail.Value ForeColor $(if ($null -eq $av) { $Clr.Text } elseif ($av -ge 99) { $Clr.Ok } elseif ($av -ge 90) { $Clr.Warn } else { $Clr.Bad })
    Set-Prop $Kpi.avail.Sub Text 'туннель без сбоев'
    $td = Get-TodayTraffic 'u'
    Set-Prop $Kpi.today.Value Text $(if ($td) { '↓ ' + (Format-Bytes $td[0]) } else { '—' })
    Set-Prop $Kpi.today.Sub Text $(if ($td) { '↑ ' + (Format-Bytes $td[1]) + ' отдано' } else { 'с агента 1.8' })
    $peers = @(Get-Peers)
    $wg = Get-Snap 'wg'
    if ($peers.Count) {
        Set-Prop $Kpi.clients.Value Text ('{0} из {1}' -f @($peers | Where-Object { $_.active }).Count, $peers.Count)
        Set-Prop $Kpi.clients.Sub Text 'на связи за 3 мин'
    } else {
        $m = $(if ($wg) { [regex]::Match((@($wg.details) -join ' '), 'Клиенты: (\d+) активных из (\d+)') } else { $null })
        Set-Prop $Kpi.clients.Value Text $(if ($m -and $m.Success) { "$($m.Groups[1].Value) из $($m.Groups[2].Value)" } else { '—' })
        Set-Prop $Kpi.clients.Sub Text 'на связи за 3 мин'
    }
    $cn = Get-Snap 'counters'
    if ($cn) {
        Set-Prop $Kpi.fixes.Value Text ('{0}' -f ([int]$cn.restarts + [int]$cn.reconnects + [int]$cn.icsFixes))
        Set-Prop $Kpi.fixes.Sub Text 'с запуска агента'
        $tip.SetToolTip($Kpi.fixes.Panel, ('Перезапусков MeduzaVPN: {0}, переподключений туннеля: {1}, восстановлений раздачи: {2}' -f $cn.restarts, $cn.reconnects, $cn.icsFixes))
    } else { Set-Prop $Kpi.fixes.Value Text '—'; Set-Prop $Kpi.fixes.Sub Text 'с агента 1.8' }

    # высота таблиц — по числу строк
    foreach ($c in $script:Canvases) {
        $sp = $c.Tag
        if ($sp.Rows) { $h = [int](& $sp.Rows); if ($h -gt 0) { Set-Prop $c Height $h } }
        if (-not $sp.Live -and $c.Visible) { $c.Invalidate() }
    }
}

# раз в секунду: живой трафик и счётчики событий
function Update-Live {
    Update-LiveTraffic
    if ($script:CurPage -eq 'wg') { $before = $script:WgListAt; Update-WgList; if ($script:WgListAt -ne $before) { Invalidate-Visible } }
    $u = Get-LiveLast 'u'
    Set-Prop $Kpi.speed.Value Text $(if ($u) { '↓ ' + (Format-Rate $u[0]) } else { '—' })
    Set-Prop $Kpi.speed.Sub Text $(if ($u) { '↑ ' + (Format-Rate $u[1]) } else { 'туннель не найден' })
    foreach ($k in 'u', 'w', 'p') {
        $v = Get-LiveLast $k; $td = Get-TodayTraffic $k
        $nm = $(if ($script:AdNames) { $script:AdNames[$k] } else { '' })
        Set-Prop $TrafKpi[$k].Value Text $(if ($v) { '↓ ' + (Format-Rate $v[0]) } else { '—' })
        Set-Prop $TrafKpi[$k].Sub Text ($(if ($v) { '↑ ' + (Format-Rate $v[1]) } else { $(if ($nm) { "«$nm» — нет данных" } else { 'адаптер не найден' }) }) +
            $(if ($td) { ' · сегодня ' + (Format-Bytes ($td[0] + $td[1])) } else { '' }))
    }
    if ($script:AdNames -and $script:AdNames.p) { Set-Prop $TrafBtns.p Text $script:AdNames.p }
    try { Update-LogCounts } catch { }
    $lc = $script:LogCnt
    Set-Prop $Kpi.events.Value Text ('{0} ⚠  ·  {1} ✖' -f $lc.Warn, $lc.Err)
    Set-Prop $Kpi.events.Value ForeColor $(if ($lc.Err) { $Clr.Bad } elseif ($lc.Warn) { $Clr.Warn } else { $Clr.Ok })
    Set-Prop $Kpi.events.Sub Text 'предупр. · ошибки'
    foreach ($c in $script:Canvases) { if ($c.Tag.Live -and $c.Visible) { $c.Invalidate() } }
}

function Update-All {
    try { Receive-Background } catch { }
    try {
        $changed = Read-Status
        $fresh = Update-Header
        if ($changed -or $fresh -ne $script:fresh) { $script:fresh = $fresh; Update-Data $fresh }
    } catch { Set-Footer "Ошибка обновления: $($_.Exception.Message)" }
    try { Update-Live } catch { }
    try { Update-LogView } catch { }
}

$content.Controls.AddRange(@($pages.Values))
$form.Controls.AddRange(@($main, $sidebar, $footer))

function Set-DoubleBuffered($Ctl) {
    if ($Ctl -is [Windows.Forms.Panel] -or $Ctl -is [Windows.Forms.TableLayoutPanel] -or $Ctl -is [Windows.Forms.FlowLayoutPanel] -or $Ctl -is [Windows.Forms.Label]) {
        $dbProp.SetValue($Ctl, $true, $null)
    }
    foreach ($ch in $Ctl.Controls) { Set-DoubleBuffered $ch }
}
$dbProp.SetValue($form, $true, $null)
Set-DoubleBuffered $form
Show-Page 'home'
Set-Footer 'Готово'

# ---------------------------------------------------------------- предпросмотр (для проверки вёрстки)
if ($Preview) {
    $form.StartPosition = 'Manual'; $form.Location = New-Object Drawing.Point(-3000, -3000)
    $form.Show(); [Windows.Forms.Application]::DoEvents()
    Request-AgentInfo
    $sw = [Diagnostics.Stopwatch]::StartNew(); Update-All; Write-Host "Первый Update-All: $($sw.ElapsedMilliseconds) мс"
    for ($i = 0; $i -lt 6; $i++) { Start-Sleep -Milliseconds 400; $sw.Restart(); Update-All; [Windows.Forms.Application]::DoEvents() }
    Write-Host "Повторный Update-All: $($sw.ElapsedMilliseconds) мс"
    $script:statusStamp = $null; $sw.Restart(); Update-All; Write-Host "Update-All с новыми данными: $($sw.ElapsedMilliseconds) мс"
    $sw.Restart(); Update-LiveTraffic; Write-Host "Замер трафика: $($sw.ElapsedMilliseconds) мс · адаптеры: $(($script:AdNames.GetEnumerator() | ForEach-Object { "$($_.Key)='$($_.Value)'" }) -join ' ')"
    while ($script:bg['agentinfo']) { Start-Sleep -Milliseconds 100; [void](Receive-Background) }
    foreach ($pg in ($(if ($env:VG_PAGES) { $env:VG_PAGES -split ',' } else { @('home', 'meduza', 'ultra', 'wg', 'ics', 'zapret', 'traffic', 'log', 'settings', 'diag') }))) {
        Show-Page $pg; [Windows.Forms.Application]::DoEvents()
        $sw.Restart(); Update-All; [Windows.Forms.Application]::DoEvents()
        if ($env:VG_SCROLL -and $pages[$pg].AutoScroll) { $pages[$pg].AutoScrollPosition = New-Object Drawing.Point(0, [int]$env:VG_SCROLL); [Windows.Forms.Application]::DoEvents() }
        if ($env:VG_HOVER) { foreach ($c in $script:Canvases) { if ($c.Visible -and $c.Tag.Kind -in 'rate', 'timeline' -and -not $c.Tag.Mini) { $c.Tag.Hover = [int]($c.Width * 0.7) } } }
        if ($env:VG_HOVER) { foreach ($c in $script:Canvases) { if ($c.Visible -and $c.Tag.Kind -eq 'zres') { $c.Tag.HoverY = 60 } } }
        foreach ($c in $script:Canvases) { if ($c.Visible) { $c.Refresh() } }
        $ms = $sw.ElapsedMilliseconds
        $bmp = New-Object Drawing.Bitmap $form.Width, $form.Height
        $form.DrawToBitmap($bmp, (New-Object Drawing.Rectangle 0, 0, $form.Width, $form.Height))
        $bmp.Save(($Preview -replace '\.png$', "-$pg.png"), [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
        Write-Host "страница $pg — обновление+отрисовка $ms мс"
    }
    $form.Close()
    return
}

# ---------------------------------------------------------------- таймер
$timer = New-Object Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    if ($showEvt -and $showEvt.WaitOne(0)) {
        $form.Show(); if ($form.WindowState -eq 'Minimized') { $form.WindowState = 'Normal' }
        $form.TopMost = $true; $form.TopMost = $false; $form.Activate()
    }
    # окно скрыто в значок у часов или свёрнуто — не перерисовывать страницы, только снимать трафик (график не прерывается)
    if ($form.Visible -and $form.WindowState -ne 'Minimized') { Update-All }
    else { try { Update-LiveTraffic } catch { } }
})
# код окна обновился (автообновление) — открыть новое окно и закрыть это
$MonCode = @('VpnGuardMonitor.ps1', 'Amnezia.ps1', 'Wg.ps1', 'Qr.cs')
function Get-MonStamp { ($MonCode | ForEach-Object { $fp = Join-Path $Root $_; if (Test-Path $fp) { (Get-Item $fp).LastWriteTimeUtc.Ticks } }) -join '|' }
$script:MonStamp = Get-MonStamp
$script:MonCheckAt = Get-Date
function Test-MonUpdated {
    if ($Demo -or $Preview -or ((Get-Date) - $script:MonCheckAt).TotalSeconds -lt 10) { return }
    $script:MonCheckAt = Get-Date
    $now = Get-MonStamp
    if ($now -eq $script:MonStamp) { return }
    $script:MonStamp = $now
    $err = $null; [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'VpnGuardMonitor.ps1'), [ref]$null, [ref]$err)
    if ($err.Count) { Set-Footer "Новая версия окна с ошибкой ($($err[0].Message)) — остаюсь на текущей"; return }
    Set-Footer 'VpnGuard обновился — перезапускаю окно…'
    Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $Root 'VpnGuardMonitor.ps1')`" -Restarted"
    $timer.Stop(); $form.Close()
}
$timer.Add_Tick({ try { Test-MonUpdated } catch { } })
$form.Add_Shown({ Request-AgentInfo; Update-All; $timer.Start() })
$form.Add_FormClosed({ $timer.Stop(); try { $script:mutex.ReleaseMutex() } catch { } })

[Windows.Forms.Application]::Run($form)
