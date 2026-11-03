#Requires -Version 5.1
<#
  Модуль zapret-discord-youtube для VpnGuard (подключается из VpnGuard.ps1 через dot-source).

  Что делает:
    - ставит/обновляет zapret-discord-youtube (Flowseal) из последнего релиза GitHub;
    - подбирает рабочую стратегию (general*.bat) — запускает winws.exe с её параметрами
      и проверяет сайты curl'ом напрямую через физический адаптер (мимо VPN);
    - держит winws.exe запущенным с выбранной стратегией;
    - выводит адреса YouTube/Google и Discord из туннеля MeduzaVPN ULTRA (маршруты через Ethernet),
      при выключении возвращает их в VPN;
    - периодически проверяет, что сайты открываются; если нет — переподбирает стратегию,
      если не работает ни одна — временно отключает zapret (трафик снова через VPN).

  Ограничение zapret на Windows: работает только для трафика самого компьютера;
  клиентам wg_server YouTube/Discord при включённом zapret могут быть недоступны.
#>

$ZapretRepo   = 'Flowseal/zapret-discord-youtube'
$ZStatePath   = Join-Path $DataDir 'zapret-state.json'
$ZTestPath    = Join-Path $DataDir 'zapret-test.json'
$ZGooglePath  = Join-Path $DataDir 'zapret-google-ranges.json'
$ZNeverRoute  = @('8.8.8.0/24', '8.8.4.0/24')   # публичный DNS остаётся в VPN

$ZState = @{
    version = ''; remoteVersion = ''; lastUpdateCheck = [datetime]::MinValue
    strategy = ''; lastTest = [datetime]::MinValue; lastScore = 0; lastTotal = 0; results = @()
    routes = @(); lastRouteRefresh = [datetime]::MinValue
    healthAt = [datetime]::MinValue; healthOk = 0; healthTotal = 0; healthFails = 0
    fallbackUntil = [datetime]::MinValue; winwsPid = 0; runningStrategy = ''; lastError = ''
    healthChecks = @(); videoHost = ''; videoHostAt = [datetime]::MinValue; videoHostVia = ''; ytJs = ''; ytJsAt = ''; ggc = @()
    releases = @(); releasesAt = ''
}

# в режиме «без VPN» zapret включён всегда (это и есть способ открыть YouTube/Discord)
function Get-ZCfg {
    $z = $Cfg.zapret
    if (-not $z.enabled -and (Get-Command Get-VpnMode -ErrorAction SilentlyContinue) -and (Get-VpnMode) -eq 'zapret') { $c = $z.Clone(); $c.enabled = $true; return $c }
    return $z
}
function Test-ZDirect { [bool]((Get-Command Get-VpnMode -ErrorAction SilentlyContinue) -and (Get-VpnMode) -eq 'zapret') }
function Get-ZapretDir { $z = Get-ZCfg; if ($z.dir) { return $z.dir }; return (Join-Path $Root 'zapret') }

function Import-ZState {
    if (-not (Test-Path $ZStatePath)) { return }
    try {
        $s = Get-Content $ZStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $s.PSObject.Properties) {
            if ($ZState.ContainsKey($p.Name)) {
                $v = $p.Value
                if ($ZState[$p.Name] -is [datetime]) { try { $v = [datetime]$v } catch { $v = [datetime]::MinValue } }
                $ZState[$p.Name] = $v
            }
        }
        $ZState.routes  = @($ZState.routes)
        $ZState.results = @($ZState.results)
    } catch { }
}
function Save-ZState {
    $o = @{}
    foreach ($k in $ZState.Keys) { $v = $ZState[$k]; if ($v -is [datetime]) { $v = $v.ToString('o') }; $o[$k] = $v }
    $o | ConvertTo-Json -Depth 8 | Set-Content $ZStatePath -Encoding UTF8
}
Import-ZState

# ---------------------------------------------------------------- установка / обновление

function Get-ZapretLocalVersion {
    $f = Join-Path (Get-ZapretDir) '.service\version.txt'
    if (Test-Path $f) { return (Get-Content $f -TotalCount 1).Trim() }
    $sb = Join-Path (Get-ZapretDir) 'service.bat'
    if (Test-Path $sb) {
        $mt = Select-String -Path $sb -Pattern 'LOCAL_VERSION=([\d\.]+)' | Select-Object -First 1
        if ($mt) { return $mt.Matches[0].Groups[1].Value }
    }
    return ''
}

function Test-ZapretInstalled { Test-Path (Join-Path (Get-ZapretDir) 'bin\winws.exe') }

# релиз: последний или конкретная версия (тег, например 1.10.2)
function Get-ZapretRelease([string]$Version = '') {
    $url = $(if ($Version) { "https://api.github.com/repos/$ZapretRepo/releases/tags/$Version" } else { "https://api.github.com/repos/$ZapretRepo/releases/latest" })
    $r = Invoke-RestMethod $url -Headers @{ 'User-Agent' = 'VpnGuard' } -TimeoutSec 30 -UseBasicParsing
    $asset = $r.assets | Where-Object { $_.name -like '*.zip' } | Select-Object -First 1
    if (-not $asset) { throw 'в релизе нет .zip' }
    [pscustomobject]@{ Version = "$($r.tag_name)".TrimStart('v'); Url = $asset.browser_download_url; Name = $asset.name; Size = $asset.size }
}

# создать пользовательские списки, без которых стратегии не запускаются (как service.bat load_user_lists)
function Initialize-ZapretUserLists {
    $l = Join-Path (Get-ZapretDir) 'lists'
    if (-not (Test-Path $l)) { return }
    $files = @{
        'ipset-exclude-user.txt' = '203.0.113.113/32'
        'list-general-user.txt'  = "# Never leave this file empty`r`ndomain.example.abc"
        'list-exclude-user.txt'  = 'domain.example.abc'
    }
    foreach ($n in $files.Keys) {
        $p = Join-Path $l $n
        if (-not (Test-Path $p)) { [IO.File]::WriteAllText($p, $files[$n] + "`r`n", (New-Object Text.UTF8Encoding $false)) }
    }
}

function Install-Zapret($Release) {
    $dir = Get-ZapretDir
    Set-Activity "скачиваю zapret $($Release.Version)"
    Write-Log "zapret: загрузка $($Release.Url)"
    $zip = Join-Path $DlDir $Release.Name
    Invoke-WebRequest -Uri $Release.Url -OutFile $zip -UseBasicParsing -TimeoutSec 300
    if ($Release.Size -and (Get-Item $zip).Length -ne $Release.Size) { throw "размер архива не совпал ($((Get-Item $zip).Length) вместо $($Release.Size))" }
    $tmp = Join-Path $DlDir 'zapret_x'
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive $zip $tmp -Force
    $winws = Get-ChildItem $tmp -Recurse -Filter 'winws.exe' | Select-Object -First 1
    if (-not $winws) { throw 'в архиве нет bin\winws.exe' }
    $srcRoot = $winws.Directory.Parent.FullName

    Set-Activity "устанавливаю zapret $($Release.Version)"
    $wasRunning = [bool](Get-Process winws -ErrorAction SilentlyContinue)
    Stop-Winws
    # драйвер держит WinDivert64.sys — выгрузить, чтобы файл можно было заменить
    if (Get-Service -Name 'WinDivert' -ErrorAction SilentlyContinue) { try { Stop-Service -Name 'WinDivert' -Force -ErrorAction Stop } catch { } }
    # сохранить пользовательские списки
    $keep = @{}
    if (Test-Path (Join-Path $dir 'lists')) {
        Get-ChildItem (Join-Path $dir 'lists') -Filter '*-user.txt' | ForEach-Object { $keep[$_.Name] = [IO.File]::ReadAllBytes($_.FullName) }
    }
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }
    $copyErr = @()
    Get-ChildItem $srcRoot -Force | ForEach-Object {
        try { Copy-Item $_.FullName $dir -Recurse -Force -ErrorAction Stop } catch { $copyErr += "$($_.Exception.Message)" }
    }
    if ($copyErr.Count) { Write-Log "zapret: не все файлы заменены: $($copyErr[0])" 'WARN' }
    foreach ($n in $keep.Keys) { [IO.File]::WriteAllBytes((Join-Path (Join-Path $dir 'lists') $n), $keep[$n]) }
    Get-ChildItem $dir -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
    Initialize-ZapretUserLists
    Remove-Item $tmp, $zip -Recurse -Force -ErrorAction SilentlyContinue

    $ZState.version = Get-ZapretLocalVersion
    if (-not $ZState.version) { $ZState.version = $Release.Version }
    # стратегии могли измениться — переподобрать
    $ZState.lastTest = [datetime]::MinValue
    Save-ZState
    Write-Log "zapret: установлена версия $($ZState.version) в $dir"
    return $wasRunning
}

# список версий для выбора (кэш 12 ч)
function Get-ZapretReleases([switch]$Force) {
    $at = [datetime]::MinValue; try { $at = [datetime]$ZState.releasesAt } catch { }
    if (-not $Force -and @($ZState.releases).Count -and ((Get-Date) - $at).TotalHours -lt 12) { return @($ZState.releases) }
    try {
        $list = Invoke-RestMethod "https://api.github.com/repos/$ZapretRepo/releases?per_page=20" -Headers @{ 'User-Agent' = 'VpnGuard' } -TimeoutSec 30 -UseBasicParsing
        $ZState.releases = @(@($list) | Where-Object { -not $_.draft -and @($_.assets | Where-Object { $_.name -like '*.zip' }).Count } | ForEach-Object { [ordered]@{ v = "$($_.tag_name)".TrimStart('v'); tag = "$($_.tag_name)"; date = ([datetime]$_.published_at).ToString('dd.MM.yyyy'); pre = [bool]$_.prerelease } })
        $ZState.releasesAt = (Get-Date).ToString('o')
        Save-ZState
    } catch { Write-Log "zapret: не удалось получить список версий: $($_.Exception.Message)" 'WARN' }
    return @($ZState.releases)
}

function Invoke-ZapretUpdate([switch]$Force) {
    $z = Get-ZCfg
    $installed = Test-ZapretInstalled
    $sinceCheck = ((Get-Date) - $ZState.lastUpdateCheck).TotalMinutes
    # выбрана конкретная версия — ставим именно её и не обновляем
    $pin = "$($z.version)".Trim()
    if ($pin) {
        $local = Get-ZapretLocalVersion
        if ($installed -and $local -and "$local".TrimStart('v') -eq $pin.TrimStart('v')) { $ZState.version = $local; return }   # строкой: 1.9.9c и 1.9.9d — разные
        if (-not $Force -and $sinceCheck -lt 10) { return }
        $ZState.lastUpdateCheck = Get-Date
        $tag = $(($ZState.releases | Where-Object { "$($_.v)" -eq $pin.TrimStart('v') } | Select-Object -First 1).tag); if (-not $tag) { $tag = $pin }
        try { $rel = Get-ZapretRelease $tag } catch { $ZState.lastError = "версия $pin не найдена на GitHub: $($_.Exception.Message)"; Write-Log "zapret: $($ZState.lastError)" 'ERROR'; Save-ZState; return }
        Write-Log "zapret: ставлю выбранную версию $($rel.Version) (установлена: $(if ($local) { $local } else { 'нет' }))" 'WARN'
        try { [void](Install-Zapret $rel); $ZState.lastError = '' } catch { $ZState.lastError = "установка: $($_.Exception.Message)"; Write-Log "zapret: ошибка установки: $($_.Exception.Message)" 'ERROR' }
        Save-ZState
        return
    }
    if (-not $Force) {
        if ($installed) {
            if (-not $z.autoUpdate) { return }
            if ($sinceCheck -lt [double]$z.updateCheckHours * 60) { return }
        } elseif ($sinceCheck -lt 10) { return }      # не установлен: пробуем не чаще раза в 10 мин
    }
    $ZState.lastUpdateCheck = Get-Date
    try { $rel = Get-ZapretRelease } catch { Write-Log "zapret: не удалось узнать последнюю версию: $($_.Exception.Message)" 'WARN'; Save-ZState; return }
    $ZState.remoteVersion = $rel.Version
    $local = Get-ZapretLocalVersion
    if ($installed -and $local -and (ConvertTo-Ver $rel.Version) -le (ConvertTo-Ver $local)) {
        $ZState.version = $local; Save-ZState
        Write-Log "zapret $local — актуальная версия"
        return
    }
    Write-Log "zapret: доступна версия $($rel.Version) (установлена: $(if ($local) { $local } else { 'нет' }))"
    try { [void](Install-Zapret $rel) } catch { $ZState.lastError = "установка: $($_.Exception.Message)"; Write-Log "zapret: ошибка установки: $($_.Exception.Message)" 'ERROR' }
    Save-ZState
}

# ---------------------------------------------------------------- стратегии и winws

function Get-ZapretStrategies {
    $dir = Get-ZapretDir
    if (-not (Test-Path $dir)) { return @() }
    @(Get-ChildItem $dir -Filter 'general*.bat' | Sort-Object { [regex]::Replace($_.BaseName, '\d+', { $args[0].Value.PadLeft(4, '0') }) } |
        ForEach-Object { $_.BaseName })
}

# параметры winws.exe из .bat: склеить строки с ^, подставить %BIN% %LISTS% и игровой фильтр
function Get-StrategyArgs([string]$Name) {
    $dir = Get-ZapretDir
    $bat = Join-Path $dir "$Name.bat"
    if (-not (Test-Path $bat)) { return $null }
    $raw = [IO.File]::ReadAllText($bat) -replace '\^\s*\r?\n', ' '
    $line = ($raw -split '\r?\n') | Where-Object { $_ -match 'winws\.exe' } | Select-Object -First 1
    if (-not $line) { return $null }
    $mt = [regex]::Match($line, 'winws\.exe"?\s+(.*)$')
    if (-not $mt.Success) { return $null }
    $a = $mt.Groups[1].Value.Trim()
    $z = Get-ZCfg
    $gt = '12'; $gu = '12'   # 12 = игровой фильтр выключен (как в service.bat)
    if ($z.gameFilter -in 'all', 'tcp') { $gt = '1024-65535' }
    if ($z.gameFilter -in 'all', 'udp') { $gu = '1024-65535' }
    $a = $a.Replace('%BIN%', (Join-Path $dir 'bin') + '\').Replace('%LISTS%', (Join-Path $dir 'lists') + '\')
    $a = $a.Replace('%GameFilterTCP%', $gt).Replace('%GameFilterUDP%', $gu).Replace('%~dp0', $dir + '\')
    if ($a -match '%[A-Za-z_]+%') { Write-Log "zapret: в стратегии '$Name' остались неизвестные переменные: $($Matches[0])" 'WARN' }
    return $a
}

function Get-WinwsProcs { @(Get-Process winws -ErrorAction SilentlyContinue) }

function Stop-Winws {
    $p = Get-WinwsProcs
    if ($p) { $p | Stop-Process -Force -ErrorAction SilentlyContinue; $p | ForEach-Object { try { $_.WaitForExit(5000) | Out-Null } catch { } } }
    $ZState.winwsPid = 0
}

# служба «zapret» от service.bat конфликтует с нашим winws — остановить
function Stop-ZapretService {
    $s = Get-Service -Name 'zapret' -ErrorAction SilentlyContinue
    if (-not $s) { return }
    try {
        if ($s.Status -ne 'Stopped') {
            Write-Log 'zapret: остановлена служба «zapret» (установлена через service.bat), иначе два winws мешают друг другу' 'WARN'
            Stop-Service -Name 'zapret' -Force -ErrorAction Stop
        }
        if ($s.StartType -ne 'Disabled') { Set-Service -Name 'zapret' -StartupType Disabled -ErrorAction Stop }
    } catch { Write-Log "zapret: не удалось остановить службу zapret: $($_.Exception.Message)" 'WARN' }
}

function Start-Winws([string]$Name) {
    $a = Get-StrategyArgs $Name
    if (-not $a) { throw "не удалось прочитать параметры стратегии '$Name'" }
    $bin = Join-Path (Get-ZapretDir) 'bin'
    $p = Start-Process -FilePath (Join-Path $bin 'winws.exe') -ArgumentList $a -WorkingDirectory $bin -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 1500
    if ($p.HasExited) { throw "winws.exe завершился сразу (код $($p.ExitCode)) со стратегией '$Name'" }
    $ZState.winwsPid = $p.Id
    return $p
}

# ---------------------------------------------------------------- проверка сайтов

# физический путь в интернет (не ULTRA и не wg_server)
function Get-PhysicalPath {
    $cands = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { -not (Test-TunnelAlias $_.InterfaceAlias) -and $_.NextHop -and $_.NextHop -ne '0.0.0.0' })
    $best = $null; $bestM = [int]::MaxValue
    foreach ($r in $cands) {
        $a = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue
        if (-not $a -or $a.Status -ne 'Up') { continue }
        $im = (Get-NetIPInterface -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric
        $mt = [int]$r.RouteMetric + [int]$im
        if ($mt -lt $bestM) { $bestM = $mt; $best = $r }
    }
    if (-not $best) { return $null }
    $ip = Get-AdapterIPv4 $best.InterfaceAlias
    if (-not $ip) { return $null }
    [pscustomobject]@{ IfIndex = $best.ifIndex; Alias = $best.InterfaceAlias; Gateway = $best.NextHop; Ip = $ip }
}

# что проверять: сайты из настроек + загрузка страницы целиком (провайдеры обрывают TLS после ~16 КБ)
# + видеосервер YouTube (rr*---sn-*.googlevideo.com — с него идёт само видео; сайт может открываться, а видео нет)
function Get-ZTargets {
    $z = Get-ZCfg
    $t = @(@($z.testTargets) | Where-Object { $_ })
    if ($z.videoCheck -ne $false) {
        if ($t -notcontains 'ytspeed') { $t += 'ytspeed' }
        if ($t -notcontains 'ytvideo') { $t += 'ytvideo' }
    }
    return $t
}

function Get-ZTargetLabel([string]$Spec) {
    switch -regex ($Spec) {
        '^ytvideo$'                 { return 'YouTube: видео (googlevideo)' }
        '^ytspeed$'                 { return 'YouTube: скорость загрузки' }
        '^get\s.*youtube\.com'      { return 'YouTube: загрузка страницы' }
        'redirector\.googlevideo'   { return 'YouTube: выбор видеосервера' }
        'ytimg\.com'                { return 'YouTube: превью' }
        'youtube\.com|youtu\.be'    { return 'YouTube: сайт' }
        'gateway\.discord'          { return 'Discord: чат (gateway)' }
        'cdn\.discordapp|discordcdn' { return 'Discord: файлы (CDN)' }
        'discord'                   { return 'Discord: сайт' }
    }
    return (($Spec -replace '^get\s+', '') -replace '^https?://', '' -replace '/.*$', '')
}

# почему curl не открыл сайт — понятными словами
function Get-CurlReason([int]$Exit, [string]$Code, [long]$Size, [long]$Min, [int]$Ms = 0) {
    if ($Exit -eq 0 -and $Min -and $Size -lt $Min) { return ('получено только {0:N0} КБ — загрузка обрывается' -f ($Size / 1KB)) }
    if ($Exit -eq 0 -and $Code -notmatch '^[1-5]\d\d$') { return 'нет HTTP-ответа' }
    if ($Exit -eq 0) { return '' }
    # застряло на ~16–40 КБ — типичный обрыв DPI; больше — данные идут, но медленно (замедление)
    if ($Exit -eq 28 -and $Size -gt 0 -and $Size -lt 40KB) { return ('оборвалось после {0:N0} КБ — DPI режет загрузку' -f ($Size / 1KB)) }
    if ($Exit -eq 28 -and $Size -gt 0) { return ('медленно: {0:N0} КБ за {1:N0} с (≈{2:N0} КБ/с) — похоже на замедление' -f ($Size / 1KB), ([Math]::Max(1, $Ms) / 1000), ($Size / 1KB / [Math]::Max(1, $Ms / 1000))) }
    switch ($Exit) {
        6  { return 'не найден адрес (DNS)' }
        7  { return 'нет соединения' }
        18 { return 'передача оборвалась' }
        28 { return 'таймаут — похоже на блокировку' }
        35 { return 'сброс при TLS-рукопожатии (DPI)' }
        52 { return 'пустой ответ' }
        56 { return 'соединение сброшено (DPI)' }
        60 { return 'чужой сертификат — заглушка провайдера' }
        -1 { return 'curl не завершился' }
        -2 { return 'не удалось узнать адрес видеосервера' }
    }
    return "ошибка curl $Exit"
}

# адрес видеосервера YouTube (узел rr1---sn-….googlevideo.com) для этого провайдера; кэш 6 ч
function Find-ZVideoHost([string]$SrcIp, [int]$TimeoutSec = 8, [switch]$PhysOnly) {
    $curl = Join-Path $env:windir 'System32\curl.exe'
    $vias = @($SrcIp); if ($SrcIp -and -not $PhysOnly) { $vias += '' }      # сначала напрямую, потом как получится (через VPN)
    foreach ($via in $vias) {
        $ifa = $(if ($via) { "--interface $via " } else { '' })
        $r = Invoke-Exe $curl ('-s --connect-timeout 4 -m ' + $TimeoutSec + ' ' + $ifa + '"https://redirector.googlevideo.com/report_mapping?di=no"') ($TimeoutSec + 5)
        $mt = [regex]::Match("$($r.Out)", '\b(sn-[a-z0-9-]{4,})')
        if ($mt.Success) { $script:ZVideoVia = $(if ($via) { 'direct' } else { 'vpn' }); return "rr1---$($mt.Groups[1].Value).googlevideo.com" }
        $r = Invoke-Exe $curl ('-s -L --connect-timeout 4 -m ' + ($TimeoutSec + 7) + ' ' + $ifa + '-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "https://www.youtube.com/watch?v=jNQXAC9IVRw"') ($TimeoutSec + 12)
        $mt = [regex]::Match("$($r.Out)", 'rr\d{1,2}---(sn-[a-z0-9-]{4,})\.googlevideo\.com')
        if ($mt.Success) { $script:ZVideoVia = $(if ($via) { 'direct' } else { 'vpn' }); return "rr1---$($mt.Groups[1].Value).googlevideo.com" }
    }
    return ''
}
function Get-ZVideoHost([string]$SrcIp, [int]$TimeoutSec = 8) {
    $at = [datetime]::MinValue; try { $at = [datetime]$ZState.videoHostAt } catch { }
    # найденный через VPN — чужой (зарубежный) сервер; раз в 30 мин пробуем узнать настоящий, напрямую
    $fresh = $(if ("$($ZState.videoHostVia)" -eq 'vpn') { ((Get-Date) - $at).TotalMinutes -lt 30 } else { ((Get-Date) - $at).TotalHours -lt 6 })
    if ($ZState.videoHost -and $fresh) { return "$($ZState.videoHost)" }
    # не нашли недавно — не искать снова при каждой проверке (поиск при блокировке занимает до минуты)
    if ($script:ZVideoMissAt -and ((Get-Date) - $script:ZVideoMissAt).TotalMinutes -lt 30) { return "$($ZState.videoHost)" }
    $h = Find-ZVideoHost $SrcIp $TimeoutSec
    if ($h) {
        if ($script:ZVideoVia -eq 'vpn' -and "$($ZState.videoHostVia)" -eq 'direct' -and $ZState.videoHost) { $ZState.videoHostAt = Get-Date; return "$($ZState.videoHost)" }   # прямой лучше
        if ($script:ZVideoVia -eq 'direct' -and "$($ZState.videoHost)" -ne $h) { $ZState.lastRouteRefresh = [datetime]::MinValue }   # новый сервер провайдера — сразу добавить маршруты
        $ZState.videoHost = $h; $ZState.videoHostAt = Get-Date; $ZState.videoHostVia = $script:ZVideoVia; $script:ZVideoMissAt = $null; return $h
    }
    $script:ZVideoMissAt = Get-Date
    return "$($ZState.videoHost)"      # не узнали — старый адрес лучше, чем ничего
}

# большой статический файл с www.youtube.com (плеер base.js, 2–3 МБ): по его скорости видно замедление YouTube
function Get-ZYtSpeedUrl([string]$SrcIp) {
    $at = [datetime]::MinValue; try { $at = [datetime]$ZState.ytJsAt } catch { }
    if ($ZState.ytJs -and ((Get-Date) - $at).TotalHours -lt 6) { return "$($ZState.ytJs)" }
    $curl = Join-Path $env:windir 'System32\curl.exe'
    $ifa = $(if ($SrcIp) { "--interface $SrcIp " } else { '' })
    $r = Invoke-Exe $curl ('-s -L --compressed --connect-timeout 4 -m 15 ' + $ifa + '-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36" "https://www.youtube.com/"') 20
    $mt = [regex]::Match("$($r.Out)", '/s/player/[A-Za-z0-9_\-]+/[A-Za-z0-9_\.\-]+/[A-Za-z_]+/base\.js')
    if ($mt.Success) { $ZState.ytJs = "https://www.youtube.com$($mt.Value)"; $ZState.ytJsAt = (Get-Date).ToString('o'); return "$($ZState.ytJs)" }
    return "$($ZState.ytJs)"
}

# параллельно проверить сайты curl'ом с привязкой к IP физического адаптера (мимо VPN)
# цель: URL (HEAD-запрос) · 'get URL' (скачать целиком, нужно ≥ 64 КБ) · 'ytvideo' (видеосервер YouTube)
function Test-ZapretTargets([string]$SrcIp, [string[]]$Urls, [int]$TimeoutSec = 5) {
    $curl = Join-Path $env:windir 'System32\curl.exe'
    # адрес видеосервера — заранее, чтобы не задерживать остальные проверки
    $vh = $(if ($Urls -contains 'ytvideo') { Get-ZVideoHost $SrcIp ([Math]::Max(6, $TimeoutSec)) } else { '' })
    $ys = $(if ($Urls -contains 'ytspeed') { Get-ZYtSpeedUrl $SrcIp } else { '' })
    $jobs = foreach ($spec in $Urls) {
        $u = $spec; $get = $false
        if ($spec -eq 'ytvideo') {
            $h = $vh
            if (-not $h) { [pscustomobject]@{ Url = $spec; U = ''; Get = $false; P = $null; Sw = $null }; continue }
            $u = "https://$h/generate_204"
        } elseif ($spec -eq 'ytspeed') {
            if (-not $ys) { [pscustomobject]@{ Url = $spec; U = ''; Get = $false; P = $null; Sw = $null }; continue }
            $u = $ys; $get = $true
        } elseif ($spec -match '^get\s+(\S+)') { $u = $Matches[1]; $get = $true }
        $psi = New-Object Diagnostics.ProcessStartInfo $curl
        $mode = $(if ($get) { '-L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"' } else { '-I' })
        $tmo = $(if ($get) { $TimeoutSec + 5 } else { $TimeoutSec })
        $ifa = $(if ($SrcIp) { " --interface $SrcIp" } else { '' })
        $psi.Arguments = $mode + ' -s -o NUL -w "%{http_code} %{size_download} %{time_total} %{time_connect} %{time_appconnect}" -m ' + $tmo + ' --connect-timeout 3' + $ifa + ' "' + $u + '"'
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        [pscustomobject]@{ Url = $spec; U = $u; Get = $get; P = [Diagnostics.Process]::Start($psi); Sw = [Diagnostics.Stopwatch]::StartNew() }
    }
    foreach ($j in $jobs) {
        if (-not $j.P) { continue }
        $lim = $(if ($j.Get) { $TimeoutSec + 8 } else { $TimeoutSec + 3 })
        if (-not $j.P.WaitForExit([int][Math]::Max(500, $lim * 1000 - $j.Sw.ElapsedMilliseconds))) { try { $j.P.Kill() } catch { } }
    }
    foreach ($j in $jobs) {
        $lbl = Get-ZTargetLabel $j.Url
        if (-not $j.P) { [pscustomobject]@{ Url = $j.Url; Label = $lbl; Ok = $false; Code = ''; Exit = -2; Why = $(if ($j.Url -eq 'ytspeed') { 'не удалось открыть www.youtube.com' } else { (Get-CurlReason -2 '' 0 0) }); Kb = 0; Ms = -1; Host = ''; Mbit = 0 }; continue }
        $out = ''; try { $out = $j.P.StandardOutput.ReadToEnd().Trim() } catch { }
        $exit = $(if ($j.P.HasExited) { $j.P.ExitCode } else { -1 })
        $pp = @($out -split '\s+'); $code = "$($pp[0])"; $size = 0L; if ($pp.Count -gt 1) { [void][long]::TryParse($pp[1], [ref]$size) }
        $tt = 0.0; if ($pp.Count -gt 2) { [void][double]::TryParse($pp[2], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$tt) }
        $tc = 0.0; $ta = 0.0
        if ($pp.Count -gt 4) { [void][double]::TryParse($pp[3], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$tc); [void][double]::TryParse($pp[4], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$ta) }
        $ms = $(if ($tt -gt 0) { [int]($tt * 1000) } else { [int]$j.Sw.ElapsedMilliseconds })
        $min = $(if ($j.Get) { 65536 } else { 0 })
        $why = Get-CurlReason $exit $code $size $min $ms
        # скорость YouTube: нужно ≥ 1,5 Мбит/с (видео 480p); показываем замер всегда
        $mbit = 0.0
        if ($j.Url -eq 'ytspeed' -and $size -gt 0) {
            $mbit = [Math]::Round($size * 8 / 1e6 / [Math]::Max(0.2, $ms / 1000), 1)
            if ($exit -in 0, 28) { $why = $(if ($mbit -ge 1.5) { '' } else { "≈$mbit Мбит/с — мало для видео (замедление)" }) }
        }
        # таймаут: на каком этапе застряло
        if ($exit -eq 28 -and $size -eq 0 -and $pp.Count -gt 4) {
            if ($tc -eq 0) { $why = 'не соединяется — адрес недоступен или заблокирован' }
            elseif ($ta -eq 0 -and $j.U -like 'https:*') { $why = 'зависает TLS-рукопожатие — блокировка по имени сайта (DPI)' }
            else { $why = 'сервер не ответил — таймаут после соединения' }
        }
        [pscustomobject]@{ Url = $j.Url; Label = $lbl; Ok = (-not $why); Code = $code; Exit = $exit; Why = $why
            Kb = [int]($size / 1KB); Ms = $ms; Host = ([uri]$j.U).Host; Mbit = $mbit }
    }
}

# компактная запись результатов проверки (для окна)
function ConvertTo-ZChecks($Results) {
    @(foreach ($r in @($Results)) { [ordered]@{ n = "$($r.Label)"; ok = [bool]$r.Ok; why = "$($r.Why)"; ms = [int]$r.Ms; h = "$($r.Host)"; kb = [int]$r.Kb; mbit = [double]$r.Mbit } })
}

function Get-ZapretTestRunner {
    if (-not (Test-Path $ZTestPath)) { return $null }
    try { $t = Get-Content $ZTestPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
    if ($t.running -and $t.pid -and (Get-Process -Id ([int]$t.pid) -ErrorAction SilentlyContinue)) { return $t }
    return $null
}

# запуск подбора в отдельном процессе — агент продолжает следить за VPN
function Start-ZapretTest([string]$Reason) {
    if (Get-ZapretTestRunner) { return }
    if (-not (Test-ZapretInstalled)) { Write-Log 'zapret: не установлен — подбирать нечего' 'WARN'; return }
    Write-Log "zapret: запускаю подбор стратегии ($Reason)"
    $p = Start-Process powershell.exe -WindowStyle Hidden -WorkingDirectory $Root -PassThru `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $Root 'VpnGuard.ps1')`" -ZapretTest"
    @{ running = $true; pid = $p.Id; started = (Get-Date).ToString('o'); index = 0; total = 0; current = ''; results = @() } |
        ConvertTo-Json -Depth 5 | Set-Content $ZTestPath -Encoding UTF8
    $ZState.winwsPid = 0
}

# тело процесса подбора (VpnGuard.ps1 -ZapretTest)
function Invoke-ZapretTestRun {
    $z = Get-ZCfg
    $path = Get-PhysicalPath
    $prog = [ordered]@{ running = $true; pid = $PID; started = (Get-Date).ToString('o'); index = 0; total = 0; current = ''; results = @(); best = ''; error = '' }
    $write = { $prog | ConvertTo-Json -Depth 8 | Set-Content $ZTestPath -Encoding UTF8 }
    try {
        if (-not $path) { throw 'не найден физический адаптер с выходом в интернет' }
        $names = @(Get-ZapretStrategies)
        if (-not $names.Count) { throw 'нет файлов general*.bat' }
        $urls = @(Get-ZTargets)
        $prog.total = $names.Count + 1
        Stop-ZapretService
        Stop-Winws
        $res = New-Object System.Collections.ArrayList
        # адрес видеосервера узнать заново (через VPN, если напрямую закрыт)
        if ($urls -contains 'ytvideo') { $ZState.videoHost = ''; $ZState.videoHost = Find-ZVideoHost $path.Ip 8; if ($ZState.videoHost) { $ZState.videoHostAt = Get-Date; $ZState.videoHostVia = $script:ZVideoVia } else { $script:ZVideoMissAt = Get-Date } }
        $prog.videoHost = "$($ZState.videoHost)"; $prog.videoHostVia = "$($ZState.videoHostVia)"

        # без zapret: понять, блокирует ли провайдер вообще
        $prog.index = 1; $prog.current = '(без zapret)'; & $write
        $base = @(Test-ZapretTargets $path.Ip $urls ([int]$z.curlTimeoutSec))
        [void]$res.Add([ordered]@{ name = '(без zapret)'; ok = @($base | Where-Object Ok).Count; total = $urls.Count
            failed = @($base | Where-Object { -not $_.Ok } | ForEach-Object { $_.Label }); checks = @(ConvertTo-ZChecks $base); ms = 0 })

        $i = 1
        foreach ($n in $names) {
            $i++; $prog.index = $i; $prog.current = $n; $prog.results = @($res); & $write
            $ok = 0; $failed = @(); $err = ''; $checks = @(); $ms = 0
            try {
                [void](Start-Winws $n)
                Start-Sleep -Milliseconds 800
                $r = @(Test-ZapretTargets $path.Ip $urls ([int]$z.curlTimeoutSec))
                # адрес видеосервера до сих пор неизвестен, а YouTube с этой стратегией открылся — узнать его напрямую и проверить видео
                if (-not $ZState.videoHost -and ($urls -contains 'ytvideo') -and @($r | Where-Object { ($_.Ok -or $_.Kb -gt 0) -and $_.Label -like 'YouTube*' -and $_.Url -notin 'ytvideo', 'ytspeed' }).Count) {
                    $vh = Find-ZVideoHost $path.Ip 6 -PhysOnly
                    if ($vh) {
                        $ZState.videoHost = $vh; $ZState.videoHostAt = Get-Date; $ZState.videoHostVia = 'direct'; $prog.videoHost = $vh; $prog.videoHostVia = 'direct'
                        $v = @(Test-ZapretTargets $path.Ip @('ytvideo') ([int]$z.curlTimeoutSec))
                        $r = @(@($r | Where-Object { $_.Url -ne 'ytvideo' }) + $v)
                        foreach ($row in $res) { foreach ($c in @($row.checks)) { if ($c.n -like '*видео*' -and -not $c.ok) { $c.why = 'не проверено — адрес видеосервера узнан позже' } } }
                    }
                }
                $ok = @($r | Where-Object Ok).Count
                $failed = @($r | Where-Object { -not $_.Ok } | ForEach-Object { $_.Label })
                $checks = @(ConvertTo-ZChecks $r)
                $ms = [int](@($r | Where-Object Ok | ForEach-Object { $_.Ms }) | Measure-Object -Sum).Sum
            } catch { $err = $_.Exception.Message }
            Stop-Winws
            [void]$res.Add([ordered]@{ name = $n; ok = $ok; total = $urls.Count; failed = $failed; error = $err; checks = $checks; ms = $ms })
        }
        $prog.results = @($res)
        # лучшая: больше всего открытых сайтов; при равенстве — где работает видео, затем быстрее
        $bestRow = $res | Where-Object { $_.name -ne '(без zapret)' } | Sort-Object @{ e = { $_.ok }; Descending = $true },
            @{ e = { [int](@($_.checks | Where-Object { $_.n -like '*видео*' -and $_.ok }).Count) }; Descending = $true },
            @{ e = { [double](@($_.checks | Where-Object { $_.n -like '*скорость*' -or $_.n -like '*загрузка страницы*' } | ForEach-Object { if ($_.mbit) { $_.mbit * 1000 } else { $_.kb } }) | Measure-Object -Sum).Sum }; Descending = $true }, @{ e = { $_.ms } } | Select-Object -First 1
        $prog.best = $(if ($bestRow -and $bestRow.ok -gt 0) { $bestRow.name } else { '' })
    } catch {
        $prog.error = $_.Exception.Message
    } finally {
        Stop-Winws
        $prog.running = $false; $prog.finished = (Get-Date).ToString('o')
        & $write
    }
}

# забрать результат подбора, когда процесс закончил
function Receive-ZapretTest {
    if (-not (Test-Path $ZTestPath)) { return $false }
    try { $t = Get-Content $ZTestPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $false }
    if ($t.running) {
        if ($t.pid -and -not (Get-Process -Id ([int]$t.pid) -ErrorAction SilentlyContinue)) {
            Write-Log 'zapret: процесс подбора завершился аварийно' 'ERROR'
            $t.running = $false; $t.error = 'процесс подбора завершился аварийно'
        } else { return $false }
    }
    if ($t.PSObject.Properties['consumed'] -and $t.consumed) { return $false }
    $t | Add-Member -NotePropertyName consumed -NotePropertyValue $true -Force
    $t | ConvertTo-Json -Depth 8 | Set-Content $ZTestPath -Encoding UTF8

    $ZState.lastTest = Get-Date
    $ZState.results = @($t.results | ForEach-Object { [ordered]@{ name = $_.name; ok = $_.ok; total = $_.total; error = "$($_.error)"; checks = @($_.checks | Where-Object { $_ }) } })
    if ($t.PSObject.Properties['videoHost'] -and $t.videoHost) { $ZState.videoHost = "$($t.videoHost)"; $ZState.videoHostAt = Get-Date; $ZState.videoHostVia = $(if ($t.PSObject.Properties['videoHostVia']) { "$($t.videoHostVia)" } else { '' }) }
    if ($t.error) {
        $ZState.lastError = "подбор: $($t.error)"
        Write-Log "zapret: подбор не удался: $($t.error)" 'ERROR'
    } elseif ($t.best) {
        $row = $t.results | Where-Object { $_.name -eq $t.best } | Select-Object -First 1
        $ZState.strategy = $t.best; $ZState.lastScore = [int]$row.ok; $ZState.lastTotal = [int]$row.total
        $ZState.fallbackUntil = [datetime]::MinValue; $ZState.healthFails = 0; $ZState.lastError = ''
        Write-Log ("zapret: лучшая стратегия — '{0}' ({1}/{2} сайтов)" -f $t.best, $row.ok, $row.total)
    } else {
        $ZState.strategy = ''; $ZState.lastScore = 0
        $ZState.fallbackUntil = (Get-Date).AddHours(2)
        $ZState.lastError = 'ни одна стратегия не открыла сайты'
        Write-Log 'zapret: ни одна стратегия не сработала — YouTube/Discord остаются в VPN, повторю через 2 ч' 'WARN'
    }
    Save-ZState
    return $true
}

# ---------------------------------------------------------------- маршруты мимо VPN

function Get-GoogleRanges {
    $fresh = (Test-Path $ZGooglePath) -and ((Get-Date) - (Get-Item $ZGooglePath).LastWriteTime).TotalHours -lt 24
    if (-not $fresh) {
        try {
            $j = Invoke-RestMethod 'https://www.gstatic.com/ipranges/goog.json' -TimeoutSec 20 -UseBasicParsing
            @($j.prefixes | Where-Object { $_.ipv4Prefix } | ForEach-Object { $_.ipv4Prefix }) | ConvertTo-Json | Set-Content $ZGooglePath -Encoding UTF8
        } catch { Write-Log "zapret: не удалось обновить диапазоны Google: $($_.Exception.Message)" 'WARN' }
    }
    # ConvertFrom-Json в PS 5.1 отдаёт JSON-массив одним объектом — разворачиваем поэлементно
    if (Test-Path $ZGooglePath) { return @((Get-Content $ZGooglePath -Raw | ConvertFrom-Json) | ForEach-Object { "$_" } | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+/\d+$' }) }
    return @()
}

function Get-ZapretRouteDomains {
    $z = Get-ZCfg
    $d = New-Object System.Collections.Generic.HashSet[string]
    foreach ($x in @($z.routeDomains)) { if ($x) { [void]$d.Add($x.Trim().TrimStart('^')) } }
    $lists = Join-Path (Get-ZapretDir) 'lists'
    # свой список доменов (из окна) тоже должен идти мимо VPN, иначе zapret его не увидит
    foreach ($f in @($z.routeDomainLists) + @('list-general-user.txt') | Select-Object -Unique) {
        $p = Join-Path $lists $f
        if (Test-Path $p) {
            Get-Content $p | ForEach-Object { $l = $_.Trim().TrimStart('^'); if ($l -and -not $l.StartsWith('#') -and $l -ne 'domain.example.abc') { [void]$d.Add($l) } }
        }
    }
    @($d)
}

# кэш-серверы YouTube у провайдера (rrN---sn-XXXX.googlevideo.com): их адреса — в сети провайдера, не в диапазонах Google.
# Без маршрута к ним видео в режиме с VPN уходит в туннель и не грузится (кэш отвечает только своим абонентам).
function Get-ZGgcPrefixes {
    $vh = "$($ZState.videoHost)"
    if (-not $vh -or "$($ZState.videoHostVia)" -ne 'direct') { return @($ZState.ggc | Where-Object { $_ }) }
    $cl = $vh -replace '^rr\d+---', ''
    $set = New-Object System.Collections.Generic.HashSet[string]
    foreach ($i in 1..20) {
        try {
            Resolve-DnsName -Name "rr$i---$cl" -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } |
                ForEach-Object { $o = $_.IPAddress -split '\.'; [void]$set.Add("$($o[0]).$($o[1]).$($o[2]).0/24") }
        } catch { }
    }
    $google = @(Get-GoogleRanges)
    $list = @($set | Where-Object { $_ })
    if ($list.Count) {
        $new = @($list | Where-Object { @($ZState.ggc) -notcontains $_ })
        if ($new.Count) { Write-Log "zapret: видеосерверы YouTube у провайдера ($cl): $($list -join ', ') — пускаю мимо VPN" }
        $ZState.ggc = $list
    }
    return @($ZState.ggc | Where-Object { $_ })
}

function Get-ZapretPrefixes {
    $z = Get-ZCfg
    $set = New-Object System.Collections.Generic.HashSet[string]
    if ($z.routeGoogleRanges) { foreach ($p in Get-GoogleRanges) { [void]$set.Add($p) } }
    if ($z.routeGoogleRanges -and $z.routeIspVideo -ne $false) { foreach ($p in Get-ZGgcPrefixes) { [void]$set.Add($p) } }
    foreach ($dom in Get-ZapretRouteDomains) {
        try {
            Resolve-DnsName -Name $dom -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                Where-Object { $_.Type -eq 'A' } | ForEach-Object { [void]$set.Add("$($_.IPAddress)/32") }
        } catch { }
    }
    # старые записи /32 оставляем (IP у CDN меняются, а маршрут лишним не будет)
    foreach ($r in @($ZState.routes)) { if ($r.p -like '*/32') { [void]$set.Add($r.p) } }
    foreach ($n in $ZNeverRoute) { [void]$set.Remove($n) }
    $list = @($set | Where-Object { $_ -notmatch '^(8\.8\.8\.|8\.8\.4\.)' })
    if ($list.Count -gt [int]$z.maxRoutes) { $list = $list[0..([int]$z.maxRoutes - 1)] }
    return $list
}

function Remove-ZapretRoutes {
    $n = 0
    foreach ($r in @($ZState.routes)) {
        Remove-NetRoute -DestinationPrefix $r.p -InterfaceIndex ([int]$r.i) -NextHop $r.g -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
        $n++
    }
    if ($n) { Write-Log "zapret: убрано $n маршрутов — YouTube/Discord снова через VPN" }
    $ZState.routes = @()
    Save-ZState
}

function Sync-ZapretRoutes([switch]$Refresh) {
    # без VPN весь трафик и так идёт напрямую — отдельные маршруты не нужны
    if (Test-ZDirect) { if (@($ZState.routes).Count) { Remove-ZapretRoutes }; return }
    $path = Get-PhysicalPath
    if (-not $path) { Write-Log 'zapret: нет физического выхода в интернет — маршруты не ставлю' 'WARN'; return }
    $routes = @($ZState.routes)
    # сменился адаптер или шлюз — убрать старые маршруты
    if ($routes.Count -and ($routes | Where-Object { [int]$_.i -ne $path.IfIndex -or $_.g -ne $path.Gateway })) {
        Write-Log "zapret: сменился выход в интернет ($($path.Alias) через $($path.Gateway)) — переставляю маршруты"
        Remove-ZapretRoutes; $routes = @(); $Refresh = $true
    }
    $needRefresh = $Refresh -or -not $routes.Count -or ((Get-Date) - $ZState.lastRouteRefresh).TotalMinutes -ge 30
    $want = $(if ($needRefresh) { Get-ZapretPrefixes } else { @($routes | ForEach-Object { $_.p }) })
    if ($needRefresh) { $ZState.lastRouteRefresh = Get-Date }

    $have = @{}
    Get-NetRoute -InterfaceIndex $path.IfIndex -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        ForEach-Object { $have[$_.DestinationPrefix] = $true }
    $added = 0
    foreach ($p in $want) {
        if ($have.ContainsKey($p)) { continue }
        try {
            New-NetRoute -DestinationPrefix $p -InterfaceIndex $path.IfIndex -NextHop $path.Gateway -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
            $added++
        } catch { }
    }
    $wantSet = New-Object System.Collections.Generic.HashSet[string] (, [string[]]$want)
    foreach ($r in $routes) {
        if (-not $wantSet.Contains($r.p)) { Remove-NetRoute -DestinationPrefix $r.p -InterfaceIndex ([int]$r.i) -NextHop $r.g -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue }
    }
    $ZState.routes = @($want | ForEach-Object { [ordered]@{ p = $_; i = $path.IfIndex; g = $path.Gateway } })
    if ($added) { Write-Log "zapret: добавлено $added маршрутов мимо VPN через $($path.Alias) (всего $($want.Count))" }
    Save-ZState
}

# ---------------------------------------------------------------- включение / выключение / наблюдение

function Set-ZapretEnabled([bool]$On) {
    Set-ConfigValue 'zapret.enabled' $On
    if ($On) {
        Write-Log 'zapret: включён из окна'
        $ZState.fallbackUntil = [datetime]::MinValue
        Save-ZState
    } else {
        Write-Log 'zapret: выключен из окна'
        Disable-ZapretNow
    }
}

function Disable-ZapretNow {
    # идёт подбор — остановить и его
    $t = Get-ZapretTestRunner
    if ($t) {
        Stop-Process -Id ([int]$t.pid) -Force -ErrorAction SilentlyContinue
        @{ running = $false; consumed = $true; error = 'подбор прерван: zapret выключен' } | ConvertTo-Json | Set-Content $ZTestPath -Encoding UTF8
        Write-Log 'zapret: подбор стратегии прерван'
    }
    if (@($ZState.routes).Count) { Remove-ZapretRoutes }
    if ($ZState.winwsPid -or (Get-WinwsProcs)) { Stop-Winws; Write-Log 'zapret: winws остановлен' }
    Save-ZState
}

function Invoke-ZapretWatch {
    $z = Get-ZCfg
    if (-not $z) { return }
    $finished = Receive-ZapretTest
    try { [void](Get-ZapretReleases) } catch { }        # список версий для выбора — раз в 12 ч
    if (Get-ZapretTestRunner) { return }                 # идёт подбор — winws и маршруты не трогаем

    # ставим/обновляем, если включён; если выключен, но уже установлен — только обновляем
    if ($z.enabled -or ($z.autoUpdate -and (Test-ZapretInstalled))) { Invoke-ZapretUpdate }
    if (-not $z.enabled) {
        if (@($ZState.routes).Count -or $ZState.winwsPid) { Disable-ZapretNow }
        # winws, запущенный не нами (старая копия VpnGuard, service.bat, вручную): при выключенном zapret
        # он всё равно меняет трафик YouTube/Discord — в том числе через туннель — и путает проверки
        $foreign = @(Get-CimInstance Win32_Process -Filter "Name='winws.exe'" -ErrorAction SilentlyContinue)
        if ($foreign.Count) {
            foreach ($wc in $foreign) { Write-Log "zapret выключен, но работает чужой winws (PID $($wc.ProcessId), $($wc.ExecutablePath)) — останавливаю" 'WARN' }
            Stop-ZapretService
            Stop-Winws
        }
        return
    }
    if (-not (Test-ZapretInstalled)) { $ZState.lastError = 'zapret не установлен (нет доступа к GitHub?)'; return }

    # «нет рабочей стратегии» — ждём, трафик в VPN
    if ($ZState.fallbackUntil -gt (Get-Date)) {
        if (@($ZState.routes).Count -or $ZState.winwsPid) { Disable-ZapretNow }
        return
    }
    if ($ZState.fallbackUntil -ne [datetime]::MinValue -and $ZState.fallbackUntil -le (Get-Date)) {
        $ZState.fallbackUntil = [datetime]::MinValue; Start-ZapretTest 'повтор после неудачного подбора'; return
    }

    # какая стратегия: вручную из настроек или подобранная
    $strategy = $(if ($z.strategy) { $z.strategy } else { $ZState.strategy })
    $stale = ((Get-Date) - $ZState.lastTest).TotalHours -ge [double]$z.retestHours
    if (-not $z.strategy -and (-not $strategy -or $stale)) {
        Start-ZapretTest $(if (-not $strategy) { 'стратегия ещё не выбрана' } else { "прошло больше $($z.retestHours) ч" })
        return
    }
    if (-not (Get-ZapretStrategies | Where-Object { $_ -eq $strategy })) {
        $ZState.lastError = "стратегия '$strategy' не найдена"
        if ($z.strategy) { return } else { $ZState.strategy = ''; Start-ZapretTest 'стратегия пропала после обновления'; return }
    }

    # winws должен работать с нужной стратегией
    $p = $null
    if ($ZState.winwsPid) { $p = Get-Process -Id $ZState.winwsPid -ErrorAction SilentlyContinue; if ($p -and $p.ProcessName -ne 'winws') { $p = $null } }
    if (-not $p -or $ZState.runningStrategy -ne $strategy) {
        Stop-ZapretService
        Stop-Winws
        try {
            Set-Activity "запускаю zapret ($strategy)"
            [void](Start-Winws $strategy)
            $ZState.runningStrategy = $strategy
            $ZState.lastError = ''
            $ZState.healthAt = [datetime]::MinValue      # сразу проверить сайты с новой стратегией
            Write-Log "zapret: winws запущен со стратегией '$strategy' (PID $($ZState.winwsPid))"
        } catch {
            $ZState.lastError = $_.Exception.Message
            Write-Log "zapret: $($_.Exception.Message)" 'ERROR'
            Save-ZState
            return
        }
    }

    Sync-ZapretRoutes

    # проверка, что сайты открываются
    if (((Get-Date) - $ZState.healthAt).TotalMinutes -ge [double]$z.healthCheckMin) {
        $path = Get-PhysicalPath
        if ($path) {
            $r = @(Test-ZapretTargets $path.Ip @(Get-ZTargets) ([int]$z.curlTimeoutSec))
            $ZState.healthAt = Get-Date
            $ZState.healthOk = @($r | Where-Object Ok).Count
            $ZState.healthTotal = $r.Count
            $ZState.healthChecks = @(ConvertTo-ZChecks $r)
            $minOk = [Math]::Max(1, [Math]::Min([int]$ZState.lastScore, $r.Count) - 1)
            $bad = @($r | Where-Object { -not $_.Ok })
            $badSig = ($bad | ForEach-Object { $_.Label }) -join '|'
            if ($bad.Count -and ($badSig -ne $script:ZBadSig -or $ZState.healthOk -lt $minOk)) {
                Write-Log ("zapret: не прошли проверку: {0}" -f (($bad | ForEach-Object { "$($_.Label) — $($_.Why)" }) -join '; ')) $(if ($ZState.healthOk -lt $minOk) { 'WARN' } else { 'INFO' })
            } elseif (-not $bad.Count -and $script:ZBadSig) { Write-Log 'zapret: все проверки снова проходят' }
            $script:ZBadSig = $badSig
            if ($ZState.healthOk -lt $minOk) {
                $ZState.healthFails++
                Write-Log ("zapret: открылось {0}/{1} сайтов" -f $ZState.healthOk, $r.Count) 'WARN'
                if ($ZState.healthFails -ge 2 -and -not $z.strategy) { $ZState.healthFails = 0; Start-ZapretTest 'стратегия перестала работать' }
            } else { $ZState.healthFails = 0 }
        }
    }
    Save-ZState
}

# ---------------------------------------------------------------- для окна и диагностики

# списки изменили в окне: перезапустить winws (он читает списки при старте) и пересчитать маршруты
function Invoke-ZapretReload {
    $z = Get-ZCfg
    if (-not $z.enabled) { Write-Log 'zapret: списки сохранены — применятся при включении zapret'; return }
    Set-Activity 'zapret: применяю списки'
    $name = $ZState.runningStrategy
    if ($name) {
        Stop-Winws; Start-Sleep -Milliseconds 500
        try { [void](Start-Winws $name); $ZState.runningStrategy = $name } catch { Write-Log "zapret: перезапуск winws: $($_.Exception.Message)" 'ERROR' }
    }
    try { Sync-ZapretRoutes -Refresh } catch { Write-Log "zapret: маршруты: $($_.Exception.Message)" 'ERROR' }
    Save-ZState
    Write-Log 'zapret: списки применены — winws перезапущен, маршруты пересчитаны'
}

# сколько TCP-соединений этого ПК сейчас идёт по маршрутам zapret (мимо VPN) — .NET, без WMI
$script:ZNetCache = @{ Key = ''; Hosts = $null; Nets = $null }
function ConvertTo-ZIp([byte[]]$b) { ([long]$b[0] -shl 24) -bor ([long]$b[1] -shl 16) -bor ([long]$b[2] -shl 8) -bor [long]$b[3] }
function Get-ZapretConnCount {
    $routes = @($ZState.routes)
    if (-not $routes.Count) { return 0 }
    $key = "$($routes.Count)|$($ZState.lastRouteRefresh)"
    if ($script:ZNetCache.Key -ne $key) {
        $hosts = New-Object 'Collections.Generic.HashSet[long]'; $nets = New-Object Collections.ArrayList
        foreach ($r in $routes) {
            $pp = "$($r.p)" -split '/'
            try { $v = ConvertTo-ZIp ([Net.IPAddress]::Parse($pp[0]).GetAddressBytes()) } catch { continue }
            $len = [int]$pp[1]
            if ($len -ge 32) { [void]$hosts.Add($v) }
            else { $mt = (0xFFFFFFFFL -shl (32 - $len)) -band 0xFFFFFFFFL; [void]$nets.Add(@(($v -band $mt), $mt)) }
        }
        $script:ZNetCache = @{ Key = $key; Hosts = $hosts; Nets = $nets }
    }
    $n = 0
    foreach ($c in [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpConnections()) {
        if ($c.State -ne 'Established') { continue }
        $a = $c.RemoteEndPoint.Address
        if ($a.IsIPv4MappedToIPv6) { $a = $a.MapToIPv4() }
        if ($a.AddressFamily -ne 'InterNetwork') { continue }
        $v = ConvertTo-ZIp $a.GetAddressBytes()
        if ($script:ZNetCache.Hosts.Contains($v)) { $n++; continue }
        foreach ($nt in $script:ZNetCache.Nets) { if (($v -band $nt[1]) -eq $nt[0]) { $n++; break } }
    }
    return $n
}

function Get-ZapretSnapshot {
    $z = Get-ZCfg
    $t = Get-ZapretTestRunner
    $inst = Test-ZapretInstalled
    $strategy = $(if ($z.strategy) { $z.strategy } else { $ZState.strategy })
    $winws = $ZState.winwsPid -and (Get-Process -Id $ZState.winwsPid -ErrorAction SilentlyContinue)
    if ($t)                                         { $lv = 1; $st = "Подбор стратегии $($t.index)/$($t.total)" }
    elseif (-not $z.enabled)                        { $lv = -1; $st = 'Выключен' }
    elseif (-not $inst)                             { $lv = 2; $st = 'Не установлен' }
    elseif ($ZState.fallbackUntil -gt (Get-Date))   { $lv = 1; $st = $(if (Test-ZDirect) { 'Нет рабочей стратегии — повтор позже' } else { 'Нет рабочей стратегии — всё через VPN' }) }
    elseif ($ZState.lastError)                      { $lv = 2; $st = 'Ошибка' }
    elseif (-not $winws)                            { $lv = 1; $st = 'Запускается' }
    elseif ($ZState.healthTotal -and $ZState.healthOk -lt $ZState.healthTotal) {
        $lv = 1; $st = "Работает частично ($($ZState.healthOk)/$($ZState.healthTotal))"
        if (@($ZState.healthChecks | Where-Object { $_ -and -not $_.ok -and "$($_.n)" -like '*видео*' }).Count) { $st = 'Нет видео YouTube' }
    }
    else                                            { $lv = 0; $st = 'Работает' }

    $ver = $(if ($ZState.version) { $ZState.version } else { Get-ZapretLocalVersion })
    $verLine = 'Версия: ' + $(if ($ver) { $ver } else { 'не установлен' })
    if ($ZState.remoteVersion -and $ver -and (ConvertTo-Ver $ZState.remoteVersion) -gt (ConvertTo-Ver $ver)) { $verLine += " (есть $($ZState.remoteVersion))" }
    $vpnOn = (Get-Command Get-VpnMode -ErrorAction SilentlyContinue) -and (Get-VpnMode) -ne 'zapret'
    $vpnWarn = $(if ($z.enabled -and $vpnOn) { 'Включён вместе с VPN: YouTube и Discord этого ПК идут мимо VPN через zapret (провайдер их замедляет), а у клиентов wg_server, пока zapret включён, они не открываются — zapret работает только для самого ПК. Через VPN YouTube обычно быстрее; если zapret нужен — режим «Без VPN».' } else { '' })
    $d = @(
        $vpnWarn,
        $verLine,
        ('Стратегия: ' + $(if ($strategy) { $strategy + $(if ($z.strategy) { ' (вручную)' } elseif ($ZState.lastTotal) { " · $($ZState.lastScore)/$($ZState.lastTotal) при подборе" } else { '' }) } else { '—' })),
        $(if ($t) { "Сейчас проверяю: $($t.current)" } elseif ($ZState.healthTotal) { "Проверка $(Format-When $ZState.healthAt): открылось $($ZState.healthOk)/$($ZState.healthTotal)" } else { 'Проверка: ещё не было' }),
        $(if (-not $t) { $bad = @($ZState.healthChecks | Where-Object { $_ -and -not $_.ok }); if ($bad.Count) { 'Не прошли: ' + (($bad | ForEach-Object { "$($_.n) ($($_.why))" }) -join '; ') } }),
        "Маршрутов мимо VPN: $(@($ZState.routes).Count)",
        $(if ($ZState.lastError) { "Ошибка: $($ZState.lastError)" } else { '' })
    )
    $conns = 0
    if ($z.enabled) { try { $conns = Get-ZapretConnCount } catch { } }
    $kv = @(
        @('Включён', $(if ($z.enabled) { 'да' + $(if ($vpnOn) { ' — вместе с VPN (см. предупреждение выше)' } else { ' — режим «Без VPN»' }) } else { 'нет' })),
        @('Версия', $(if ($ver) { "$ver" } else { 'не установлен' })),
        @('На GitHub', $(if ($ZState.remoteVersion) { "$($ZState.remoteVersion)" } else { '—' })),
        @('Выбранная версия', $(if ($z.version) { "$($z.version) — закреплена, не обновляется" } else { 'последняя (обновляется сама)' })),
        @('Проверка обновлений', $(if ($ZState.lastUpdateCheck) { "$($ZState.lastUpdateCheck)" } else { '—' })),
        @('Стратегия', $(if ($strategy) { $strategy + $(if ($z.strategy) { ' (выбрана вручную)' } else { ' (подобрана)' }) } else { '—' })),
        @('Запущена', $(if ($winws) { "$($ZState.runningStrategy) · winws PID $($ZState.winwsPid)" } else { 'winws не запущен' })),
        @('Последний подбор', $(if ($ZState.lastTest) { "$($ZState.lastTest)" } else { '—' })),
        @('Проверка сайтов', $(if ($ZState.healthTotal) { "$($ZState.healthOk)/$($ZState.healthTotal) · $($ZState.healthAt)" } else { '—' })),
        @('Видеосервер YouTube', $(if ($ZState.videoHost) { "$($ZState.videoHost)" + $(if ("$($ZState.videoHostVia)" -eq 'direct') { ' (провайдера, найден напрямую)' } elseif ("$($ZState.videoHostVia)" -eq 'vpn') { ' (найден через VPN — не тот, что у браузера)' } else { '' }) } else { '—' })),
        @('Видеосерверы провайдера мимо VPN', $(if (@($ZState.ggc).Count) { (@($ZState.ggc) -join ', ') } else { '—' })),
        @('Маршрутов мимо VPN', "$(@($ZState.routes).Count)"),
        @('Соединений мимо VPN сейчас', $(if ($z.enabled) { "$conns (TCP к YouTube/Discord и своим доменам)" } else { '—' })),
        @('Папка', "$(Get-ZapretDir)")
    )
    [ordered]@{
        level = $lv; state = $st; details = @($d | Where-Object { $_ }); kv = $kv
        enabled = [bool]$z.enabled; strategies = @(Get-ZapretStrategies); testing = [bool]$t
        results = @($ZState.results)
        current = "$strategy"
        manual = "$($z.strategy)"
        running = "$($ZState.runningStrategy)"
        checks = @($ZState.healthChecks | Where-Object { $_ })
        checkedAt = $(if ($ZState.healthAt -ne [datetime]::MinValue) { $ZState.healthAt.ToString('HH:mm') } else { '' })
        videoCheck = ($z.videoCheck -ne $false)
        vpnWarn = "$vpnWarn"
        version = "$ver"; pinned = "$($z.version)"; latest = "$($ZState.remoteVersion)"
        versions = @(@($ZState.releases) | Where-Object { $_ } | ForEach-Object { [ordered]@{ v = "$($_.v)"; date = "$($_.date)"; pre = [bool]$_.pre } })
        conns = $conns
        dir = "$(Get-ZapretDir)"
        progress =$(if ($t) { [ordered]@{ index = $t.index; total = $t.total; current = "$($t.current)" } } else { $null })
    }
}

function Write-ZapretDiag {
    $z = Get-ZCfg
    Write-Host "Включён: $($z.enabled) · папка: $(Get-ZapretDir) (установлен: $(Test-ZapretInstalled))"
    Write-Host "Версия: $(Get-ZapretLocalVersion) · на GitHub: $($ZState.remoteVersion) · проверка обновлений: $($ZState.lastUpdateCheck)"
    Write-Host "Стратегия: вручную='$($z.strategy)' подобрана='$($ZState.strategy)' запущена='$($ZState.runningStrategy)' · последний подбор: $($ZState.lastTest)"
    Write-Host "Видеосервер YouTube: $($ZState.videoHost) ($($ZState.videoHostAt), найден: $($ZState.videoHostVia)) · проверка видео: $($z.videoCheck -ne $false) · сети видеосерверов провайдера: $(@($ZState.ggc) -join ', ')"
    foreach ($r in @($ZState.results)) {
        $bad = @($r.checks | Where-Object { $_ -and -not $_.ok } | ForEach-Object { "$($_.n): $($_.why)" })
        Write-Host ("  {0,-32} {1}/{2} {3}" -f $r.name, $r.ok, $r.total, $(if ($bad.Count) { '· не прошли: ' + ($bad -join '; ') } else { '' }))
    }
    $wc = Get-CimInstance Win32_Process -Filter "Name='winws.exe'" -ErrorAction SilentlyContinue
    if ($wc) { foreach ($x in $wc) { Write-Host "winws PID $($x.ProcessId): $($x.CommandLine.Substring(0, [Math]::Min(160, $x.CommandLine.Length)))…" } } else { Write-Host 'winws: не запущен' }
    $s = Get-Service -Name 'zapret' -ErrorAction SilentlyContinue
    if ($s) { Write-Host "Служба zapret (service.bat): $($s.Status) / $($s.StartType)" }
    $wd = Get-Service -Name 'WinDivert' -ErrorAction SilentlyContinue
    if ($wd) { Write-Host "Драйвер WinDivert: $($wd.Status)" }
    $p = Get-PhysicalPath
    Write-Host ('Физический выход: ' + $(if ($p) { "$($p.Alias) IP $($p.Ip) шлюз $($p.Gateway)" } else { '!! не найден' }))
    Write-Host "Маршрутов мимо VPN: $(@($ZState.routes).Count) · обновлены: $($ZState.lastRouteRefresh)"
    Write-Host "Проверка сайтов: $($ZState.healthOk)/$($ZState.healthTotal) в $($ZState.healthAt) · ошибка: $($ZState.lastError)"
    if ($p -and (Test-ZapretInstalled)) {
        Write-Host 'Проверка сайтов напрямую (мимо VPN) сейчас:'
        foreach ($r in Test-ZapretTargets $p.Ip @(Get-ZTargets) ([int]$z.curlTimeoutSec)) { Write-Host ("  {0,-34} {1,-4} {2} (код {3}, curl {4}, {5} КБ, {6} мс) {7}" -f $r.Label, $(if ($r.Ok) { 'OK' } else { 'НЕТ' }), $r.Host, $r.Code, $r.Exit, $r.Kb, $r.Ms, $r.Why) }
    }
}
