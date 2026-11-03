# VpnGuard — модуль AmneziaWG: альтернатива MeduzaVPN.
# Туннель — служба клиента AmneziaWG для Windows (amneziawg.exe /installtunnelservice), как у WireGuard.
# Конфиги (страны/серверы) хранятся в data\amnezia\<имя>.conf; импорт — файл .conf из AmneziaVPN или ключ vpn://.
# Подключается и агентом, и окном. Нужны $Cfg (или $A в окне), $DataDir.

$AwgDir = Join-Path $DataDir 'amnezia'

function Get-ACfg { if ($script:Cfg -and $script:Cfg.amnezia) { return $script:Cfg.amnezia }; return $script:A }
function Get-AwgServicePrefix { $av = Get-ACfg; $(if ($av.servicePrefix) { $av.servicePrefix } else { 'AmneziaWGTunnel$' }) }

# имя туннеля = имя файла = имя адаптера: латиница, цифры, _ = + . - (до 32 символов)
function ConvertTo-TunnelName([string]$s) {
    $tr = @{ 'а'='a';'б'='b';'в'='v';'г'='g';'д'='d';'е'='e';'ё'='e';'ж'='zh';'з'='z';'и'='i';'й'='y';'к'='k';'л'='l';'м'='m';'н'='n';'о'='o';'п'='p';'р'='r';'с'='s';'т'='t';'у'='u';'ф'='f';'х'='h';'ц'='c';'ч'='ch';'ш'='sh';'щ'='sch';'ъ'='';'ы'='y';'ь'='';'э'='e';'ю'='yu';'я'='ya' }
    $o = -join ("$s".ToLower().ToCharArray() | ForEach-Object { $c = "$_"; if ($tr.ContainsKey($c)) { $tr[$c] } else { $c } })
    $o = ($o -replace '[^a-z0-9_=+.\-]+', '_').Trim('_')
    if (-not $o) { $o = 'awg' }
    if ($o -notmatch '^awg') { $o = "awg_$o" }
    if ($o.Length -gt 32) { $o = $o.Substring(0, 32) }
    return $o
}

# ключ vpn:// из AmneziaVPN: base64url(qCompress(JSON)); внутри контейнер AmneziaWG с готовым конфигом
function ConvertFrom-AmneziaKey([string]$Key) {
    $b64 = ($Key.Trim() -replace '^vpn://', '').Replace('-', '+').Replace('_', '/')
    while ($b64.Length % 4) { $b64 += '=' }
    $bytes = [Convert]::FromBase64String($b64)
    $json = $null
    if ($bytes[0] -eq [byte][char]'{') { $json = [Text.Encoding]::UTF8.GetString($bytes) }
    else {
        # qCompress: 4 байта длины + zlib (2 байта заголовка + deflate)
        $ms = New-Object IO.MemoryStream($bytes, 6, ($bytes.Length - 6))
        $ds = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress)
        $json = (New-Object IO.StreamReader($ds, [Text.Encoding]::UTF8)).ReadToEnd()
    }
    $j = $json | ConvertFrom-Json
    $conf = $null
    foreach ($c in @($j.containers)) {
        foreach ($p in $c.PSObject.Properties) {
            $v = $p.Value
            if ($v -and $v.PSObject -and $v.PSObject.Properties['last_config']) {
                try { $lc = "$($v.last_config)" | ConvertFrom-Json; if ($lc.config) { $conf = "$($lc.config)" } } catch { }
                if (-not $conf -and "$($v.last_config)" -match '\[Interface\]') { $conf = "$($v.last_config)" }
            }
            if ($conf) { break }
        }
        if ($conf) { break }
    }
    if (-not $conf) { throw 'В ключе нет конфига AmneziaWG (возможно, это другой протокол). В AmneziaVPN выберите «Поделиться» → формат AmneziaWG и импортируйте файл .conf.' }
    $d1 = $(if ($j.dns1) { "$($j.dns1)" } else { '1.1.1.1' }); $d2 = $(if ($j.dns2) { "$($j.dns2)" } else { '1.0.0.1' })
    $conf = $conf.Replace('$PRIMARY_DNS', $d1).Replace('$SECONDARY_DNS', $d2)
    $name = $(if ($j.description) { "$($j.description)" } elseif ($j.hostName) { "$($j.hostName)" } else { 'amnezia' })
    [pscustomobject]@{ Name = $name; Text = $conf }
}

# подготовить конфиг: маршрут 0.0.0.0/0 → две половины. Тогда клиент не включает «блокировку вне туннеля»
# (иначе не работают маршруты zapret мимо VPN), а wg_server продолжает отвечать клиентам через физический адаптер.
function Format-AmneziaConf([string]$Text) {
    $lines = @($Text -split "`r?`n")
    if (-not ($lines -match '^\s*\[Interface\]') -or -not ($lines -match '^\s*\[Peer\]')) { throw 'Это не конфиг WireGuard/AmneziaWG: нет секций [Interface] и [Peer]' }
    if (-not ($lines -match '^\s*PrivateKey\s*=')) { throw 'В конфиге нет PrivateKey' }
    $av = Get-ACfg
    $out = foreach ($l in $lines) {
        if ($av.splitDefaultRoute -ne $false -and $l -match '^\s*AllowedIPs\s*=\s*(.+)$') {
            $ips = @($Matches[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $ips = @($ips | ForEach-Object { if ($_ -eq '0.0.0.0/0') { '0.0.0.0/1'; '128.0.0.0/1' } elseif ($_ -eq '::/0') { '::/1'; '8000::/1' } else { $_ } })
            "AllowedIPs = $($ips -join ', ')"
        } else { $l }
    }
    return (@($out) -join "`r`n").TrimEnd() + "`r`n"
}

function Import-AmneziaConfig([string]$Text, [string]$Name = '') {
    $t = $Text.Trim()
    if ($t -match '^vpn://') { $k = ConvertFrom-AmneziaKey $t; $t = $k.Text; if (-not $Name) { $Name = $k.Name } }
    if (-not $Name) { $Name = 'amnezia' }
    $conf = Format-AmneziaConf $t
    $tn = ConvertTo-TunnelName $Name
    if (-not (Test-Path $AwgDir)) { New-Item -ItemType Directory $AwgDir -Force | Out-Null }
    $base = $tn; $i = 2
    while (Test-Path (Join-Path $AwgDir "$tn.conf")) { $tn = "$base$i"; $i++ }
    $file = Join-Path $AwgDir "$tn.conf"
    $title = $Name.Trim() -replace '[\r\n]', ' '
    [IO.File]::WriteAllText($file, "# Name = $title`r`n" + $conf, (New-Object Text.UTF8Encoding $false))
    try { & icacls.exe $file /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null } catch { }
    return $tn
}

function Get-AmneziaConfigs {
    if (-not (Test-Path $AwgDir)) { return @() }
    @(Get-ChildItem $AwgDir -Filter '*.conf' | Sort-Object Name | ForEach-Object {
        $txt = [IO.File]::ReadAllText($_.FullName)
        $nm = [regex]::Match($txt, '(?m)^#\s*Name\s*=\s*(.+?)\s*$').Groups[1].Value
        [pscustomobject]@{
            name = $_.BaseName; title = $(if ($nm) { $nm } else { $_.BaseName })
            endpoint = [regex]::Match($txt, '(?m)^\s*Endpoint\s*=\s*(\S+)').Groups[1].Value
            address = [regex]::Match($txt, '(?m)^\s*Address\s*=\s*([^\r\n]+)').Groups[1].Value.Trim()
            file = $_.FullName
        }
    })
}

function Remove-AmneziaConfig([string]$Name) {
    $fp = Join-Path $AwgDir "$Name.conf"
    if (Test-Path $fp) {
        $bk = Join-Path $DataDir 'backup'
        if (-not (Test-Path $bk)) { New-Item -ItemType Directory $bk -Force | Out-Null }
        Move-Item $fp (Join-Path $bk ("amnezia-{0}-{1}.conf" -f $Name, (Get-Date -Format 'yyyyMMdd-HHmmss'))) -Force
    }
}

function Get-AmneziaActive {
    $av = Get-ACfg
    $list = @(Get-AmneziaConfigs)
    if ($av.active -and ($list | Where-Object { $_.name -eq $av.active })) { return "$($av.active)" }
    if ($list.Count) { return $list[0].name }
    return ''
}

# ---------------------------------------------------------------- управление туннелем (агент)
function Get-AwgExe { $av = Get-ACfg; $(if ($av.exe) { $av.exe } else { 'C:\Program Files\AmneziaWG\amneziawg.exe' }) }

function Start-AmneziaTunnel([string]$Name) {
    $exe = Get-AwgExe
    if (-not (Test-Path $exe)) { throw "AmneziaWG не установлен ($exe) — установите его на вкладке «Компоненты»" }
    $fp = Join-Path $AwgDir "$Name.conf"
    if (-not (Test-Path $fp)) { throw "нет конфига $fp" }
    $r = Invoke-Exe $exe ('/installtunnelservice "{0}"' -f $fp) 60
    if ($r.Code -ne 0) { throw "installtunnelservice: код $($r.Code) $($r.Err)" }
    $svc = (Get-AwgServicePrefix) + $Name
    try { Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
}

function Stop-AmneziaTunnel([string]$Name) {
    $svc = Get-Service -Name ((Get-AwgServicePrefix) + $Name) -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    $exe = Get-AwgExe
    if (Test-Path $exe) { $r = Invoke-Exe $exe ('/uninstalltunnelservice "{0}"' -f $Name) 60; if ($r.Code -eq 0) { return } }
    try { Stop-Service -Name $svc.Name -Force -ErrorAction Stop } catch { }
}

# все наши туннели AmneziaWG, кроме указанного
function Stop-AmneziaTunnels([string]$Except = '') {
    $pfx = Get-AwgServicePrefix
    foreach ($c in @(Get-AmneziaConfigs)) {
        if ($c.name -eq $Except) { continue }
        if (Get-Service -Name ($pfx + $c.name) -ErrorAction SilentlyContinue) {
            Write-Log "AmneziaWG: отключаю туннель $($c.name)"
            Stop-AmneziaTunnel $c.name
        }
    }
}

function Wait-UpAdapter([string]$Name, [int]$Sec = 20) {
    $deadline = (Get-Date).AddSeconds($Sec)
    do { if (Get-UpAdapter $Name) { return $true }; Start-Sleep -Seconds 1 } while ((Get-Date) -lt $deadline)
    return $false
}

function Test-AmneziaTraffic([string]$Name) {
    $ip = Get-AdapterIPv4 $Name
    $ok = $false
    if ($ip) { foreach ($h in $M.probeHosts) { if (Test-TcpVia $ip $h) { $ok = $true; break } } }
    $State.awgTraffic = $ok; $State.awgTrafficAt = Get-Date
    return $ok
}

function Restart-AmneziaTunnel([string]$Name, [string]$Reason) {
    $now = Get-Date
    while ($State.awgRestarts.Count -gt 0 -and $State.awgRestarts[0] -lt $now.AddMinutes(-30)) { $State.awgRestarts.RemoveAt(0) }
    if ($State.awgRestarts.Count -ge [int]$M.maxRestartsPer30Min) { Write-Log "AmneziaWG: слишком много перезапусков за 30 мин, пауза ($Reason)" 'WARN'; return }
    [void]$State.awgRestarts.Add($now)
    $State.awgLastRestart = $now; $State.awgLastReason = $Reason; $State.restartCount++
    Write-Log "AmneziaWG: ПЕРЕЗАПУСК туннеля $Name — $Reason" 'WARN'
    Set-Activity "перезапускаю AmneziaWG ($Name)"
    Stop-AmneziaTunnel $Name; Start-Sleep -Seconds 2
    try { Start-AmneziaTunnel $Name; $State.reconnectCount++ } catch { Write-Log "AmneziaWG: $($_.Exception.Message)" 'ERROR'; return }
    if (Wait-UpAdapter $Name 20) { Write-Log "AmneziaWG: туннель $Name поднят"; $State.forceIcs = $true }
}

$script:AwgWarnAt = [datetime]::MinValue
function Invoke-AmneziaWatch {
    $name = Get-AmneziaActive
    if (-not $name) {
        if (((Get-Date) - $script:AwgWarnAt).TotalMinutes -ge 10) { Write-Log 'AmneziaWG: нет ни одного конфига — импортируйте его в окне (вкладка AmneziaWG)' 'WARN'; $script:AwgWarnAt = Get-Date }
        return
    }
    if (-not (Test-Path (Get-AwgExe))) {
        if (((Get-Date) - $script:AwgWarnAt).TotalMinutes -ge 10) { Write-Log "AmneziaWG не установлен ($(Get-AwgExe)) — установите на вкладке «Компоненты»" 'ERROR'; $script:AwgWarnAt = Get-Date }
        return
    }
    Stop-AmneziaTunnels $name
    $svcName = (Get-AwgServicePrefix) + $name
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log "AmneziaWG: подключаю туннель $name"
        Set-Activity "подключаю AmneziaWG ($name)"
        try { Start-AmneziaTunnel $name; $State.reconnectCount++ } catch { Write-Log "AmneziaWG: $($_.Exception.Message)" 'ERROR'; return }
        if (Wait-UpAdapter $name 20) { Write-Log "AmneziaWG: туннель $name поднят"; $State.forceIcs = $true }
        return
    }
    if ($svc.Status -ne 'Running') {
        Write-Log "AmneziaWG: служба туннеля в состоянии $($svc.Status) — запускаю" 'WARN'
        try { Start-Service -Name $svcName -ErrorAction Stop } catch { Restart-AmneziaTunnel $name 'служба не запускается' }
        return
    }
    if (-not (Get-UpAdapter $name)) {
        $State.awgDownTicks++; $State.awgTraffic = $null
        Write-Log "AmneziaWG: адаптер $name не поднят ($($State.awgDownTicks))" 'WARN'
        if ($State.awgDownTicks -ge 2) { $State.awgDownTicks = 0; Restart-AmneziaTunnel $name 'адаптер не поднят' }
        return
    }
    $State.awgDownTicks = 0
    if (Test-AmneziaTraffic $name) { $State.awgProbeFailures = 0; return }
    $State.awgProbeFailures++
    Write-Log ("AmneziaWG: нет трафика через туннель ({0}/{1})" -f $State.awgProbeFailures, $M.probeFailuresBeforeReconnect) 'WARN'
    if ($State.awgProbeFailures -ge [int]$M.probeFailuresBeforeReconnect) { $State.awgProbeFailures = 0; Restart-AmneziaTunnel $name 'туннель не пропускает трафик' }
}

# тест конфигов: по очереди поднять каждый и проверить трафик (аналог теста протоколов MeduzaVPN)
function Invoke-AmneziaConfigTest {
    $list = @(Get-AmneziaConfigs)
    if (-not $list.Count) { Write-Log 'AmneziaWG: нет конфигов для теста' 'WARN'; return }
    if (-not (Test-Path (Get-AwgExe))) { Write-Log 'AmneziaWG: не установлен — тест невозможен' 'WARN'; return }
    $res = New-Object Collections.ArrayList
    $State.awgTest = [ordered]@{ running = $true; index = 0; total = $list.Count; current = ''; results = $res; at = '' }
    Write-Log "AmneziaWG: тест конфигов: $(($list | ForEach-Object { $_.name }) -join ', ')" 'WARN'
    $active = Get-AmneziaActive
    # два туннеля: на время теста трафик — через MeduzaVPN
    if ((Get-VpnMode) -eq 'dual' -and (Get-DualActive) -eq 'amnezia' -and (Test-KindOk 'meduza')) { Switch-DualActive 'meduza' 'тест конфигов AmneziaWG' }
    Stop-AmneziaTunnels ''
    $i = 0
    foreach ($c in $list) {
        $i++; $State.awgTest.index = $i; $State.awgTest.current = $c.title
        Set-Activity "тест AmneziaWG: $($c.title) ($i/$($list.Count))"
        $sw = [Diagnostics.Stopwatch]::StartNew(); $err = ''; $okN = 0; $ms = New-Object Collections.ArrayList
        try {
            Start-AmneziaTunnel $c.name
            if (Wait-UpAdapter $c.name 20) {
                Start-Sleep -Seconds 2
                $ip = Get-AdapterIPv4 $c.name
                foreach ($h in $M.probeHosts) { $t = [Diagnostics.Stopwatch]::StartNew(); if ($ip -and (Test-TcpVia $ip $h 3000)) { $okN++; [void]$ms.Add($t.ElapsedMilliseconds) } }
            } else { $err = 'туннель не поднялся' }
        } catch { $err = $_.Exception.Message }
        $conn = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        Stop-AmneziaTunnel $c.name
        [void]$res.Add([ordered]@{ protocol = $c.title; name = $c.name; ok = ($okN -gt 0); probes = "$okN/$(@($M.probeHosts).Count)"; connectSec = $conn
            pingMs = $(if ($ms.Count) { [int](($ms | Measure-Object -Average).Average) } else { -1 }); adapter = $c.name; error = $err })
        Write-Log ("AmneziaWG: тест {0}: {1}" -f $c.title, $(if ($okN) { "работает, отклик $([int](($ms | Measure-Object -Average).Average)) мс" } else { "НЕ работает $err" }))
        try { Write-StatusSnapshot } catch { }
    }
    $State.awgTest.running = $false; $State.awgTest.current = ''; $State.awgTest.at = (Get-Date).ToString('dd.MM HH:mm')
    if ((Get-VpnMode) -in 'amnezia', 'dual' -and $active) {
        Set-Activity "возвращаю AmneziaWG ($active)"
        try { Start-AmneziaTunnel $active; [void](Wait-UpAdapter $active 20) } catch { }
        $State.forceIcs = $true
    }
}

# состояние туннеля из awg.exe: рукопожатие, принято/отправлено
function Get-AwgTunnelInfo([string]$Name) {
    $awg = Join-Path (Split-Path (Get-AwgExe)) 'awg.exe'
    if (-not $Name -or -not (Test-Path $awg)) { return $null }
    $r = Invoke-Exe $awg ('show "{0}" dump' -f $Name) 8
    if ($r.Code -ne 0 -or -not $r.Out) { return $null }
    $lines = @($r.Out -split "`r?`n" | Where-Object { $_ })
    if ($lines.Count -lt 2) { return $null }
    $fp = $lines[1] -split "`t"      # первая строка — интерфейс, дальше пиры
    if ($fp.Count -lt 8) { return $null }
    $hs = [long]0; [void][long]::TryParse($fp[4], [ref]$hs)
    $rx = [long]0; [void][long]::TryParse($fp[5], [ref]$rx)
    $tx = [long]0; [void][long]::TryParse($fp[6], [ref]$tx)
    [pscustomobject]@{ Endpoint = $fp[2]; HsAgo = $(if ($hs -gt 0) { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $hs } else { -1 }); Rx = $rx; Tx = $tx }
}

function Format-AwgBytes([double]$b) { if ($b -ge 1GB) { '{0:N2} ГБ' -f ($b / 1GB) } elseif ($b -ge 1MB) { '{0:N1} МБ' -f ($b / 1MB) } else { '{0:N0} КБ' -f ($b / 1KB) } }

# карточка состояния AmneziaWG — как у MeduzaVPN
function Get-AmneziaStatus {
    $mode = Get-VpnMode
    $used = $mode -in 'amnezia', 'dual'
    $exe = Get-AwgExe; $inst = Test-Path $exe
    $name = Get-AmneziaActive
    $cfgx = $(if ($name) { @(Get-AmneziaConfigs) | Where-Object { $_.name -eq $name } | Select-Object -First 1 } else { $null })
    $svc = $(if ($name) { Get-Service -Name ((Get-AwgServicePrefix) + $name) -ErrorAction SilentlyContinue } else { $null })
    $ad = $(if ($name) { Get-NetAdapter -Name $name -ErrorAction SilentlyContinue } else { $null })
    $up = [bool]($ad -and $ad.Status -eq 'Up')
    $ip = $(if ($up) { Get-AdapterIPv4 $name } else { $null })
    $ti = $(if ($up) { try { Get-AwgTunnelInfo $name } catch { $null } } else { $null })
    $ver = ''; if ($inst) { try { $ver = (Get-Item $exe).VersionInfo.ProductVersion } catch { } }
    $tst = $State.awgTest
    if ($tst -and $tst.running)        { $lv = 1; $st = "Тест конфигов $($tst.index)/$($tst.total)" }
    elseif (-not $used)                { $lv = -1; $st = $(if ($svc -and $svc.Status -eq 'Running') { 'Не используется (туннель поднят)' } else { 'Не используется' }) }
    elseif (-not $inst)                { $lv = 2; $st = 'Не установлен' }
    elseif (-not $name)                { $lv = 2; $st = 'Нет конфига' }
    elseif (-not $svc)                 { $lv = 2; $st = 'Туннель не подключён' }
    elseif ($svc.Status -ne 'Running') { $lv = 2; $st = "Служба: $($svc.Status)" }
    elseif (-not $up)                  { $lv = 1; $st = 'Адаптер не поднят' }
    elseif ($State.awgTraffic -eq $false) { $lv = 1; $st = 'Нет трафика' }
    elseif ($ti -and $ti.HsAgo -gt 180) { $lv = 1; $st = 'Нет рукопожатия с сервером' }
    else                               { $lv = 0; $st = 'Подключён' }
    if ($mode -eq 'dual' -and $lv -eq 0) { $st = $(if ((Get-DualActive) -eq 'amnezia') { 'Подключён · активный' } else { 'Подключён · резерв' }) }
    $hsTxt = $(if (-not $ti) { '—' } elseif ($ti.HsAgo -lt 0) { 'не было' } elseif ($ti.HsAgo -lt 120) { "$($ti.HsAgo) с назад" } else { "$([int]($ti.HsAgo / 60)) мин назад" })
    $d = @(
        $(if ($cfgx) { "Конфиг: $($cfgx.title) · сервер $($cfgx.endpoint)" } else { 'Конфиг: нет' }),
        ('Туннель: ' + $(if ($up) { "IP $ip · рукопожатие $hsTxt" } elseif ($svc) { "$($svc.Status)" } else { 'не подключён' })),
        ('Трафик: ' + $(if ($State.awgTraffic -eq $true) { 'OK' } elseif ($State.awgTraffic -eq $false) { 'НЕТ' } else { '—' }) + ", проверка $(Format-When $State.awgTrafficAt)"),
        "Перезапуски: $($State.awgRestarts.Count) за 30 мин, посл. $(Format-When $State.awgLastRestart)"
    )
    $kv = @(
        @('Клиент AmneziaWG', $(if ($inst) { "установлен · версия $ver" } else { "не установлен ($exe)" })),
        @('Используется', $(if ($mode -eq 'amnezia') { 'да — режим AmneziaWG' } elseif ($mode -eq 'dual') { 'да — режим «два туннеля» (' + $(if ((Get-DualActive) -eq 'amnezia') { 'активный' } else { 'резерв' }) + ')' } else { 'нет (другой режим)' })),
        @('Активный конфиг', $(if ($cfgx) { "$($cfgx.title) ($name)" } else { '—' })),
        @('Сервер', $(if ($ti -and $ti.Endpoint -and $ti.Endpoint -ne '(none)') { "$($ti.Endpoint)" } elseif ($cfgx) { "$($cfgx.endpoint)" } else { '—' })),
        @('Служба', $(if ($svc) { "$($svc.Name) · $($svc.Status) / $($svc.StartType)" } else { 'не установлена' })),
        @('Адаптер', $(if ($ad) { "$($ad.Status) · IP $(if ($ip) { $ip } else { '—' })" } else { 'отсутствует' })),
        @('Последнее рукопожатие', $hsTxt),
        @('Принято / отправлено', $(if ($ti) { "$(Format-AwgBytes $ti.Rx) / $(Format-AwgBytes $ti.Tx)" } else { '—' })),
        @('Проверка трафика', ($(if ($State.awgTraffic -eq $true) { 'OK' } elseif ($State.awgTraffic -eq $false) { 'НЕТ' } else { '—' }) + " · $(Format-When $State.awgTrafficAt)")),
        @('Сбоев проверки подряд', "$($State.awgProbeFailures) (перезапуск после $($M.probeFailuresBeforeReconnect))"),
        @('Перезапусков за 30 мин', "$($State.awgRestarts.Count) из $($M.maxRestartsPer30Min) допустимых"),
        @('Последний перезапуск', (Format-When $State.awgLastRestart)),
        @('Причина', $(if ($State.awgLastReason) { $State.awgLastReason } else { '—' })),
        @('Конфигов', "$(@(Get-AmneziaConfigs).Count)")
    )
    [pscustomobject]@{ Level = $lv; State = $st; Details = @($d | Where-Object { $_ }); Kv = $kv; Up = $up }
}

function Get-AmneziaSnapshot {
    $list = @(Get-AmneziaConfigs)
    $exe = Get-AwgExe
    $s = Get-AmneziaStatus
    [ordered]@{
        level = $s.Level; state = $s.State; details = $s.Details; kv = $s.Kv
        installed = [bool](Test-Path $exe)
        active    = Get-AmneziaActive
        configs   = @($list | ForEach-Object { [ordered]@{ name = $_.name; title = $_.title; endpoint = $_.endpoint; address = $_.address
                        running = [bool](Get-Service -Name ((Get-AwgServicePrefix) + $_.name) -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }) } })
        test      = $State.awgTest
    }
}
