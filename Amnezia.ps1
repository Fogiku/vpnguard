# VpnGuard — модуль AmneziaVPN: альтернатива MeduzaVPN (режим «AmneziaVPN», id режима — amnezia).
# Приложение AmneziaVPN (amnezia-vpn/amnezia-client): сервер, протокол и подключение настраиваются в самом приложении.
# Командной строки у него нет, поэтому VpnGuard: держит приложение запущенным, находит адаптер туннеля
# (имя или описание содержит «Amnezia»/tun2socks — зависит от протокола), проверяет трафик через него и при сбое
# перезапускает приложение и его службу. Чтобы после перезапуска туннель поднимался сам, в AmneziaVPN включите
# «Автоподключение» (Настройки → Подключение) и «Автозапуск» (Настройки → Приложение).
# Подключается и агентом, и окном. Нужны $Cfg (или $A в окне), $DataDir.

function Get-ACfg { if ($script:Cfg -and $script:Cfg.amnezia) { return $script:Cfg.amnezia }; return $script:A }

# путь к AmneziaVPN.exe: из настроек, из записи установщика, по умолчанию
function Get-AwgExe {
    $av = Get-ACfg
    if ($av -and "$($av.exe)" -like '*AmneziaVPN*.exe') { return "$($av.exe)" }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        $e = Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { "$($_.DisplayName)" -match '^AmneziaVPN' } | Select-Object -First 1
        if ($e -and $e.InstallLocation -and (Test-Path (Join-Path $e.InstallLocation 'AmneziaVPN.exe'))) { return (Join-Path $e.InstallLocation 'AmneziaVPN.exe') }
    }
    return 'C:\Program Files\AmneziaVPN\AmneziaVPN.exe'
}
function Get-AvpnServiceName { $av = Get-ACfg; $(if ($av -and $av.serviceName) { "$($av.serviceName)" } else { 'AmneziaVPN-service' }) }
function Get-AvpnPattern { $av = Get-ACfg; $(if ($av -and $av.adapterPattern) { "$($av.adapterPattern)" } else { 'amnezia|tun2socks|TAP-Windows Adapter V9' }) }
function Get-AvpnProc { Get-Process -Name 'AmneziaVPN' -ErrorAction SilentlyContinue | Select-Object -First 1 }

# адаптер туннеля AmneziaVPN (работающий — в первую очередь); имя запоминаем: оно нужно раздаче и маршрутам, пока туннель переподключается
function Get-AvpnAdapter {
    $rx = Get-AvpnPattern
    # адаптеры старых туннелей AmneziaWG, которые создавал сам VpnGuard (data\amnezia*\*.conf), — не туннель AmneziaVPN
    $old = @(foreach ($d in (Join-Path $DataDir 'amnezia'), (Join-Path $DataDir 'amnezia-old')) { Get-ChildItem $d -Filter '*.conf' -ErrorAction SilentlyContinue | ForEach-Object { $_.BaseName } })
    $all = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { ($_.Name -match $rx -or $_.Description -match $rx) -and $old -notcontains $_.Name })
    $ad = @($all | Sort-Object { $_.OperationalStatus -ne 'Up' }) | Select-Object -First 1
    if ($ad) { if ($State) { $State.awgAdapter = $ad.Name }; return $ad }
    return $null
}
function Get-AmneziaActive {
    $ad = Get-AvpnAdapter
    if ($ad) { return $ad.Name }
    if ($State -and $State.awgAdapter) { return "$($State.awgAdapter)" }
    return ''
}
# конфигов больше нет (их хранит AmneziaVPN) — оставлено для совместимости
function Get-AmneziaConfigs { @() }
function Test-AmneziaAlias([string]$Alias) { if (-not $Alias) { return $false }; return [bool]($Alias -match (Get-AvpnPattern) -or ($State -and $Alias -eq $State.awgAdapter)) }

function Wait-UpAdapter([string]$Name, [int]$Sec = 20) {
    $deadline = (Get-Date).AddSeconds($Sec)
    do { if (Get-UpAdapter $Name) { return $true }; Start-Sleep -Seconds 1 } while ((Get-Date) -lt $deadline)
    return $false
}
function Wait-AvpnUp([int]$Sec = 60) {
    $deadline = (Get-Date).AddSeconds($Sec)
    do { $ad = Get-AvpnAdapter; if ($ad -and "$($ad.OperationalStatus)" -eq 'Up') { return $ad.Name }; Start-Sleep -Seconds 2 } while ((Get-Date) -lt $deadline)
    return ''
}

function Test-AmneziaTraffic([string]$Name) {
    $ip = $(if ($Name) { Get-AdapterIPv4 $Name } else { $null })
    $ok = $false
    if ($ip) { foreach ($h in $M.probeHosts) { if (Test-TcpVia $ip $h) { $ok = $true; break } } }
    $State.awgTraffic = $ok; $State.awgTrafficAt = Get-Date
    return $ok
}

function Start-AmneziaApp {
    $exe = Get-AwgExe
    if (-not (Test-Path $exe)) { throw "AmneziaVPN не установлен ($exe) — установите его на вкладке «Компоненты»" }
    $svc = Get-Service -Name (Get-AvpnServiceName) -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') { try { Start-Service -Name $svc.Name -ErrorAction Stop } catch { Write-Log "AmneziaVPN: служба $($svc.Name) не запускается: $($_.Exception.Message)" 'WARN' } }
    Write-Log "AmneziaVPN: запуск $exe"
    Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -WindowStyle Minimized | Out-Null
    $State.awgStartedAt = Get-Date
}

# закрыть приложение и разорвать туннель: служба AmneziaVPN держит туннель и после закрытия окна — перезапускаем её
function Stop-AmneziaApp {
    $p = @(Get-Process -Name 'AmneziaVPN' -ErrorAction SilentlyContinue)
    foreach ($x in $p) { try { $x.Kill(); [void]$x.WaitForExit(10000) } catch { } }
    Get-Service -Name 'AmneziaWGTunnel$*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' -and $_.Name -match 'AmneziaVPN' } |
        ForEach-Object { try { Stop-Service -Name $_.Name -Force -ErrorAction Stop } catch { } }
    $svc = Get-Service -Name (Get-AvpnServiceName) -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { try { Restart-Service -Name $svc.Name -Force -ErrorAction Stop } catch { Write-Log "AmneziaVPN: перезапуск службы: $($_.Exception.Message)" 'WARN' } }
}

# совместимость с режимами: «отключить AmneziaVPN» (кроме указанного — у AmneziaVPN туннель один)
# -Close — закрыть и само приложение (при смене режима); без него — только если туннель поднят
function Stop-AmneziaTunnels([string]$Except = '', [switch]$Close) {
    if ($Except) { return }
    $ad = Get-AvpnAdapter
    if (($Close -and (Get-AvpnProc)) -or ($ad -and "$($ad.OperationalStatus)" -eq 'Up')) { Write-Log 'AmneziaVPN: отключаю (выбран другой режим)'; Stop-AmneziaApp }
}

function Restart-AmneziaTunnel([string]$Name, [string]$Reason) {
    $now = Get-Date
    while ($State.awgRestarts.Count -gt 0 -and $State.awgRestarts[0] -lt $now.AddMinutes(-30)) { $State.awgRestarts.RemoveAt(0) }
    if ($State.awgRestarts.Count -ge [int]$M.maxRestartsPer30Min) { Write-Log "AmneziaVPN: слишком много перезапусков за 30 мин, пауза ($Reason)" 'WARN'; return }
    [void]$State.awgRestarts.Add($now)
    $State.awgLastRestart = $now; $State.awgLastReason = $Reason; $State.restartCount++
    Write-Log "AmneziaVPN: ПЕРЕЗАПУСК — $Reason" 'WARN'
    Set-Activity 'перезапускаю AmneziaVPN'
    Stop-AmneziaApp; Start-Sleep -Seconds 3
    try { Start-AmneziaApp; $State.reconnectCount++ } catch { Write-Log "AmneziaVPN: $($_.Exception.Message)" 'ERROR'; return }
    $n = Wait-AvpnUp 60
    if ($n) { Write-Log "AmneziaVPN: туннель поднят ($n)"; $State.forceIcs = $true; $State.awgDownTicks = 0 }
    else { Write-Log 'AmneziaVPN: после перезапуска туннель не поднялся — проверьте, что в AmneziaVPN включено «Автоподключение»' 'WARN' }
}

$script:AwgWarnAt = [datetime]::MinValue
function Invoke-AmneziaWatch {
    $exe = Get-AwgExe
    if (-not (Test-Path $exe)) {
        if (((Get-Date) - $script:AwgWarnAt).TotalMinutes -ge 10) { Write-Log "AmneziaVPN не установлен ($exe) — установите на вкладке «Компоненты» и добавьте сервер в приложении" 'ERROR'; $script:AwgWarnAt = Get-Date }
        return
    }
    if (-not (Get-AvpnProc)) {
        Write-Log 'AmneziaVPN: приложение не запущено' 'WARN'
        try { Start-AmneziaApp } catch { Write-Log "AmneziaVPN: $($_.Exception.Message)" 'ERROR' }
        return
    }
    $ad = Get-AvpnAdapter
    if ($ad -and "$($ad.OperationalStatus)" -eq 'Up') {
        $State.awgDownTicks = 0
        if (Test-AmneziaTraffic $ad.Name) { $State.awgProbeFailures = 0; return }
        $State.awgProbeFailures++
        Write-Log "AmneziaVPN: нет трафика через туннель ($($State.awgProbeFailures)/$($M.probeFailuresBeforeReconnect))" 'WARN'
        if ($State.awgProbeFailures -ge [int]$M.probeFailuresBeforeReconnect) { $State.awgProbeFailures = 0; Restart-AmneziaTunnel $ad.Name 'туннель не пропускает трафик' }
        return
    }
    $State.awgTraffic = $null
    $since = $(if ($State.awgStartedAt) { ((Get-Date) - $State.awgStartedAt).TotalSeconds } else { 1e9 })
    if ($since -lt [int]$M.startupGraceSec) { return }      # приложение только запущено — даём ему подключиться
    $State.awgDownTicks++
    Write-Log "AmneziaVPN: туннель не подключён ($($State.awgDownTicks)/3)$(if ($State.awgDownTicks -eq 1) { ' — включите в AmneziaVPN «Автоподключение», иначе после перезапуска он не подключится сам' })" 'WARN'
    if ($State.awgDownTicks -ge 3) { $State.awgDownTicks = 0; Restart-AmneziaTunnel '' 'туннель не подключается' }
}

function Invoke-AmneziaConfigTest { Write-Log 'AmneziaVPN: тест конфигов не поддерживается — серверы и протоколы выбираются в самом приложении AmneziaVPN' 'WARN' }
function Get-AwgTunnelInfo([string]$Name) { $null }

# карточка состояния AmneziaVPN — как у MeduzaVPN
function Get-AmneziaStatus {
    $mode = Get-VpnMode
    $used = $mode -in 'amnezia', 'dual'
    $exe = Get-AwgExe; $inst = Test-Path $exe
    $proc = Get-AvpnProc
    $svc = Get-Service -Name (Get-AvpnServiceName) -ErrorAction SilentlyContinue
    $ad = Get-AvpnAdapter
    $up = [bool]($ad -and "$($ad.OperationalStatus)" -eq 'Up')
    $ip = $(if ($up) { Get-AdapterIPv4 $ad.Name } else { $null })
    $ver = ''; if ($inst) { try { $ver = (Get-Item $exe).VersionInfo.ProductVersion } catch { } }
    if (-not $used)                    { $lv = -1; $st = $(if ($up) { 'Не используется (туннель поднят)' } elseif ($proc) { 'Не используется (запущен)' } else { 'Не используется' }) }
    elseif (-not $inst)                { $lv = 2; $st = 'Не установлен' }
    elseif (-not $proc)                { $lv = 2; $st = 'Не запущен' }
    elseif (-not $up)                  { $lv = 1; $st = 'Туннель не подключён' }
    elseif ($State.awgTraffic -eq $false) { $lv = 1; $st = 'Нет трафика' }
    else                               { $lv = 0; $st = 'Подключён' }
    if ($mode -eq 'dual' -and $lv -eq 0) { $st = $(if ((Get-DualActive) -eq 'amnezia') { 'Подключён · активный' } else { 'Подключён · резерв' }) }
    $trTxt = $(if ($State.awgTraffic -eq $true) { 'OK' } elseif ($State.awgTraffic -eq $false) { 'НЕТ' } else { '—' })
    $d = @(
        $(if ($inst) { "AmneziaVPN $ver · " + $(if ($proc) { "PID $($proc.Id)" } else { 'не запущен' }) } else { 'AmneziaVPN не установлен' }),
        ('Туннель: ' + $(if ($up) { "$($ad.Name) · IP $ip" } elseif ($ad) { "$($ad.Name) — $($ad.OperationalStatus)" } else { 'не подключён' })),
        "Трафик: $trTxt, проверка $(Format-When $State.awgTrafficAt)",
        "Перезапуски: $($State.awgRestarts.Count) за 30 мин, посл. $(Format-When $State.awgLastRestart)"
    )
    $kv = @(
        @('Приложение AmneziaVPN', $(if ($inst) { "установлено · версия $ver" } else { "не установлено ($exe)" })),
        @('Процесс', $(if ($proc) { "PID $($proc.Id) · $([int]($proc.WorkingSet64 / 1MB)) МБ" } else { 'не запущен' })),
        @('Служба', $(if ($svc) { "$($svc.Name) · $($svc.Status) / $($svc.StartType)" } else { 'не найдена' })),
        @('Используется', $(if ($mode -eq 'amnezia') { 'да — режим AmneziaVPN' } elseif ($mode -eq 'dual') { 'да — режим «два туннеля» (' + $(if ((Get-DualActive) -eq 'amnezia') { 'активный' } else { 'резерв' }) + ')' } else { 'нет (другой режим)' })),
        @('Адаптер туннеля', $(if ($ad) { "$($ad.Name) · $($ad.Description) · $($ad.OperationalStatus)" } else { 'не найден (туннель не подключён)' })),
        @('IP', $(if ($ip) { $ip } else { '—' })),
        @('Проверка трафика', "$trTxt · $(Format-When $State.awgTrafficAt)"),
        @('Сбоев проверки подряд', "$($State.awgProbeFailures) (перезапуск после $($M.probeFailuresBeforeReconnect))"),
        @('Перезапусков за 30 мин', "$($State.awgRestarts.Count) из $($M.maxRestartsPer30Min) допустимых"),
        @('Последний перезапуск', (Format-When $State.awgLastRestart)),
        @('Причина', $(if ($State.awgLastReason) { $State.awgLastReason } else { '—' })),
        @('Сервер и протокол', 'выбираются в приложении AmneziaVPN; там же включите «Автоподключение»')
    )
    [pscustomobject]@{ Level = $lv; State = $st; Details = @($d | Where-Object { $_ }); Kv = $kv; Up = $up }
}

function Get-AmneziaSnapshot {
    $s = Get-AmneziaStatus
    $ad = Get-AvpnAdapter
    [ordered]@{
        level = $s.Level; state = $s.State; details = $s.Details; kv = $s.Kv
        installed = [bool](Test-Path (Get-AwgExe))
        running   = [bool](Get-AvpnProc)
        active    = $(if ($ad) { $ad.Name } else { '' })
        adapter   = $(if ($ad) { $ad.Name } else { '' })
        configs   = @()
        test      = $null
    }
}
