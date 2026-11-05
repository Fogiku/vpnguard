# VpnGuard — модуль Diag.ps1: Диагностика (VpnGuard.ps1 -Diag) и краткое состояние (-Status): раздача ICS, маршруты, журнал.
# Подключается из VpnGuard.ps1 (точкой — в его области видимости).

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
            if ($false) {          # клиенты — во вкладке WG-Server веб-интерфейса
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
        $swl = @(); try { $swl = @(([IO.File]::ReadAllText($StatusPath) | ConvertFrom-Json).software) } catch { }
        foreach ($s in $swl) { Write-Host ("Компонент {0,-24} установлен: {1,-12} последний: {2,-10} нужен: {3} {4}" -f $s.name, $(if ($s.installed) { $s.installed } else { '—' }), $s.latest, $s.needed, $s.error) }
    }

    Section 'zapret-discord-youtube'
    Try-Run {
        # zapret ведёт агент (agent\Zapret.cs, Z*.cs) — его состояние из status.json
        $zs = $null; try { $zs = ([IO.File]::ReadAllText($StatusPath) | ConvertFrom-Json).zapret } catch { }
        if (-not $zs) { Write-Host '!! нет данных zapret в status.json (агент не работает?)' }
        else {
            Write-Host "Состояние: $($zs.state)"
            foreach ($d in @($zs.details)) { if ($d) { Write-Host "  $d" } }
            foreach ($kv in @($zs.kv)) { Write-Host ('  {0,-34} {1}' -f $kv[0], $kv[1]) }
            foreach ($r in @($zs.results)) { $bad = @($r.checks | Where-Object { $_ -and -not $_.ok } | ForEach-Object { "$($_.n): $($_.why)" }); Write-Host ("  {0,-32} {1}/{2} {3}" -f $r.name, $r.ok, $r.total, $(if ($bad.Count) { '· не прошли: ' + ($bad -join '; ') } else { '' })) }
        }
        $wc = Get-CimInstance Win32_Process -Filter "Name='winws.exe'" -ErrorAction SilentlyContinue
        if ($wc) { foreach ($x in $wc) { Write-Host "winws PID $($x.ProcessId): $($x.CommandLine.Substring(0, [Math]::Min(160, $x.CommandLine.Length)))…" } } else { Write-Host 'winws: не запущен' }
    }

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
            # раздачу чинит агент на C# (модуль «Раздача») — отправить ему команду и дождаться
            Set-Content (Join-Path $DataDir ("cmd\{0}.cmd" -f [DateTime]::UtcNow.Ticks)) 'reapply-ics' -Encoding ASCII
            Write-Host 'Команда агенту: восстановить раздачу — жду до 60 с…'
            $dl = (Get-Date).AddSeconds(60); do { Start-Sleep -Seconds 3; $st = Get-IcsStatus } while (-not $st.Ok -and (Get-Date) -lt $dl)
            Write-Host ("Итог: '{0}' включён={1} тип={2}; '{3}' включён={4} тип={5}; OK={6}" -f `
                (Get-UplinkName), $st.Public.Enabled, $st.Public.Type, $W.interfaceName, $st.Private.Enabled, $st.Private.Type, $st.Ok)
        }
    }
    Section 'Конец отчёта'
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
