# VpnGuard — HTTP-сервер (процесс «VpnGuard.ps1 -RemoteServer», агент держит его запущенным):
#   • веб-интерфейс (web\index.html + /api/…) — с этого ПК без пароля, из домашней сети и от клиентов wg_server — по паролю web.token;
#   • удалённая диагностика — включается из окна на N часов (remote.*), доступ по одноразовому токену remote.token.
# Ключи и токены в ответах диагностики маскируются; конфиги клиентов WireGuard отдаются только веб-интерфейсу.

$RemoteStatePath = Join-Path $DataDir 'remote-state.json'
$RemoteRule      = 'VpnGuard remote diagnostics'

# команды агенту, которые можно отправить удалённо. $true — прерывают интернет клиентам (нужно remote.allowActions)
$RemoteCmds = [ordered]@{
    'check-now' = $false; 'zapret-check' = $false; 'meduza-catalog' = $false; 'software-check' = $false; 'app-check' = $false; 'app-update' = $false
    'reconnect' = $true; 'reconnect-meduza' = $true; 'reconnect-awg' = $true; 'restart-wg' = $true; 'reapply-ics' = $true
    'zapret-test' = $true; 'zapret-reload' = $true; 'meduza-test' = $true; 'awg-test' = $true; 'dual-switch' = $true
    'meduza-proto-reset' = $true; 'restart-meduza' = $true
}

function Get-RCfg {
    $d = @{ enabled = $false; until = ''; token = ''; port = 8765; allowFrom = 'any'; allowActions = $false }
    if ($Cfg.remote) { foreach ($k in @($Cfg.remote.Keys)) { $d[$k] = $Cfg.remote[$k] } }
    return $d
}
function Get-WCfg {
    $d = @{ enabled = $true; port = 8765; token = '' }
    if ($Cfg.web) { foreach ($k in @($Cfg.web.Keys)) { $d[$k] = $Cfg.web[$k] } }
    return $d
}
function New-WebToken { $b = New-Object byte[] 12; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | ForEach-Object { $_.ToString('x2') }) }
function Get-RemoteUntil($r) { try { if ($r.until) { return [datetime]$r.until } } catch { }; return [datetime]::MinValue }
function Test-RemoteOn($r) { [bool]($r.enabled -and "$($r.token)".Length -ge 16 -and (Get-RemoteUntil $r) -gt (Get-Date)) }

function Hide-Secrets([string]$Text) {
    if (-not $Text) { return $Text }
    $t = [regex]::Replace($Text, '(?im)^(\s*(PrivateKey|PresharedKey)\s*=\s*)\S+', '$1***')
    $t = [regex]::Replace($t, 'vpn://[A-Za-z0-9_\-+/=]+', 'vpn://***')
    $t = [regex]::Replace($t, '("token"\s*:\s*")[^"]*(")', '$1***$2')
    return $t
}

# ---------------------------------------------------------------- агент: держать сервер запущенным, пока включено
function Get-RemoteProc {
    if (-not (Test-Path $RemoteStatePath)) { return $null }
    try { $s = Get-Content $RemoteStatePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
    if (-not $s.pid -or -not $s.running) { return $null }
    $p = Get-Process -Id ([int]$s.pid) -ErrorAction SilentlyContinue
    if ($p -and $p.ProcessName -like 'powershell*') { return $p }
    return $null
}
function Sync-RemoteFirewall($r) {
    $from = $(if (-not (Test-RemoteOn $r) -or "$($r.allowFrom)" -eq 'local') { @('LocalSubnet') + @($(try { $a = Get-WgServerAddress; if ($a) { ($a -replace '\.\d+$', '.0') + '/24' } } catch { })) | Where-Object { $_ } } else { @('Any') })
    # Windows возвращает адреса в своём виде (маска вместо /24) — сравниваем с тем, что ставили сами
    $sig = "$($r.port)|$($from -join ',')"
    $rule = Get-NetFirewallRule -DisplayName $RemoteRule -ErrorAction SilentlyContinue
    $ok = [bool]($rule -and $script:RemoteFwSig -eq $sig)
    if ($rule -and -not $ok -and -not $script:RemoteFwSig) {
        # агент перезапустился: правило уже есть — проверить порт и «откуда» без учёта формата адресов
        $pf = $rule | Get-NetFirewallPortFilter; $af = $rule | Get-NetFirewallAddressFilter
        $isAny = (@($af.RemoteAddress) -join ',') -eq 'Any'
        $ok = ("$($pf.LocalPort)" -eq "$($r.port)") -and ($isAny -eq ($from[0] -eq 'Any'))
    }
    if ($rule -and -not $ok) { Remove-NetFirewallRule -DisplayName $RemoteRule -ErrorAction SilentlyContinue }
    if ($ok) { $script:RemoteFwSig = $sig }
    if (-not $ok) {
        New-NetFirewallRule -DisplayName $RemoteRule -Direction Inbound -Protocol TCP -LocalPort ([int]$r.port) -RemoteAddress $from -Action Allow -Profile Any | Out-Null
        $script:RemoteFwSig = $sig
        Write-Log "Удалённая диагностика: правило брандмауэра — TCP $($r.port), откуда: $($from -join ', ')"
    }
}
function Stop-RemoteServer([string]$Why) {
    $p = Get-RemoteProc
    if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; Write-Log "Веб-сервер VpnGuard остановлен ($Why)" }
    if (Get-NetFirewallRule -DisplayName $RemoteRule -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -DisplayName $RemoteRule -ErrorAction SilentlyContinue }
    if (Test-Path $RemoteStatePath) {
        try { $s = Get-Content $RemoteStatePath -Raw -Encoding UTF8 | ConvertFrom-Json; $s.running = $false; $s | ConvertTo-Json -Depth 5 | Set-Content $RemoteStatePath -Encoding UTF8 } catch { }
    }
}
function Invoke-RemoteWatch {
    $r = Get-RCfg
    if ($r.enabled -and (Get-RemoteUntil $r) -le (Get-Date)) {
        Write-Log 'Удалённая диагностика: время вышло — выключаю'
        Set-ConfigValue 'remote.enabled' $false
        $r = Get-RCfg
    }
    $wc = Get-WCfg
    if (-not $wc.enabled -and -not (Test-RemoteOn $r)) {
        if ((Get-RemoteProc) -or (Get-NetFirewallRule -DisplayName $RemoteRule -ErrorAction SilentlyContinue)) { Stop-RemoteServer 'веб-интерфейс выключен, диагностика выключена' }
        return
    }
    if ($wc.enabled -and "$($wc.token)".Length -lt 12) { Set-ConfigValue 'web.token' (New-WebToken); Write-Log 'Веб-интерфейс: создан пароль для входа с других устройств (виден в окне и в config.json, web.token)' }
    $r.port = [int](Get-WCfg).port
    Sync-RemoteFirewall $r
    if (-not (Get-RemoteProc)) {
        Write-Log "Веб-сервер VpnGuard: запускаю на порту $($r.port)$(if (Test-RemoteOn $r) { " · удалённая диагностика до $((Get-RemoteUntil $r).ToString('dd.MM HH:mm'))" })" 'WARN'
        Start-Process powershell.exe -WindowStyle Hidden -WorkingDirectory $Root `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $Root 'VpnGuard.ps1')`" -RemoteServer" | Out-Null
    }
}
function Get-RemoteSnapshot {
    $r = Get-RCfg
    $s = $null; if (Test-Path $RemoteStatePath) { try { $s = Get-Content $RemoteStatePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
    [ordered]@{
        enabled = (Test-RemoteOn $r); until = $(if ((Get-RemoteUntil $r) -gt [datetime]::MinValue) { (Get-RemoteUntil $r).ToString('o') } else { '' })
        port = [int](Get-WCfg).port; allowActions = [bool]$r.allowActions; allowFrom = "$($r.allowFrom)"; web = [bool](Get-WCfg).enabled
        running = [bool](Get-RemoteProc); error = $(if ($s) { "$($s.error)" } else { '' })
        requests = $(if ($s) { [int]$s.requests } else { 0 }); last = $(if ($s -and $s.last) { "$($s.last)" } else { '' })
    }
}

# ---------------------------------------------------------------- сервер (процесс VpnGuard.ps1 -RemoteServer)
function Invoke-Captured([scriptblock]$Sb) {
    try { (& $Sb 2>&1 | Out-String -Width 260) } catch { "ошибка: $($_.Exception.Message)`n" }
}
function Invoke-PsFile([string]$ArgLine, [int]$TimeoutSec = 240) {
    $psi = New-Object Diagnostics.ProcessStartInfo 'powershell.exe'
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $Root 'VpnGuard.ps1')`" $ArgLine"
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8; $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    $p = [Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; return "таймаут $TimeoutSec с`n" + $o.Result }
    $t = $o.Result; if ($e.Result.Trim()) { $t += "`n===== stderr =====`n" + $e.Result }
    return $t
}

function Get-RLogs([int]$Days = 2, [int]$Minutes = 0, [int]$MaxLines = 5000) {
    $files = @(Get-ChildItem $LogDir -Filter 'vpnguard-*.log' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last ([Math]::Max(1, $Days)))
    $lines = New-Object Collections.Generic.List[string]
    foreach ($f in $files) {
        try { $fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite'); $rd = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8); while ($null -ne ($l = $rd.ReadLine())) { $lines.Add($l) }; $rd.Dispose() } catch { }
    }
    $out = @($lines)
    if ($Minutes -gt 0) {
        $since = (Get-Date).AddMinutes(-$Minutes).ToString('yyyy-MM-dd HH:mm:ss')
        $out = @($out | Where-Object { $_.Length -ge 19 -and $_.Substring(0, 19) -ge $since })
    }
    if ($out.Count -gt $MaxLines) { $out = $out[($out.Count - $MaxLines)..($out.Count - 1)] }
    return ($out -join "`n")
}

function Get-RNet {
    Invoke-Captured {
        '===== ipconfig /all'; & ipconfig.exe /all
        '===== route print -4'; & route.exe print -4
        '===== адаптеры'; Get-NetAdapter | Sort-Object ifIndex | Format-Table ifIndex, Name, InterfaceDescription, Status, LinkSpeed -AutoSize
        '===== IPv4-интерфейсы (метрики, пересылка)'; Get-NetIPInterface -AddressFamily IPv4 | Sort-Object InterfaceMetric | Format-Table ifIndex, InterfaceAlias, InterfaceMetric, AutomaticMetric, ConnectionState, Forwarding, NlMtu -AutoSize
        '===== IPv4-адреса'; Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress, PrefixLength, PrefixOrigin -AutoSize
        '===== DNS-серверы'; Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Format-Table InterfaceAlias, ServerAddresses -AutoSize
        '===== профили сетей'; Get-NetConnectionProfile | Format-Table InterfaceAlias, Name, NetworkCategory, IPv4Connectivity -AutoSize
        '===== правила брандмауэра VpnGuard / WireGuard'; Get-NetFirewallRule | Where-Object { $_.DisplayName -match 'VpnGuard|WireGuard|WS4W|wg_server' } | Format-Table DisplayName, Enabled, Direction, Action, Profile -AutoSize
        '===== прослушиваемые UDP-порты WireGuard'; Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in 51820, 51821, [int]$W.newServerPort } | Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize
    }
}

function Get-Short([string]$t, [int]$n = 300) { $t = ($t -replace '\s+', ' ').Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) + '…' } else { $t } }
function Get-RSystem {
    Invoke-Captured {
        $os = Get-CimInstance Win32_OperatingSystem
        "Windows: $($os.Caption) $($os.Version) (сборка $($os.BuildNumber)) · загрузка $($os.LastBootUpTime) · аптайм $([int]((Get-Date) - $os.LastBootUpTime).TotalHours) ч"
        "PowerShell: $($PSVersionTable.PSVersion) · .NET: $([Environment]::Version) · память свободно $([int]($os.FreePhysicalMemory / 1024)) из $([int]($os.TotalVisibleMemorySize / 1024)) МБ"
        "Агент VpnGuard: $AgentVersion · папка $Root"
        '===== процессы'
        Get-Process | Where-Object { $_.ProcessName -match 'medusa|meduza|winws|wireguard|amnezia|awg|ws4w|WgServer|powershell' } |
            Format-Table Id, ProcessName, @{ n = 'CPU,с'; e = { [int]$_.CPU } }, @{ n = 'МБ'; e = { [int]($_.WorkingSet64 / 1MB) } }, StartTime, Responding -AutoSize
        '===== службы'
        Get-Service | Where-Object { $_.Name -match 'WireGuard|AmneziaWG|SharedAccess|zapret|WinDivert|iphlpsvc|Dnscache|BFE|mpssvc|MeduzaVPN' } | Format-Table Name, Status, StartType, DisplayName -AutoSize
        '===== задачи планировщика'
        Get-ScheduledTask | Where-Object { $_.TaskName -like 'VpnGuard*' } | ForEach-Object { $i = $_ | Get-ScheduledTaskInfo; "$($_.TaskName): $($_.State) · последний запуск $($i.LastRunTime) код $($i.LastTaskResult)" }
        '===== журнал System: ошибки и предупреждения за 48 ч (до 150)'
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3; StartTime = (Get-Date).AddHours(-48) } -MaxEvents 150 -ErrorAction Stop |
                ForEach-Object { '{0:dd.MM HH:mm:ss} [{1}] {2}: {3}' -f $_.TimeCreated, $_.LevelDisplayName, $_.ProviderName, (Get-Short "$($_.Message)") }
        } catch { "нет событий или нет доступа: $($_.Exception.Message)" }
        '===== журнал Application: сбои программ за 7 дней'
        try {
            Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 400 -ErrorAction Stop |
                Where-Object { "$($_.Message)" -match 'medusa|meduza|winws|wireguard|amnezia|powershell' } | Select-Object -First 40 |
                ForEach-Object { '{0:dd.MM HH:mm:ss} {1}: {2}' -f $_.TimeCreated, $_.ProviderName, (Get-Short "$($_.Message)") }
        } catch { "нет событий: $($_.Exception.Message)" }
    }
}

# живые проверки, которые не мешают работе: туннели, внешний IP, DNS, сайты напрямую и через туннель
function Get-RCheck {
    Invoke-Captured {
        $curl = Join-Path $env:windir 'System32\curl.exe'
        $pub = { param($ip) $a = $(if ($ip) { "--interface $ip " } else { '' }); $r = Invoke-Exe $curl ("-s --connect-timeout 4 -m 8 $a" + 'https://api.ipify.org') 12; $(if ($r.Code -eq 0 -and $r.Out) { $r.Out } else { "нет ответа (curl $($r.Code))" }) }
        "Режим: $(Get-VpnMode) · трафик через: '$(Get-ActiveTunnel)' · выход ICS: '$(Get-UplinkName)'"
        $phys = Get-PhysicalPath
        "Физический выход: $(if ($phys) { "$($phys.Alias) IP $($phys.Ip) шлюз $($phys.Gateway) · внешний IP $(& $pub $phys.Ip)" } else { 'не найден' })"
        "Маршрут по умолчанию: внешний IP $(& $pub '')"
        '===== туннели'
        foreach ($k in 'meduza', 'amnezia') {
            $n = Get-KindAdapter $k
            $ad = $(if ($n) { Get-NetAdapter -Name $n -ErrorAction SilentlyContinue } else { $null })
            if (-not $ad) { "${k}: адаптер '$n' отсутствует"; continue }
            $ip = Get-AdapterIPv4 $n
            $pr = @(foreach ($h in $M.probeHosts) { $sw = [Diagnostics.Stopwatch]::StartNew(); $ok = ($ip -and (Test-TcpVia $ip $h 3000)); "$h=$(if ($ok) { "$($sw.ElapsedMilliseconds) мс" } else { 'НЕТ' })" })
            $met = (Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric
            "${k}: '$n' $($ad.Status) IP $ip метрика $met · $($pr -join ', ')$(if ($ip -and $ad.Status -eq 'Up') { ' · внешний IP ' + (& $pub $ip) })"
        }
        if ($k = Get-AmneziaActive) { try { $ti = Get-AwgTunnelInfo $k; if ($ti) { "awg: сервер $($ti.Endpoint) · рукопожатие $($ti.HsAgo) с назад · принято $($ti.Rx) · отправлено $($ti.Tx)" } } catch { } }
        '===== DNS'
        foreach ($d in 'www.youtube.com', 'redirector.googlevideo.com', 'discord.com', 'api.ipify.org') {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try { $a = @(Resolve-DnsName $d -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }); "$d → $($a -join ', ') ($($sw.ElapsedMilliseconds) мс)" } catch { "$d → ошибка: $($_.Exception.Message)" }
        }
        $fmt = { param($list) foreach ($r in $list) { '  {0,-30} {1,-4} {2,-40} {3,6} мс {4,6} КБ  {5}' -f $r.Label, $(if ($r.Ok) { 'OK' } else { 'НЕТ' }), $r.Host, $r.Ms, $r.Kb, $r.Why } }
        if ($phys) { '===== сайты напрямую (мимо VPN, как их видит zapret)'; & $fmt @(Test-ZapretTargets $phys.Ip @(Get-ZTargets) 5) }
        $tun = Get-ActiveTunnel
        $zr = @($ZState.routes).Count
        # скорость: 10 МБ с Cloudflare (не в маршрутах zapret) — напрямую и через туннель
        '===== скорость загрузки (10 МБ с speed.cloudflare.com, до 20 с)'
        $spd = { param($ip, $name) $a = $(if ($ip) { "--interface $ip " } else { '' }); $r = Invoke-Exe $curl ("-s -o NUL --connect-timeout 5 -m 20 -w ""%{speed_download} %{size_download}"" $a" + '"https://speed.cloudflare.com/__down?bytes=10000000"') 25
            $pp = "$($r.Out)" -split '\s+'; $v = 0.0; [void][double]::TryParse($pp[0], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$v)
            '  {0,-28} {1,8:N1} Мбит/с  ({2:N1} МБ, curl {3})' -f $name, ($v * 8 / 1e6), ([double]$pp[1] / 1MB), $r.Code }
        if ($phys) { & $spd $phys.Ip "напрямую ($($phys.Alias))" }
        foreach ($k in 'meduza', 'amnezia') { $n = Get-KindAdapter $k; if ($n -and (Get-UpAdapter $n)) { & $spd (Get-AdapterIPv4 $n) "через туннель $n" } }
        if ($zr) { "===== маршрутов zapret мимо VPN: $zr — YouTube/Discord идут через физический адаптер, поэтому проверка «через туннель» для них не показательна (пакеты с адресом туннеля уходят не туда)" }
        if ($tun -and (Get-UpAdapter $tun) -and -not $zr) { "===== сайты через туннель '$tun'"; & $fmt @(Test-ZapretTargets (Get-AdapterIPv4 $tun) @('https://www.youtube.com', 'get https://www.youtube.com/', 'ytvideo', 'https://discord.com', 'https://gateway.discord.gg') 6) }
        '===== клиенты wg_server'
        $pe = $null; try { $pe = Get-WgPeers } catch { }
        if ($pe) { "активных $($pe.Active) из $($pe.Total), порт $($pe.Port)"; foreach ($p in @($pe.List)) { '  {0,-20} {1,-16} рукопожатие {2,6} с  ↓{3} ↑{4}  {5}' -f $p.name, $p.ip, $p.hsAgo, $p.tx, $p.rx, $p.endpoint } } else { 'нет данных (туннель не поднят или нет wg.exe)' }
    }
}

function Get-RFiles {
    $o = [ordered]@{}
    foreach ($n in 'status.json', 'state.json', 'zapret-state.json', 'zapret-test.json', 'remote-state.json') {
        $p = Join-Path $DataDir $n
        if (Test-Path $p) { try { $o[$n] = Get-Content $p -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $o[$n] = "не читается: $($_.Exception.Message)" } }
    }
    $c = $null; if (Test-Path $ConfigPath) { try { $c = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
    $o['config.json'] = $c
    $o['config (с умолчаниями)'] = $Cfg
    $o['amnezia-конфиги'] = @(try { Get-AmneziaConfigs | ForEach-Object { [ordered]@{ name = $_.name; title = $_.title; endpoint = $_.endpoint; address = $_.address } } } catch { })
    $o['data'] = @(Get-ChildItem $DataDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\(downloads|logs)\\' } | ForEach-Object { '{0}  {1:N0} Б  {2:dd.MM HH:mm}' -f $_.FullName.Substring($DataDir.Length + 1), $_.Length, $_.LastWriteTime })
    return (Hide-Secrets ($o | ConvertTo-Json -Depth 8))
}

function Get-RIndex($r) {
    @"
VpnGuard $AgentVersion — удалённая диагностика (включена до $((Get-RemoteUntil $r).ToString('dd.MM.yyyy HH:mm')))
Токен — заголовок X-Token или параметр ?t=…

GET /status              состояние агента (status.json)
GET /check               живые проверки: туннели, внешний IP, DNS, сайты напрямую и через туннель, клиенты wg_server
GET /diag                полный отчёт «Диагностика» (до 3 мин)
GET /net                 сеть: ipconfig, маршруты, метрики, DNS, брандмауэр
GET /system              Windows, процессы, службы, задачи, журналы событий
GET /logs?days=2         журнал агента (можно minutes=30, lines=5000)
GET /files               config.json, state, zapret-state, результаты подбора, список data
GET /bundle              всё сразу (кроме /diag; добавьте ?diag=1)
GET /cmd?c=…             команда агенту: $(($RemoteCmds.Keys | Where-Object { -not $RemoteCmds[$_] }) -join ', ')
                         $(if ($r.allowActions) { 'разрешены и прерывающие: ' + (($RemoteCmds.Keys | Where-Object { $RemoteCmds[$_] }) -join ', ') } else { 'прерывающие интернет (тесты протоколов/стратегий, переподключение) — выключены в окне' })
"@
}

function Send-RResponse($Ctx, [int]$Code, [string]$Body, [string]$Type = 'text/plain; charset=utf-8') {
    Send-RBytes $Ctx $Code ([Text.Encoding]::UTF8.GetBytes($Body)) $Type
}
function Send-RBytes($Ctx, [int]$Code, [byte[]]$Bytes, [string]$Type) {
    $Ctx.Response.StatusCode = $Code; $Ctx.Response.ContentType = $Type
    $Ctx.Response.Headers['Cache-Control'] = 'no-store'
    $Ctx.Response.Headers['X-Content-Type-Options'] = 'nosniff'
    $Ctx.Response.Headers['X-Frame-Options'] = 'DENY'
    try { $Ctx.Response.OutputStream.Write($Bytes, 0, $Bytes.Length) } catch { }
    try { $Ctx.Response.Close() } catch { }
}
function Send-RJson($Ctx, $Obj, [int]$Code = 200) { Send-RResponse $Ctx $Code ($Obj | ConvertTo-Json -Depth 8 -Compress) 'application/json; charset=utf-8' }

# команды веб-интерфейса — то же, что кнопки окна
$WebCmds = @('check-now', 'reconnect', 'reconnect-meduza', 'reconnect-awg', 'restart-meduza', 'restart-wg', 'reapply-ics', 'check-update',
    'zapret-on', 'zapret-off', 'zapret-test', 'zapret-update', 'zapret-reload', 'zapret-check', 'meduza-test', 'meduza-catalog', 'meduza-proto-reset',
    'awg-test', 'software-check', 'install-missing', 'app-check', 'app-update', 'dual-switch')
# настройки, которые можно менять из веб-интерфейса, с проверкой значения
$WebCfgKeys = [ordered]@{
    'vpn.mode'         = '^(meduza|amnezia|dual|zapret)$'
    'vpn.primary'      = '^(meduza|amnezia)$'
    'zapret.strategy'  = '^[\w \(\)\-\.]{0,60}$'
    'meduza.serviceId' = '^[\w \-\.\(\)]{0,100}$'
    'meduza.protocol'  = '^[a-z0-9\-]{1,40}$'
    'amnezia.active'   = '^[a-z0-9_=+.\-]{1,32}$'
    'update.auto'      = 'bool'
    'zapret.videoCheck' = 'bool'
}

# адрес в запросе должен быть IP или именем этого ПК — защита от DNS rebinding
function Test-RHost($Req) {
    $h = "$($Req.Url.Host)".ToLower()
    if ($h -eq 'localhost' -or $h -eq "$env:COMPUTERNAME".ToLower()) { return $true }
    $ip = $null; return [Net.IPAddress]::TryParse($h.Trim('[', ']'), [ref]$ip)
}
function Read-RBody($Req) {
    if (-not $Req.HasEntityBody) { return $null }
    $t = (New-Object IO.StreamReader($Req.InputStream, [Text.Encoding]::UTF8)).ReadToEnd()
    if ($t.Length -gt 65536) { return $null }
    try { return ($t | ConvertFrom-Json) } catch { return $null }
}
$script:QrReady = $false
function Get-QrPng([string]$Text) {
    if (-not $script:QrReady) {
        Add-Type -AssemblyName System.Drawing
        if (-not ('VpnGuard.Qr' -as [type])) { Add-Type -TypeDefinition (Get-Content (Join-Path $Root 'Qr.cs') -Raw -Encoding UTF8) }
        $script:QrReady = $true
    }
    $mt = [VpnGuard.Qr]::Encode($Text, 1, 0, -1)
    $n = $mt.GetLength(0); $q = 4; $px = 8
    $bmp = New-Object Drawing.Bitmap (($n + 2 * $q) * $px), (($n + 2 * $q) * $px)
    $g = [Drawing.Graphics]::FromImage($bmp); $g.Clear([Drawing.Color]::White)
    for ($y = 0; $y -lt $n; $y++) { for ($x = 0; $x -lt $n; $x++) { if ($mt[$y, $x]) { $g.FillRectangle([Drawing.Brushes]::Black, ($x + $q) * $px, ($y + $q) * $px, $px, $px) } } }
    $g.Dispose()
    $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
    return $ms.ToArray()
}
function Get-RWgClient([string]$Ip) {
    $l = Get-WgClients
    @($l.Clients) | Where-Object { "$($_.Ip)" -eq $Ip } | Select-Object -First 1
}
function Send-RCmd([string]$C, [string]$From) {
    Set-Content -Path (Join-Path $CmdDir ('{0}.cmd' -f [DateTime]::UtcNow.Ticks)) -Value $C -Encoding ASCII
    Write-Log "Веб-интерфейс: команда агенту '$C' ($From)"
}

function Invoke-RemoteRequest($Ctx, $r) {
    $req = $Ctx.Request
    $ip = "$($req.RemoteEndPoint.Address)"
    $path = $req.Url.AbsolutePath.TrimEnd('/').ToLower(); if (-not $path) { $path = '/' }
    $q = $req.QueryString
    $wc = Get-WCfg
    if (-not (Test-RHost $req)) { Send-RResponse $Ctx 400 'неверный адрес'; return }

    # кто спрашивает: этот ПК — веб без пароля; пароль web.token — веб; токен диагностики — диагностика
    $tok = "$($req.Headers['X-Token'])"; if (-not $tok) { $tok = "$($q['t'])" }
    if (-not $tok -and $req.Cookies['vg']) { $tok = "$($req.Cookies['vg'].Value)" }
    $role = ''
    if ($wc.enabled -and ($req.IsLocal -or ("$($wc.token)".Length -ge 12 -and $tok -ceq "$($wc.token)"))) { $role = 'web' }
    elseif ((Test-RemoteOn $r) -and $tok -and $tok -ceq "$($r.token)") { $role = 'diag' }

    # страница веб-интерфейса доступна всем (в ней нет данных — их отдаёт /api после входа)
    if ($path -in '/', '/index.html' -and $wc.enabled -and -not ($role -eq 'diag' -and $req.Headers['X-Token'])) {
        $f = Join-Path $Root 'web\index.html'
        if (Test-Path $f) { Send-RBytes $Ctx 200 ([IO.File]::ReadAllBytes($f)) 'text/html; charset=utf-8' } else { Send-RResponse $Ctx 404 'нет файла web\index.html' }
        return
    }
    if ($path -eq '/api/login' -and $req.HttpMethod -eq 'POST') {
        $b = Read-RBody $req
        $ban = $script:RBad[$ip]
        if ($ban -and $ban.Until -gt (Get-Date)) { Send-RJson $Ctx @{ ok = $false; error = 'слишком много попыток, подождите 15 минут' } 403; return }
        if ($wc.enabled -and $b -and "$($wc.token)".Length -ge 12 -and "$($b.password)" -ceq "$($wc.token)") {
            $script:RBad.Remove($ip)
            $Ctx.Response.Headers.Add('Set-Cookie', "vg=$($wc.token); Path=/; Max-Age=2592000; HttpOnly; SameSite=Strict")
            Write-Log "Веб-интерфейс: вход с $ip"
            Send-RJson $Ctx @{ ok = $true }; return
        }
        if (-not $ban -or ($ban.Until -ne [datetime]::MinValue -and $ban.Until -le (Get-Date))) { $ban = @{ Count = 0; Until = [datetime]::MinValue } }
        $ban.Count++; if ($ban.Count -ge 10) { $ban.Until = (Get-Date).AddMinutes(15); Write-Log "Веб-интерфейс: $ip — 10 неверных паролей, блокирую на 15 мин" 'WARN' }
        $script:RBad[$ip] = $ban
        Send-RJson $Ctx @{ ok = $false; error = 'неверный пароль' } 401; return
    }
    if ($path -eq '/api/whoami') { Send-RJson $Ctx @{ role = $role; local = [bool]$req.IsLocal; version = $AgentVersion }; return }

    if (-not $role) {
        $ban = $script:RBad[$ip]
        if ($ban -and $ban.Until -gt (Get-Date)) { Send-RResponse $Ctx 403 'слишком много неверных токенов, подождите 15 минут'; return }
        if ($tok) {
            if (-not $ban -or ($ban.Until -ne [datetime]::MinValue -and $ban.Until -le (Get-Date))) { $ban = @{ Count = 0; Until = [datetime]::MinValue } }
            $ban.Count++; if ($ban.Count -ge 10) { $ban.Until = (Get-Date).AddMinutes(15); Write-Log "Удалённый доступ: $ip — 10 неверных токенов, блокирую на 15 мин" 'WARN' }
            $script:RBad[$ip] = $ban
        }
        Send-RResponse $Ctx 401 'нужен вход: пароль веб-интерфейса или токен диагностики (X-Token или ?t=)'; return
    }
    # изменения — только POST с заголовком X-VG (чужая страница в браузере так отправить не сможет)
    $isApiWrite = $path -like '/api/*' -and $path -notin '/api/status', '/api/logs', '/api/wg/clients', '/api/wg/conf', '/api/wg/qr', '/api/whoami'
    if ($isApiWrite -and ($req.HttpMethod -ne 'POST' -or -not $req.Headers['X-VG'])) { Send-RResponse $Ctx 405 'нужен POST с заголовком X-VG'; return }

    $script:RState.requests++; $script:RState.last = "$(Get-Date -Format 'dd.MM HH:mm:ss') $ip $path"
    Save-RState
    if ($role -eq 'diag' -and $path -ne '/status') { Write-Log "Удалённая диагностика: $ip запросил $path$(if ($q['c']) { " ($($q['c']))" })" }
    $int = { param($n, $d) $v = 0; if ([int]::TryParse("$($q[$n])", [ref]$v)) { $v } else { $d } }
    $readStatus = { if (Test-Path $StatusPath) { [IO.File]::ReadAllText($StatusPath, [Text.Encoding]::UTF8) } else { '{}' } }
    $webOnly = { if ($role -ne 'web') { Send-RResponse $Ctx 403 'только для веб-интерфейса'; return $false }; return $true }

    switch ($path) {
        # ---------------- веб-интерфейс
        '/api/status' { Send-RResponse $Ctx 200 (Hide-Secrets (& $readStatus)) 'application/json; charset=utf-8' }
        '/api/logs'   { Send-RResponse $Ctx 200 (Hide-Secrets (Get-RLogs (& $int 'days' 1) (& $int 'minutes' 0) (& $int 'lines' 3000))) }
        '/api/cmd' {
            $b = Read-RBody $req; $c = "$($b.c)"
            if ($role -eq 'diag') {
                if (-not $RemoteCmds.Contains($c)) { Send-RJson $Ctx @{ ok = $false; error = "команда '$c' недоступна" } 400; return }
                if ($RemoteCmds[$c] -and -not $r.allowActions) { Send-RJson $Ctx @{ ok = $false; error = 'прерывающие команды выключены в окне' } 403; return }
            } elseif ($WebCmds -notcontains $c -and $c -notmatch '^install [a-z]+$') { Send-RJson $Ctx @{ ok = $false; error = "неизвестная команда '$c'" } 400; return }
            Send-RCmd $c "$role, $ip"
            Send-RJson $Ctx @{ ok = $true }
        }
        '/api/config' {
            if (-not (& $webOnly)) { return }
            $b = Read-RBody $req; $k = "$($b.key)"; $v = $b.value
            if (-not $WebCfgKeys.Contains($k)) { Send-RJson $Ctx @{ ok = $false; error = "настройку '$k' здесь менять нельзя" } 400; return }
            $rule = $WebCfgKeys[$k]
            if ($rule -eq 'bool') { $v = [bool]$v } elseif ("$v" -notmatch $rule) { Send-RJson $Ctx @{ ok = $false; error = "недопустимое значение для $k" } 400; return } else { $v = "$v" }
            Set-ConfigValue $k $v
            Write-Log "Веб-интерфейс: $k = '$v' ($ip)"
            Send-RCmd 'check-now' "после изменения $k"
            Send-RJson $Ctx @{ ok = $true }
        }
        '/api/wg/clients' {
            if (-not (& $webOnly)) { return }
            try { $l = Get-WgClients; Send-RJson $Ctx @{ ok = $true; endpoint = "$($l.Endpoint)"; clients = @(@($l.Clients) | ForEach-Object { [ordered]@{ name = "$($_.Name)"; ip = "$($_.Ip)"; source = "$($_.Source)"; hasConf = [bool]($_.File -and (Test-Path $_.File)) } }) } }
            catch { Send-RJson $Ctx @{ ok = $false; error = $_.Exception.Message } 500 }
        }
        '/api/wg/conf' {
            if (-not (& $webOnly)) { return }
            $c = Get-RWgClient "$($q['ip'])"
            if (-not $c -or -not $c.File -or -not (Test-Path $c.File)) { Send-RJson $Ctx @{ ok = $false; error = 'конфиг этого клиента на ПК не хранится — удалите и создайте заново' } 404; return }
            Send-RJson $Ctx @{ ok = $true; name = "$($c.Name)"; text = [IO.File]::ReadAllText($c.File) }
        }
        '/api/wg/qr' {
            if (-not (& $webOnly)) { return }
            $c = Get-RWgClient "$($q['ip'])"
            if (-not $c -or -not $c.File -or -not (Test-Path $c.File)) { Send-RResponse $Ctx 404 'нет конфига'; return }
            Send-RBytes $Ctx 200 (Get-QrPng ([IO.File]::ReadAllText($c.File))) 'image/png'
        }
        '/api/wg/add' {
            if (-not (& $webOnly)) { return }
            $b = Read-RBody $req; $n = "$($b.name)".Trim()
            if ($n -notmatch '^[\w\- \.а-яА-ЯёЁ]{1,40}$') { Send-RJson $Ctx @{ ok = $false; error = 'имя: буквы, цифры, пробел, - _ . (до 40)' } 400; return }
            try { $c = New-WgClient $n; Write-Log "Веб-интерфейс: создан клиент WireGuard «$($c.Name)» $($c.Ip) ($ip)"; Send-RJson $Ctx @{ ok = $true; name = "$($c.Name)"; ip = "$($c.Ip)"; text = "$($c.Text)" } }
            catch { Send-RJson $Ctx @{ ok = $false; error = $_.Exception.Message } 500 }
        }
        '/api/wg/remove' {
            if (-not (& $webOnly)) { return }
            $b = Read-RBody $req; $c = Get-RWgClient "$($b.ip)"
            if (-not $c) { Send-RJson $Ctx @{ ok = $false; error = 'клиент не найден' } 404; return }
            try { $n = Remove-WgClient $c.PublicKey; Write-Log "Веб-интерфейс: удалён клиент WireGuard «$n» ($ip)"; Send-RJson $Ctx @{ ok = $true; name = "$n" } }
            catch { Send-RJson $Ctx @{ ok = $false; error = $_.Exception.Message } 500 }
        }
        # ---------------- удалённая диагностика (и веб)
        '/'        { Send-RResponse $Ctx 200 (Get-RIndex $r) }
        '/status'  { Send-RResponse $Ctx 200 (Hide-Secrets (& $readStatus)) 'application/json; charset=utf-8' }
        '/check'   { Send-RResponse $Ctx 200 (Hide-Secrets (Get-RCheck)) }
        '/diag'    { Send-RResponse $Ctx 200 (Hide-Secrets (Invoke-PsFile '-Diag' 240)) }
        '/net'     { Send-RResponse $Ctx 200 (Hide-Secrets (Get-RNet)) }
        '/system'  { Send-RResponse $Ctx 200 (Hide-Secrets (Get-RSystem)) }
        '/logs'    { Send-RResponse $Ctx 200 (Hide-Secrets (Get-RLogs (& $int 'days' 2) (& $int 'minutes' 0) (& $int 'lines' 5000))) }
        '/files'   { Send-RResponse $Ctx 200 (Get-RFiles) 'application/json; charset=utf-8' }
        '/bundle'  {
            $sb = New-Object Text.StringBuilder
            foreach ($part in @(@('СИСТЕМА', { Get-RSystem }), @('ЖИВЫЕ ПРОВЕРКИ', { Get-RCheck }), @('СЕТЬ', { Get-RNet }), @('ФАЙЛЫ И НАСТРОЙКИ', { Get-RFiles }), @('ЖУРНАЛ (2 дня)', { Get-RLogs 2 0 4000 }))) {
                [void]$sb.AppendLine("`n################ $($part[0]) ################"); [void]$sb.AppendLine((& $part[1]))
            }
            if ($q['diag'] -eq '1') { [void]$sb.AppendLine("`n################ ДИАГНОСТИКА ################"); [void]$sb.AppendLine((Invoke-PsFile '-Diag' 240)) }
            Send-RResponse $Ctx 200 (Hide-Secrets $sb.ToString())
        }
        '/cmd' {
            $c = "$($q['c'])"
            if (-not $RemoteCmds.Contains($c)) { Send-RResponse $Ctx 400 "неизвестная команда '$c'. Можно: $($RemoteCmds.Keys -join ', ')"; return }
            if ($RemoteCmds[$c] -and -not $r.allowActions -and $role -ne 'web') { Send-RResponse $Ctx 403 "команда '$c' прерывает интернет клиентам — разрешите такие команды в окне (Диагностика → Удалённая диагностика)"; return }
            Send-RCmd $c "$role, $ip"
            Send-RResponse $Ctx 200 "команда '$c' отправлена агенту; результат — в /logs?minutes=10 и /status"
        }
        default    { Send-RResponse $Ctx 404 "нет такого адреса. Список: /" }
    }
}

function Save-RState { try { $script:RState | ConvertTo-Json -Depth 4 | Set-Content $RemoteStatePath -Encoding UTF8 } catch { } }
function Test-ServerNeeded($r) { (Get-WCfg).enabled -or (Test-RemoteOn $r) }

function Invoke-RemoteServer {
    $r = Get-RCfg; $wc = Get-WCfg
    $port = [int]$wc.port
    $script:RState = [ordered]@{ pid = $PID; running = $true; started = (Get-Date).ToString('o'); port = $port; requests = 0; last = ''; error = '' }
    $script:RBad = @{}
    if (-not (Test-ServerNeeded $r)) { $script:RState.running = $false; $script:RState.error = 'веб-интерфейс и диагностика выключены'; Save-RState; return }
    $l = New-Object Net.HttpListener
    $l.Prefixes.Add("http://+:$port/")
    try { $l.Start() } catch { $script:RState.running = $false; $script:RState.error = "порт ${port}: $($_.Exception.Message)"; Save-RState; Write-Log "Веб-сервер VpnGuard: не удалось открыть порт ${port}: $($_.Exception.Message)" 'ERROR'; return }
    Save-RState
    Write-Log "Веб-сервер VpnGuard: слушает TCP $port (PID $PID) — откройте http://localhost:$port/"
    $stamp = $(try { (Get-Item $ConfigPath).LastWriteTimeUtc } catch { $null })
    $codeStamp = { (@('Remote.ps1', 'VpnGuard.ps1', 'Zapret.ps1', 'Amnezia.ps1', 'Update.ps1', 'Wg.ps1') | ForEach-Object { $f = Join-Path $Root $_; if (Test-Path $f) { (Get-Item $f).LastWriteTimeUtc.Ticks } }) -join '|' }
    $code = & $codeStamp
    try {
        while ($true) {
            $task = $l.GetContextAsync()
            while (-not $task.Wait(2000)) {
                # перечитать настройки; всё выключили / сменили порт / код обновили — выйти (агент перезапустит новый)
                $now = $(try { (Get-Item $ConfigPath).LastWriteTimeUtc } catch { $null })
                if ($now -ne $stamp) { $stamp = $now; try { Import-Config } catch { }; $r = Get-RCfg }
                if (-not (Test-ServerNeeded $r) -or [int](Get-WCfg).port -ne $port) { return }
                if ((& $codeStamp) -ne $code) { Write-Log 'Веб-сервер VpnGuard: код обновлён — перезапуск'; return }
            }
            $ctx = $task.Result
            try { Invoke-RemoteRequest $ctx $r } catch { try { Send-RResponse $ctx 500 "ошибка: $($_.Exception.Message)" } catch { } }
        }
    } finally {
        try { $l.Stop(); $l.Close() } catch { }
        $script:RState.running = $false; Save-RState
    }
}
