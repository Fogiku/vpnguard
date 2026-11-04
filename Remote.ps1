# VpnGuard — веб-сервер (bin\VpnGuardWeb.exe из Web.cs; часть PowerShell держит его запущенным) и задачи для него (-WebTask):
#   • веб-интерфейс (web\index.html + /api/…) — с этого ПК без пароля, из домашней сети и от клиентов wg_server — по паролю web.token;
#   • удалённая диагностика — включается из окна на N часов (remote.*), доступ по одноразовому токену remote.token.
# Ключи и токены в ответах диагностики маскируются; конфиги клиентов WireGuard отдаются только веб-интерфейсу.

$RemoteStatePath = Join-Path $DataDir 'remote-state.json'
$RemoteRule      = 'VpnGuard remote diagnostics'

function Get-RCfg {
    $d = @{ enabled = $false; until = ''; token = ''; port = 8765; allowFrom = 'any'; allowActions = $false }
    if ($Cfg.remote) { foreach ($k in @($Cfg.remote.Keys)) { $d[$k] = $Cfg.remote[$k] } }
    return $d
}
function Get-WCfg {
    $d = @{ enabled = $true; port = 8765; token = ''; requirePassword = $true }
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
    if ($p -and ($p.ProcessName -like 'powershell*' -or $p.ProcessName -eq 'VpnGuardWeb')) { return $p }
    return $null
}

# ---------------------------------------------------------------- сервер на C#: собрать встроенным csc.exe (.NET Framework) и запустить
$WebExe = Join-Path $(if ($BinDir) { $BinDir } else { Join-Path $Root 'bin' }) 'VpnGuardWeb.exe'
function Get-Csc {
    foreach ($c in "$env:windir\Microsoft.NET\Framework64\v4.0.30319\csc.exe", "$env:windir\Microsoft.NET\Framework\v4.0.30319\csc.exe") { if (Test-Path $c) { return $c } }
    return ''
}
# собрать программу на C# из исходников рядом (встроенный csc.exe .NET Framework); подпись = sha256 исходников
$script:CsBuildFail = @{}
function Build-CsExe([string]$Exe, [string[]]$Sources, [string]$Target, [string[]]$Refs) {
    $src = @($Sources | ForEach-Object { Join-Path $Root $_ })
    if (@($src | Where-Object { -not (Test-Path $_) }).Count) { return $false }
    $sig = (@($src | ForEach-Object { (Get-FileHash $_ -Algorithm SHA256).Hash }) -join '|')
    if ((Test-Path $Exe) -and "$(Get-Content "$Exe.sig" -Raw -ErrorAction SilentlyContinue)".Trim() -eq $sig) { return $true }
    if ($script:CsBuildFail[$Exe] -eq $sig) { return $false }
    $csc = Get-Csc
    if (-not $csc) { $script:CsBuildFail[$Exe] = $sig; Write-Log "Сборка $(Split-Path $Exe -Leaf): нет компилятора .NET (csc.exe)" 'WARN'; return $false }
    $name = [IO.Path]::GetFileNameWithoutExtension($Exe)
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
    New-Item -ItemType Directory (Split-Path $Exe) -Force | Out-Null
    $tmp = "$Exe.new"; Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    $r = Invoke-Exe $csc ("/nologo /target:$Target /optimize+ /out:`"$tmp`" " + (($Refs | ForEach-Object { "/r:$_" }) -join ' ') + ' ' + (($src | ForEach-Object { "`"$_`"" }) -join ' ')) 180
    if ($r.Code -ne 0 -or -not (Test-Path $tmp)) {
        $script:CsBuildFail[$Exe] = $sig
        Write-Log "Сборка $name не удалась (код $($r.Code)): $((("$($r.Out) $($r.Err)" -split "`n") | Where-Object { $_ -match 'error' } | Select-Object -First 3) -join ' | ')" 'ERROR'
        return $false
    }
    Move-Item $tmp $Exe -Force
    Set-Content "$Exe.sig" $sig -Encoding ASCII
    Write-Log "Собрано на C#: $name ($([int]((Get-Item $Exe).Length / 1KB)) КБ)"
    return $true
}

# ---------------------------------------------------------------- значок у часов (вместо окна): задача VpnGuardMonitor и ярлык открывают его
$TrayExe = Join-Path $(if ($BinDir) { $BinDir } else { Join-Path $Root 'bin' }) 'VpnGuardTray.exe'
$script:TrayCheckAt = [datetime]::MinValue
function Invoke-TrayWatch {
    if (((Get-Date) - $script:TrayCheckAt).TotalMinutes -lt 5) { return }
    $script:TrayCheckAt = Get-Date
    $t = Get-ScheduledTask -TaskName 'VpnGuardMonitor' -ErrorAction SilentlyContinue
    if (-not $t) { return }
    $want = -not ($Cfg.ui -and $Cfg.ui.tray -eq $false)
    $isTray = "$($t.Actions[0].Execute)" -like '*VpnGuardTray.exe'
    if ($want) {
        $was = [bool](Get-Process VpnGuardTray -ErrorAction SilentlyContinue)
        if (-not (Build-CsExe $TrayExe @('Tray.cs') 'winexe' @('System.Windows.Forms.dll', 'System.Drawing.dll', 'System.Web.Extensions.dll'))) { return }
        if ($was -and $isTray -and -not (Get-Process VpnGuardTray -ErrorAction SilentlyContinue)) { & schtasks.exe /run /tn VpnGuardMonitor | Out-Null }   # пересобран — запустить снова
        if (-not $isTray) {
            $trig = @($t.Triggers | Where-Object { $_ })        # у задачи может не быть триггеров — без пустых элементов
            if (-not @($trig | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' }).Count) { $trig += New-ScheduledTaskTrigger -AtLogOn -User $t.Principal.UserId }
            Set-ScheduledTask -TaskName 'VpnGuardMonitor' -Action (New-ScheduledTaskAction -Execute $TrayExe -Argument "`"$Root`"" -WorkingDirectory $Root) -Trigger $trig | Out-Null
            Write-Log 'Значок у часов: ярлык VpnGuard и вход в Windows теперь открывают значок (веб-интерфейс по щелчку); классическое окно — в меню значка' 'WARN'
            if (-not (Get-Process VpnGuardTray -ErrorAction SilentlyContinue)) { & schtasks.exe /run /tn VpnGuardMonitor | Out-Null }
        }
    } elseif ($isTray) {
        Set-ScheduledTask -TaskName 'VpnGuardMonitor' -Action (New-HiddenPsAction (Join-Path $Root 'VpnGuardMonitor.ps1')) | Out-Null
        Get-Process VpnGuardTray -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Log 'Значок у часов выключен (ui.tray = false): ярлык снова открывает классическое окно'
    }
}

# веб-сервер на C# (Web.cs + Qr.cs → bin\VpnGuardWeb.exe)
function Build-WebExe { Build-CsExe $WebExe @('Web.cs', 'Qr.cs') 'exe' @('System.Web.Extensions.dll', 'System.Drawing.dll') }
function Start-WebServer {
    if (-not (Build-WebExe)) { return '' }
    $a = "`"$Root`""; if ($ConfigPath -ne (Join-Path $Root 'config.json')) { $a += " `"$ConfigPath`"" }
    Start-Process $WebExe -ArgumentList $a -WindowStyle Hidden -WorkingDirectory $Root | Out-Null
    return 'C#'
}

# ---------------------------------------------------------------- задачи для сервера на C# (VpnGuard.ps1 -WebTask имя [-WebArg base64])
function Invoke-WebTask([string]$Task, [string]$Arg) {
    [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
    $argText = $(if ($Arg) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Arg)) } else { '' })
    $out = { param($o) [Console]::Out.Write(($o | ConvertTo-Json -Depth 6 -Compress)) }
    try {
        switch ($Task) {
            'check'  { [Console]::Out.Write((Get-RCheck)) }
            'net'    { [Console]::Out.Write((Get-RNet)) }
            'system' { [Console]::Out.Write((Get-RSystem)) }
            'files'  { [Console]::Out.Write((Get-RFiles)) }
            'diag'   { Invoke-Diag }
            { $_ -in 'bundle', 'bundle-diag' } {
                foreach ($part in @(@('СИСТЕМА', { Get-RSystem }), @('ЖИВЫЕ ПРОВЕРКИ', { Get-RCheck }), @('СЕТЬ', { Get-RNet }), @('ФАЙЛЫ И НАСТРОЙКИ', { Get-RFiles }), @('ЖУРНАЛ (2 дня)', { Get-RLogs 2 0 4000 }))) {
                    [Console]::Out.WriteLine("`n################ $($part[0]) ################"); [Console]::Out.WriteLine((& $part[1]))
                }
                if ($Task -eq 'bundle-diag') { [Console]::Out.WriteLine("`n################ ДИАГНОСТИКА ################"); Invoke-Diag }
            }
            'wg-clients' {
                $l = Get-WgClients
                & $out ([ordered]@{ ok = $true; endpoint = "$($l.Endpoint)"; clients = @(@($l.Clients) | ForEach-Object { [ordered]@{ name = "$($_.Name)"; ip = "$($_.Ip)"; source = "$($_.Source)"; hasConf = [bool]($_.File -and (Test-Path $_.File)); dns = $(if ($_.File -and (Test-Path $_.File)) { $dl = Select-String -Path $_.File -Pattern '^\s*DNS\s*=\s*(.+)$' | Select-Object -First 1; if ($dl) { $dl.Matches[0].Groups[1].Value.Trim() } else { '' } } else { '' }) } }) })
            }
            'wg-conf' {
                $c = Get-RWgClient $argText
                if (-not $c -or -not $c.File -or -not (Test-Path $c.File)) { & $out @{ ok = $false; error = 'конфиг этого клиента на ПК не хранится — удалите и создайте заново' } }
                else { & $out ([ordered]@{ ok = $true; name = "$($c.Name)"; text = [IO.File]::ReadAllText($c.File) }) }
            }
            'wg-add'    { $c = New-WgClient $argText; & $out ([ordered]@{ ok = $true; name = "$($c.Name)"; ip = "$($c.Ip)"; text = "$($c.Text)" }) }
            'wg-remove' {
                $c = Get-RWgClient $argText
                if (-not $c) { & $out @{ ok = $false; error = 'клиент не найден' } } else { $n = Remove-WgClient $c.PublicKey; & $out ([ordered]@{ ok = $true; name = "$n" }) }
            }
            default { & $out @{ ok = $false; error = "неизвестная задача '$Task'" } }
        }
    } catch { & $out @{ ok = $false; error = $_.Exception.Message } }
}
function Sync-RemoteFirewall($r) {
    $from = @(if (-not (Test-RemoteOn $r) -or "$($r.allowFrom)" -eq 'local') { @('LocalSubnet') + @($(try { $a = Get-WgServerAddress; if ($a) { ($a -replace '\.\d+$', '.0') + '/24' } } catch { })) | Where-Object { $_ } } else { @('Any') })
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
    if ($wc.enabled -and $wc.requirePassword -ne $false -and "$($wc.token)".Length -lt 6) { Set-ConfigValue 'web.token' (New-WebToken); Write-Log 'Веб-интерфейс: создан пароль для входа с других устройств (виден в окне и в config.json, web.token)' }
    $r.port = [int](Get-WCfg).port
    Sync-RemoteFirewall $r
    # прежний сервер на PowerShell (до 3.10) — заменить сервером на C#
    $cur = Get-RemoteProc
    if ($cur -and $cur.ProcessName -like 'powershell*' -and (Build-WebExe)) { Write-Log 'Веб-сервер: перехожу с PowerShell на C#'; Stop-Process -Id $cur.Id -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1 }
    if (-not (Get-RemoteProc)) {
        if (Start-WebServer) { Write-Log "Веб-сервер VpnGuard: запускаю на порту $($r.port)$(if (Test-RemoteOn $r) { " · удалённая диагностика до $((Get-RemoteUntil $r).ToString('dd.MM HH:mm'))" })" 'WARN' }
        else { Write-Log 'Веб-сервер VpnGuard не собрался (Web.cs) — веб-интерфейс и удалённая диагностика недоступны' 'ERROR' }
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
        '===== TCP (метки времени нужны стратегиям zapret с fooling=ts)'; & netsh.exe interface tcp show global; Get-NetTCPSetting -ErrorAction SilentlyContinue | Format-Table SettingName, Timestamps, AutoTuningLevelLocal, CongestionProvider -AutoSize
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
        Get-Process | Where-Object { $_.ProcessName -match 'medusa|meduza|winws|wireguard|amnezia|awg|ws4w|WgServer|powershell|VpnGuardWeb|VpnGuardTray|VpnGuardAgent' } |
            Format-Table Id, ProcessName, @{ n = 'CPU,с'; e = { [int]$_.CPU } }, @{ n = 'МБ'; e = { [int]($_.WorkingSet64 / 1MB) } }, StartTime, Responding -AutoSize
        '===== командные строки (powershell и VpnGuard)'
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe' or Name like 'VpnGuard%'" -ErrorAction SilentlyContinue |
            ForEach-Object { $cl = "$($_.CommandLine)" -replace '\s+', ' '; '{0,6}  {1}' -f $_.ProcessId, $cl.Substring(0, [Math]::Min(220, $cl.Length)) }
        '===== службы'
        Get-Service | Where-Object { $_.Name -match 'WireGuard|Amnezia|SharedAccess|zapret|WinDivert|iphlpsvc|Dnscache|BFE|mpssvc|MeduzaVPN' } | Format-Table Name, Status, StartType, DisplayName -AutoSize
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
        # видеосервер YouTube у провайдера: находится ли его имя системным DNS (через VPN), DNS роутера и 8.8.8.8
        $vhn = "$($ZState.videoHost)"
        if ($vhn) {
            "===== DNS видеосервера $vhn"
            $gw = $(if ($phys) { "$($phys.Gateway)" } else { '' })
            foreach ($srv in @(@('системный (как у браузера)', ''), @("роутер $gw", $gw), @('Google 8.8.8.8', '8.8.8.8'), @('Cloudflare 1.1.1.1', '1.1.1.1'))) {
                if ($srv[0] -like 'роутер*' -and -not $srv[1]) { continue }
                $sw = [Diagnostics.Stopwatch]::StartNew()
                try {
                    $prm = @{ Name = $vhn; Type = 'A'; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }; if ($srv[1]) { $prm.Server = $srv[1] }
                    $a = @(Resolve-DnsName @prm | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress })
                    '  {0,-28} → {1} ({2} мс)' -f $srv[0], $(if ($a) { $a -join ', ' } else { 'нет A-записей' }), $sw.ElapsedMilliseconds
                } catch { '  {0,-28} → ошибка: {1} ({2} мс)' -f $srv[0], $_.Exception.Message, $sw.ElapsedMilliseconds }
            }
            'Какие DNS-серверы у адаптеров:'
            Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | ForEach-Object { '  {0,-28} {1}' -f $_.InterfaceAlias, ($_.ServerAddresses -join ', ') }
            foreach ($ip in @(try { Resolve-DnsName $vhn -Type A -DnsOnly -QuickTimeout -Server $(if ($gw) { $gw } else { '8.8.8.8' }) -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress } } catch { }) | Select-Object -First 1) {
                $rt = Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias } | Select-Object -Last 1
                "  маршрут к $ip → $($rt.InterfaceAlias) (через $($rt.NextHop))"
                $ok = $(if ($phys) { Test-TcpVia $phys.Ip "${ip}:443" 3000 } else { $false })
                "  TCP 443 к $ip напрямую (Ethernet): $(if ($ok) { 'соединяется' } else { 'НЕ соединяется' })"
            }
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


function Get-RWgClient([string]$Ip) {
    $l = Get-WgClients
    @($l.Clients) | Where-Object { "$($_.Ip)" -eq $Ip } | Select-Object -First 1
}


