# VpnGuard — модуль WS4W / WireGuard: клиенты сервера wg_server и создание сервера, если настроек нет.
# Подключается и агентом (VpnGuard.ps1), и окном (VpnGuardMonitor.ps1). Нужны переменные $W (настройки ws4w) и $DataDir.
#
# Что меняется в конфиге сервера: блоки [Peer] добавляются/удаляются, остальное не трогается.
# Перед каждым изменением — копия в data\backup. Изменения применяются сразу (wg set), без перезапуска туннеля.

$WgClientsDir = Join-Path $DataDir 'clients'
$WgBackupDir  = Join-Path $DataDir 'backup'

function Find-WgConf {
    if ($W.configPath -and (Test-Path $W.configPath)) { return $W.configPath }
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $W.serviceName
    if (Test-Path -LiteralPath $svcKey) {
        $img = (Get-ItemProperty -LiteralPath $svcKey).ImagePath
        $m = [regex]::Match("$img", '/tunnelservice\s+"?([^"]+?\.conf(\.dpapi)?)"?\s*$')
        if ($m.Success -and (Test-Path $m.Groups[1].Value)) { return $m.Groups[1].Value }
    }
    if ($State -and $State.wgConfPath -and (Test-Path $State.wgConfPath)) { return $State.wgConfPath }
    $n = $W.interfaceName
    $candidates = @(
        "$env:APPDATA\WS4W\server_wg\$n.conf",
        "$env:ProgramData\WS4W\$n.conf",
        "$env:LOCALAPPDATA\WS4W\$n.conf",
        (Join-Path $DataDir "wg\$n.conf"),
        "$env:ProgramFiles\WireGuard\Data\Configurations\$n.conf.dpapi",
        "$env:ProgramFiles\WireGuard\Data\Configurations\$n.conf"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

function Get-WgExe { Join-Path (Split-Path $W.wireguardExe) 'wg.exe' }

function Invoke-WgTool([string]$Arguments, [string]$StdIn = $null) {
    $exe = Get-WgExe
    if (-not (Test-Path $exe)) { throw "не найден $exe — установлен ли WireGuard?" }
    $psi = New-Object Diagnostics.ProcessStartInfo $exe
    $psi.Arguments = $Arguments; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    # .NET Framework пишет преамбулу кодировки консоли в stdin сразу при запуске — wg.exe принимает её за мусор в ключе.
    # Поэтому на время запуска — кодировка без преамбулы.
    $oldEnc = $null
    try { $oldEnc = [Console]::InputEncoding; [Console]::InputEncoding = New-Object Text.ASCIIEncoding } catch { }
    try { $p = [Diagnostics.Process]::Start($psi) }
    finally { if ($oldEnc) { try { [Console]::InputEncoding = $oldEnc } catch { } } }
    # сырые ASCII-байты: StreamWriter может добавить BOM/другую кодировку — wg.exe тогда не принимает ключ
    # (и закрываем сам поток: StandardInput.Close() дописал бы преамбулу UTF-8 после ключа)
    $bs = $p.StandardInput.BaseStream
    if ($null -ne $StdIn) { $bytes = [Text.Encoding]::ASCII.GetBytes($StdIn); $bs.Write($bytes, 0, $bytes.Length); $bs.Flush() }
    $bs.Close()
    $out = $p.StandardOutput.ReadToEnd(); $err = $p.StandardError.ReadToEnd()
    if (-not $p.WaitForExit(10000)) { try { $p.Kill() } catch { }; throw "wg.exe $Arguments — нет ответа" }
    if ($p.ExitCode -ne 0) { throw ("wg.exe {0}: {1}" -f ($Arguments -split ' ')[0], $err.Trim()) }
    return $out.Trim()
}

function New-WgKeyPair {
    $priv = Invoke-WgTool 'genkey'
    $pub = Invoke-WgTool 'pubkey' "$priv`n"
    @{ Private = $priv; Public = $pub }
}

function Read-TextLines([string]$Path) { @([IO.File]::ReadAllLines($Path)) }   # UTF-8 с BOM и без
function Write-TextLines([string]$Path, [string[]]$Lines) {
    # без BOM: WireGuard читает конфиг как есть
    [IO.File]::WriteAllText($Path, (($Lines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding $false))
}

function Backup-WgConf([string]$Path) {
    if (-not (Test-Path $WgBackupDir)) { New-Item -ItemType Directory $WgBackupDir -Force | Out-Null }
    $dst = Join-Path $WgBackupDir ('{0}-{1}.conf' -f [IO.Path]::GetFileNameWithoutExtension($Path), (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    Copy-Item $Path $dst -Force
    # хранить последние 30 копий
    Get-ChildItem $WgBackupDir -Filter '*.conf' | Sort-Object LastWriteTime -Descending | Select-Object -Skip 30 | Remove-Item -Force -ErrorAction SilentlyContinue
}

# разбор конфига: секции с номерами строк (для удаления блока [Peer])
function Read-WgConf([string]$Path) {
    $lines = Read-TextLines $Path
    $secs = New-Object Collections.ArrayList
    $cur = $null
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match '^\s*\[(\w+)\]') {
            $cur = @{ Type = $Matches[1]; Start = $i; End = $i; Keys = @{}; Comments = New-Object Collections.ArrayList }
            [void]$secs.Add($cur); continue
        }
        if (-not $cur) { continue }
        $cur.End = $i
        if ($l -match '^\s*[#;]\s*(.*?)\s*$') { [void]$cur.Comments.Add($Matches[1]); continue }
        if ($l -match '^\s*(\w+)\s*=\s*(.*?)\s*$') { $cur.Keys[$Matches[1]] = $Matches[2] }
    }
    # хвостовые пустые строки секции не считаем её частью
    foreach ($s in $secs) { while ($s.End -gt $s.Start -and -not $lines[$s.End].Trim()) { $s.End-- } }
    @{ Lines = $lines; Sections = $secs }
}

function ConvertTo-IpUInt([string]$ip) { $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes(); [array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
function ConvertFrom-IpUInt([uint32]$v) { $b = [BitConverter]::GetBytes($v); [array]::Reverse($b); (New-Object Net.IPAddress (, $b)).ToString() }

function Get-PeerName($Sec) {
    foreach ($c in $Sec.Comments) {
        if ($c -match '^(?:Name|Client|Имя)\s*[=:]\s*(.+)$') { return $Matches[1].Trim() }
    }
    foreach ($c in $Sec.Comments) { if ($c -and $c -notmatch '^VpnGuard') { return $c } }
    return $null
}

# сведения о сервере: адрес, порт, ключ, клиенты
function Get-WgServerInfo {
    $conf = Find-WgConf
    if (-not $conf) { throw 'Конфиг сервера wg_server не найден. Настройте его в WS4W или включите «Создавать сервер сам» в настройках.' }
    if ($conf -like '*.dpapi') { throw "Конфиг сервера зашифрован WireGuard ($conf) — клиентами можно управлять только в WS4W." }
    $c = Read-WgConf $conf
    $if = $c.Sections | Where-Object { $_.Type -eq 'Interface' } | Select-Object -First 1
    if (-not $if -or -not $if.Keys['PrivateKey']) { throw "В $conf нет [Interface] с PrivateKey" }
    $addr = ("$($if.Keys['Address'])" -split ',')[0].Trim()
    if ($addr -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { throw "Не понял адрес сервера '$addr' в $conf" }
    $ip = $Matches[1]; $prefix = [int]$Matches[2]
    $peers = foreach ($s in $c.Sections | Where-Object { $_.Type -eq 'Peer' }) {
        $aip = ("$($s.Keys['AllowedIPs'])" -split ',')[0].Trim() -replace '/\d+$', ''
        [pscustomobject]@{ PublicKey = "$($s.Keys['PublicKey'])"; Ip = $aip; Name = (Get-PeerName $s); Managed = [bool]($s.Comments -match '^VpnGuard') }
    }
    [pscustomobject]@{
        Conf = $conf; Ip = $ip; Prefix = $prefix; ListenPort = $(if ($if.Keys['ListenPort']) { [int]$if.Keys['ListenPort'] } else { 51820 })
        PublicKey = (Invoke-WgTool 'pubkey' "$($if.Keys['PrivateKey'])`n")
        Peers = @($peers)
    }
}

# клиентские конфиги: наши (data\clients) и WS4W (папки рядом с конфигом сервера)
$script:WgClientFileCache = @{ Stamp = ''; List = @() }
function Get-WgClientFiles([string]$ServerConf) {
    $dirs = @($WgClientsDir)
    if ($ServerConf) { $dirs += (Split-Path (Split-Path $ServerConf)) }
    $files = @(@(foreach ($d in $dirs | Select-Object -Unique) {
        if (Test-Path $d) { Get-ChildItem $d -Recurse -Depth 2 -Filter '*.conf' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $ServerConf -and $_.FullName -notlike "$WgBackupDir*" } }
    }) | Select-Object -First 300)
    $stamp = ($files | ForEach-Object { "$($_.FullName)|$($_.LastWriteTimeUtc.Ticks)" }) -join ';'
    if ($stamp -eq $script:WgClientFileCache.Stamp) { return $script:WgClientFileCache.List }
    $list = foreach ($f in $files) {
        try {
            $c = Read-WgConf $f.FullName
            $if = $c.Sections | Where-Object { $_.Type -eq 'Interface' } | Select-Object -First 1
            $pe = $c.Sections | Where-Object { $_.Type -eq 'Peer' } | Select-Object -First 1
            if (-not $if -or -not $pe -or -not $if.Keys['PrivateKey']) { continue }
            [pscustomobject]@{
                File = $f.FullName; Name = $f.BaseName
                Ip = (("$($if.Keys['Address'])" -split ',')[0].Trim() -replace '/\d+$', '')
                Endpoint = "$($pe.Keys['Endpoint'])"; Dns = "$($if.Keys['DNS'])"
                Ours = $f.FullName.StartsWith($WgClientsDir, [StringComparison]::OrdinalIgnoreCase)
            }
        } catch { }
    }
    $script:WgClientFileCache = @{ Stamp = $stamp; List = @($list) }
    return $script:WgClientFileCache.List
}

# список клиентов для окна: пиры сервера + найденные файлы конфигов
function Get-WgClients {
    $info = Get-WgServerInfo
    $files = @(Get-WgClientFiles $info.Conf)
    $res = foreach ($p in $info.Peers) {
        $f = $files | Where-Object { $_.Ip -eq $p.Ip } | Select-Object -First 1
        [pscustomobject]@{
            Name = $(if ($p.Name) { $p.Name } elseif ($f) { $f.Name } else { $p.Ip })
            Ip = $p.Ip; PublicKey = $p.PublicKey; File = $(if ($f) { $f.File } else { '' })
            Source = $(if ($p.Managed -or ($f -and $f.Ours)) { 'VpnGuard' } elseif ($f) { 'WS4W' } else { 'только на сервере' })
        }
    }
    [pscustomobject]@{ Info = $info; Clients = @($res) }
}

function Get-PhysicalIp {
    $r = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -notlike 'MeduzaVPN*' -and $_.InterfaceAlias -ne $W.interfaceName -and $_.NextHop -ne '0.0.0.0' } |
        Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric } | Select-Object -First 1)
    if (-not $r.Count) { return $null }
    $a = Get-NetIPAddress -InterfaceIndex $r[0].ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
    if ($a) { return $a.IPAddress }
    return $null
}

# адрес, по которому клиенты подключаются: из настроек → из существующих клиентов → внешний IP провайдера
function Get-WgEndpoint($Info) {
    if ($W.endpoint) { $e = "$($W.endpoint)".Trim(); if ($e -notmatch ':\d+$') { $e += ":$($Info.ListenPort)" }; return $e }
    $f = @(Get-WgClientFiles $Info.Conf) | Where-Object { $_.Endpoint } | Select-Object -First 1
    if ($f) { return $f.Endpoint }
    $src = Get-PhysicalIp
    $curl = Join-Path $env:windir 'System32\curl.exe'
    foreach ($u in 'https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com') {
        try {
            $a = '-s -m 6 ' + $(if ($src) { "--interface $src " } else { '' }) + $u
            $ip = (& $curl $a.Split(' ') 2>$null | Out-String).Trim()
            if ($ip -match '^\d+\.\d+\.\d+\.\d+$') { return "${ip}:$($Info.ListenPort)" }
        } catch { }
    }
    throw 'Не удалось узнать внешний адрес — укажите его в настройках (WS4W → «Адрес для клиентов»).'
}

function Get-WgClientDns($Info) {
    if ($W.clientDns) { return "$($W.clientDns)" }
    $f = @(Get-WgClientFiles $Info.Conf) | Where-Object { $_.Dns } | Select-Object -First 1
    if ($f) { return $f.Dns }
    return $Info.Ip   # DNS-прокси раздачи (ICS) на адресе сервера
}

function Test-WgTunnelUp { $s = Get-Service -Name $W.serviceName -ErrorAction SilentlyContinue; [bool]($s -and $s.Status -eq 'Running') }

function New-WgClient([string]$Name) {
    $Name = $Name.Trim()
    if ($Name -notmatch '^[\w\-\. ]{1,32}$') { throw 'Имя клиента: буквы, цифры, пробел, - _ . (до 32 символов)' }
    $info = Get-WgServerInfo
    if (@($info.Peers | Where-Object { $_.Name -eq $Name }).Count) { throw "Клиент «$Name» уже есть" }
    $safe = ($Name -replace '\s+', '_')
    if (-not (Test-Path $WgClientsDir)) { New-Item -ItemType Directory $WgClientsDir -Force | Out-Null }
    $file = Join-Path $WgClientsDir "$safe.conf"
    if (Test-Path $file) { throw "Файл $file уже существует" }

    # свободный адрес в подсети сервера
    $mask = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $info.Prefix))
    $net = (ConvertTo-IpUInt $info.Ip) -band $mask
    $bcast = $net + [uint32]([Math]::Pow(2, 32 - $info.Prefix) - 1)
    $used = New-Object Collections.Generic.HashSet[string]
    [void]$used.Add($info.Ip)
    foreach ($p in $info.Peers) { [void]$used.Add($p.Ip) }
    foreach ($f in Get-WgClientFiles $info.Conf) { [void]$used.Add($f.Ip) }
    $ip = $null
    for ($v = $net + 2; $v -lt $bcast; $v++) { $cand = ConvertFrom-IpUInt ([uint32]$v); if (-not $used.Contains($cand)) { $ip = $cand; break } }
    if (-not $ip) { throw 'В подсети сервера не осталось свободных адресов' }

    $endpoint = Get-WgEndpoint $info
    $dns = Get-WgClientDns $info
    $keys = New-WgKeyPair
    $psk = Invoke-WgTool 'genpsk'

    $client = @(
        '[Interface]', "PrivateKey = $($keys.Private)", "Address = $ip/32", "DNS = $dns", '',
        '[Peer]', "PublicKey = $($info.PublicKey)", "PresharedKey = $psk", 'AllowedIPs = 0.0.0.0/0', "Endpoint = $endpoint", 'PersistentKeepalive = 25'
    )
    Backup-WgConf $info.Conf
    $lines = @(Read-TextLines $info.Conf)
    while ($lines.Count -and -not $lines[$lines.Count - 1].Trim()) { $lines = @($lines[0..($lines.Count - 2)]) }
    $lines += @('', '[Peer]', "# Name = $Name", "# VpnGuard: created $(Get-Date -Format 'yyyy-MM-dd HH:mm')", "PublicKey = $($keys.Public)", "PresharedKey = $psk", "AllowedIPs = $ip/32")
    Write-TextLines $info.Conf $lines
    Write-TextLines $file $client

    # применить сразу, без перезапуска туннеля
    if (Test-WgTunnelUp) {
        $tmp = Join-Path $env:TEMP ("vg-psk-{0}.txt" -f [Guid]::NewGuid().ToString('N'))
        try {
            [IO.File]::WriteAllText($tmp, $psk)
            [void](Invoke-WgTool ('set {0} peer {1} preshared-key "{2}" allowed-ips {3}/32' -f $W.interfaceName, $keys.Public, $tmp, $ip))
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    [pscustomobject]@{ Name = $Name; Ip = $ip; File = $file; Text = ($client -join "`r`n"); Endpoint = $endpoint }
}

function Remove-WgClient([string]$PublicKey) {
    $info = Get-WgServerInfo
    $c = Read-WgConf $info.Conf
    $sec = $c.Sections | Where-Object { $_.Type -eq 'Peer' -and $_.Keys['PublicKey'] -eq $PublicKey } | Select-Object -First 1
    if (-not $sec) { throw 'Клиент не найден в конфиге сервера' }
    $peer = $info.Peers | Where-Object { $_.PublicKey -eq $PublicKey } | Select-Object -First 1
    $start = $sec.Start
    # комментарии вплотную над [Peer] (например «# Name = …») относятся к этому клиенту
    while ($start -gt 0 -and $c.Lines[$start - 1] -match '^\s*[#;]') { $start-- }
    if ($start -gt 0 -and -not $c.Lines[$start - 1].Trim()) { $start-- }
    Backup-WgConf $info.Conf
    $keep = @(for ($i = 0; $i -lt $c.Lines.Count; $i++) { if ($i -lt $start -or $i -gt $sec.End) { $c.Lines[$i] } })
    Write-TextLines $info.Conf $keep
    if (Test-WgTunnelUp) { try { [void](Invoke-WgTool ('set {0} peer {1} remove' -f $W.interfaceName, $PublicKey)) } catch { } }
    # файл клиента: наш — удалить, из WS4W — убрать в копии (иначе WS4W вернёт клиента)
    $f = @(Get-WgClientFiles $info.Conf) | Where-Object { $peer -and $_.Ip -eq $peer.Ip } | Select-Object -First 1
    if ($f) {
        if ($f.Ours) { Remove-Item $f.File -Force -ErrorAction SilentlyContinue }
        else {
            if (-not (Test-Path $WgBackupDir)) { New-Item -ItemType Directory $WgBackupDir -Force | Out-Null }
            Move-Item $f.File (Join-Path $WgBackupDir ('client-{0}-{1}.conf' -f $f.Name, (Get-Date -Format 'yyyyMMdd-HHmmss'))) -Force
        }
    }
    return $(if ($peer -and $peer.Name) { $peer.Name } else { $PublicKey.Substring(0, 8) })
}

# создать сервер wg_server, если настроек нет вообще (ни конфига, ни службы)
function Initialize-WgServer {
    if (-not (Test-Path $W.wireguardExe)) { throw "WireGuard не установлен ($($W.wireguardExe)) — установите WireGuard или WS4W" }
    $dir = Join-Path $DataDir 'wg'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }
    $conf = Join-Path $dir "$($W.interfaceName).conf"
    if (Test-Path $conf) { throw "Конфиг $conf уже существует" }
    $addr = $(if ($W.newServerAddress) { "$($W.newServerAddress)" } else { '10.253.0.1/24' })
    $port = $(if ($W.newServerPort) { [int]$W.newServerPort } else { 51820 })
    $keys = New-WgKeyPair
    Write-TextLines $conf @('[Interface]', '# VpnGuard: server created automatically', "PrivateKey = $($keys.Private)", "ListenPort = $port", "Address = $addr")
    # доступ только администраторам и SYSTEM — в файле закрытый ключ
    try { & icacls.exe $conf /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null } catch { }
    $r = Invoke-Exe $W.wireguardExe ('/installtunnelservice "{0}"' -f $conf) 60
    if ($r.Code -ne 0) { throw "installtunnelservice: код $($r.Code) $($r.Err)" }
    try {
        if (-not (Get-NetFirewallRule -DisplayName 'VpnGuard wg_server' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName 'VpnGuard wg_server' -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow -Profile Any | Out-Null
        }
    } catch { }
    return $conf
}
