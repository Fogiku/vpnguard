# VpnGuard — задачи веб-сервера (-WebTask: клиенты WireGuard, полный отчёт «Диагностика») и сборка программ на C# (Build-CsExe — агент).
# Веб-сервер и значок держит запущенными агент (agent\WebHost.cs); удалённая диагностика — в WebDiag.cs.
#   • веб-интерфейс (web\index.html + /api/…) — с этого ПК без пароля, из домашней сети и от клиентов wg_server — по паролю web.token;
#   • удалённая диагностика — включается из окна на N часов (remote.*), доступ по одноразовому токену remote.token.
# Ключи и токены в ответах диагностики маскируются; конфиги клиентов WireGuard отдаются только веб-интерфейсу.

$RemoteStatePath = Join-Path $DataDir 'remote-state.json'
$RemoteRule      = 'VpnGuard remote diagnostics'

function Hide-Secrets([string]$Text) {
    if (-not $Text) { return $Text }
    $t = [regex]::Replace($Text, '(?im)^(\s*(PrivateKey|PresharedKey)\s*=\s*)\S+', '$1***')
    $t = [regex]::Replace($t, 'vpn://[A-Za-z0-9_\-+/=]+', 'vpn://***')
    $t = [regex]::Replace($t, '("token"\s*:\s*")[^"]*(")', '$1***$2')
    return $t
}

# ---------------------------------------------------------------- агент: держать сервер запущенным, пока включено
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
# веб-сервер на C# (Web.cs + Qr.cs + WebDiag.cs → bin\VpnGuardWeb.exe)
# ---------------------------------------------------------------- раздача (ICS): подробное состояние и пробное включение отдельным процессом
# (чтобы понять, почему EnableSharing отвечает 0x80040201): хранилище HomeNet целиком, реестр, службы, попытки в двух порядках, журналы
function Invoke-IcsTest([string]$Arg) {
    $p = "$Arg".Split('|'); $pub = $p[0]; $priv = $(if ($p.Count -gt 1 -and $p[1]) { $p[1] } else { 'wg_server' })
    Write-Host "Публичное (раздаёт): $pub · частное (получает): $priv"
    Write-Host "`n== службы"
    foreach ($s in 'SharedAccess', 'Netman', 'RasMan', 'EventSystem', 'SENS', 'mpssvc', 'BFE', 'NlaSvc', 'netprofm', 'iphlpsvc', 'Winmgmt') {
        $x = Get-Service $s -ErrorAction SilentlyContinue; if ($x) { Write-Host ("  {0,-13} {1,-8} {2}" -f $s, $x.Status, $x.StartType) } else { Write-Host "  $s — нет" }
    }
    Write-Host "`n== реестр SharedAccess\Parameters"
    try { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' | Format-List * | Out-String -Width 200 | Write-Host } catch { Write-Host $_.Exception.Message }
    Write-Host "== HomeNet: HNet_Connection"
    try { Get-CimInstance -Namespace root\Microsoft\HomeNet -ClassName HNet_Connection | Select-Object Name, Guid, IsLanConnection | Format-Table -AutoSize | Out-String -Width 200 | Write-Host } catch { Write-Host $_.Exception.Message }
    Write-Host "== HomeNet: HNet_ConnectionProperties (все)"
    try { Get-CimInstance -Namespace root\Microsoft\HomeNet -ClassName HNet_ConnectionProperties | Select-Object Connection, IsIcsPublic, IsIcsPrivate, IsFirewalled, IsBridgeMember | Format-Table -AutoSize | Out-String -Width 250 | Write-Host } catch { Write-Host $_.Exception.Message }
    $hns = New-Object -ComObject HNetCfg.HNetShare
    $find = { param($n) foreach ($c in $hns.EnumEveryConnection) { $pr = $hns.NetConnectionProps.Invoke($c); if ($pr.Name -eq $n) { return $hns.INetSharingConfigurationForINetConnection.Invoke($c) } }; return $null }
    $show = { foreach ($c in $hns.EnumEveryConnection) { $pr = $hns.NetConnectionProps.Invoke($c); $cf = $hns.INetSharingConfigurationForINetConnection.Invoke($c); Write-Host ("  {0,-22} включено={1} тип={2} статус={3} guid={4}" -f $pr.Name, $cf.SharingEnabled, $cf.SharingConnectionType, $pr.Status, $pr.Guid) } }
    Write-Host "`n== подключения (до)"; & $show
    $try = { param($n, $t) $cf = & $find $n; if (-not $cf) { Write-Host "  $n — не найдено"; return $false }
        try { if ($cf.SharingEnabled) { $cf.DisableSharing() }; $cf.EnableSharing($t); Write-Host "  $n тип $t — OK"; return $true }
        catch { $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }; Write-Host ("  {0} тип {1} — ОШИБКА 0x{2:X8}: {3}" -f $n, $t, $e.HResult, $e.Message); return $false } }
    Write-Host "`n== попытка 1: сначала частное, потом публичное"
    $a = & $try $priv 1; $b = & $try $pub 0
    if (-not ($a -and $b)) {
        Write-Host "`n== попытка 2: снять всё, сначала публичное, потом частное"
        foreach ($c in $hns.EnumEveryConnection) { $cf = $hns.INetSharingConfigurationForINetConnection.Invoke($c); if ($cf.SharingEnabled) { try { $cf.DisableSharing() } catch { } } }
        Start-Sleep 2; $b = & $try $pub 0; $a = & $try $priv 1
    }
    Write-Host "`n== подключения (после)"; & $show
    Write-Host "`n== журналы (последние события раздачи, брандмауэра и системы событий)"
    foreach ($lg in 'Microsoft-Windows-SharedAccess_NAT/Operational', 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall') {
        try { Get-WinEvent -LogName $lg -MaxEvents 8 -ErrorAction Stop | ForEach-Object { Write-Host ("  {0:dd.MM HH:mm:ss} [{1}] {2}: {3}" -f $_.TimeCreated, $_.LevelDisplayName, $lg.Split('/')[0], ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(220, ($_.Message -replace '\s+', ' ').Length))) } } catch { Write-Host "  $lg — $($_.Exception.Message)" }
    }
    try { Get-WinEvent -FilterHashtable @{ LogName = 'Application', 'System'; StartTime = (Get-Date).AddHours(-3) } -ErrorAction Stop | Where-Object { $_.ProviderName -match 'SharedAccess|EventSystem|COM|Netman|RasMan|ICS|HNet' } | Select-Object -First 15 | ForEach-Object { Write-Host ("  {0:dd.MM HH:mm:ss} [{1}] {2}: {3}" -f $_.TimeCreated, $_.LevelDisplayName, $_.ProviderName, ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(220, ($_.Message -replace '\s+', ' ').Length))) } } catch { Write-Host "  журналы Application/System: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------- задачи для сервера на C# (VpnGuard.ps1 -WebTask имя [-WebArg base64])
function Invoke-WebTask([string]$Task, [string]$Arg) {
    [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
    $argText = $(if ($Arg) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Arg)) } else { '' })
    $out = { param($o) [Console]::Out.Write(($o | ConvertTo-Json -Depth 6 -Compress)) }
    try {
        switch ($Task) {
            'diag'   { Invoke-Diag }      # полный отчёт «Диагностика»; сеть, система, проверки, файлы — на C# (WebDiag.cs)
            'ics-test' { Invoke-IcsTest $argText }
            default { & $out @{ ok = $false; error = "неизвестная задача '$Task'" } }
        }
    } catch { & $out @{ ok = $false; error = $_.Exception.Message } }
}
# ---------------------------------------------------------------- сервер (процесс VpnGuard.ps1 -RemoteServer)
# живые проверки, которые не мешают работе: туннели, внешний IP, DNS, сайты напрямую и через туннель
