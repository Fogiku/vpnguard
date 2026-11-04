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


function Get-AwgTunnelInfo([string]$Name) { $null }


