# VpnGuard — модуль «Компоненты»: установка и обновление всего нужного софта.
# MeduzaVPN и его CLI, WireGuard (для wg_server), AmneziaWG, WS4W (окно настройки сервера), zapret.
# Источники — официальные: сервер сборок MeduzaVPN, download.wireguard.com, релизы GitHub.
# Проверка: подпись Authenticode (где издатель известен) и sha256 из GitHub (если GitHub его отдаёт).

$SwDlDir = Join-Path $DataDir 'downloads'

$SwDefs = [ordered]@{
    meduza    = @{ name = 'MeduzaVPN';            purpose = 'VPN (режим MeduzaVPN)' }
    meduzacli = @{ name = 'MeduzaVPN CLI';        purpose = 'управление MeduzaVPN из агента' }
    wireguard = @{ name = 'WireGuard';            purpose = 'туннель wg_server для клиентов' }
    amneziawg = @{ name = 'AmneziaWG';            purpose = 'VPN (режим AmneziaWG)'; repo = 'amnezia-vpn/amneziawg-windows-client'; asset = 'amd64.*\.msi$'; reg = '^AmneziaWG'; signer = 'Privacy Technologies OU' }
    ws4w      = @{ name = 'WS4W';                 purpose = 'окно настройки сервера (не обязательно)'; repo = 'micahmo/WgServerforWindows'; asset = '\.(msi|exe)$'; reg = '^(WS4W|WireGuard Server For Windows)' }
    zapret    = @{ name = 'zapret-discord-youtube'; purpose = 'YouTube и Discord мимо блокировок' }
}

function Get-InstalledApp([string]$Pattern) {
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        $e = Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $Pattern } | Select-Object -First 1
        if ($e) { return $e }
    }
    return $null
}

function Get-GitHubLatest([string]$Repo, [string]$AssetRx) {
    $r = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'VpnGuard' } -TimeoutSec 30 -UseBasicParsing
    $a = @($r.assets | Where-Object { $_.name -match $AssetRx } | Sort-Object { $_.name -notmatch 'amd64|x64|setup' }) | Select-Object -First 1
    if (-not $a) { throw "в релизе $($r.tag_name) нет подходящего файла" }
    [pscustomobject]@{
        Version = (ConvertTo-Ver $r.tag_name); Tag = "$($r.tag_name)"; Url = $a.browser_download_url; File = $a.name
        Sha256 = $(if ($a.PSObject.Properties['digest'] -and "$($a.digest)" -match '^sha256:([0-9a-f]{64})$') { $Matches[1].ToUpper() } else { '' })
    }
}

function Get-WireGuardLatest {
    $html = (Invoke-WebRequest 'https://download.wireguard.com/windows-client/' -UseBasicParsing -TimeoutSec 30).Content
    $vers = @([regex]::Matches($html, 'wireguard-amd64-(\d+\.\d+(?:\.\d+)*)\.msi') | ForEach-Object { $_.Groups[1].Value } | Sort-Object { [version]$_ } -Descending)
    if (-not $vers.Count) { throw 'не нашёл MSI на download.wireguard.com' }
    $v = $vers[0]
    [pscustomobject]@{ Version = [version]$v; Tag = $v; Url = "https://download.wireguard.com/windows-client/wireguard-amd64-$v.msi"; File = "wireguard-amd64-$v.msi"; Sha256 = '' }
}

function Save-VerifiedFile($Rel, [string]$Signer = '') {
    if (-not (Test-Path $SwDlDir)) { New-Item -ItemType Directory $SwDlDir -Force | Out-Null }
    $dst = Join-Path $SwDlDir $Rel.File
    Write-Log "Компоненты: загрузка $($Rel.Url)"
    Invoke-WebRequest $Rel.Url -OutFile $dst -UseBasicParsing -TimeoutSec 600
    if ($Rel.Sha256) {
        $h = (Get-FileHash $dst -Algorithm SHA256).Hash
        if ($h -ne $Rel.Sha256) { Remove-Item $dst -Force; throw "sha256 не совпал с GitHub ($h)" }
    }
    $sig = Get-AuthenticodeSignature $dst
    if ($Signer) {
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch [regex]::Escape($Signer)) { Remove-Item $dst -Force; throw "подпись не прошла проверку (ожидался «$Signer», статус $($sig.Status))" }
    } elseif ($sig.Status -ne 'Valid' -and $sig.Status -ne 'NotSigned') {
        # неподписанный файл допускаем только с совпавшим sha256 из GitHub
        Remove-Item $dst -Force; throw "подпись повреждена (статус $($sig.Status))"
    } elseif ($sig.Status -eq 'NotSigned' -and -not $Rel.Sha256) {
        Remove-Item $dst -Force; throw 'файл не подписан и GitHub не дал sha256 — установите вручную'
    }
    return $dst
}

function Install-Package([string]$Path, [string]$ExtraMsi = '') {
    if ($Path -like '*.msi') {
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$Path`" /qn /norestart $ExtraMsi" -Wait -PassThru
        if ($p.ExitCode -notin 0, 3010) { throw "msiexec завершился с кодом $($p.ExitCode)" }
    } else {
        # у установщика нет известного тихого режима — откроется окно установки
        $p = Start-Process $Path -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "установщик завершился с кодом $($p.ExitCode)" }
    }
}

function Get-SwInstalled([string]$Id) {
    switch ($Id) {
        'meduza'    { $v = Get-MeduzaVersion; if ($v -gt [version]'0.0') { return "$v" }; return '' }
        'meduzacli' { if (Test-Path (Get-CliPath)) { $vi = (Get-Item (Get-CliPath)).VersionInfo.ProductVersion; return $(if ($vi) { "$vi" } else { 'есть' }) }; return '' }
        'wireguard' { $e = Get-InstalledApp '^WireGuard$'; if ($e) { return "$($e.DisplayVersion)" }; if (Test-Path $W.wireguardExe) { return 'есть' }; return '' }
        'amneziawg' { $e = Get-InstalledApp $SwDefs.amneziawg.reg; if ($e) { return "$($e.DisplayVersion)" }; if (Test-Path (Get-AwgExe)) { return 'есть' }; return '' }
        'ws4w'      { $e = Get-InstalledApp $SwDefs.ws4w.reg; if ($e) { return "$($e.DisplayVersion)" }; return '' }
        'zapret'    { $v = Get-ZapretLocalVersion; return $(if ($v) { "$v" } else { '' }) }
    }
    return ''
}

function Test-SwNeeded([string]$Id) {
    $mode = Get-VpnMode
    switch ($Id) {
        'meduza'    { return $mode -eq 'meduza' }
        'meduzacli' { return $mode -eq 'meduza' }
        'wireguard' { return $true }
        'amneziawg' { return $mode -eq 'amnezia' }
        'ws4w'      { return $false }
        'zapret'    { return [bool]((Get-ZCfg).enabled) }
    }
    return $false
}

# последние версии — раз в N часов (или по кнопке)
function Invoke-SoftwareCheck([switch]$Force) {
    if (-not $State.software) { $State.software = @{} }
    $hours = $(if ($Cfg.software -and $Cfg.software.checkHours) { [double]$Cfg.software.checkHours } else { 12 })
    if (-not $Force -and $State.softwareCheckedAt -and ((Get-Date) - $State.softwareCheckedAt).TotalHours -lt $hours) { return }
    $State.softwareCheckedAt = Get-Date
    Set-Activity 'проверяю версии компонентов'
    foreach ($id in $SwDefs.Keys) {
        $st = $State.software[$id]; if (-not $st) { $st = @{}; $State.software[$id] = $st }
        try {
            switch ($id) {
                'meduza'    { $f = (Get-Release).files | Where-Object { $_.key -eq 'MeduzaVPN-Setup.exe' } | Select-Object -First 1; $st.latest = "$(ConvertTo-Ver ($f.version -split '\+')[0])"; $State.remoteVersion = ConvertTo-Ver ($f.version -split '\+')[0] }
                'meduzacli' { $f = (Get-Release).files | Where-Object { $_.key -eq 'meduzavpn-windows.zip' } | Select-Object -First 1; $st.latest = "$(ConvertTo-Ver $f.version)" }
                'wireguard' { $st.latest = "$((Get-WireGuardLatest).Version)" }
                'zapret'    { $r = Get-ZapretRelease; $st.latest = "$($r.version)" }
                default     { $d = $SwDefs[$id]; $st.latest = "$((Get-GitHubLatest $d.repo $d.asset).Version)" }
            }
            $st.error = ''
        } catch { $st.error = "проверка: $($_.Exception.Message)" }
    }
    Write-Log 'Компоненты: версии проверены'
}

function Install-Software([string]$Id) {
    if (-not $SwDefs.Contains($Id)) { Write-Log "Компоненты: неизвестный компонент $Id" 'WARN'; return }
    if (-not $State.software) { $State.software = @{} }
    $st = $State.software[$Id]; if (-not $st) { $st = @{}; $State.software[$Id] = $st }
    $nm = $SwDefs[$Id].name
    $st.status = 'устанавливается'; $st.error = ''
    Set-Activity "устанавливаю $nm"
    try {
        switch ($Id) {
            'meduza'    { Invoke-MeduzaUpdate -Force }
            'meduzacli' { $State.cliSha256 = ''; Update-MeduzaCli (Get-Release) }
            'zapret'    { Invoke-ZapretUpdate -Force }
            'wireguard' {
                $rel = Get-WireGuardLatest
                $f = Save-VerifiedFile $rel 'WireGuard LLC'
                Write-Log "Компоненты: устанавливаю WireGuard $($rel.Version) (туннель wg_server на несколько секунд прервётся)" 'WARN'
                Install-Package $f 'DO_NOT_LAUNCH=1'
                Remove-Item $f -Force -ErrorAction SilentlyContinue
                $State.forceIcs = $true
            }
            default {
                $d = $SwDefs[$Id]
                $rel = Get-GitHubLatest $d.repo $d.asset
                $f = Save-VerifiedFile $rel "$($d.signer)"
                Write-Log "Компоненты: устанавливаю $nm $($rel.Version)"
                Install-Package $f $(if ($Id -eq 'amneziawg') { 'DO_NOT_LAUNCH=1' } else { '' })
                Remove-Item $f -Force -ErrorAction SilentlyContinue
            }
        }
        $st.status = ''
        Write-Log "Компоненты: $nm — установлена версия $(Get-SwInstalled $Id)"
    } catch {
        $st.status = ''; $st.error = $_.Exception.Message
        Write-Log "Компоненты: $nm — ошибка установки: $($_.Exception.Message)" 'ERROR'
    }
}

# поставить всё, что нужно для текущего режима и чего нет
function Install-MissingSoftware {
    foreach ($id in $SwDefs.Keys) { if ((Test-SwNeeded $id) -and -not (Get-SwInstalled $id)) { Install-Software $id } }
}

function Get-SoftwareSnapshot {
    @(foreach ($id in $SwDefs.Keys) {
        $d = $SwDefs[$id]; $st = $(if ($State.software) { $State.software[$id] } else { $null })
        $inst = ''; try { $inst = Get-SwInstalled $id } catch { }
        $latest = $(if ($st) { "$($st.latest)" } else { '' })
        $upd = [bool]($inst -and $latest -and $inst -ne 'есть' -and (ConvertTo-Ver $latest) -gt (ConvertTo-Ver $inst))
        [ordered]@{ id = $id; name = $d.name; purpose = $d.purpose; installed = $inst; latest = $latest; update = $upd
                    needed = (Test-SwNeeded $id); status = $(if ($st) { "$($st.status)" } else { '' }); error = $(if ($st) { "$($st.error)" } else { '' }) }
    })
}
