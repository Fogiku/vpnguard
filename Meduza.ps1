# VpnGuard — модуль Meduza.ps1: MeduzaVPN: приложение, CLI, подключение, проверка трафика, обновление приложения и CLI.
# Подключается из VpnGuard.ps1 (точкой — в его области видимости).

# ---------------------------------------------------------------- MeduzaVPN

function Get-MeduzaUninstallEntry {
    $keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like 'MeduzaVPN*' } |
        Select-Object -First 1
}

function Get-MeduzaExe {
    if ($M.exePath) { return $M.exePath }
    $e = Get-MeduzaUninstallEntry
    if ($e -and $e.InstallLocation) { return (Join-Path $e.InstallLocation 'medusa_vpn.exe') }
    return 'C:\Program Files\MeduzaVPN\medusa_vpn.exe'
}

function Get-MeduzaVersion {
    $e = Get-MeduzaUninstallEntry
    if ($e -and $e.DisplayVersion) { return (ConvertTo-Ver $e.DisplayVersion) }
    $exe = Get-MeduzaExe
    if (Test-Path $exe) { return (ConvertTo-Ver (Get-Item $exe).VersionInfo.ProductVersion) }
    return [version]'0.0'
}

function Get-CliPath {
    if ($M.cliPath) { return $M.cliPath }
    return (Join-Path $BinDir 'meduzavpn.exe')
}

function Test-MeduzaPipe {
    try {
        $want = '\\.\pipe\' + $M.pipeName
        return [bool]([IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -ieq $want })
    } catch { return $false }
}

function Invoke-MeduzaCli([string]$Arguments, [int]$TimeoutSec = 30) {
    $cli = Get-CliPath
    if (-not (Test-Path $cli)) { return [pscustomobject]@{ Code = -2; Out = ''; Err = 'CLI не найден' } }
    Invoke-Exe $cli $Arguments $TimeoutSec
}

# протокол, которым подключаться сейчас: выбранный или запасной (если выбранный перестал работать)
function Get-MzProtocol { if ($State.mzProtoOverride) { return "$($State.mzProtoOverride)" }; return "$($M.protocol)" }

function Connect-Meduza([int]$TimeoutSec = 0) {
    if (-not (Test-MeduzaPipe)) {
        Write-Log 'Канал управления MeduzaVPN недоступен (включите "Управление из командной строки" в настройках приложения) — жду автоподключения самого приложения' 'WARN'
        return $false
    }
    $proto = Get-MzProtocol
    $a = 'connect'
    if ($M.serviceId) { $a += ' "' + $M.serviceId + '"' }
    if ($proto)       { $a += ' --protocol ' + $proto }
    $a += ' --wait'
    Set-Activity "подключаю MeduzaVPN ($proto)"
    $State.reconnectCount++
    Write-Log "MeduzaVPN: meduzavpn $a"
    $r = Invoke-MeduzaCli $a $(if ($TimeoutSec) { $TimeoutSec } else { [int]$M.connectTimeoutSec + 30 })
    if ($r.Code -ne 0) {
        Write-Log ("MeduzaVPN: connect завершился с кодом {0}: {1} {2}" -f $r.Code, $r.Out, $r.Err) 'WARN'
    }
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if (Get-UpAdapter $M.adapterName) { Write-Log "MeduzaVPN: туннель подключён ($proto)"; return $true }
        # другой протокол — адаптер может называться иначе
        $alt = @(Get-NetAdapter -Name 'MeduzaVPN*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }) | Select-Object -First 1
        if ($alt) { $M.adapterName = $alt.Name; Write-Log "MeduzaVPN: подключён, адаптер «$($alt.Name)» ($proto)"; return $true }
        Start-Sleep -Seconds 2
    }
    return [bool](Get-UpAdapter $M.adapterName)
}


function Disconnect-Meduza {
    if (Test-MeduzaPipe) {
        $r = Invoke-MeduzaCli 'disconnect' 30
        Write-Log ("MeduzaVPN: disconnect (код {0})" -f $r.Code)
    }
}

function Start-Meduza {
    $exe = Get-MeduzaExe
    if (-not (Test-Path $exe)) { Write-Log "MeduzaVPN не найден: $exe" 'ERROR'; return }
    Write-Log "MeduzaVPN: запуск $exe"
    Set-Activity 'запускаю MeduzaVPN'
    Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) | Out-Null
    $State.meduzaStartedAt = Get-Date
    $State.probeFailures = 0
    $State.notResponding = 0
    $State.downTicks = 0
    # ждём канал управления, затем сразу подключаем ULTRA
    $deadline = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $deadline -and -not (Test-MeduzaPipe)) { Start-Sleep -Seconds 2 }
    Start-Sleep -Seconds 3
    if (-not (Get-UpAdapter $M.adapterName) -and (Test-MeduzaPipe)) { [void](Connect-Meduza) }
}

function Stop-Meduza {
    Disconnect-Meduza
    $procs = Get-Process -Name $M.processName -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Log 'MeduzaVPN: остановка процесса'
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        $procs | ForEach-Object { try { $_.WaitForExit(15000) | Out-Null } catch { } }
    }
}


function Test-MeduzaTraffic {
    $ip = Get-AdapterIPv4 $M.adapterName
    $ok = $false
    if ($ip) { foreach ($h in $M.probeHosts) { if (Test-TcpVia $ip $h) { $ok = $true; break } } }
    $State.lastTraffic = $ok
    $State.lastTrafficAt = Get-Date
    return $ok
}


# ---------------------------------------------------------------- MeduzaVPN update

function Get-Release {
    Invoke-RestMethod -Uri ($M.releaseUrl + '?t=' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -TimeoutSec 30 -UseBasicParsing
}

function Get-VerifiedDownload($File, [string]$Target) {
    $urls = @($File.versioned_url, $File.url) | Where-Object { $_ }
    foreach ($u in $urls) {
        try {
            Write-Log "Загрузка $u"
            Set-Activity ('скачиваю ' + [IO.Path]::GetFileName($u))
            Invoke-WebRequest -Uri $u -OutFile $Target -UseBasicParsing -TimeoutSec 900
            $hash = (Get-FileHash $Target -Algorithm SHA256).Hash
            if ($File.sha256 -and $hash -ne $File.sha256.ToUpper()) { throw "sha256 не совпал ($hash)" }
            return $true
        } catch {
            Write-Log "Загрузка не удалась: $($_.Exception.Message)" 'WARN'
            Remove-Item $Target -Force -ErrorAction SilentlyContinue
        }
    }
    return $false
}

function Update-MeduzaCli($Release) {
    $f = $Release.files | Where-Object { $_.key -eq 'meduzavpn-windows.zip' } | Select-Object -First 1
    if (-not $f) { return }
    $cli = Get-CliPath
    if ((Test-Path $cli) -and $State.cliSha256 -eq $f.sha256) { return }
    $zip = Join-Path $DlDir 'meduzavpn-windows.zip'
    if (-not (Get-VerifiedDownload $f $zip)) { return }
    $tmp = Join-Path $DlDir 'cli_x'
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive $zip $tmp -Force
    $new = Get-ChildItem $tmp -Recurse -Filter 'meduzavpn.exe' | Select-Object -First 1
    if ($new -and (Test-Signature $new.FullName)) {
        Copy-Item $new.FullName $cli -Force
        $State.cliSha256 = $f.sha256
        Save-State
        Write-Log "CLI meduzavpn обновлён до $($f.version)"
    } else {
        Write-Log 'CLI meduzavpn: подпись не прошла проверку, не устанавливаю' 'ERROR'
    }
    Remove-Item $tmp, $zip -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-MeduzaUpdate([switch]$Force) {
    if (-not $M.autoUpdate -and -not $Force) { return }
    if (-not $Force -and (Get-VpnMode) -ne 'meduza') { return }   # в других режимах — только по кнопке
    if (-not $Force -and ((Get-Date) - $State.lastUpdateCheck).TotalHours -lt [double]$M.updateCheckHours) { return }
    $State.lastUpdateCheck = Get-Date
    Save-State

    try { $rel = Get-Release } catch { Write-Log "Не удалось получить release.json: $($_.Exception.Message)" 'WARN'; return }
    try { Update-MeduzaCli $rel } catch { Write-Log "Обновление CLI: $($_.Exception.Message)" 'WARN' }

    $f = $rel.files | Where-Object { $_.key -eq 'MeduzaVPN-Setup.exe' } | Select-Object -First 1
    if (-not $f) { Write-Log 'В release.json нет MeduzaVPN-Setup.exe' 'WARN'; return }
    $remote = ConvertTo-Ver ($f.version -split '\+')[0]
    $local  = Get-MeduzaVersion
    $State.remoteVersion = $remote
    if ($remote -le $local) { Write-Log "MeduzaVPN $local — актуальная версия"; return }

    Write-Log "MeduzaVPN: доступно обновление $local -> $remote"
    $setup = Join-Path $DlDir ("MeduzaVPN-Setup-{0}.exe" -f $remote)
    if (-not (Get-VerifiedDownload $f $setup)) { return }
    if (-not (Test-Signature $setup)) {
        Write-Log 'Установщик MeduzaVPN не прошёл проверку подписи — обновление отменено' 'ERROR'
        Remove-Item $setup -Force -ErrorAction SilentlyContinue
        return
    }

    $State.updating = $true
    $updFlag = Join-Path $DataDir 'meduza-updating.flag'
    try { Set-Content $updFlag (Get-Date).ToString('o') -Encoding ASCII } catch { }   # агент на C# не трогает MeduzaVPN, пока идёт установка
    try { Write-PsStatus } catch { }
    try {
        Stop-Meduza
        Write-Log "MeduzaVPN: установка $remote"
        Set-Activity "устанавливаю MeduzaVPN $remote"
        $p = Start-Process -FilePath $setup -ArgumentList $M.installerArgs -PassThru
        if (-not $p.WaitForExit(15 * 60 * 1000)) { try { $p.Kill() } catch { }; Write-Log 'Установщик завис — прерван' 'ERROR' }
        else { Write-Log "Установщик завершился с кодом $($p.ExitCode)" }
        Start-Sleep -Seconds 5
        Write-Log "MeduzaVPN: теперь установлена версия $(Get-MeduzaVersion)"
    } catch {
        Write-Log "Ошибка обновления: $($_.Exception.Message)" 'ERROR'
    } finally {
        $State.updating = $false
        Remove-Item $setup, $updFlag -Force -ErrorAction SilentlyContinue
    }
    # установщик мог сам запустить приложение
    Start-Sleep -Seconds 5
    if ((Get-VpnMode) -ne 'meduza') { if ($Cfg.vpn.stopInactive) { Stop-Meduza } }
    elseif (-not (Get-Process -Name $M.processName -ErrorAction SilentlyContinue)) { Start-Meduza }
    else { $State.meduzaStartedAt = Get-Date }
}
