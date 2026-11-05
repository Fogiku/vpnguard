# VpnGuard — модуль Setup.ps1: Задачи планировщика (агент, значок у часов) и ярлыки.
# Подключается из VpnGuard.ps1 (точкой — в его области видимости).

# ---------------------------------------------------------------- задачи планировщика

$AgentTask   = 'VpnGuard'
$MonitorTask = 'VpnGuardMonitor'

function New-HiddenPsAction([string]$File) {
    New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory $Root `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$File`""
}

function Set-MonitorShortcuts([bool]$Create) {
    $paths = @(
        (Join-Path ([Environment]::GetFolderPath('Desktop')) 'VpnGuard.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Programs')) 'VpnGuard.lnk')
    )
    foreach ($p in $paths) {
        if (-not $Create) { Remove-Item $p -Force -ErrorAction SilentlyContinue; continue }
        $sh = New-Object -ComObject WScript.Shell
        $lnk = $sh.CreateShortcut($p)
        $lnk.TargetPath = "$env:windir\System32\schtasks.exe"
        $lnk.Arguments = "/run /tn `"$MonitorTask`""
        $lnk.WindowStyle = 7
        $lnk.IconLocation = "$env:windir\System32\shell32.dll,18"
        $lnk.Description = 'VpnGuard — мониторинг и управление MeduzaVPN и WS4W'
        $lnk.Save()
    }
}

function Invoke-SetupTask([string]$What) {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    switch ($What) {
        'agent' {
            $tLogon = New-ScheduledTaskTrigger -AtLogOn -User $user
            $tLogon.Delay = 'PT20S'
            $tRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
            $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName $AgentTask -Action (New-HiddenPsAction (Join-Path $Root 'VpnGuard.ps1')) `
                -Trigger $tLogon, $tRepeat -Settings $set -Principal $principal -Force | Out-Null
            Write-Log "Задача $AgentTask зарегистрирована для $user"
        }
        'remove-agent' {
            Unregister-ScheduledTask -TaskName $AgentTask -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Задача $AgentTask удалена"
        }
        { $_ -in 'monitor', 'monitor-logon' } {
            # MultipleInstances Parallel: второй запуск просто выводит уже открытое окно на передний план
            $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel
            $tray = Join-Path $BinDir 'VpnGuardTray.exe'
            $act = New-ScheduledTaskAction -Execute $tray -Argument "`"$Root`"" -WorkingDirectory $Root      # значок у часов (собирается частью PowerShell)
            $reg = @{ TaskName = $MonitorTask; Action = $act; Settings = $set; Principal = $principal; Force = $true }
            if ($What -eq 'monitor-logon') { $reg.Trigger = New-ScheduledTaskTrigger -AtLogOn -User $user }
            Register-ScheduledTask @reg | Out-Null
            Set-MonitorShortcuts $true
            Write-Log "Задача $MonitorTask зарегистрирована (при входе: $($What -eq 'monitor-logon'))"
        }
        'remove-monitor' {
            Unregister-ScheduledTask -TaskName $MonitorTask -Confirm:$false -ErrorAction SilentlyContinue
            Set-MonitorShortcuts $false
        }
    }
}
