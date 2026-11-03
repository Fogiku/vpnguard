#Requires -Version 5.1
# Удаление VpnGuard (MeduzaVPN, WS4W и общий доступ не трогаются).
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    return
}
foreach ($t in 'VpnGuard', 'VpnGuardMonitor') {
    Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
}
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -match 'VpnGuard(Monitor)?\.ps1' -and $_.ProcessId -ne $PID } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
# zapret: остановить winws и вернуть YouTube/Discord в VPN (убрать наши маршруты)
Get-Process winws -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$zs = Join-Path $PSScriptRoot 'data\zapret-state.json'
if (Test-Path $zs) {
    try {
        $n = 0
        foreach ($r in @((Get-Content $zs -Raw -Encoding UTF8 | ConvertFrom-Json).routes)) {
            Remove-NetRoute -DestinationPrefix $r.p -InterfaceIndex ([int]$r.i) -NextHop $r.g -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
            $n++
        }
        if ($n) { Write-Host "Убрано маршрутов zapret: $n" }
    } catch { }
}
# удалённая диагностика: закрыть порт
Remove-NetFirewallRule -DisplayName 'VpnGuard remote diagnostics' -ErrorAction SilentlyContinue
foreach ($p in (Join-Path ([Environment]::GetFolderPath('Desktop')) 'VpnGuard.lnk'), (Join-Path ([Environment]::GetFolderPath('Programs')) 'VpnGuard.lnk')) {
    Remove-Item $p -Force -ErrorAction SilentlyContinue
}
Write-Host 'VpnGuard удалён. Папку можно удалить вручную.'
Read-Host 'Нажмите Enter'
