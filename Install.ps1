#Requires -Version 5.1
# Установка VpnGuard: агент + окно мониторинга, CLI MeduzaVPN, настройки ICS/служб.
$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    return
}

$Root   = $PSScriptRoot
$Script = Join-Path $Root 'VpnGuard.ps1'
function Invoke-Agent([string]$Arguments) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '$Script' $Arguments" }

Write-Host "== VpnGuard: установка из $Root для пользователя $($id.Name)" -ForegroundColor Cyan

Write-Host '-- Загрузка CLI meduzavpn (проверка sha256 и подписи)...'
Invoke-Agent '-InstallCli'

Write-Host '-- Служба общего доступа (ICS) -> Автоматически'
Set-Service SharedAccess -StartupType Automatic
$k = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\SharedAccess'
if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
Set-ItemProperty $k -Name EnableRebootPersistConnection -Value 1 -Type DWord

$wg = Get-Service -Name 'WireGuardTunnel$wg_server' -ErrorAction SilentlyContinue
if ($wg) { Set-Service -Name 'WireGuardTunnel$wg_server' -StartupType Automatic; Write-Host '-- Служба WireGuardTunnel$wg_server -> Автоматически' }
else     { Write-Warning 'Служба WireGuardTunnel$wg_server не найдена. VpnGuard создаст сервер сам (или на вкладке WG-Server веб-интерфейса).' }

Write-Host '-- Задача агента (при входе + каждые 5 мин, наивысшие права)'
Invoke-Agent '-SetupTask agent'
Write-Host '-- Окно мониторинга (ярлык "VpnGuard" на рабочем столе и в меню Пуск)'
Invoke-Agent '-SetupTask monitor'

Start-ScheduledTask -TaskName 'VpnGuard'
Start-ScheduledTask -TaskName 'VpnGuardMonitor'

Write-Host ''
Write-Host 'Готово. Окно VpnGuard открыто. Осталось один раз сделать вручную:' -ForegroundColor Green
Write-Host '  1) В MeduzaVPN: Настройки -> включить управление из командной строки (CLI control).'
Write-Host '  2) В MeduzaVPN выбрать сервер с ULTRA и при желании включить автоподключение.'
Write-Host '  3) Для подъёма после перезагрузки без ручного входа — автовход Windows'
Write-Host '     (Sysinternals Autologon: https://learn.microsoft.com/sysinternals/downloads/autologon).'
Read-Host 'Нажмите Enter'
