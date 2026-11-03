#Requires -Version 5.1
<#
  Клиент удалённой диагностики VpnGuard: скачать с другого ПК всё нужное для поиска проблем в одну папку.

    .\RemoteDiag.ps1 -Address 1.2.3.4 -Token abc…            # всё (с полным отчётом «Диагностика»)
    .\RemoteDiag.ps1 -Address 1.2.3.4:8765 -Token abc… -Quick  # без отчёта (быстрее)
    .\RemoteDiag.ps1 -Address 1.2.3.4 -Token abc… -Cmd zapret-check   # команда агенту, потом журнал за 10 мин

  Адрес и токен — из окна VpnGuard: Диагностика → Удалённая диагностика → «Скопировать данные для подключения».
#>
param(
    [Parameter(Mandatory)] [string]$Address,
    [Parameter(Mandatory)] [string]$Token,
    [string]$Out = '',
    [switch]$Quick,
    [string]$Cmd = '',
    [int]$WaitSec = 60
)
$ErrorActionPreference = 'Stop'
$base = $Address.Trim().TrimEnd('/')
if ($base -notmatch '^https?://') { $base = "http://$base" }
if ($base -notmatch ':\d+$') { $base += ':8765' }
if (-not $Out) { $Out = Join-Path (Get-Location) ('vpnguard-remote-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')) }
New-Item -ItemType Directory $Out -Force | Out-Null

function Get-Part([string]$Path, [string]$File, [int]$Timeout = 120) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $r = Invoke-WebRequest -Uri "$base$Path" -Headers @{ 'X-Token' = $Token } -TimeoutSec $Timeout -UseBasicParsing
        $txt = [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray())
        [IO.File]::WriteAllText((Join-Path $Out $File), $txt, (New-Object Text.UTF8Encoding $true))
        Write-Host ('{0,-22} OK  {1,8:N0} байт  {2,5:N1} с' -f $Path, $txt.Length, $sw.Elapsed.TotalSeconds)
        return $txt
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception.Response) { try { $msg = "HTTP $([int]$_.Exception.Response.StatusCode): " + (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch { } }
        Write-Host ('{0,-22} ОШИБКА: {1}' -f $Path, $msg) -ForegroundColor Red
        return $null
    }
}

if (-not (Get-Part '/' 'index.txt' 15)) { Write-Host "Нет связи с $base — проверьте адрес, токен, проброс порта и что диагностика включена." -ForegroundColor Red; exit 1 }
if ($Cmd) {
    [void](Get-Part "/cmd?c=$([uri]::EscapeDataString($Cmd))" 'cmd.txt' 30)
    Write-Host "Жду $WaitSec с, пока агент выполнит…"; Start-Sleep -Seconds $WaitSec
    [void](Get-Part '/logs?minutes=10' 'logs-after-cmd.txt' 30)
    [void](Get-Part '/status' 'status.json' 30)
    return
}
foreach ($p in @(@('/status', 'status.json', 30), @('/files', 'files.json', 60), @('/check', 'check.txt', 180), @('/net', 'net.txt', 60),
                 @('/system', 'system.txt', 120), @('/logs?days=3', 'logs.txt', 60))) { [void](Get-Part $p[0] $p[1] $p[2]) }
if (-not $Quick) { [void](Get-Part '/diag' 'diag.txt' 300) }
Write-Host "Готово: $Out"
