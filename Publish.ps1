#Requires -Version 5.1
<#
  Выпуск новой версии VpnGuard для автообновления (запускается на компьютере разработчика).

    .\Publish.ps1 -Repo владелец/vpnguard -Notes "что изменилось"     # первый раз: создаст git-репозиторий и привяжет GitHub
    .\Publish.ps1 -Notes "что изменилось"                            # дальше

  Что делает: собирает vpnguard-manifest.json (версия из VpnGuard.ps1, sha256 каждого файла приложения),
  делает коммит и git push. Агенты на других ПК увидят новую версию при следующей проверке (раз в update.checkHours).
  config.json, data\, zapret\, bin\ в репозиторий не попадают.
#>
param([string]$Repo = '', [string]$Notes = '', [switch]$NoPush)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$git = (Get-Command git -ErrorAction Stop).Source

# файлы приложения
$files = @(Get-ChildItem $Root -File | Where-Object { $_.Extension -in '.ps1', '.cmd', '.cs', '.md' } | Sort-Object Name)
foreach ($f in $files | Where-Object Extension -eq '.ps1') {
    $err = $null; [void][Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$err)
    if ($err.Count) { throw "$($f.Name): $($err[0].Message) (строка $($err[0].Extent.StartLineNumber)) — выпуск отменён" }
}
$ver = [regex]::Match([IO.File]::ReadAllText((Join-Path $Root 'VpnGuard.ps1')), "\`$AgentVersion\s*=\s*'([^']+)'").Groups[1].Value
if (-not $ver) { throw 'не нашёл $AgentVersion в VpnGuard.ps1' }
$build = Get-Date -Format 'yyyyMMdd-HHmm'

if (-not (Test-Path (Join-Path $Root '.git'))) {
    & $git init -b main | Out-Null
    Write-Host 'Создан git-репозиторий'
}
# без преобразования переводов строк — иначе sha256 на GitHub не совпадёт с манифестом
[IO.File]::WriteAllText((Join-Path $Root '.gitattributes'), "* -text`n")
[IO.File]::WriteAllText((Join-Path $Root '.gitignore'), "config.json`ndata/`nzapret/`nbin/`n*.tmp`n*.new`n")
if ($Repo) {
    $url = "https://github.com/$Repo.git"
    $have = (& $git remote) -contains 'origin'
    if ($have) { & $git remote set-url origin $url } else { & $git remote add origin $url }
    Write-Host "GitHub: $url"
}

$m = [ordered]@{
    version = $ver; build = $build; notes = $Notes; date = (Get-Date).ToString('o')
    files = @($files | ForEach-Object { [ordered]@{ path = $_.Name; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(); size = $_.Length } })
}
[IO.File]::WriteAllText((Join-Path $Root 'vpnguard-manifest.json'), ($m | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))

& $git add -A
$st = & $git status --porcelain
if (-not $st) { Write-Host 'Изменений нет — выпускать нечего'; return }
$who = @(); if (-not (& $git config user.name)) { $who = @('-c', 'user.name=VpnGuard', '-c', 'user.email=vpnguard@localhost') }
& $git @who commit -q -m "VpnGuard $ver ($build)$(if ($Notes) { ": $Notes" })" -m 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
Write-Host "Версия $ver, сборка $build, файлов: $($files.Count)"
if ($NoPush) { Write-Host 'Без отправки (-NoPush)'; return }
& $git push -u origin main
if ($LASTEXITCODE -ne 0) { throw 'git push не удался — проверьте вход в GitHub и что репозиторий создан' }
Write-Host 'Опубликовано. Агенты обновятся при следующей проверке или по кнопке «Обновить сейчас».'
