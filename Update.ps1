# VpnGuard — автообновление самого приложения из репозитория GitHub.
# Источник: https://github.com/<update.repo> (ветка update.branch). В корне репозитория — vpnguard-manifest.json:
#   { "version": "2.2", "build": "20261103-1530", "notes": "...", "files": [ { "path": "VpnGuard.ps1", "sha256": "...", "size": 123 }, ... ] }
# Файлы берутся по SHA коммита (raw.githubusercontent.com/<repo>/<sha>/<path>) — неизменяемые адреса, без кэша.
# Каждый файл сверяется с sha256 из манифеста, .ps1 проверяются парсером, старые файлы — в data\backup\app-*.
# config.json, data\, zapret\, bin\ не трогаются никогда.

$AppStatePath = Join-Path $DataDir 'app-update.json'
$AppState = @{ sha = ''; version = ''; build = ''; at = ''; latestSha = ''; latestVersion = ''; latestBuild = ''; notes = ''; checkedAt = ''; error = ''; pending = 0 }
if (Test-Path $AppStatePath) { try { $s = Get-Content $AppStatePath -Raw -Encoding UTF8 | ConvertFrom-Json; foreach ($p in $s.PSObject.Properties) { if ($AppState.ContainsKey($p.Name)) { $AppState[$p.Name] = $p.Value } } } catch { } }
function Save-AppState { try { $AppState | ConvertTo-Json -Depth 4 | Set-Content $AppStatePath -Encoding UTF8 } catch { } }

function Get-UCfg {
    $d = @{ repo = 'Fogiku/vpnguard'; branch = 'main'; auto = $true; checkHours = 3; token = '' }
    if ($Cfg.update) { foreach ($k in @($Cfg.update.Keys)) { $d[$k] = $Cfg.update[$k] } }
    return $d
}
function Get-UHeaders($u) {
    $h = @{ 'User-Agent' = 'VpnGuard-updater' }
    if ($u.token) { $h['Authorization'] = "token $($u.token)" }   # для закрытого репозитория
    return $h
}
# путь из манифеста: только файлы приложения в его папке
function Test-AppPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z0-9_\-\.]+(/[A-Za-z0-9_\-\.]+)*$' -or $Path -match '\.\.') { return $false }
    if ($Path -match '^(data|zapret|bin|\.git)(/|$)' -or $Path -ieq 'config.json') { return $false }
    return ($Path -match '\.(ps1|cmd|cs|md|txt|html|js|css)$')
}
function Get-LocalSha([string]$Path) { if (Test-Path $Path) { (Get-FileHash $Path -Algorithm SHA256).Hash.ToLower() } else { '' } }

function Get-AppLatest {
    $u = Get-UCfg
    if (-not $u.repo) { throw 'не указан репозиторий (Настройки → Обновление приложения)' }
    $c = Invoke-RestMethod "https://api.github.com/repos/$($u.repo)/commits/$($u.branch)" -Headers (Get-UHeaders $u) -TimeoutSec 30 -UseBasicParsing
    $sha = "$($c.sha)"
    if ($sha -notmatch '^[0-9a-f]{40}$') { throw 'GitHub не вернул коммит' }
    $mt = Invoke-RestMethod "https://raw.githubusercontent.com/$($u.repo)/$sha/vpnguard-manifest.json" -Headers (Get-UHeaders $u) -TimeoutSec 30 -UseBasicParsing
    if ($mt -is [string]) { $mt = $mt | ConvertFrom-Json }
    if (-not $mt.files) { throw 'в репозитории нет vpnguard-manifest.json или он пустой' }
    $files = @($mt.files | Where-Object { $_ -and (Test-AppPath "$($_.path)") -and "$($_.sha256)" -match '^[0-9a-fA-F]{64}$' })
    $changed = @($files | Where-Object { (Get-LocalSha (Join-Path $Root ("$($_.path)" -replace '/', '\'))) -ne "$($_.sha256)".ToLower() })
    [pscustomobject]@{ Sha = $sha; Version = "$($mt.version)"; Build = "$($mt.build)"; Notes = "$($mt.notes)"; Files = $files; Changed = $changed; Repo = $u.repo }
}

function Invoke-AppUpdateCheck([switch]$Install, [switch]$Force) {
    $u = Get-UCfg
    if (-not $u.repo) { $AppState.error = 'не указан репозиторий'; return }
    $AppState.checkedAt = (Get-Date).ToString('o')
    try { $l = Get-AppLatest } catch { $AppState.error = "проверка: $($_.Exception.Message)"; Save-AppState; Write-Log "Обновление VpnGuard: $($AppState.error)" 'WARN'; return }
    $AppState.latestSha = $l.Sha; $AppState.latestVersion = $l.Version; $AppState.latestBuild = $l.Build; $AppState.notes = $l.Notes
    $AppState.pending = @($l.Changed).Count; $AppState.error = ''
    if (-not $l.Changed.Count) {
        if ($AppState.sha -ne $l.Sha) { $AppState.sha = $l.Sha; $AppState.version = $l.Version; $AppState.build = $l.Build }
        Save-AppState; return
    }
    Write-Log ("Обновление VpnGuard: доступна версия {0} (сборка {1}), изменилось файлов: {2} — {3}" -f $l.Version, $l.Build, $l.Changed.Count, (($l.Changed | ForEach-Object { $_.path }) -join ', '))
    Save-AppState
    if ($Install -or $Force) { Install-AppUpdate $l }
}

function Install-AppUpdate($L) {
    $u = Get-UCfg
    Set-Activity "обновляю VpnGuard до $($L.Version)"
    $stage = Join-Path $DataDir ('update\' + $L.Sha.Substring(0, 12))
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory $stage -Force | Out-Null
    try {
        # 1. скачать и сверить
        foreach ($f in $L.Changed) {
            $rel = "$($f.path)" -replace '/', '\'
            $dst = Join-Path $stage $rel
            New-Item -ItemType Directory (Split-Path $dst) -Force | Out-Null
            $url = "https://raw.githubusercontent.com/$($L.Repo)/$($L.Sha)/$($f.path)"
            Invoke-WebRequest $url -OutFile $dst -Headers (Get-UHeaders $u) -TimeoutSec 120 -UseBasicParsing
            $h = Get-LocalSha $dst
            if ($h -ne "$($f.sha256)".ToLower()) { throw "контрольная сумма $($f.path) не совпала (скачано $h)" }
            # 2. код без синтаксических ошибок
            if ($rel -like '*.ps1') {
                $err = $null; [void][Management.Automation.Language.Parser]::ParseFile($dst, [ref]$null, [ref]$err)
                if ($err.Count) { throw "$($f.path) содержит ошибку: $($err[0].Message) (строка $($err[0].Extent.StartLineNumber))" }
            }
        }
        # 3. резервная копия заменяемых файлов (храним 5 последних)
        $bk = Join-Path $DataDir ('backup\app-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $(if ($AppState.version) { $AppState.version } else { $AgentVersion }))
        New-Item -ItemType Directory $bk -Force | Out-Null
        foreach ($f in $L.Changed) {
            $src = Join-Path $Root ("$($f.path)" -replace '/', '\')
            if (Test-Path $src) { $d = Join-Path $bk ("$($f.path)" -replace '/', '\'); New-Item -ItemType Directory (Split-Path $d) -Force | Out-Null; Copy-Item $src $d -Force }
        }
        Get-ChildItem (Join-Path $DataDir 'backup') -Directory -Filter 'app-*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -Skip 5 | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        # 4. заменить: модули и окно — сначала, VpnGuard.ps1 — последним (по нему агент перезапускается)
        $ordered = @($L.Changed | Sort-Object { if ("$($_.path)" -eq 'VpnGuard.ps1') { 1 } else { 0 } })
        foreach ($f in $ordered) {
            $rel = "$($f.path)" -replace '/', '\'
            $dst = Join-Path $Root $rel
            New-Item -ItemType Directory (Split-Path $dst) -Force | Out-Null
            $tmp = "$dst.new"
            Copy-Item (Join-Path $stage $rel) $tmp -Force
            Move-Item $tmp $dst -Force
        }
        $AppState.sha = $L.Sha; $AppState.version = $L.Version; $AppState.build = $L.Build; $AppState.at = (Get-Date).ToString('o'); $AppState.pending = 0; $AppState.error = ''
        Save-AppState
        Write-Log ("Обновление VpnGuard: установлена версия {0} (сборка {1}), файлов: {2}; копия старых — {3}. Агент и окно перезапустятся сами." -f $L.Version, $L.Build, $L.Changed.Count, $bk) 'WARN'
    } catch {
        $AppState.error = "установка: $($_.Exception.Message)"; Save-AppState
        Write-Log "Обновление VpnGuard не установлено: $($_.Exception.Message) — работаю на текущей версии" 'ERROR'
    } finally {
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-AppUpdateWatch {
    $u = Get-UCfg
    if (-not $u.repo -or -not $u.auto) { return }
    $at = [datetime]::MinValue; try { if ($AppState.checkedAt) { $at = [datetime]$AppState.checkedAt } } catch { }
    if (((Get-Date) - $at).TotalHours -lt [double]$u.checkHours) { return }
    Invoke-AppUpdateCheck -Install
}

function Get-AppSnapshot {
    $u = Get-UCfg
    [ordered]@{
        repo = "$($u.repo)"; branch = "$($u.branch)"; auto = [bool]$u.auto; checkHours = [int]$u.checkHours
        version = $AgentVersion; build = "$($AppState.build)"; sha = "$($AppState.sha)"; installedAt = "$($AppState.at)"
        latestVersion = "$($AppState.latestVersion)"; latestBuild = "$($AppState.latestBuild)"; notes = "$($AppState.notes)"
        pending = [int]$AppState.pending; checkedAt = "$($AppState.checkedAt)"; error = "$($AppState.error)"
    }
}
