#Requires -Version 5.1
<#
  Проверка кода VpnGuard перед выпуском (запускает Publish.ps1; можно и вручную).

    .\Test.ps1          # всё: синтаксис, правила, запуск функций агента, установщик обновлений, веб-сервер, окно
    .\Test.ps1 -Quick   # только синтаксис и правила (несколько секунд)

  Правила ловят ошибки, которые PowerShell пропускает до момента выполнения:
    • «@('имя', $a + $b)» — запятая сильнее «+», получается массив из 3 элементов, а не строка;
    • переменная с тем же именем в другом регистре ($f и $F — в PowerShell это одна переменная);
    • функция с именем, совпадающим с встроенным псевдонимом (R, H, …);
    • результат Where-Object в массивах для JSON (массивы превращаются в {"value":…,"Count":…}).
#>
param([switch]$Quick)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$fail = New-Object Collections.ArrayList
$warn = New-Object Collections.ArrayList
function Fail([string]$m) { [void]$fail.Add($m); Write-Host "  ✗ $m" -ForegroundColor Red }
function Warn([string]$m) { [void]$warn.Add($m); Write-Host "  ! $m" -ForegroundColor Yellow }
function Ok([string]$m) { Write-Host "  ✓ $m" -ForegroundColor Green }
$sw = [Diagnostics.Stopwatch]::StartNew()
$files = @(Get-ChildItem $Root -Filter '*.ps1' -File)

# ---------------------------------------------------------------- 1. синтаксис и кодировка
Write-Host '1. Синтаксис и кодировка'
$asts = @{}
foreach ($f in $files) {
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    $hasCyr = [Text.Encoding]::UTF8.GetString($bytes) -match '[а-яА-Я]'
    if ($hasCyr -and -not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) { Fail "$($f.Name): нет BOM UTF-8 — Windows PowerShell 5.1 прочитает русский текст неверно" }
    $txt = [IO.File]::ReadAllText($f.FullName)
    if ($txt -match '[\x00-\x08\x0B\x0C\x0E-\x1F]') { Fail "$($f.Name): управляющие символы в тексте (испорченный «\b», «\a»?)" }
    $err = $null; $tok = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
    if ($err.Count) { foreach ($e in $err | Select-Object -First 3) { Fail "$($f.Name):$($e.Extent.StartLineNumber): $($e.Message)" } } else { $asts[$f.Name] = $ast }
}
$web = Join-Path $Root 'web\index.html'
if (Test-Path $web) {
    $h = [IO.File]::ReadAllText($web)
    if ($h -notmatch '</html>\s*$') { Fail 'web\index.html: файл обрезан' }
    if ($h -match '(src|href)="https?://') { Fail 'web\index.html: внешние ссылки на скрипты/стили — веб-интерфейс должен работать без интернета' }
    foreach ($m in [regex]::Matches($h, '(?:src|href)="([^"]+\.(?:js|css))"')) { if (-not (Test-Path (Join-Path $Root ('web\' + $m.Groups[1].Value)))) { Fail "web\index.html: нет файла web\$($m.Groups[1].Value)" } }
}
if (-not $fail.Count) { Ok "файлов: $($files.Count), без синтаксических ошибок" }

# ---------------------------------------------------------------- 1б. единая схема настроек
Write-Host '1б. Единая схема настроек (config-schema.txt): все ключи из кода есть в схеме, запасные значения в коде совпадают с ней'
$schF = Join-Path $Root 'config-schema.txt'
if (-not (Test-Path $schF)) { Fail 'нет config-schema.txt' }
else {
    $sch = @{}; foreach ($e in @((Get-Content $schF -Raw -Encoding UTF8 | ConvertFrom-Json).settings)) { $sch["$($e.key)"] = $e.default }
    $code = (@(Get-ChildItem (Join-Path $Root 'agent') -Filter '*.cs' -File | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) + [IO.File]::ReadAllText((Join-Path $Root 'Web.cs'))) -join "`n"
    $bad = @()
    foreach ($m in [regex]::Matches($code, 'Cfg(?:Int|Bool|Str|List)\(\s*"([\w.]*\w)"')) { if (-not $sch.ContainsKey($m.Groups[1].Value)) { $bad += "$($m.Groups[1].Value) — ключа нет в схеме" } }
    foreach ($m in [regex]::Matches($code, 'Cfg(Int|Bool|Str)\(\s*"([\w.]+)"\s*,\s*(-?\d+|true|false|@?"(?:[^"\\]|\\.)*")\s*\)')) {
        $k = $m.Groups[2].Value; $lit = $m.Groups[3].Value
        if (-not $sch.ContainsKey($k)) { continue }
        $v = switch ($m.Groups[1].Value) {
            'Int'  { [int]$lit }
            'Bool' { $lit -eq 'true' }
            'Str'  { if ($lit.StartsWith('@')) { $lit.Substring(2, $lit.Length - 3) } else { $lit.Substring(1, $lit.Length - 2).Replace('\\', '\') } }
        }
        if ("$v" -ne "$($sch[$k])") { $bad += "$k — в коде $lit, в схеме $($sch[$k])" }
    }
    foreach ($m in [regex]::Matches($code, 'CfgList\(\s*"([\w.]+)"\s*,\s*new\[\]\s*\{([^}]*)\}')) {
        $k = $m.Groups[1].Value; $vals = @([regex]::Matches($m.Groups[2].Value, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
        if ($sch.ContainsKey($k) -and (@($sch[$k]) -join ',') -ne ($vals -join ',')) { $bad += "$k — в коде [$($vals -join ', ')], в схеме [$(@($sch[$k]) -join ', ')]" }
    }
    if ($bad.Count) { $bad | Select-Object -Unique | ForEach-Object { Fail "схема настроек: $_" } } else { Ok "настроек в схеме: $($sch.Count), код с ней согласован" }
}

# ---------------------------------------------------------------- 2. правила
Write-Host '2. Правила'
$aliases = @{}; foreach ($a in Get-Alias) { $aliases[$a.Name.ToLower()] = $a.Definition }
# короткие глобальные переменные каждого файла ($F, $W, $M …); модули видят глобальные агента и окна
$globalsOf = @{}
foreach ($n in $asts.Keys) {
    $g = @{}
    foreach ($as in $asts[$n].EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] }) {
        $v = $as.Left; if ($v -is [Management.Automation.Language.ConvertExpressionAst]) { $v = $v.Child }
        if ($v -is [Management.Automation.Language.VariableExpressionAst]) { $nm = $v.VariablePath.UserPath -replace '^script:', ''; if ($nm.Length -le 3) { $g[$nm] = 1 } }
    }
    # и заданные внутри функций через $script:X (например, $script:W в Import-Config)
    foreach ($v in $asts[$n].FindAll({ $args[0] -is [Management.Automation.Language.VariableExpressionAst] -and $args[0].VariablePath.UserPath -like 'script:*' }, $true)) { $nm = $v.VariablePath.UserPath.Substring(7); if ($nm.Length -le 3) { $g[$nm] = 1 } }
    $globalsOf[$n] = $g
}
$hostGlobals = @{}; foreach ($h in 'VpnGuard.ps1') { if ($globalsOf[$h]) { foreach ($k in $globalsOf[$h].Keys) { $hostGlobals[$k] = 1 } } }
$rules = 0
$reported = @{}
foreach ($n in $asts.Keys) {
    $ast = $asts[$n]
    # модули агента видят глобальные VpnGuard.ps1; Wg.ps1 и Amnezia.ps1 подключаются ещё и в окно; остальные скрипты — отдельные
    $globals = switch ($n) {
        { $_ -in 'Wg.ps1', 'Amnezia.ps1' } { $hostGlobals; break }
        { $_ -in 'Zapret.ps1', 'Software.ps1', 'Remote.ps1', 'Update.ps1' } { $globalsOf['VpnGuard.ps1']; break }
        default { $globalsOf[$n] }
    }
    # запятая сильнее «+»: ('a', $x) + 'y'
    foreach ($b in $ast.FindAll({ $args[0] -is [Management.Automation.Language.BinaryExpressionAst] -and $args[0].Operator -eq 'Plus' -and $args[0].Left -is [Management.Automation.Language.ArrayLiteralAst] }, $true)) {
        Fail "${n}:$($b.Extent.StartLineNumber): «$($b.Left.Extent.Text.Substring(0, [Math]::Min(40, $b.Left.Extent.Text.Length)))… + …» — запятая сильнее «+», возьмите выражение в скобки"; $rules++
    }
    foreach ($fd in $ast.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        # функции с именами встроенных псевдонимов
        if ($aliases.ContainsKey($fd.Name.ToLower())) { Fail "${n}:$($fd.Extent.StartLineNumber): функция «$($fd.Name)» совпадает с псевдонимом → $($aliases[$fd.Name.ToLower()])"; $rules++ }
        # локальная переменная, отличающаяся от глобальной только регистром ($f при глобальной $F): из-за динамических областей
        # она подменяет глобальную и во всех функциях, вызванных отсюда
        $assigned = @()
        foreach ($as in $fd.Body.FindAll({ $args[0] -is [Management.Automation.Language.AssignmentStatementAst] }, $true)) { $v = $as.Left; if ($v -is [Management.Automation.Language.ConvertExpressionAst]) { $v = $v.Child }; if ($v -is [Management.Automation.Language.VariableExpressionAst]) { $assigned += , @($v.VariablePath.UserPath, $v.Extent.StartLineNumber) } }
        foreach ($fe in $fd.Body.FindAll({ $args[0] -is [Management.Automation.Language.ForEachStatementAst] }, $true)) { $assigned += , @($fe.Variable.VariablePath.UserPath, $fe.Extent.StartLineNumber) }
        if ($fd.Parameters) { foreach ($pa in $fd.Parameters) { $assigned += , @($pa.Name.VariablePath.UserPath, $pa.Extent.StartLineNumber) } }
        if ($fd.Body.ParamBlock) { foreach ($pa in $fd.Body.ParamBlock.Parameters) { $assigned += , @($pa.Name.VariablePath.UserPath, $pa.Extent.StartLineNumber) } }
        foreach ($x in $assigned) {
            foreach ($g in $globals.Keys) {
                if ($g.ToLower() -eq "$($x[0])".ToLower() -and $g -cne $x[0]) {
                    $key = "$n|$($fd.Name)|$($x[0])"; if ($reported[$key]) { continue }; $reported[$key] = 1
                    Fail "${n}:$($x[1]): в функции $($fd.Name) переменная `$$($x[0]) подменяет глобальную `$$g (в PowerShell это одна переменная)"; $rules++
                }
            }
        }
    }
    # kv через Where-Object → в JSON строки-массивы превращаются в {"value":…}
    foreach ($a in $ast.FindAll({ $args[0] -is [Management.Automation.Language.HashtableAst] }, $true)) {
        foreach ($p in $a.KeyValuePairs) {
            if ("$($p.Item1)" -eq 'kv' -and $p.Item2.Extent.Text -match '\|\s*Where-Object') { Fail "${n}:$($p.Item2.Extent.StartLineNumber): kv = …| Where-Object — строки-массивы испортятся в JSON, используйте foreach"; $rules++ }
        }
    }
}if (-not $rules) { Ok 'нарушений нет' }

if ($Quick) {
    Write-Host ''
    if ($fail.Count) { Write-Host "ОШИБОК: $($fail.Count) ($([int]$sw.Elapsed.TotalSeconds) с)" -ForegroundColor Red; exit 1 }
    Write-Host "Всё в порядке ($([int]$sw.Elapsed.TotalSeconds) с)" -ForegroundColor Green; exit 0
}

# ---------------------------------------------------------------- 3. запуск кода в песочнице
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('vpnguard-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $tmp -Force | Out-Null
function Invoke-Child([string]$Script, [int]$TimeoutSec = 120) {
    $f = Join-Path $tmp ('t' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.ps1')
    [IO.File]::WriteAllText($f, $Script, (New-Object Text.UTF8Encoding $true))
    $psi = New-Object Diagnostics.ProcessStartInfo 'powershell.exe'
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$f`""
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8; $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    $p = [Diagnostics.Process]::Start($psi); $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; return [pscustomobject]@{ Code = -1; Out = $o.Result; Err = "таймаут $TimeoutSec с" } }
    [pscustomobject]@{ Code = $p.ExitCode; Out = $o.Result; Err = $e.Result }
}
# загрузка функций агента без основного цикла (данные — во временной папке)
$loader = @"
`$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
`$Root = '$Root'
`$DataDir = '$tmp\data'; New-Item -ItemType Directory `$DataDir -Force | Out-Null
`$LogDir = `$DataDir; `$DlDir = `$DataDir; `$CmdDir = Join-Path `$DataDir 'cmd'; New-Item -ItemType Directory `$CmdDir -Force | Out-Null
`$ConfigPath = Join-Path `$DataDir 'config.json'; `$StatusPath = Join-Path `$DataDir 'status.json'; `$StatePath = Join-Path `$DataDir 'state.json'
`$ast = [Management.Automation.Language.Parser]::ParseFile("`$Root\VpnGuard.ps1", [ref]`$null, [ref]`$null)
foreach (`$fd in `$ast.FindAll({ `$args[0] -is [Management.Automation.Language.FunctionDefinitionAst] }, `$false)) { . ([scriptblock]::Create(`$fd.Extent.Text)) }
foreach (`$st in `$ast.EndBlock.Statements) {
    if (`$st -is [Management.Automation.Language.AssignmentStatementAst] -and `$st.Extent.Text -notmatch 'Mutex|SelfStamp|SelfPath|\`$Root|\`$DataDir|ConfigPath|LogDir|DlDir|CmdDir|StatePath|StatusPath|BinDir|MyInvocation') { . ([scriptblock]::Create(`$st.Extent.Text)) }
}
Import-Config
function Write-Log([string]`$Message, [string]`$Level = 'INFO') { }
foreach (`$modName in 'Zapret', 'Wg', 'Amnezia', 'Software', 'Remote', 'Update') { . (Join-Path `$Root "`$modName.ps1") }
`$script:IsAgentLoop = `$true

"@

Write-Host '4. Установка обновлений (сверка sha256, проверка кода, отказ при ошибке)'
$r = Invoke-Child ($loader + @'
$app = Join-Path $DataDir 'app'; $remote = Join-Path $DataDir 'remote'; New-Item -ItemType Directory $app, $remote -Force | Out-Null
'a.ps1', 'b.ps1' | ForEach-Object { Set-Content (Join-Path $app $_) "'old'" -Encoding UTF8; Set-Content (Join-Path $remote $_) "'new'" -Encoding UTF8 }
Set-Content (Join-Path $remote 'bad.ps1') 'function x {' -Encoding UTF8
$Root = $app
function Invoke-WebRequest { param($Uri, $OutFile, $Headers, $TimeoutSec, [switch]$UseBasicParsing) Copy-Item (Join-Path $remote (($Uri -split '/')[-1])) $OutFile -Force }
$mk = { param([string[]]$names) $f = @($names | ForEach-Object { [pscustomobject]@{ path = $_; sha256 = (Get-FileHash (Join-Path $remote $_)).Hash.ToLower() } }); [pscustomobject]@{ Sha = ('a' * 40); Version = '9'; Build = 't'; Files = $f; Changed = $f; Repo = 'x/y' } }
Install-AppUpdate (& $mk @('a.ps1'))
$ok1 = (Get-Content (Join-Path $app 'a.ps1')) -eq "'new'"
Install-AppUpdate (& $mk @('b.ps1', 'bad.ps1'))
$ok2 = (Get-Content (Join-Path $app 'b.ps1')) -eq "'old'" -and $AppState.error -match 'ошибк'
$l = & $mk @('b.ps1'); $l.Changed[0].sha256 = ('0' * 64); Install-AppUpdate $l
$ok3 = (Get-Content (Join-Path $app 'b.ps1')) -eq "'old'" -and $AppState.error -match 'сумма'
$ok4 = -not (Test-AppPath '../x.ps1') -and -not (Test-AppPath 'config.json') -and -not (Test-AppPath 'data/x.ps1') -and (Test-AppPath 'web/index.html')
"R $ok1 $ok2 $ok3 $ok4"
'@) 120
if ($r.Out -match 'R True True True True') { Ok 'обновление ставится; с ошибкой в коде и с неверной суммой — не ставится; опасные пути отброшены' } else { Fail "обновления: $($r.Out.Trim()) $($r.Err.Trim())" }

Write-Host '5. Веб-сервер на C# (сборка встроенным csc, вход, защита, настройки, задачи PowerShell)'
$csc = @("$env:windir\Microsoft.NET\Framework64\v4.0.30319\csc.exe", "$env:windir\Microsoft.NET\Framework\v4.0.30319\csc.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
$exe = Join-Path $tmp 'VpnGuardWeb.exe'
$co = & $csc /nologo /target:exe /optimize+ "/out:$exe" /r:System.Web.Extensions.dll /r:System.Drawing.dll (Join-Path $Root 'Web.cs') (Join-Path $Root 'Qr.cs') 2>&1
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) { foreach ($l in @($co) | Where-Object { "$_" -match 'error' } | Select-Object -First 5) { Fail "сборка Web.cs: $l" } }
else {
    $wd = Join-Path $tmp 'webdata'; New-Item -ItemType Directory (Join-Path $wd 'cmd'), (Join-Path $wd 'logs') -Force | Out-Null
    $port = Get-Random -Minimum 20000 -Maximum 40000
    $wcfg = Join-Path $tmp 'webcfg.json'
    @{ web = @{ enabled = $true; port = $port; token = 'testtoken12345678'; requirePassword = $true }; zapret = @{ videoCheck = $true } } | ConvertTo-Json -Depth 4 | Set-Content $wcfg -Encoding UTF8
    @{ updated = (Get-Date).ToString('o'); agentVersion = 'test'; history = @() } | ConvertTo-Json | Set-Content (Join-Path $wd 'status.json') -Encoding UTF8
    $srv = Start-Process $exe -ArgumentList "`"$Root`" `"$wcfg`" `"$wd`"" -PassThru -WindowStyle Hidden
    $base = "http://127.0.0.1:$port"; $res = @()
    $up = $false; for ($k = 0; $k -lt 30 -and -not $up; $k++) { Start-Sleep -Milliseconds 300; try { $null = Invoke-WebRequest "$base/api/whoami" -UseBasicParsing -TimeoutSec 3; $up = $true } catch { } }
    if (-not $up) { $res += 'сервер не запустился' } else {
        $w = Invoke-RestMethod "$base/api/whoami" -UseBasicParsing
        if ($w.role -ne 'web' -or $w.engine -ne 'csharp') { $res += "с этого ПК роль '$($w.role)', движок '$($w.engine)'" }
        $pg = Invoke-WebRequest "$base/" -UseBasicParsing; if ($pg.StatusCode -ne 200 -or $pg.Content -notmatch 'VpnGuard') { $res += 'страница / не отдаётся' }
        try { $null = (Invoke-WebRequest "$base/api/status" -UseBasicParsing).Content | ConvertFrom-Json } catch { $res += '/api/status — не JSON' }
        foreach ($bad in @(
            @{ n = 'POST без X-VG принят'; u = '/api/cmd'; h = @{}; b = '{"c":"check-now"}' },
            @{ n = 'неизвестная команда принята'; u = '/api/cmd'; h = @{ 'X-VG' = '1' }; b = '{"c":"del x"}' },
            @{ n = 'запрещённая настройка принята'; u = '/api/config'; h = @{ 'X-VG' = '1' }; b = '{"key":"web.token","value":"x"}' },
            @{ n = 'короткий пароль принят'; u = '/api/websettings'; h = @{ 'X-VG' = '1' }; b = '{"password":"abc"}' })) {
            try { Invoke-WebRequest "$base$($bad.u)" -Method Post -Headers $bad.h -Body $bad.b -ContentType 'application/json' -UseBasicParsing | Out-Null; $res += $bad.n } catch { }
        }
        try { Invoke-WebRequest "$base/api/status" -Headers @{ Host = 'evil.example' } -UseBasicParsing | Out-Null; $res += 'чужое имя хоста принято' } catch { }
        # разрешённая настройка: config.json остаётся читаемым для агента
        $null = Invoke-RestMethod "$base/api/config" -Method Post -Headers @{ 'X-VG' = '1' } -Body '{"key":"zapret.videoCheck","value":false}' -ContentType 'application/json' -UseBasicParsing
        try { $cj = Get-Content $wcfg -Raw -Encoding UTF8 | ConvertFrom-Json; if ($cj.zapret.videoCheck -ne $false -or $cj.web.token -ne 'testtoken12345678') { $res += 'config.json записан неверно' } } catch { $res += 'config.json испорчен после записи' }
        $null = Invoke-RestMethod "$base/api/cmd" -Method Post -Headers @{ 'X-VG' = '1' } -Body '{"c":"check-now"}' -ContentType 'application/json' -UseBasicParsing
        if (-not (Get-ChildItem (Join-Path $wd 'cmd') -Filter '*.cmd')) { $res += 'команда агенту не записана' }
        # задача через PowerShell (мост C# → VpnGuard.ps1 -WebTask)
        $wgc = Invoke-RestMethod "$base/api/wg/clients" -UseBasicParsing -TimeoutSec 90
        if ($null -eq $wgc.ok) { $res += "мост к PowerShell не вернул JSON: $wgc" }
        $ws = Invoke-RestMethod "$base/api/websettings" -UseBasicParsing; if ($ws.password -ne 'testtoken12345678') { $res += '/api/websettings не видит пароль' }
    }
    try { Stop-Process -Id $srv.Id -Force } catch { }
    if ($res) { foreach ($x in $res) { Fail "веб (C#): $x" } } else { Ok "собран ($([int]((Get-Item $exe).Length / 1KB)) КБ); вход, защита, запись config.json, команды агенту, мост к PowerShell" }
}
Write-Host '5б. Значок у часов на C# (сборка и запуск)'
$tray = Join-Path $tmp 'VpnGuardTray.exe'
$co = & $csc /nologo /target:winexe /optimize+ "/out:$tray" /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll (Join-Path $Root 'Tray.cs') 2>&1
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tray)) { foreach ($l in @($co) | Where-Object { "$_" -match 'error' } | Select-Object -First 5) { Fail "сборка Tray.cs: $l" } }
else {
    $tr = Join-Path $tmp 'trayroot'; New-Item -ItemType Directory (Join-Path $tr 'data') -Force | Out-Null; '#' | Set-Content (Join-Path $tr 'VpnGuard.ps1')
    $st2 = [ordered]@{ updated = (Get-Date).ToString('o'); staleAfterSec = 300; vpn = @{ mode = 'meduza' } }
    foreach ($k in 'ultra', 'meduza', 'wg', 'ics', 'zapret') { $st2[$k] = @{ level = $(if ($k -eq 'zapret') { 2 } else { 0 }); state = 'тест'; enabled = $true } }
    $st2 | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $tr 'data\status.json') -Encoding UTF8
    $tp = Start-Process $tray -ArgumentList "`"$tr`"" -PassThru
    Start-Sleep -Seconds 4; $tp.Refresh()
    if ($tp.HasExited) { Fail "значок завершился сразу (код $($tp.ExitCode))" } else { Ok "собран ($([int]((Get-Item $tray).Length / 1KB)) КБ), запускается и читает состояние"; Stop-Process -Id $tp.Id -Force }
}
Write-Host '5в. Агент на C# с zapret (сборка и снимок состояния в режимах meduza, amnezia, dual, zapret)'
$agx = Join-Path $tmp 'VpnGuardAgent.exe'
$co = & $csc /nologo /target:winexe /optimize+ "/out:$agx" /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Management.dll /r:System.Core.dll /r:Microsoft.CSharp.dll /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll @(Get-ChildItem (Join-Path $Root 'agent') -Filter '*.cs' -File | ForEach-Object FullName) 2>&1
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $agx)) { foreach ($l in @($co) | Where-Object { "$_" -match 'error' } | Select-Object -First 5) { Fail "сборка агента C#: $l" } }
else {
    $ar = Join-Path $tmp 'agentroot'; New-Item -ItemType Directory (Join-Path $ar 'data\amnezia') -Force | Out-Null
    "`$AgentVersion = '9.9'" | Set-Content (Join-Path $ar 'VpnGuard.ps1') -Encoding UTF8
    "[Interface]`r`n# Name = Тест`r`nAddress = 10.8.0.2/32`r`n[Peer]`r`nEndpoint = 1.2.3.4:51820" | Set-Content (Join-Path $ar 'data\amnezia\test1.conf') -Encoding UTF8
    @{ updated = (Get-Date).ToString('o'); activity = ''; zapret = @{ level = 0; state = 'Работает'; details = @('x'); kv = @(, @('Ключ', 'Значение')); enabled = $true; conns = 3 }; software = @(@{ id = 'x'; installed = '1' }); meduzaRemoteVersion = '1.2.3' } | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $ar 'data\status-ps.json') -Encoding UTF8
    $bad = @()
    foreach ($mode in 'meduza', 'amnezia', 'zapret') {
        $acfg = Join-Path $ar 'config.json'
        @{ vpn = @{ mode = $mode }; agent = @{ engine = 'csharp' } } | ConvertTo-Json -Depth 4 | Set-Content $acfg -Encoding UTF8
        $p = Start-Process $agx -ArgumentList "`"$ar`" `"$acfg`" --snapshot" -PassThru -Wait -WindowStyle Hidden
        if ($p.ExitCode -ne 0) { $bad += "${mode}: код выхода $($p.ExitCode)"; continue }
        try { $j = Get-Content (Join-Path $ar 'data\status.json') -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $bad += "${mode}: status.json не JSON"; continue }
        if ($j.engine -ne 'csharp' -or $j.vpn.mode -ne $mode) { $bad += "${mode}: engine/vpn.mode = $($j.engine)/$($j.vpn.mode)" }
        foreach ($k in 'meduza', 'ultra', 'wg', 'ics', 'zapret', 'amnezia') {
            $o = $j.$k
            if ($null -eq $o) { $bad += "$mode/${k}: нет раздела"; continue }
            if ($null -eq $o.level -or -not "$($o.state)") { $bad += "$mode/${k}: нет level/state" }
            foreach ($row in @($o.kv)) { if (@($row).Count -ne 2) { $bad += "$mode/${k}: строка kv из $(@($row).Count) элементов" } }
        }
        # zapret в пустой папке: выключен, а в режиме «без VPN» (включён всегда) — не установлен
        $zw = $(if ($mode -eq 'zapret') { 'Не установлен' } else { 'Выключен' })
        if ($j.zapret.state -ne $zw -or $null -eq $j.zapret.strategies -or $j.zapret.enabled -ne ($mode -eq 'zapret')) { $bad += "${mode}: zapret — '$($j.zapret.state)', ждали '$zw'" }
        if (@($j.software).Count -ne 1) { $bad += "${mode}: компоненты не взяты из status-ps.json" }
        # AmneziaVPN не установлен в пустой папке; адаптер старого туннеля AmneziaWG (data\amnezia) — не туннель AmneziaVPN
        if ($mode -eq 'amnezia' -and ($j.amnezia.state -notin 'Не установлен', 'Не запущен', 'Туннель не подключён', 'Подключён', 'Нет трафика' -or $j.amnezia.installed -eq $null -or $j.ultra.title -ne 'Туннель: AmneziaVPN')) { $bad += "amnezia: состояние '$($j.amnezia.state)', заголовок '$($j.ultra.title)'" }
        if (@($j.history).Count -lt 1) { $bad += "${mode}: нет истории" }
        # два туннеля: трафик через основной (MeduzaVPN), резерв — AmneziaVPN
        if ($mode -eq 'dual' -and ($j.vpn.kind -ne 'meduza' -or $j.ultra.standby.kind -ne 'amnezia' -or $j.amnezia.level -eq -1)) { $bad += "dual: kind '$($j.vpn.kind)', резерв '$($j.ultra.standby.kind)', amnezia level $($j.amnezia.level)" }
    }
    if ($bad) { $bad | Select-Object -Unique | ForEach-Object { Fail "агент C#: $_" } } else { Ok "собран ($([int]((Get-Item $agx).Length / 1KB)) КБ); снимок состояния в четырёх режимах совпадает по форме с агентом PowerShell" }
}
Write-Host '5г. Логика агента (самопроверка --selftest: схема настроек, команды, события, быстрое переключение, проверка узлов, история)'
if (Test-Path $agx) {
    $sr = Join-Path $tmp 'selftest'; New-Item -ItemType Directory $sr -Force | Out-Null
    $so = Join-Path $tmp 'selftest.txt'
    $sp = Start-Process $agx -ArgumentList "`"$sr`" --selftest" -Wait -PassThru -RedirectStandardOutput $so -WindowStyle Hidden
    $lines = @(Get-Content $so -Encoding UTF8 -ErrorAction SilentlyContinue)
    $nf = @($lines | Where-Object { $_ -like 'FAIL*' })
    if ($sp.ExitCode -ne 0 -or $nf.Count -or -not ($lines -contains 'ВСЁ OK')) { foreach ($l in $nf) { Fail "самопроверка: $($l.Substring(5))" }; if (-not $nf.Count) { Fail "самопроверка: код $($sp.ExitCode) $(($lines | Select-Object -Last 2) -join ' ')" } }
    else { Ok "сценариев: $(@($lines | Where-Object { $_ -like 'OK *' }).Count), все прошли" }
}

Write-Host '7. Имена клиентов WG-Server (формат WS4W «# 1» над [Peer] и VpnGuard «# Name =» внутри; агент C# и список одинаково)'
$pr = Join-Path $tmp 'peers'; New-Item -ItemType Directory (Join-Path $pr 'srv\server_wg'), (Join-Path $pr 'srv\clients_wg\c1'), (Join-Path $pr 'data\logs') -Force | Out-Null
$pconf = Join-Path $pr 'srv\server_wg\wg_server.conf'
[IO.File]::WriteAllText($pconf, (@('# wg', '[Interface]', 'ListenPort=51820', 'Address=192.168.15.1/24', 'PrivateKey=AAAA', '', '', '# 1', '[Peer]', 'PublicKey=KEY1', 'AllowedIPs=192.168.15.4', '', '', '# 2', '[Peer]', 'PublicKey=KEY2', 'AllowedIPs=192.168.15.5/32', '',
    '[Peer]', '# Name = телефон', '# VpnGuard: created 2026-11-03 11:53', 'PublicKey = KEY4', 'AllowedIPs = 192.168.15.10/32', '', '[Peer]', '# Name = ноутбук', '# VpnGuard: created 2026-11-04 10:00', 'PublicKey = KEY5', 'AllowedIPs = 192.168.15.11/32', '',
    '[Peer]', 'PublicKey = KEY6', 'AllowedIPs = 192.168.15.12/32') -join "`r`n"), (New-Object Text.UTF8Encoding $false))
"[Interface]`r`nPrivateKey = X`r`nAddress = 192.168.15.12/32`r`n[Peer]`r`nPublicKey = Y" | Set-Content (Join-Path $pr 'srv\clients_wg\c1\планшет.conf') -Encoding UTF8
@{ ws4w = @{ configPath = $pconf } } | ConvertTo-Json | Set-Content (Join-Path $pr 'config.json') -Encoding UTF8
$r = Invoke-Child @"
[Console]::OutputEncoding = New-Object Text.UTF8Encoding `$false
`$DataDir = '$pr\data'; `$W = @{ configPath = '$pconf'; interfaceName = 'wg_server'; serviceName = 'x' }; `$State = `$null
. '$Root\Wg.ps1'
`$c = Read-WgConf '$pconf'
`$o = @(foreach (`$s in `$c.Sections | Where-Object { `$_.Type -eq 'Peer' }) { "`$(`$s.Keys['PublicKey'])=`$(Get-PeerName `$s)" }) -join ';'
`$p2 = `$c.Sections | Where-Object { `$_.Keys['PublicKey'] -eq 'KEY1' }; if (`$c.Lines[`$p2.End] -match '#') { `$o += ';END' }
`$asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes('$agx')); `$Ty = `$asm.GetType('VpnGuard.Agent'); `$bf = [Reflection.BindingFlags]'NonPublic,Static,Public'
foreach (`$kv in @{ Root = '$pr'; DataDir = '$pr\data'; LogDir = '$pr\data\logs'; ConfigPath = '$pr\config.json' }.GetEnumerator()) { `$Ty.GetField(`$kv.Key, `$bf).SetValue(`$null, `$kv.Value) }
`$Ty.GetMethod('LoadCfg', `$bf).Invoke(`$null, @(`$true)); `$Ty.GetMethod('LoadPeerNames', `$bf).Invoke(`$null, @())
`$bk = `$Ty.GetField('PeerNamesByKey', `$bf).GetValue(`$null); `$bi = `$Ty.GetField('PeerNamesByIp', `$bf).GetValue(`$null)
`$cs = @(foreach (`$k in 'KEY1', 'KEY2', 'KEY4', 'KEY5', 'KEY6') { `$v = ''; [void]`$bk.TryGetValue(`$k, [ref]`$v); "`$k=`$v" }) -join ';'
`$v = ''; [void]`$bi.TryGetValue('192.168.15.12', [ref]`$v)
"WG `$o"; "CS `$cs;IP=`$v"
"@ 120
$wantWg = 'KEY1=1;KEY2=2;KEY4=телефон;KEY5=ноутбук;KEY6='; $wantCs = 'KEY1=1;KEY2=2;KEY4=телефон;KEY5=ноутбук;KEY6=;IP=планшет'
$okWg = [bool]($r.Out -split "`n" | Where-Object { $_.Trim() -eq "WG $wantWg" })
$okCs = [bool]($r.Out -split "`n" | Where-Object { $_.Trim() -eq "CS $wantCs" })
if ($okWg -and $okCs) { Ok 'имена клиентов: «1», «2» (WS4W), «телефон», «ноутбук» (VpnGuard), «планшет» (по файлу) — одинаково в списке и в агенте' }
else { Fail "имена клиентов: $(($r.Out + ' ' + $r.Err).Trim())" }

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail.Count) { Write-Host "ОШИБОК: $($fail.Count) ($([int]$sw.Elapsed.TotalSeconds) с)" -ForegroundColor Red; exit 1 }
Write-Host "Всё в порядке ($([int]$sw.Elapsed.TotalSeconds) с)" -ForegroundColor Green
exit 0
