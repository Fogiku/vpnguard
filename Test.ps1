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
}
if (-not $fail.Count) { Ok "файлов: $($files.Count), без синтаксических ошибок" }

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
$hostGlobals = @{}; foreach ($h in 'VpnGuard.ps1', 'VpnGuardMonitor.ps1') { if ($globalsOf[$h]) { foreach ($k in $globalsOf[$h].Keys) { $hostGlobals[$k] = 1 } } }
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

Write-Host '3. Состояние агента во всех режимах'
$r = Invoke-Child ($loader + @'
$bad = @()
foreach ($mode in 'meduza', 'dual', 'amnezia', 'zapret') {
    $Cfg.vpn.mode = $mode
    Write-StatusSnapshot
    $raw = [IO.File]::ReadAllText($StatusPath)
    if ($raw -match '"value"\s*:\s*\[[^\]]*\]\s*,\s*"Count"') { $bad += "${mode}: массив превратился в {value,Count}" }
    $j = $raw | ConvertFrom-Json
    foreach ($k in 'meduza', 'ultra', 'wg', 'ics', 'zapret', 'amnezia') {
        $o = $j.$k
        if ($null -eq $o) { $bad += "$mode/${k}: нет раздела"; continue }
        if ($null -eq $o.level -or -not "$($o.state)") { $bad += "$mode/${k}: нет level/state" }
        foreach ($row in @($o.kv)) { if (@($row).Count -ne 2) { $bad += "$mode/${k}: строка kv из $(@($row).Count) элементов: $((@($row)) -join ' | ')" } }
    }
}
if ($bad) { $bad | Select-Object -Unique | ForEach-Object { "BAD $_" } } else { 'OK' }
'@) 180
if ($r.Out -match '(?m)^OK\s*$') { Ok 'снимок состояния в режимах meduza, dual, amnezia, zapret' } else { foreach ($l in ($r.Out + $r.Err) -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 12) { Fail "снимок: $($l.Trim())" } }

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

Write-Host '5. Веб-сервер и веб-интерфейс'
$port = Get-Random -Minimum 20000 -Maximum 40000
$r = Invoke-Child ($loader + @"
`$Cfg.web.port = $port; `$Cfg.web.token = 'testtoken12345678'; `$Cfg.web.enabled = `$true
`$job = [powershell]::Create(); `$null = `$job
`$stat = [ordered]@{ updated = (Get-Date).ToString('o'); agentVersion = 'test'; history = @(); vpn = @{ mode = 'meduza' } }
`$stat | ConvertTo-Json | Set-Content `$StatusPath -Encoding UTF8
`$srv = Start-Job -ArgumentList `$Root, `$DataDir, $port -ScriptBlock { param(`$root, `$data, `$port)
    `$c = @{ web = @{ enabled = `$true; port = `$port; token = 'testtoken12345678' } } | ConvertTo-Json; Set-Content "`$data\srvcfg.json" `$c -Encoding UTF8
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "`$root\VpnGuard.ps1" -RemoteServer -ConfigPath "`$data\srvcfg.json" }
`$base = "http://127.0.0.1:$port"
`$up = `$false; for (`$i = 0; `$i -lt 40 -and -not `$up; `$i++) { Start-Sleep -Milliseconds 500; try { `$null = Invoke-WebRequest "`$base/api/whoami" -UseBasicParsing -TimeoutSec 3; `$up = `$true } catch { } }
`$res = @()
if (-not `$up) { `$res += 'сервер не запустился' } else {
    `$p = Invoke-WebRequest "`$base/" -UseBasicParsing; if (`$p.StatusCode -ne 200 -or `$p.Content -notmatch 'VpnGuard') { `$res += 'страница / не отдаётся' }
    `$w = Invoke-RestMethod "`$base/api/whoami" -UseBasicParsing; if (`$w.role -ne 'web') { `$res += "с этого ПК роль '`$(`$w.role)' вместо web" }
    try { Invoke-WebRequest "`$base/api/cmd" -Method Post -Body '{"c":"check-now"}' -UseBasicParsing | Out-Null; `$res += 'POST без X-VG принят' } catch { }
    try { Invoke-WebRequest "`$base/api/cmd" -Method Post -Headers @{ 'X-VG' = '1' } -Body '{"c":"del x"}' -UseBasicParsing | Out-Null; `$res += 'неизвестная команда принята' } catch { }
    try { Invoke-WebRequest "`$base/api/status" -Headers @{ Host = 'evil.example' } -UseBasicParsing | Out-Null; `$res += 'чужое имя хоста принято' } catch { }
    try { Invoke-WebRequest "`$base/api/config" -Method Post -Headers @{ 'X-VG' = '1' } -Body '{"key":"web.token","value":"x"}' -UseBasicParsing | Out-Null; `$res += 'запрещённая настройка принята' } catch { }
    `$s = Invoke-WebRequest "`$base/api/status" -UseBasicParsing; try { `$null = `$s.Content | ConvertFrom-Json } catch { `$res += '/api/status — не JSON' }
}
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { `$_.CommandLine -match 'RemoteServer' -and `$_.CommandLine -match 'srvcfg' } | ForEach-Object { Stop-Process -Id `$_.ProcessId -Force }
Stop-Job `$srv -ErrorAction SilentlyContinue; Remove-Job `$srv -Force -ErrorAction SilentlyContinue
if (`$res) { `$res | ForEach-Object { "BAD `$_" } } else { 'OK' }
"@) 120
if ($r.Out -match '(?m)^OK\s*$') { Ok 'страница, вход с этого ПК, защита (POST без X-VG, чужие команды и настройки, DNS rebinding)' } else { foreach ($l in ($r.Out + $r.Err) -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 8) { Fail "веб: $($l.Trim())" } }

Write-Host '6. Окно (отрисовка всех страниц на тестовых данных)'
$demo = Join-Path $tmp 'demo'; New-Item -ItemType Directory $demo -Force | Out-Null
$st = [ordered]@{ updated = (Get-Date).ToString('o'); staleAfterSec = 300; agentVersion = 'test'; intervalSec = 30; history = @(); vpn = @{ mode = 'meduza'; name = 'MeduzaVPN' } }
foreach ($k in 'meduza', 'ultra', 'wg', 'ics', 'zapret', 'amnezia') { $st[$k] = [ordered]@{ level = 0; state = 'Работает'; details = @('тест'); kv = @(, @('Ключ', 'Значение')) } }
$st | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $demo 'status.json') -Encoding UTF8
$png = Join-Path $tmp 'pv.png'
$psi = New-Object Diagnostics.ProcessStartInfo 'powershell.exe'
$psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$Root\VpnGuardMonitor.ps1`" -Demo -StatusFile `"$demo\status.json`" -Preview `"$png`""
$psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
$enc = [Text.Encoding]::GetEncoding((Get-Culture).TextInfo.OEMCodePage); $psi.StandardOutputEncoding = $enc; $psi.StandardErrorEncoding = $enc
$p = [Diagnostics.Process]::Start($psi); $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
if (-not $p.WaitForExit(150000)) { try { $p.Kill() } catch { }; Fail 'окно: таймаут отрисовки' }
else {
    $pages = @([regex]::Matches($o.Result, 'страница (\w+)') | ForEach-Object { $_.Groups[1].Value })
    if ($e.Result.Trim()) { Fail "окно: $(($e.Result -split "`n" | Select-Object -First 3) -join ' ')" }
    elseif ($pages.Count -lt 8) { Fail "окно: отрисовано страниц $($pages.Count) ($($o.Result.Trim()))" }
    else { Ok "окно: отрисованы страницы $($pages -join ', ')" }
}

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fail.Count) { Write-Host "ОШИБОК: $($fail.Count) ($([int]$sw.Elapsed.TotalSeconds) с)" -ForegroundColor Red; exit 1 }
Write-Host "Всё в порядке ($([int]$sw.Elapsed.TotalSeconds) с)" -ForegroundColor Green
exit 0
