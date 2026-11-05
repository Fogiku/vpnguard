# VpnGuard — задачи веб-сервера (-WebTask: клиенты WireGuard, полный отчёт «Диагностика») и сборка программ на C# (Build-CsExe — агент).
# Веб-сервер и значок держит запущенными агент (agent\WebHost.cs); удалённая диагностика — в WebDiag.cs.
#   • веб-интерфейс (web\index.html + /api/…) — с этого ПК без пароля, из домашней сети и от клиентов wg_server — по паролю web.token;
#   • удалённая диагностика — включается из окна на N часов (remote.*), доступ по одноразовому токену remote.token.
# Ключи и токены в ответах диагностики маскируются; конфиги клиентов WireGuard отдаются только веб-интерфейсу.

$RemoteStatePath = Join-Path $DataDir 'remote-state.json'
$RemoteRule      = 'VpnGuard remote diagnostics'

function Hide-Secrets([string]$Text) {
    if (-not $Text) { return $Text }
    $t = [regex]::Replace($Text, '(?im)^(\s*(PrivateKey|PresharedKey)\s*=\s*)\S+', '$1***')
    $t = [regex]::Replace($t, 'vpn://[A-Za-z0-9_\-+/=]+', 'vpn://***')
    $t = [regex]::Replace($t, '("token"\s*:\s*")[^"]*(")', '$1***$2')
    return $t
}

# ---------------------------------------------------------------- агент: держать сервер запущенным, пока включено
# ---------------------------------------------------------------- сервер на C#: собрать встроенным csc.exe (.NET Framework) и запустить
$WebExe = Join-Path $(if ($BinDir) { $BinDir } else { Join-Path $Root 'bin' }) 'VpnGuardWeb.exe'
function Get-Csc {
    foreach ($c in "$env:windir\Microsoft.NET\Framework64\v4.0.30319\csc.exe", "$env:windir\Microsoft.NET\Framework\v4.0.30319\csc.exe") { if (Test-Path $c) { return $c } }
    return ''
}
# собрать программу на C# из исходников рядом (встроенный csc.exe .NET Framework); подпись = sha256 исходников
$script:CsBuildFail = @{}
function Build-CsExe([string]$Exe, [string[]]$Sources, [string]$Target, [string[]]$Refs) {
    $src = @($Sources | ForEach-Object { Join-Path $Root $_ })
    if (@($src | Where-Object { -not (Test-Path $_) }).Count) { return $false }
    $sig = (@($src | ForEach-Object { (Get-FileHash $_ -Algorithm SHA256).Hash }) -join '|')
    if ((Test-Path $Exe) -and "$(Get-Content "$Exe.sig" -Raw -ErrorAction SilentlyContinue)".Trim() -eq $sig) { return $true }
    if ($script:CsBuildFail[$Exe] -eq $sig) { return $false }
    $csc = Get-Csc
    if (-not $csc) { $script:CsBuildFail[$Exe] = $sig; Write-Log "Сборка $(Split-Path $Exe -Leaf): нет компилятора .NET (csc.exe)" 'WARN'; return $false }
    $name = [IO.Path]::GetFileNameWithoutExtension($Exe)
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
    New-Item -ItemType Directory (Split-Path $Exe) -Force | Out-Null
    $tmp = "$Exe.new"; Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    $r = Invoke-Exe $csc ("/nologo /target:$Target /optimize+ /out:`"$tmp`" " + (($Refs | ForEach-Object { "/r:$_" }) -join ' ') + ' ' + (($src | ForEach-Object { "`"$_`"" }) -join ' ')) 180
    if ($r.Code -ne 0 -or -not (Test-Path $tmp)) {
        $script:CsBuildFail[$Exe] = $sig
        Write-Log "Сборка $name не удалась (код $($r.Code)): $((("$($r.Out) $($r.Err)" -split "`n") | Where-Object { $_ -match 'error' } | Select-Object -First 3) -join ' | ')" 'ERROR'
        return $false
    }
    Move-Item $tmp $Exe -Force
    Set-Content "$Exe.sig" $sig -Encoding ASCII
    Write-Log "Собрано на C#: $name ($([int]((Get-Item $Exe).Length / 1KB)) КБ)"
    return $true
}

# ---------------------------------------------------------------- значок у часов (вместо окна): задача VpnGuardMonitor и ярлык открывают его
# веб-сервер на C# (Web.cs + Qr.cs + WebDiag.cs → bin\VpnGuardWeb.exe)
# ---------------------------------------------------------------- задачи для сервера на C# (VpnGuard.ps1 -WebTask имя [-WebArg base64])
function Invoke-WebTask([string]$Task, [string]$Arg) {
    [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
    $argText = $(if ($Arg) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Arg)) } else { '' })
    $out = { param($o) [Console]::Out.Write(($o | ConvertTo-Json -Depth 6 -Compress)) }
    try {
        switch ($Task) {
            'diag'   { Invoke-Diag }      # полный отчёт «Диагностика»; сеть, система, проверки, файлы — на C# (WebDiag.cs)
            'wg-clients' {
                $l = Get-WgClients
                & $out ([ordered]@{ ok = $true; endpoint = "$($l.Endpoint)"; clients = @(@($l.Clients) | ForEach-Object { [ordered]@{ name = "$($_.Name)"; ip = "$($_.Ip)"; source = "$($_.Source)"; hasConf = [bool]($_.File -and (Test-Path $_.File)); dns = $(if ($_.File -and (Test-Path $_.File)) { $dl = Select-String -Path $_.File -Pattern '^\s*DNS\s*=\s*(.+)$' | Select-Object -First 1; if ($dl) { $dl.Matches[0].Groups[1].Value.Trim() } else { '' } } else { '' }) } }) })
            }
            'wg-conf' {
                $c = Get-RWgClient $argText
                if (-not $c -or -not $c.File -or -not (Test-Path $c.File)) { & $out @{ ok = $false; error = 'конфиг этого клиента на ПК не хранится — удалите и создайте заново' } }
                else { & $out ([ordered]@{ ok = $true; name = "$($c.Name)"; text = [IO.File]::ReadAllText($c.File) }) }
            }
            'wg-add'    { $c = New-WgClient $argText; & $out ([ordered]@{ ok = $true; name = "$($c.Name)"; ip = "$($c.Ip)"; text = "$($c.Text)" }) }
            'wg-remove' {
                $c = Get-RWgClient $argText
                if (-not $c) { & $out @{ ok = $false; error = 'клиент не найден' } } else { $n = Remove-WgClient $c.PublicKey; & $out ([ordered]@{ ok = $true; name = "$n" }) }
            }
            default { & $out @{ ok = $false; error = "неизвестная задача '$Task'" } }
        }
    } catch { & $out @{ ok = $false; error = $_.Exception.Message } }
}
# ---------------------------------------------------------------- сервер (процесс VpnGuard.ps1 -RemoteServer)
# живые проверки, которые не мешают работе: туннели, внешний IP, DNS, сайты напрямую и через туннель
function Get-RWgClient([string]$Ip) {
    $l = Get-WgClients
    @($l.Clients) | Where-Object { "$($_.Ip)" -eq $Ip } | Select-Object -First 1
}


