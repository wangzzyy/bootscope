#
# 自测：对 HKCU 下一个专用测试键跑完整的 增/查/改/删/撤销 链路，
# 全程不触碰任何真实自启动项。无需管理员权限（HKCU 普通用户可写）。
#
#   pwsh -STA -ExecutionPolicy Bypass -File _selftest.ps1
#
$ErrorActionPreference = 'Stop'

# 载入主程序的函数，但跳过提权守卫与窗口显示
$main = Join-Path $PSScriptRoot 'BootScope.ps1'
if (-not (Test-Path $main)) { throw "找不到 BootScope.ps1" }
$stub = Join-Path $env:TEMP ('sm_selftest_{0}.ps1' -f $PID)
$raw  = [IO.File]::ReadAllText($main, [Text.Encoding]::UTF8)
$code = $raw.
    Replace('if (-not $isAdmin -or -not $isSta) {', 'if ($false) {').
    Replace('$win.ShowDialog() | Out-Null', '')
# 这两处替换靠精确字符串匹配。主程序改动一个空格替换就会静默失效，
# 于是「自测」会真的弹 UAC、拉起 GUI 并操作真实系统 —— 必须断言替换生效。
if ($code -eq $raw) { throw '主程序结构已变，提权守卫 / ShowDialog 的替换未生效，已中止（避免误操作真实系统）' }
[IO.File]::WriteAllText($stub, $code, [Text.UTF8Encoding]::new($true))
try { . $stub } finally { Remove-Item $stub -Force -ErrorAction SilentlyContinue }

# 把所有状态文件重定向到临时目录。否则测试写的回滚记录会永久留在用户真实的
# rollback.json 里，用户下次在正式程序里点「撤销上一步」就会把测试项写回 Run 键。
$script:TestDir  = Join-Path $env:TEMP ('sm_test_{0}' -f $PID)
New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
$script:AppDir       = $script:TestDir
$script:Journal      = Join-Path $script:TestDir 'rollback.json'
$script:SvcStateFile = Join-Path $script:TestDir 'managed-services.json'

$K  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$AP = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
$N  = '__SM_SELFTEST__'
$N2 = '__SM_SELFTEST_RENAMED__'

function Val  ($n) { try { (Get-ItemProperty $K -Name $n -EA Stop).$n } catch { '<不存在>' } }
function Appr ($n) { try { $b=(Get-Item $AP).GetValue($n); if($b){ if((($b[0] -band 1) -eq 0)){'启用'}else{'禁用'} } else {'<无记录>'} } catch {'<无记录>'} }
function Find ($n) { $script:VerifySig=$false; @(Get-AllStartupItems) | Where-Object { $_.Name -eq $n } }
function Chk  ($label,$got,$want) {
    $ok = ($got -eq $want)
    Write-Host ("  {0} {1,-34} 期望={2,-42} 实际={3}" -f $(if($ok){'PASS'}else{'FAIL'}), $label, $want, $got) `
        -ForegroundColor $(if($ok){'Green'}else{'Red'})
    if (-not $ok) { $script:fails++ }
}

$script:fails = 0
try {
    Write-Host "`n[1] 增 —— 带参数新建" -ForegroundColor Cyan
    Add-StartupItem -Kind Run -Scope HKCU -Name $N -Exe 'C:\Windows\System32\notepad.exe' -Arguments '/A test.txt'
    Chk '写入的命令（含参数）' (Val $N) '"C:\Windows\System32\notepad.exe" /A test.txt'
    Chk '启用状态'            (Appr $N) '启用'

    Write-Host "`n[2] 查 —— 枚举与解析" -ForegroundColor Cyan
    $it = Find $N
    Chk '命中条数'   $it.Count 1
    Chk '解析出的路径' $it[0].Target 'C:\Windows\System32\notepad.exe'
    Chk '解析出的参数' $it[0].Arguments '/A test.txt'
    Chk '文件状态'   $it[0].ExistText '存在'
    Chk '风险等级'   $it[0].RiskText '正常'

    Write-Host "`n[3] 改 —— 禁用" -ForegroundColor Cyan
    Set-StartupItemEnabled -Item $it[0] -Enabled $false
    Chk '启用状态' (Appr $N) '禁用'

    Write-Host "`n[4] 改 —— 禁用后编辑（用过期对象，验证不会被悄悄重新启用）" -ForegroundColor Cyan
    Update-StartupItem -Item $it[0] -NewName $N -NewCmd '"C:\Windows\System32\calc.exe" /X'
    Chk '命令已更新'       (Val $N) '"C:\Windows\System32\calc.exe" /X'
    Chk '禁用状态被保留'   (Appr $N) '禁用'

    Write-Host "`n[5] 改 —— 改名（验证启用状态随之迁移）" -ForegroundColor Cyan
    $it = Find $N
    Update-StartupItem -Item $it[0] -NewName $N2 -NewCmd '"C:\Windows\System32\calc.exe" /X'
    Chk '旧名已移除'       (Val $N)  '<不存在>'
    Chk '旧名 Approved 已清' (Appr $N) '<无记录>'
    Chk '新名已写入'       (Val $N2) '"C:\Windows\System32\calc.exe" /X'
    Chk '禁用状态已迁移'   (Appr $N2) '禁用'

    Write-Host "`n[6] 删 —— 删除并写入回滚日志" -ForegroundColor Cyan
    $it = Find $N2
    Remove-StartupItem -Item $it[0]
    Chk '注册表值已删'     (Val $N2)  '<不存在>'
    Chk 'Approved 已删'    (Appr $N2) '<无记录>'

    Write-Host "`n[7] 撤销 —— 还原删除" -ForegroundColor Cyan
    $msg = Undo-LastAction
    Write-Host "  $msg"
    Chk '值已还原'         (Val $N2)  '"C:\Windows\System32\calc.exe" /X'
    Chk '禁用状态已还原'   (Appr $N2) '禁用'

    Write-Host "`n[8] 清理" -ForegroundColor Cyan
    $it = Find $N2
    Remove-StartupItem -Item $it[0]
    Chk '已清理' (Val $N2) '<不存在>'
}
catch {
    Write-Host "`n异常: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    $script:fails++
}
finally {
    foreach ($n in @($N,$N2)) {
        Remove-ItemProperty $K  -Name $n -Force -EA SilentlyContinue
        Remove-ItemProperty $AP -Name $n -Force -EA SilentlyContinue
    }
    Remove-Item -LiteralPath $script:TestDir -Recurse -Force -EA SilentlyContinue
}

Write-Host ""
if ($script:fails -eq 0) { Write-Host "全部断言通过" -ForegroundColor Green }
else { Write-Host "$($script:fails) 个断言失败" -ForegroundColor Red }
