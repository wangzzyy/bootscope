#
# 计划任务 增 / 改命令 / 改名 / 撤销 / 删 的真实链路自测
# 只操作一个专用测试任务（__SM_TASKTEST__），跑完自动清理。
# 注册根目录下的计划任务通常需要管理员权限；权限不足时整体跳过而不是报失败。
#
$ErrorActionPreference = 'Stop'

$main = Join-Path $PSScriptRoot 'BootScope.ps1'
$raw  = [IO.File]::ReadAllText($main, [Text.Encoding]::UTF8)
$code = $raw.Replace('if (-not $isAdmin -or -not $isSta) {', 'if ($false) {').
             Replace('$win.ShowDialog() | Out-Null', '')
if ($code -eq $raw) { throw '主程序结构已变，提权守卫 / ShowDialog 的替换未生效，已中止' }
$stub = Join-Path $env:TEMP ('sm_tasktest_{0}.ps1' -f $PID)
[IO.File]::WriteAllText($stub, $code, [Text.UTF8Encoding]::new($true))
try { . $stub } finally { Remove-Item $stub -Force -EA SilentlyContinue }

$script:TestDir = Join-Path $env:TEMP ('sm_tasktest_{0}' -f $PID)
New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
$script:AppDir       = $script:TestDir
$script:Journal      = Join-Path $script:TestDir 'rollback.json'
$script:SvcStateFile = Join-Path $script:TestDir 'managed-services.json'

$N  = '__SM_TASKTEST__'
$N2 = '__SM_TASKTEST_RENAMED__'
$TP = '\'

function Act ($n) {
    try {
        $t = Get-ScheduledTask -TaskName $n -TaskPath $TP -EA Stop
        $a = @($t.Actions)[0]
        if ($a.Arguments) { "$($a.Execute) $($a.Arguments)" } else { [string]$a.Execute }
    } catch { '<不存在>' }
}
function Chk ($label, $got, $want) {
    $ok = ($got -eq $want)
    Write-Host ("  {0} {1,-30} 期望={2,-46} 实际={3}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $label, $want, $got) `
        -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    if (-not $ok) { $script:fails++ }
}
$script:fails = 0

# 权限探测：注册不了就整体跳过
$canRun = $true
try {
    $a0 = New-ScheduledTaskAction -Execute 'C:\Windows\System32\notepad.exe' -Argument '/A one.txt'
    $t0 = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName $N -TaskPath $TP -Action $a0 -Trigger $t0 -Force -EA Stop | Out-Null
} catch {
    $canRun = $false
    Write-Host "`n[跳过] 无法注册测试计划任务（通常是缺少管理员权限）：$($_.Exception.Message)" -ForegroundColor Yellow
}

if ($canRun) {
    try {
        Write-Host "`n[1] 枚举到测试任务" -ForegroundColor Cyan
        $script:VerifySig = $false
        $it = @(Get-AllStartupItems) | Where-Object { $_.Name -eq $N }
        Chk '命中条数'   $it.Count 1
        Chk '类型'       $it[0].Kind 'Task'
        Chk '现在可编辑' $it[0].CanEdit $true

        Write-Host "`n[2] 改命令（不改名）" -ForegroundColor Cyan
        Update-StartupItem -Item $it[0] -NewName $N -NewCmd '"C:\Windows\System32\calc.exe" /B two'
        Chk '动作已更新' (Act $N) 'C:\Windows\System32\calc.exe /B two'

        Write-Host "`n[3] 撤销改命令" -ForegroundColor Cyan
        $null = Undo-LastAction
        Chk '动作已还原' (Act $N) 'C:\Windows\System32\notepad.exe /A one.txt'

        Write-Host "`n[4] 改名 + 改命令" -ForegroundColor Cyan
        $script:VerifySig = $false
        $it = @(Get-AllStartupItems) | Where-Object { $_.Name -eq $N }
        Update-StartupItem -Item $it[0] -NewName $N2 -NewCmd '"C:\Windows\System32\calc.exe" /C three'
        Chk '新名已建立' (Act $N2) 'C:\Windows\System32\calc.exe /C three'
        Chk '旧名已注销' (Act $N)  '<不存在>'

        Write-Host "`n[5] 撤销改名（应回到旧名旧命令，且新名消失）" -ForegroundColor Cyan
        $null = Undo-LastAction
        Chk '旧名已恢复' (Act $N)  'C:\Windows\System32\notepad.exe /A one.txt'
        Chk '新名已清除' (Act $N2) '<不存在>'

        Write-Host "`n[6] 多动作任务应被拒绝" -ForegroundColor Cyan
        $multi = @(
            (New-ScheduledTaskAction -Execute 'C:\Windows\System32\notepad.exe')
            (New-ScheduledTaskAction -Execute 'C:\Windows\System32\calc.exe')
        )
        Register-ScheduledTask -TaskName $N -TaskPath $TP -Action $multi -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Force | Out-Null
        $script:VerifySig = $false
        $it = @(Get-AllStartupItems) | Where-Object { $_.Name -eq $N }
        $rejected = $false
        try { Update-StartupItem -Item $it[0] -NewName $N -NewCmd '"C:\Windows\System32\calc.exe"' }
        catch { $rejected = ($_.Exception.Message -match '个动作') }
        Chk '多动作任务被拒绝' $rejected $true

        Write-Host "`n[7] 删除" -ForegroundColor Cyan
        $script:VerifySig = $false
        $it = @(Get-AllStartupItems) | Where-Object { $_.Name -eq $N }
        Remove-StartupItem -Item $it[0]
        Chk '任务已删除' (Act $N) '<不存在>'
        Chk '删除不可撤销被标出' (Test-RecordUndoable -Action 'delete' -Kind 'Task' -Extra @{}) $false
    }
    catch {
        Write-Host "`n异常: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace
        $script:fails++
    }
    finally {
        Write-Host "`n[清理]" -ForegroundColor Cyan
        foreach ($n in @($N, $N2)) {
            try { Unregister-ScheduledTask -TaskName $n -TaskPath $TP -Confirm:$false -EA Stop } catch { }
        }
        Chk '测试任务已清空' ((Act $N) + (Act $N2)) '<不存在><不存在>'
    }
}
Remove-Item -LiteralPath $script:TestDir -Recurse -Force -EA SilentlyContinue

Write-Host ""
if (-not $canRun)          { Write-Host "计划任务编辑：已跳过（需要管理员权限）" -ForegroundColor Yellow }
elseif ($script:fails -eq 0) { Write-Host "计划任务编辑：全部断言通过" -ForegroundColor Green }
else                       { Write-Host "计划任务编辑：$($script:fails) 个断言失败" -ForegroundColor Red }
