#
# 批量选择 / 批量删除 / 整批撤销 自测
# 在 HKCU 下造 5 个专用测试条目，跑完整批量链路，结束后清理干净。
# 不触碰任何真实自启动项，无需管理员权限。
#
$ErrorActionPreference = 'Stop'

$main = Join-Path $PSScriptRoot 'BootScope.ps1'
$stub = Join-Path $env:TEMP ('sm_batchtest_{0}.ps1' -f $PID)
$raw  = [IO.File]::ReadAllText($main, [Text.Encoding]::UTF8)
$code = $raw.
    Replace('if (-not $isAdmin -or -not $isSta) {', 'if ($false) {').
    Replace('$win.ShowDialog() | Out-Null', '')
if ($code -eq $raw) { throw '主程序结构已变，提权守卫 / ShowDialog 的替换未生效，已中止（避免误操作真实系统）' }
[IO.File]::WriteAllText($stub, $code, [Text.UTF8Encoding]::new($true))
try { . $stub } finally { Remove-Item $stub -Force -ErrorAction SilentlyContinue }

# 状态文件重定向到临时目录，不污染用户真实的回滚日志
$script:TestDir  = Join-Path $env:TEMP ('sm_batchtest_{0}' -f $PID)
New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
$script:AppDir       = $script:TestDir
$script:Journal      = Join-Path $script:TestDir 'rollback.json'
$script:SvcStateFile = Join-Path $script:TestDir 'managed-services.json'

$K   = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$AP  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
$PFX = '__SMBATCH_'
$NAMES = 1..5 | ForEach-Object { "$PFX$_" }

function Exists ($n) { try { $null = (Get-ItemProperty $K -Name $n -EA Stop).$n; $true } catch { $false } }
function Appr   ($n) { try { $b=(Get-Item $AP).GetValue($n); if($b){ (($b[0] -band 1) -eq 0) } else { $null } } catch { $null } }
function Chk ($label,$got,$want) {
    $ok = ($got -eq $want)
    Write-Host ("  {0} {1,-38} 期望={2,-8} 实际={3}" -f $(if($ok){'PASS'}else{'FAIL'}), $label, $want, $got) `
        -ForegroundColor $(if($ok){'Green'}else{'Red'})
    if (-not $ok) { $script:fails++ }
}
$script:fails = 0

# 批量确认对话框会阻塞，自测里直接绕过
function Show-BatchConfirm { param($Items,[string]$Verb='删除') return $true }
function Show-Msg { param([string]$Text,[string]$Title='',[string]$Icon='') Write-Host "    [对话框] $($Text -split "`n" | Select-Object -First 1)" -ForegroundColor DarkGray }
function Confirm-Msg { param([string]$Text,[string]$Title='') return $true }

try {
    Write-Host "`n[1] 造 5 个测试条目" -ForegroundColor Cyan
    foreach ($i in 1..5) {
        Add-StartupItem -Kind Run -Scope HKCU -Name "$PFX$i" -Exe 'C:\Windows\System32\notepad.exe' -Arguments "/T$i"
    }
    Chk '5 项均已写入' (@($NAMES | Where-Object { Exists $_ }).Count) 5

    Write-Host "`n[2] 枚举 + 筛选到测试条目" -ForegroundColor Cyan
    $script:VerifySig = $false
    Load-Items -Sync   # 自测走同步路径；界面上是异步的
    $UI.txtSearch.Text = $PFX
    Apply-Filter
    Chk '筛选结果条数' (@($script:View).Count) 5
    Chk '计数标签'     ($UI.lblSel.Text -match '当前筛选 5 /') $true

    Write-Host "`n[3] 全选筛选结果" -ForegroundColor Cyan
    Set-ViewSelection $true
    Chk '勾选数'   (Get-Checked).Count 5
    Chk '标签已更新' ($UI.lblSel.Text -match '已勾选 5 项') $true

    Write-Host "`n[4] 反选" -ForegroundColor Cyan
    Invert-ViewSelection
    Chk '勾选数归零' (Get-Checked).Count 0

    Write-Host "`n[5] 按条件勾选（跨筛选，应重置筛选条件）" -ForegroundColor Cyan
    Select-ByPredicate { $_.Name -like "$PFX*" } '测试条目'
    Chk '勾选数'       (Get-Checked).Count 5
    Chk '筛选框已清空' ($UI.txtSearch.Text -eq '') $true
    Chk '视图已回到全量' (@($script:View).Count -eq $script:Items.Count) $true

    Write-Host "`n[6] Get-TargetItems 优先级：有勾选时忽略高亮行" -ForegroundColor Cyan
    Chk '目标数' (Get-TargetItems).Count 5

    Write-Host "`n[7] 批量删除（应共用同一批次号）" -ForegroundColor Cyan
    $targets = Get-TargetItems
    $batch = [guid]::NewGuid().ToString('N')
    foreach ($i in $targets) { Remove-StartupItem -Item $i -Batch $batch }
    Chk '注册表已清空'  (@($NAMES | Where-Object { Exists $_ }).Count) 0
    $grp = Get-LastJournalGroup
    Chk '整批日志条数'  $grp.Count 5
    Chk '批次号一致'    (@($grp | Select-Object -Unique -ExpandProperty Batch).Count) 1

    Write-Host "`n[8] 一次撤销还原整批" -ForegroundColor Cyan
    $msg = Undo-LastAction
    Write-Host "    $msg" -ForegroundColor DarkGray
    Chk '5 项全部还原'  (@($NAMES | Where-Object { Exists $_ }).Count) 5
    # 日志里可能还有此前的真实操作记录，只断言「本批次已出栈」
    Chk '本批次已出栈' (@(Read-Journal | Where-Object { $_.Batch -eq $batch }).Count) 0

    Write-Host "`n[9] 混合批次：先禁用 2 项，再整批删除并撤销，验证状态逐项还原" -ForegroundColor Cyan
    Load-Items -Sync   # 自测走同步路径；界面上是异步的
    $t = @($script:Items | Where-Object { $_.Name -like "$PFX*" } | Sort-Object Name)
    Set-StartupItemEnabled -Item $t[0] -Enabled $false
    Set-StartupItemEnabled -Item $t[1] -Enabled $false
    Load-Items -Sync   # 自测走同步路径；界面上是异步的
    $t = @($script:Items | Where-Object { $_.Name -like "$PFX*" } | Sort-Object Name)
    Chk '禁用项数' (@($t | Where-Object { -not $_.Enabled }).Count) 2
    $batch2 = [guid]::NewGuid().ToString('N')
    foreach ($i in $t) { Remove-StartupItem -Item $i -Batch $batch2 }
    $null = Undo-LastAction
    Chk '还原后总数'     (@($NAMES | Where-Object { Exists $_ }).Count) 5
    Chk '禁用状态被逐项还原' (@($NAMES | Where-Object { (Appr $_) -eq $false }).Count) 2
}
catch {
    Write-Host "`n异常: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    $script:fails++
}
finally {
    Write-Host "`n[清理]" -ForegroundColor Cyan
    foreach ($n in $NAMES) {
        Remove-ItemProperty $K  -Name $n -Force -EA SilentlyContinue
        Remove-ItemProperty $AP -Name $n -Force -EA SilentlyContinue
    }
    Chk '测试条目已清空' (@($NAMES | Where-Object { Exists $_ }).Count) 0
    Remove-Item -LiteralPath $script:TestDir -Recurse -Force -EA SilentlyContinue
}

Write-Host ""
if ($script:fails -eq 0) { Write-Host "批量功能：全部断言通过" -ForegroundColor Green }
else { Write-Host "批量功能：$($script:fails) 个断言失败" -ForegroundColor Red }
