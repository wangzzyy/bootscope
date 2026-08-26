#
# 主线程响应性 + 两阶段加载 测量
#   阶段一：不校验签名，先把列表铺到界面上
#   阶段二：后台逐个补签名，渐进填充「签名 / 签署者 / 风险」列
#
# 心跳定时器每 50ms 打一次点。主线程被占用多久，两点之间的间隔就会拉长多久。
# 「工作期间」（后台干活时）和「内容上屏那一帧」（WPF 画真实内容）分开统计 ——
# 前者变长才叫界面卡住，后者是任何应用显示新内容都要付的绘制成本。
#
$ErrorActionPreference = 'Stop'

$main = Join-Path $PSScriptRoot 'BootScope.ps1'
$raw  = [IO.File]::ReadAllText($main, [Text.Encoding]::UTF8)
$code = $raw.Replace('if (-not $isAdmin -or -not $isSta) {','if ($false) {').
             Replace('$win.ShowDialog() | Out-Null','')
if ($code -eq $raw) { throw '主程序结构已变，提权守卫 / ShowDialog 的替换未生效，已中止' }
$stub = Join-Path $env:TEMP ('sm_async_{0}.ps1' -f $PID)
[IO.File]::WriteAllText($stub, $code, [Text.UTF8Encoding]::new($true))
try { . $stub } finally { Remove-Item $stub -Force -EA SilentlyContinue }

$dir = Join-Path $env:TEMP ('sm_async_{0}' -f $PID)
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$script:AppDir       = $dir
$script:Journal      = Join-Path $dir 'rollback.json'
$script:SvcStateFile = Join-Path $dir 'managed-services.json'
$script:AiCfgFile    = Join-Path $dir 'ai-config.json'

$LOG = Join-Path $PSScriptRoot '_async.log'
Set-Content -LiteralPath $LOG -Value '' -Encoding UTF8
function W ($t) { Add-Content -LiteralPath $LOG -Value $t -Encoding UTF8 }

# 全部可变状态放一个哈希表。处理器一律**不用** GetNewClosure ——
# 闭包捕获的是创建那一刻的值快照，$script:Items 之后被重新赋值就看不到了。
$M = [hashtable]::Synchronized(@{
    all   = New-Object System.Collections.Generic.List[double]   # 全部心跳间隔
    work  = New-Object System.Collections.Generic.List[double]   # 仅工作期间
    last  = Get-Date
    t0    = $null       # ContentRendered 时刻
    tList = $null       # 列表上屏时刻
    fin   = $false
    listed = $false
})

$hb = New-Object Windows.Threading.DispatcherTimer
$hb.Interval = [TimeSpan]::FromMilliseconds(50)
$hb.Add_Tick({
    $now = Get-Date
    $gap = ($now - $M['last']).TotalMilliseconds
    $M['last'] = $now
    $M['all'].Add($gap)
    # 上屏时刻必须由心跳自己判定：观察器是 100ms 一轮，而「吸收了绘制卡顿的那一次
    # 心跳」可能比观察器更早触发，用观察器记的时刻会把绘制误算进工作期间。
    if (-not $M['tList'] -and $script:Items.Count -gt 0) { $M['tList'] = $now }
    $draw = $M['tList'] -and ([Math]::Abs(($now - $M['tList']).TotalMilliseconds) -lt 500)
    if (-not $draw) { $M['work'].Add($gap) }
})

W ("变更通知类型 SmItem 可用  : {0}" -f $script:HasInpc)

$win.Add_ContentRendered({
    $M['t0'] = Get-Date; $M['last'] = Get-Date
    $hb.Start()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Load-Items
    W ("Load-Items 阻塞主线程     : {0} ms   <<< 调用方被占用的时间" -f [int]$sw.ElapsedMilliseconds)
})

$kill = New-Object Windows.Threading.DispatcherTimer
$kill.Interval = [TimeSpan]::FromSeconds(45)
$kill.Add_Tick({ $kill.Stop(); if (-not $M['fin']) { W 'RESULT=TIMEOUT' }; try { $win.Close() } catch { } })
$kill.Start()

$watch = New-Object Windows.Threading.DispatcherTimer
$watch.Interval = [TimeSpan]::FromMilliseconds(100)
$watch.Add_Tick({
    if (-not $M['t0']) { return }

    if (-not $M['listed'] -and $script:Items.Count -gt 0) {
        $M['listed'] = $true
        if (-not $M['tList']) { $M['tList'] = Get-Date }
        $pend = @($script:Items | Where-Object { $_.SigText -eq '校验中…' }).Count
        W ""
        W ("① 列表上屏               : {0:N0} ms" -f ($M['tList'] - $M['t0']).TotalMilliseconds)
        W ("   条目数 / 待补签名      : {0} / {1}" -f $script:Items.Count, $pend)
        W ("   条目类型               : {0}" -f $script:Items[0].GetType().Name)
    }
    if (-not $M['listed']) { return }
    if (-not $script:Flags['SigDone'] -or $script:SigQueue.Count -gt 0 -or $script:SigTimer.IsEnabled) { return }

    $watch.Stop(); $hb.Stop(); $kill.Stop(); $M['fin'] = $true

    $all  = @($M['all'])
    $work = @($M['work'])
    $mxAll  = ($all  | Measure-Object -Maximum).Maximum
    $mxWork = if ($work.Count) { ($work | Measure-Object -Maximum).Maximum } else { 0 }
    $over   = @($work | Where-Object { $_ -gt 300 }).Count
    # 单次最大值对机器负载太敏感（跑测试时别的进程也在抢 CPU），
    # 用 p95 判定「是否持续阻塞」，最大值只作参考上限。
    $sorted = @($work | Sort-Object)
    $p95    = if ($sorted.Count) { $sorted[[Math]::Min($sorted.Count-1, [int][Math]::Floor($sorted.Count * 0.95))] } else { 0 }
    $filled  = @($script:Items | Where-Object { $_.SigText -and $_.SigText -notin @('校验中…','未校验','') }).Count
    $pending = @($script:Items | Where-Object { $_.SigText -eq '校验中…' }).Count

    W ("② 签名全部填完           : {0:N0} ms" -f ((Get-Date) - $M['t0']).TotalMilliseconds)
    W ""
    W ("绑定到表格的条数          : {0}" -f (@($UI.grid.ItemsSource).Count))
    W ("已填出签名结果的条目      : {0}" -f $filled)
    W ("仍停在「校验中…」的条目   : {0}   （应为 0）" -f $pending)
    W ("枚举失败数                : {0}" -f (@($script:LoadErrors).Count))
    W ("残留后台任务              : {0}   （应为 0）" -f $script:BgJobs.Count)
    W ""
    W ("心跳 {0} 次，平均间隔 {1:N0} ms   (目标 50ms)" -f $all.Count, ($all | Measure-Object -Average).Average)
    W ("【工作期间】p95 间隔      : {0:N0} ms   <<< 后台干活时界面是否持续可用" -f $p95)
    W ("【工作期间】最长间隔      : {0:N0} ms   （偶发调度抖动，看 p95 更准）" -f $mxWork)
    W ("【工作期间】超 300ms 次数 : {0} / {1}" -f $over, $work.Count)
    W ("【内容上屏】那一帧        : {0:N0} ms   （一次性，WPF 排版真实内容）" -f $mxAll)
    W ""
    $ok = ($p95 -lt 150) -and ($mxWork -lt 600) -and ($pending -eq 0) -and ($filled -gt 0) -and ($script:BgJobs.Count -eq 0)
    W ("判定                      : {0}" -f $(if ($ok) { '通过 —— 后台干活期间界面全程可交互' } else { '不通过' }))
    W ("RESULT={0}" -f $(if ($ok) { 'OK' } else { 'FAIL' }))
    try { $win.Close() } catch { }
})
$watch.Start()

$win.ShowDialog() | Out-Null
Stop-AllBgWork
Remove-Item -LiteralPath $dir -Recurse -Force -EA SilentlyContinue
Get-Content -LiteralPath $LOG
