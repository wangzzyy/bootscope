#
# 纯逻辑回归：命令行解析 / 风险矩阵 / 回滚日志耐久性 / 服务清单 / AI 协议管线。
# 只喂参数与临时文件，不触碰任何真实自启动项；除末尾三个「仅 Windows」小段外
# 也不写注册表、不访问网络，无需管理员权限。
#
#   pwsh -STA -ExecutionPolicy Bypass -File _selftest_logic.ps1
#
# 覆盖的都是只靠读代码看不出来的高危分支：
#   · Resolve-Target 的引号 / 扩展名 / 逗号解析（rundll32 x.dll,Start 会跨空格）
#   · Get-RiskInfo 的等级优先级（critical > warning > stale）
#   · 回滚日志 2000 条上限与损坏另存
#   · 服务清单多条目跟踪（曾经被逗号包装的返回值拼成 "A B" 一条的回归）
#   · 三种 AI 协议的请求体 / 响应解析 / 错误解读
#
$ErrorActionPreference = 'Stop'

# 载入主程序的函数，但跳过提权守卫与窗口显示（与其余自测同一套路）
$main = Join-Path $PSScriptRoot 'BootScope.ps1'
if (-not (Test-Path $main)) { throw "找不到 BootScope.ps1" }
$stub = Join-Path $env:TEMP ('sm_logic_{0}.ps1' -f $PID)
$raw  = [IO.File]::ReadAllText($main, [Text.Encoding]::UTF8)
$code = $raw.
    Replace('if (-not $isAdmin -or -not $isSta) {', 'if ($false) {').
    Replace('$win.ShowDialog() | Out-Null', '')
if ($code -eq $raw) { throw '主程序结构已变，提权守卫 / ShowDialog 的替换未生效，已中止（避免误操作真实系统）' }
[IO.File]::WriteAllText($stub, $code, [Text.UTF8Encoding]::new($true))
try { . $stub } finally { Remove-Item $stub -Force -ErrorAction SilentlyContinue }

# 状态文件全部重定向到临时目录，不污染用户真实的 rollback.json / 服务清单 / AI 配置
$script:TestDir = Join-Path $env:TEMP ('sm_logic_{0}' -f $PID)
New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
$script:AppDir       = $script:TestDir
$script:Journal      = Join-Path $script:TestDir 'rollback.json'
$script:SvcStateFile = Join-Path $script:TestDir 'managed-services.json'
$script:AiCfgFile    = Join-Path $script:TestDir 'ai-config.json'
$script:VerifySig    = $false
$script:SigCache     = @{}

$script:fails = 0
function Chk ($label, $got, $want) {
    $ok = ($got -eq $want)
    Write-Host ("  {0} {1,-52} 期望={2,-46} 实际={3}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $label, $want, $got) `
        -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    if (-not $ok) { $script:fails++ }
}
function Ok  ($label, $cond) { Chk $label ([bool]$cond) $true }
function Throws($label, [scriptblock]$body, [string]$match) {
    $threw = $false; $msg = ''
    try { & $body } catch { $threw = $true; $msg = $_.Exception.Message }
    if ($match) { Ok "$label (异常: $msg)" ($threw -and $msg -match $match) }
    else        { Ok "$label (异常: $msg)" $threw }
}

try {
    Write-Host "`n[1] 命令行解析 Resolve-Target" -ForegroundColor Cyan
    $r = Resolve-Target ''
    Chk '空命令' ($r.Path + '|' + $r.Args) '|'
    $r = Resolve-Target '"C:\Program Files\App\app.exe" --arg "a b"'
    Chk '带引号+参数' ($r.Path + '|' + $r.Args) 'C:\Program Files\App\app.exe|--arg "a b"'
    $r = Resolve-Target '"C:\a b\c.exe"'
    Chk '带引号无参数' ($r.Path + '|' + $r.Args) 'C:\a b\c.exe|'
    $r = Resolve-Target 'C:\Windows\System32\notepad.exe /A x'
    Chk '无引号exe+参数' ($r.Path + '|' + $r.Args) 'C:\Windows\System32\notepad.exe|/A x'
    $r = Resolve-Target 'C:\Program Files\App\app.exe /x'
    Chk '路径含空格整体' ($r.Path + '|' + $r.Args) 'C:\Program Files\App\app.exe|/x'
    $r = Resolve-Target 'C:\Windows\System32\notepad /A test.txt'
    Chk '无扩展名按首空格切' ($r.Path + '|' + $r.Args) 'C:\Windows\System32\notepad|/A test.txt'
    $r = Resolve-Target 'rundll32 C:\Windows\System32\evil.dll,Start'
    Chk 'dll+逗号' ($r.Path + '|' + $r.Args) 'rundll32 C:\Windows\System32\evil.dll|,Start'
    $r = Resolve-Target 'regsvr32 /s C:\x\y.dll'
    Chk 'dll在句中=整段路径(已知怪癖)' ($r.Path + '|' + $r.Args) 'regsvr32 /s C:\x\y.dll|'
    $r = Resolve-Target 'powershell.exe -NoProfile'
    Chk '裸exe+参数' ($r.Path + '|' + $r.Args) 'powershell.exe|-NoProfile'
    $r = Resolve-Target 'C:\Windows\notepad.exe'
    Chk '无参数exe' ($r.Path + '|' + $r.Args) 'C:\Windows\notepad.exe|'

    Write-Host "`n[2] 环境变量展开 / 文件存在性 Resolve-ExistState" -ForegroundColor Cyan
    $env:SM_LOGIC_VAR = 'C:\x y'
    Chk '环境变量展开' (Expand-Path '%SM_LOGIC_VAR%\app.exe') 'C:\x y\app.exe'
    Chk '空路径展开'   (Expand-Path '') ''
    $tmpFile = Join-Path $script:TestDir 'my app.exe'
    Set-Content -LiteralPath $tmpFile -Value 'x'
    $es = Resolve-ExistState $tmpFile
    Chk '存在的文件' ($es.State + '|' + $es.Path) ("yes|$tmpFile")
    $missing = Join-Path $script:TestDir 'nope.exe'
    $es = Resolve-ExistState $missing
    Chk '缺失的文件' ($es.State + '|' + $es.Path) ("no|$missing")
    $es = Resolve-ExistState 'zz_nonexistent_app_9x8k.exe'
    Chk '缺失的裸名' ($es.State + '|' + $es.Path) 'no|zz_nonexistent_app_9x8k.exe'
    $es = Resolve-ExistState ''
    Chk '空路径' $es.State 'na'
    $anyApp = @(Get-Command -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)[0]
    if ($anyApp) {
        $leaf = [IO.Path]::GetFileName($anyApp.Source)
        $es = Resolve-ExistState $leaf
        Chk "PATH解析裸名 $leaf" ($es.State) 'yes'
        Ok  "PATH解析出完整路径" ($es.Path -ieq $anyApp.Source)
    } else { Ok 'PATH解析裸名（无可测应用，跳过）' $true }

    Write-Host "`n[3] 风险矩阵 Get-RiskInfo（等级优先级 critical > warning > stale）" -ForegroundColor Cyan
    $rk = Get-RiskInfo -Target 'C:\Windows\System32\notepad.exe' -SigStatus 'Valid' -ExistState 'yes' -Name 'NP' -Kind 'Run' -Cmd 'x'
    Chk '正常: 等级' $rk.Level 'normal'
    Ok  '正常: 说明' ($rk.Note -match '签名有效，路径正常')
    $rk = Get-RiskInfo -Target 'C:\Windows\System32\notepad.exe' -SigStatus '未校验' -ExistState 'yes' -Name 'NP' -Kind 'Run' -Cmd 'x'
    Chk '未校验: 等级' $rk.Level 'normal'
    Ok  '未校验: 不谎称有效' ($rk.Note -match '未校验数字签名')
    $rk = Get-RiskInfo -Target 'C:\App\gone.exe' -SigStatus 'Valid' -ExistState 'no' -Name 'G' -Kind 'Run' -Cmd 'x'
    Chk '纯残留: 等级' $rk.Level 'stale'
    Ok  '纯残留: 说明' ($rk.Note -match '目标文件不存在')
    $rk = Get-RiskInfo -Target 'C:\Users\Public\gone.exe' -SigStatus 'NotSigned' -ExistState 'no' -Name 'G' -Kind 'Run' -Cmd 'x'
    Chk '残留+公共目录: 关注压过残留' $rk.Level 'warning'
    Ok  '残留+公共目录: 说明' ($rk.Note -match '所有用户可写')
    $rk = Get-RiskInfo -Target 'C:\Users\B\AppData\Local\Temp\evil.exe' -SigStatus 'NotSigned' -ExistState 'yes' -Name 'E' -Kind 'Run' -Cmd 'x'
    Chk '临时目录: 危险' $rk.Level 'critical'
    Ok  '临时目录: 说明' ($rk.Note -match '临时目录')
    $rk = Get-RiskInfo -Target 'C:\Program Files\Other\svchost.exe' -SigStatus 'NotSigned' -ExistState 'yes' -Name 'svchost' -Kind 'Run' -Cmd 'x'
    Chk '盗名系统进程: 危险' $rk.Level 'critical'
    Ok  '盗名系统进程: 说明' ($rk.Note -match '使用系统进程名')
    $rk = Get-RiskInfo -Target 'C:\Windows\System32\svchost.exe' -SigStatus 'NotSigned' -ExistState 'yes' -Name 'svchost' -Kind 'Run' -Cmd 'x'
    Chk '真系统进程: 不误报危险' $rk.Level 'warning'
    $rk = Get-RiskInfo -Target 'C:\Users\B\AppData\Roaming\Microsoft\OneDrive\evil.exe' -SigStatus 'HashMismatch' -ExistState 'yes' -Name 'E' -Kind 'Run' -Cmd 'x'
    Chk '微软目录+坏签名: 危险' $rk.Level 'critical'
    Ok  '微软目录+坏签名: 名称伪装' ($rk.Note -match '名称伪装')
    $rk = Get-RiskInfo -Target 'C:\Users\B\AppData\Roaming\Microsoft\OneDrive\evil.exe' -SigStatus '未校验' -ExistState 'yes' -Name 'E' -Kind 'Run' -Cmd 'x'
    Chk '微软目录+未校验: 关注' $rk.Level 'warning'
    Ok  '微软目录+未校验: 说明' ($rk.Note -match '签名未经确认')
    $rk = Get-RiskInfo -Target 'C:\Tools\run.bat' -SigStatus 'NotSigned' -ExistState 'yes' -Name 'R' -Kind 'Run' -Cmd 'x'
    Chk '脚本文件: 关注' $rk.Level 'warning'
    Ok  '脚本文件: 说明' ($rk.Note -match '脚本文件')
    $rk = Get-RiskInfo -Target 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -SigStatus '未校验' -ExistState 'yes' -Name 'P' -Kind 'Run' -Cmd 'x -File "C:\Users\B\evil.ps1"'
    Chk '解释器+脚本: 关注' $rk.Level 'warning'
    Ok  '解释器+脚本: 指明脚本' ($rk.Note -match '经系统解释器执行脚本' -and $rk.Note -match 'evil\.ps1')
    $rk = Get-RiskInfo -Target 'C:\Windows\System32\rundll32.exe' -SigStatus '未校验' -ExistState 'yes' -Name 'X' -Kind 'Run' -Cmd 'rundll32 C:\Temp\evil.dll,Start'
    Ok  'rundll32: 不等于正常' ($rk.Level -ne 'normal')
    Ok  'rundll32: 提到dll' ($rk.Note -match 'evil\.dll')
    $rk = Get-RiskInfo -Target 'C:\ProgramData\Acme\a.exe' -SigStatus 'NotSigned' -ExistState 'yes' -Name 'A' -Kind 'Run' -Cmd 'x'
    Chk 'ProgramData: 关注' $rk.Level 'warning'
    Ok  'ProgramData: 说明' ($rk.Note -match 'ProgramData')
    $rk = Get-RiskInfo -Target 'C:\Program Files\Denied\a.exe' -SigStatus '—' -ExistState 'denied' -Name 'A' -Kind 'Service' -Cmd 'x'
    Chk 'ACL拒绝: 不是残留' $rk.Level 'normal'
    Ok  'ACL拒绝: 说明' ($rk.Note -match '受 ACL 保护')
    Ok  'ACL拒绝: 不说文件不存在' ($rk.Note -notmatch '目标文件不存在')
    Ok  'ACL拒绝: 不说签名有效' ($rk.Note -notmatch '签名有效')
    $rk = Get-RiskInfo -Target 'C:\Users\B\AppData\Local\Temp\gone.exe' -SigStatus 'NotSigned' -ExistState 'no' -Name 'G' -Kind 'Run' -Cmd 'x'
    Chk '残留+临时目录: 危险压过残留' $rk.Level 'critical'

    Write-Host "`n[4] 回滚日志 读写 / 批次 / 出栈" -ForegroundColor Cyan
    Chk '日志文件尚不存在' (Test-Path $script:Journal) $false
    $item = [pscustomobject]@{ Name='N1'; Command='"C:\x\a.exe" /q'; Kind='Run'; Scope='HKCU'; Loc=$RUN_LOCS[0].Reg; Enabled=$true; Extra=@{ Ap='HKCU'; ApSub='Run' } }
    Write-Journal -Item $item -Action 'delete'
    $item2 = [pscustomobject]@{ Name='N2'; Command='C:\x\b.exe'; Kind='Run'; Scope='HKCU'; Loc=$RUN_LOCS[0].Reg; Enabled=$false; Extra=@{ Ap='HKCU'; ApSub='Run' } }
    Write-Journal -Item $item2 -Action 'delete'
    $all = Read-Journal
    Chk '两笔记录' $all.Count 2
    Chk '首笔字段' $all[0].Name 'N1'
    Chk '末笔字段' $all[1].Enabled $false
    Chk 'Extra 往返' $all[1].Extra.Ap 'HKCU'
    $g = Get-LastJournalGroup
    Chk '无批次→单条' $g.Count 1
    Chk '无批次→末条' $g[0].Name 'N2'
    Pop-JournalGroup -Count 1
    Chk '出栈1条' @(Read-Journal).Count 1
    Pop-JournalGroup -Count 5
    Chk '出栈到底→文件删除' (Test-Path $script:Journal) $false
    # 生产调用方一律「先赋值再数」，与函数输出的整体语义一致
    $emptyR = Read-Journal
    Chk '空日志读取' @($emptyR).Count 0
    $grp0 = Get-LastJournalGroup
    Chk '空日志→无上一批' @($grp0).Count 0
    $rr = Read-JournalRaw
    Ok 'Raw 空日志是非空数组' ($null -ne $rr)

    Write-Host "`n[4b] 回滚日志 2000 条上限（超出丢最旧）" -ForegroundColor Cyan
    $recs = 1..1995 | ForEach-Object {
        [pscustomobject]@{ Time='t'; Action='delete'; Batch="R$($_ - 1)"; Name="N$_"; Command='c:\x.exe'; Kind='Run'; Scope='HKCU'; Loc='L'; Enabled=$true; NewName=''; Undoable=$true; Extra=@{} }
    }
    Write-JournalRecords -Records $recs
    $extra = foreach ($i in 1995..2004) {
        [pscustomobject]@{ Time='t'; Action='delete'; Batch="R$i"; Name="Nx$i"; Command='c:\x.exe'; Kind='Run'; Scope='HKCU'; Loc='L'; Enabled=$true; NewName=''; Undoable=$true; Extra=@{} }
    }
    Write-JournalRecords -Records $extra
    $all2 = Read-Journal
    Chk '2005条截为2000' $all2.Count 2000
    Chk '最旧5条被丢弃' $all2[0].Batch 'R5'
    Chk '最新条保留' $all2[-1].Batch 'R2004'

    Write-Host "`n[4c] 回滚日志损坏 → 另存 + 重新开始" -ForegroundColor Cyan
    Set-Content -LiteralPath $script:Journal -Value '{oops' -Encoding UTF8
    Write-Journal -Item $item -Action 'delete'
    $all3 = Read-Journal
    Chk '损坏后重新记录' $all3.Count 1
    Ok  '损坏备份已另存' (@(Get-ChildItem -LiteralPath $script:TestDir -Filter 'rollback.json.corrupt-*').Count -ge 1)
    Ok  '警告已设置' ($null -ne $script:JournalWarning)

    Write-Host "`n[4d] 撤销失败存档 unrecoverable.json（追加不覆盖）" -ForegroundColor Cyan
    $lost = @(
        [pscustomobject]@{ Name='T1'; Command='x'; Kind='Task' },
        [pscustomobject]@{ Name='T2'; Command='y'; Kind='Service' }
    )
    $path = Save-UnrecoverableRecords -Records $lost
    Ok  '存档返回路径' (Test-Path $path)
    $path2 = Save-UnrecoverableRecords -Records @([pscustomobject]@{ Name='T3'; Command='z'; Kind='Task' })
    Chk '二次追加' (@(Get-Content $path2 -Raw -Encoding UTF8 | ConvertFrom-Json).Count) 3
    Ok  '存档路径固定' ($path -eq $path2)

    Write-Host "`n[5] 服务清单 managed-services.json（多条目跟踪回归）" -ForegroundColor Cyan
    # 回归：旧实现 return ,@(...) 逗号包装，两条以上读回时被拼成 "A B" 一条，
    # 第二个被改成手动的服务会静默弄丢第一个的跟踪记录。
    Chk '无文件为空' (@(Get-ManagedServices).Count) 0
    Set-ManagedService -Name 'FooSvc' -Tracked $true
    Set-ManagedService -Name 'foosvc' -Tracked $true
    Chk '去重(忽略大小写)' (@(Get-ManagedServices).Count) 1
    Set-ManagedService -Name 'BarSvc' -Tracked $true
    Chk '两条' (@(Get-ManagedServices).Count) 2
    Set-ManagedService -Name 'FOO svc[X]' -Tracked $true
    Set-ManagedService -Name 'FOO svc[X]' -Tracked $false
    Chk '特殊字符移除' (@(Get-ManagedServices | Where-Object { $_ -eq 'FOO svc[X]' }).Count) 0
    Set-ManagedService -Name 'FOOSVC' -Tracked $false
    Chk '移除后剩1条' (@(Get-ManagedServices).Count) 1
    Chk '剩余条目' (@(Get-ManagedServices)[0]) 'BarSvc'
    Set-Content -LiteralPath $script:SvcStateFile -Value '{broken' -Encoding UTF8
    Chk '损坏清单返回空' (@(Get-ManagedServices).Count) 0

    Write-Host "`n[6] AI 请求体：三种协议的结构差异" -ForegroundColor Cyan
    $schema = [ordered]@{ type='object' }
    $sys = 'SYS'; $ut = 'USER'
    $anth  = New-AiProvider -Name 'A' -Protocol 'anthropic' -BaseUrl 'https://api.anthropic.com' -Model 'm1'
    $relay = New-AiProvider -Name 'R' -Protocol 'anthropic' -BaseUrl 'https://relay.example.cn' -Model 'm1'
    $oai   = New-AiProvider -Name 'O' -Protocol 'openai' -BaseUrl 'https://api.openai.com/v1' -Model 'm2'
    $resp  = New-AiProvider -Name 'S' -Protocol 'openai-responses' -BaseUrl 'https://x.cn' -Model 'm3'
    $b = New-AiRequestBody -Provider $anth -System $sys -UserText $ut -Schema $schema
    Chk 'anth: 模型' $b.model 'm1'
    Chk 'anth: system 顶层' $b.system 'SYS'
    Chk 'anth: 仅 user 消息' $b.messages[0].role 'user'
    Chk 'anth: max_tokens' $b.max_tokens 16000
    Chk 'anth: 结构化输出' $b.output_config.format.type 'json_schema'
    Ok  'anth: schema 在列' ($null -ne $b.output_config.format.schema)
    Chk 'anth: 思考强度' $b.output_config.effort 'high'
    Chk 'anth: 官方 fallback' $b.fallbacks 'default'
    $b = New-AiRequestBody -Provider $relay -System $sys -UserText $ut -Schema $schema
    Ok  'anth: 中转站无 fallback' ($null -eq $b.fallbacks)
    $noe = New-AiProvider -Name 'N' -Protocol 'anthropic' -BaseUrl 'https://api.anthropic.com' -Model 'm1'
    $noe.Effort = '(不发送)'
    $b = New-AiRequestBody -Provider $noe -System $sys -UserText $ut -Schema $schema
    Ok  'anth: 不发送思考强度' ($null -eq $b.output_config['effort'])
    $b = New-AiRequestBody -Provider $oai -System $sys -UserText $ut -Schema $schema
    Chk 'oai: 消息0为system' $b.messages[0].role 'system'
    Chk 'oai: json_schema 嵌套' $b.response_format.json_schema.name 'startup_analysis'
    Chk 'oai: strict' $b.response_format.json_schema.strict $true
    Ok  'oai: schema 在列' ($null -ne $b.response_format.json_schema.schema)
    Chk 'oai: 思考强度字段' $b.reasoning_effort 'high'
    $b = New-AiRequestBody -Provider $resp -System $sys -UserText $ut -Schema $schema
    Chk 'resp: 消息0为system' $b.input[0].role 'system'
    Chk 'resp: format 拍平' $b.text.format.name 'startup_analysis'
    Chk 'resp: strict' $b.text.format.strict $true
    Ok  'resp: 无 json_schema 套层' ($null -eq $b.text.format.json_schema)
    Chk 'resp: 输出上限字段' $b.max_output_tokens 16000
    Chk 'resp: 思考强度' $b.reasoning.effort 'high'
    Ok  'resp: 无 response_format' ($null -eq $b['response_format'])

    Write-Host "`n[6b] AI 响应解析：文本提取与拒绝/截断分流" -ForegroundColor Cyan
    $resp1 = [pscustomobject]@{ content = @([pscustomobject]@{type='text'; text='aa'}, [pscustomobject]@{type='text'; text='bb'}) }
    Chk 'anth: 文本拼接' (Get-AiResponseText -Provider $anth -Resp $resp1) 'aabb'
    $respR = [pscustomobject]@{ stop_reason='refusal'; stop_details=[pscustomobject]@{category='safety'} }
    Throws 'anth: refusal 抛错' { Get-AiResponseText -Provider $anth -Resp $respR } '拒绝'
    $resp2 = [pscustomobject]@{ choices=@([pscustomobject]@{ message=[pscustomobject]@{content='hi'}; finish_reason='stop' }) }
    Chk 'oai: content' (Get-AiResponseText -Provider $oai -Resp $resp2) 'hi'
    $respF = [pscustomobject]@{ choices=@([pscustomobject]@{ message=[pscustomobject]@{content=''}; finish_reason='content_filter' }) }
    Throws 'oai: content_filter 抛错' { Get-AiResponseText -Provider $oai -Resp $respF } '内容被'
    $resp3 = [pscustomobject]@{ output=@(
            [pscustomobject]@{ type='reasoning'; content=@([pscustomobject]@{type='summary_text'; text='think'}) },
            [pscustomobject]@{ type='message'; content=@([pscustomobject]@{type='output_text'; text='x'}, [pscustomobject]@{type='output_text'; text='y'}) }
        ) }
    Chk 'resp: 跳过reasoning取正文' (Get-AiResponseText -Provider $resp -Resp $resp3) 'xy'
    $respRef = [pscustomobject]@{ output=@([pscustomobject]@{ type='message'; content=@([pscustomobject]@{type='refusal'; refusal='nope'}) }) }
    Throws 'resp: refusal 抛错' { Get-AiResponseText -Provider $resp -Resp $respRef } '拒绝'
    $respInc = [pscustomobject]@{ status='incomplete'; incomplete_details=[pscustomobject]@{reason='max_output_tokens'} }
    Throws 'resp: 截断抛错' { Get-AiResponseText -Provider $resp -Resp $respInc } '截断'
    $respErr = [pscustomobject]@{ error=[pscustomobject]@{message='boom'} }
    Throws 'resp: error 抛错' { Get-AiResponseText -Provider $resp -Resp $respErr } 'boom'
    $resp4 = [pscustomobject]@{ output=@(); output_text='z' }
    Chk 'resp: 顶层便捷字段' (Get-AiResponseText -Provider $resp -Resp $resp4) 'z'
    $u1 = [pscustomobject]@{ usage=[pscustomobject]@{ prompt_tokens=10; completion_tokens=20 } }
    $u = Get-AiUsage -Provider $oai -Resp $u1
    Chk 'oai: 用量字段' ($u.In.ToString() + '|' + $u.Out.ToString()) '10|20'
    $u2 = [pscustomobject]@{ usage=[pscustomobject]@{ input_tokens=3; output_tokens=4 } }
    $u = Get-AiUsage -Provider $resp -Resp $u2
    Chk 'resp: 用量字段' ($u.In.ToString() + '|' + $u.Out.ToString()) '3|4'

    Write-Host "`n[6c] AI 错误解读：HTTP 码 → 建议" -ForegroundColor Cyan
    function Fake-Err([int]$code, [string]$msg) {
        [pscustomobject]@{ ErrorDetails=[pscustomobject]@{ Message=$msg }; Exception=[pscustomobject]@{ Response=[pscustomobject]@{ StatusCode=$code } } }
    }
    $m = Resolve-AiError (Fake-Err 401 '{"error":{"message":"invalid key"}}') $oai
    Ok '401: Key 提示' ($m -match 'API Key 无效')
    Ok '401: 解析出 detail' ($m -match 'invalid key')
    Ok '403: 权限提示' ((Resolve-AiError (Fake-Err 403 'x') $oai) -match '无权访问')
    Ok '429: 限流提示' ((Resolve-AiError (Fake-Err 429 'x') $oai) -match '速率限制')
    Ok '400: 参数提示' ((Resolve-AiError (Fake-Err 400 'x') $oai) -match '模型名或参数')
    Ok '0: 连接提示'   ((Resolve-AiError (Fake-Err 0 'x') $oai) -match '连不上服务器')
    Ok '404 openai: 提示换 Responses' ((Resolve-AiError (Fake-Err 404 'x') $oai) -match 'Responses API')
    Ok '404 responses: 提示换 Chat' ((Resolve-AiError (Fake-Err 404 'x') $resp) -match 'Chat Completions')
    Ok '404 anthropic: 地址提示' ((Resolve-AiError (Fake-Err 404 'x') $anth) -match '地址不对')
    Ok '无 JSON detail 不炸' ((Resolve-AiError (Fake-Err 500 'plain text') $anth) -match 'plain text')

    Write-Host "`n[6d] AI 脱敏 Convert-AiRedact" -ForegroundColor Cyan
    Chk '关闭脱敏直通' (Convert-AiRedact 'C:\x\a.exe' $false) 'C:\x\a.exe'
    Chk '空文本' (Convert-AiRedact '' $true) ''
    $up = [Environment]::GetFolderPath('UserProfile')
    $red = Convert-AiRedact "$up\sub\evil.exe" $true
    Ok  '用户目录替换' ($red -match [regex]::Escape('%USERPROFILE%'))
    Ok  '原路径不再出现' ($red -notmatch [regex]::Escape($up))
    $red2 = Convert-AiRedact ($up.ToUpper() + '\x.exe') $true
    Ok  '替换忽略大小写' ($red2 -match [regex]::Escape('%USERPROFILE%'))
    if ($env:USERNAME) {
        $red3 = Convert-AiRedact "C:\Temp\run-$($env:USERNAME)\a.exe" $true
        Ok '用户名替换' ($red3 -match '<USER>' -and $red3 -notmatch [regex]::Escape($env:USERNAME))
    } else { Ok '用户名替换（本平台无 USERNAME，跳过）' $true }
    if ($env:COMPUTERNAME) {
        $red4 = Convert-AiRedact "C:\Temp\host-$($env:COMPUTERNAME)\b.exe" $true
        Ok '主机名替换' ($red4 -match '<HOST>' -and $red4 -notmatch [regex]::Escape($env:COMPUTERNAME))
    } else { Ok '主机名替换（本平台无 COMPUTERNAME，跳过）' $true }

    Write-Host "`n[6e] AI 配置载入 / 旧格式迁移 / 默认值" -ForegroundColor Cyan
    Remove-Item -LiteralPath $script:AiCfgFile -Force -EA SilentlyContinue
    $cfg0 = Get-AiConfig
    Chk '缺失配置: 默认一条' (@($cfg0.Providers).Count) 1
    Ok  '缺失配置: Active 已设' ($null -ne $cfg0.Active -and $cfg0.Active -ne '')
    $old = @{ KeyEnc='test-enc'; Model='claude-x'; Effort='low'; Redact=$false; Consented=$true } | ConvertTo-Json
    Set-Content -LiteralPath $script:AiCfgFile -Value $old -Encoding UTF8
    $cfg1 = Get-AiConfig
    Chk '旧格式迁移: 一条' (@($cfg1.Providers).Count) 1
    Chk '旧格式迁移: Active' $cfg1.Active $cfg1.Providers[0].Id
    Chk '旧格式迁移: KeyEnc' $cfg1.Providers[0].KeyEnc 'test-enc'
    Chk '旧格式迁移: Model' $cfg1.Providers[0].Model 'claude-x'
    Chk '旧格式迁移: Effort' $cfg1.Providers[0].Effort 'low'
    Chk '旧格式迁移: Redact' $cfg1.Redact $false
    Chk '旧格式迁移: Consented' $cfg1.Consented $true
    $new = @{ Active='p2'; Redact=$true; Consented=$false; Providers=@(
        @{ Id='p1'; Name=''; Protocol='weird'; BaseUrl='https://x'; KeyEnc='k1'; Model='m1'; Effort='low' },
        @{ Id='p2'; Name='B'; Protocol='openai'; BaseUrl=''; KeyEnc=''; Model='m2'; Effort='' }
    ) } | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $script:AiCfgFile -Value $new -Encoding UTF8
    $cfg2 = Get-AiConfig
    Chk '新格式: 两条' (@($cfg2.Providers).Count) 2
    Chk '新格式: 非法协议回落' $cfg2.Providers[0].Protocol 'anthropic'
    Chk '新格式: 缺名默认' $cfg2.Providers[0].Name '未命名'
    Chk '新格式: 缺强度默认' $cfg2.Providers[1].Effort 'high'
    Chk '新格式: Active 命中' $cfg2.Active 'p2'
    Save-AiConfig -Cfg $cfg2
    $cfg3 = Get-AiConfig
    Chk '保存往返: Active' $cfg3.Active 'p2'
    Chk '保存往返: 条数' (@($cfg3.Providers).Count) 2
    Chk '保存往返: Redact' $cfg3.Redact $true
    $bad = @{ Active='zzz'; Providers=@(@{ Id='real'; Name='R'; Protocol='anthropic'; BaseUrl=''; KeyEnc=''; Model=''; Effort='high' }) } | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $script:AiCfgFile -Value $bad -Encoding UTF8
    $cfg4 = Get-AiConfig
    Chk 'Active 失效回落首位' $cfg4.Active 'real'
    Set-Content -LiteralPath $script:AiCfgFile -Value '{broken' -Encoding UTF8
    $cfg5 = Get-AiConfig
    Chk '损坏配置: 默认一条' (@($cfg5.Providers).Count) 1
    Ok  '损坏配置: 不炸' ($null -ne $cfg5.Active)

    Write-Host "`n[7] 可撤销白名单 / 日志目标白名单补充" -ForegroundColor Cyan
    Ok 'Undoable: Run删' (Test-RecordUndoable -Action 'delete' -Kind 'Run' -Extra @{})
    Ok 'Undoable: lnk删' (Test-RecordUndoable -Action 'delete' -Kind 'Folder' -Extra @{Ext='.lnk'})
    Ok 'Undoable: 脚本删=否' (-not (Test-RecordUndoable -Action 'delete' -Kind 'Folder' -Extra @{Ext='.vbs'}))
    Ok 'Undoable: 任务删=否' (-not (Test-RecordUndoable -Action 'delete' -Kind 'Task' -Extra @{}))
    Ok 'Undoable: 服务删=否' (-not (Test-RecordUndoable -Action 'delete' -Kind 'Service' -Extra @{}))
    Ok 'Undoable: Run改' (Test-RecordUndoable -Action 'edit' -Kind 'Run' -Extra @{})
    Ok 'Undoable: 任务改' (Test-RecordUndoable -Action 'edit' -Kind 'Task' -Extra @{})
    Ok 'Undoable: 服务改=否' (-not (Test-RecordUndoable -Action 'edit' -Kind 'Service' -Extra @{}))
    Ok 'Undoable: 其他动作=否' (-not (Test-RecordUndoable -Action 'add' -Kind 'Run' -Extra @{}))
    $recA = New-JournalRecord -Item $item -Action 'delete'
    Ok '记录一致性: Run删可撤销' $recA.Undoable
    $itemT = [pscustomobject]@{ Name='T'; Command='x'; Kind='Task'; Scope=''; Loc='\'; Enabled=$true; Extra=@{ TaskName='T'; TaskPath='\' } }
    $recT = New-JournalRecord -Item $itemT -Action 'delete'
    Ok '记录一致性: 任务删不可撤销' (-not $recT.Undoable)
    Ok 'ApprovedKeyPath: 空hive' ($null -eq (Get-ApprovedKeyPath -Hive '' -Sub 'Run'))
    Chk 'ApprovedKeyPath: 拼接' (Get-ApprovedKeyPath -Hive 'HKCU' -Sub 'Run') 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'

    Write-Host "`n[8] New-Item2 首词回退（rundll32 x.dll,Start 不被误判残留）" -ForegroundColor Cyan
    $cand = if ([Environment]::OSVersion.Platform -eq 'Win32NT') { @('rundll32') } else { @('sh','ls','cat') }
    $first = $cand | Where-Object { Get-Command $_ -CommandType Application -EA SilentlyContinue } | Select-Object -First 1
    if ($first) {
        $it = New-Item2 -Name 'T' -Cmd "$first C:\Definitely\Not\Real\payload.dll,Start" -Kind 'Run' -Scope 'HKCU' -Label 'L' -Loc $RUN_LOCS[0].Reg -Enabled $true -CanToggle $true -CanEdit $true -CanDelete $true -Extra @{ Ap='HKCU'; ApSub='Run' }
        Chk '回退: 解析为存在' $it.ExistState 'yes'
        Chk '回退: 参数保留' $it.Arguments 'C:\Definitely\Not\Real\payload.dll,Start'
        $exSrc = (Get-Command $first -CommandType Application).Source
        Ok  '回退: 目标是首词对应可执行文件' ([IO.Path]::GetFileName($it.Target) -eq [IO.Path]::GetFileName($exSrc))
        $it2 = New-Item2 -Name 'T' -Cmd 'C:\Definitely\Missing Folder\evil.dll,Q' -Kind 'Run' -Scope 'HKCU' -Label 'L' -Loc $RUN_LOCS[0].Reg -Enabled $true -CanToggle $true -CanEdit $true -CanDelete $true -Extra @{ Ap='HKCU'; ApSub='Run' }
        Chk '回退失败: 保持原路径' $it2.Target 'C:\Definitely\Missing Folder\evil.dll'
        Chk '回退失败: 状态为缺失' $it2.ExistState 'no'
        Chk '回退失败: 参数保留' $it2.Arguments ',Q'
    } else { Ok '首词回退（无可测命令）跳过' $true }

    Write-Host "`n[9] 签名状态文案 Get-SigText" -ForegroundColor Cyan
    foreach ($pair in @(@('Valid','有效'), @('NotSigned','无签名'), @('HashMismatch','哈希不符'), @('NotTrusted','不受信任'),
                        @('UnknownError','未知错误'), @('NotSupportedFileFormat','不支持的格式'), @('Incompatible','不兼容'))) {
        Chk ("签名文案 " + $pair[0]) (Get-SigText $pair[0]) $pair[1]
    }
    Chk '签名文案: 未校验保持' (Get-SigText '未校验') '未校验'
    Chk '签名文案: 空' (Get-SigText '') ''

    if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
        Write-Host "`n[10] StartupApproved 字节语义（与任务管理器互通的基础）" -ForegroundColor Cyan
        $APK = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        $AN  = '__SM_LOGIC_APPROVED__'
        try {
            Set-ApprovedState -Hive 'HKCU' -Sub 'Run' -Name $AN -Enabled $true
            $b = (Get-Item $APK).GetValue($AN)
            Chk '启用字节: 首字节=2(偶数)' $b[0] 2
            Chk '启用字节: 长度12' $b.Length 12
            Set-ApprovedState -Hive 'HKCU' -Sub 'Run' -Name $AN -Enabled $false
            $b = (Get-Item $APK).GetValue($AN)
            Chk '禁用字节: 首字节=3(奇数)' $b[0] 3
            Chk '禁用字节: 长度12' $b.Length 12
            $ftAge = [Math]::Abs(((Get-Date) - [DateTime]::FromFileTime([BitConverter]::ToInt64($b, 4))).TotalSeconds)
            Ok  '禁用字节: FILETIME 为当前时刻' ($ftAge -lt 120)
            Set-ApprovedState -Hive 'HKCU' -Sub 'Run' -Name $AN -Enabled $true
            Chk '读回: 启用' (Get-ApprovedState -Hive 'HKCU' -Sub 'Run' -Name $AN) $true
            Set-ApprovedState -Hive 'HKCU' -Sub 'Run' -Name $AN -Enabled $false
            Chk '读回: 禁用' (Get-ApprovedState -Hive 'HKCU' -Sub 'Run' -Name $AN) $false
        } finally {
            Remove-ItemProperty -Path $APK -Name $AN -Force -EA SilentlyContinue
        }

        Write-Host "`n[11] rundll32 首词回退的最终风险（仅 Windows）" -ForegroundColor Cyan
        if (Get-Command rundll32 -CommandType Application -EA SilentlyContinue) {
            $it = New-Item2 -Name 'T' -Cmd 'rundll32 C:\Temp\evil.dll,Start' -Kind 'Run' -Scope 'HKCU' -Label 'L' -Loc $RUN_LOCS[0].Reg -Enabled $true -CanToggle $true -CanEdit $true -CanDelete $true -Extra @{ Ap='HKCU'; ApSub='Run' }
            Chk 'rundll32 回退: 目标是系统 rundll32' $it.Target 'C:\Windows\System32\rundll32.exe'
            Ok  'rundll32 回退: 风险为关注' ($it.Risk -eq 'warning')
            Ok  'rundll32 回退: 说明提到 dll' ($it.RiskNote -match 'evil\.dll')
        } else { Ok 'rundll32 回退（无 rundll32，跳过）' $true }

        Write-Host "`n[12] 启动文件夹白名单（仅 Windows）" -ForegroundColor Cyan
        $sf = $FOLDER_LOCS | Where-Object { $_.Scope -eq 'User' } | Select-Object -First 1
        if ($sf.Path) {
            $okF = $false
            try { Assert-JournalTarget ([pscustomobject]@{ Kind='Folder'; Name='X'; Loc=''; Extra=@{ File=(Join-Path $sf.Path 'x.lnk') } }) ; $okF = $true } catch { }
            Ok 'Folder 白名单: 启动文件夹内通过' $okF
            $badF = $false
            try { Assert-JournalTarget ([pscustomobject]@{ Kind='Folder'; Name='X'; Loc=''; Extra=@{ File='C:\Windows\System32\x.lnk' } }) } catch { $badF = $true }
            Ok 'Folder 白名单: 任意目录被拒' $badF
            $noF = $false
            try { Assert-JournalTarget ([pscustomobject]@{ Kind='Folder'; Name='X'; Loc=''; Extra=@{} }) } catch { $noF = $true }
            Ok 'Folder 白名单: 缺文件路径被拒' $noF
        } else { Ok 'Folder 白名单（无启动文件夹，跳过）' $true }
    }
}
catch {
    Write-Host "`n异常: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    $script:fails++
}
finally {
    Remove-Item -LiteralPath $script:TestDir -Recurse -Force -EA SilentlyContinue
    Remove-Item Env:SM_LOGIC_VAR -EA SilentlyContinue
}

Write-Host ""
if ($script:fails -eq 0) { Write-Host "纯逻辑回归：全部断言通过" -ForegroundColor Green }
else { Write-Host "纯逻辑回归：$($script:fails) 个断言失败" -ForegroundColor Red }
exit $(if ($script:fails -eq 0) { 0 } else { 1 })
