# XAML / 启动路径冒烟测试：把主程序改造成「只建界面不显示」再载入
$ErrorActionPreference = 'Stop'
$src  = Join-Path $PSScriptRoot 'BootScope.ps1'
$code = Get-Content $src -Raw

$orig = $code
# 1) 跳过提权/STA 守卫
$code = $code.Replace('if (-not $isAdmin -or -not $isSta) {', 'if ($false) {')
if ($code -eq $orig) { throw '守卫替换失败——主程序那一行的写法变了' }

# 2) 不真正弹窗
$b = $code
$code = $code.Replace('$win.ShowDialog() | Out-Null', '# smoke: 不显示窗口')
if ($code -eq $b) { throw 'ShowDialog 替换失败' }

# 3) 首次加载改为手动触发（ContentRendered 不会在不显示时触发）
$stub = Join-Path $env:TEMP "sm_smoke_$PID.ps1"
Set-Content -LiteralPath $stub -Value $code -Encoding UTF8

$fail = 0
function Ok($n, $c) { if ($c) { "  [OK]   $n" } else { $script:fail++; "  [FAIL] $n" } }

try {
    . $stub

    '--- 界面构建 ---'
    Ok 'Window 已创建'            ($null -ne $win)
    Ok '主表 grid 存在'           ($null -ne $UI.grid)
    Ok 'AI 按钮存在'              ($null -ne $UI.btnAi)
    Ok 'AI 设置按钮存在'          ($null -ne $UI.btnAiCfg)
    Ok 'AI 配置切换下拉存在'      ($null -ne $UI.cboAi)
    # 对话框里的控件在 XAML 校验那一节统一验，这里只验主窗口
    Ok '忙碌指示存在'             ($null -ne $UI.lblBusy)
    Ok '警告条存在'               ($null -ne $UI.lblWarn)
    $cols = @($UI.grid.Columns | ForEach-Object { $_.Header })
    Ok "列数 9 = 勾选 + 8 文本列 (实际 $($cols.Count))" ($cols.Count -eq 9)
    Ok 'AI 结论列存在'            ($cols -contains 'AI 结论')

    '--- 子对话框 XAML ---'
    foreach ($fn in 'Show-BatchConfirm','Show-ItemDialog','Show-AiConfigDialog','Show-AiReport') {
        Ok "$fn 已定义" ($null -ne (Get-Command $fn -EA SilentlyContinue))
    }

    '--- 新增函数 ---'
    foreach ($fn in 'Remove-RegValue','Assert-JournalTarget','Test-RecordUndoable','Write-JournalRecords',
                    'Get-ApprovedKeyPath','Get-AiConfig','Convert-AiRedact',
                    'Invoke-Guarded','Sync-UI','Format-ErrList','Get-SigText','Save-UnrecoverableRecords',
                    'Start-BgWork','Unregister-BgJob','Stop-AllBgWork','Get-FunctionSource',
                    'Set-LoadIdle','Set-AiIdle','Complete-ItemLoad','Set-Progress','Set-LoadLock',
                    'Get-AiEndpoint','Get-AiHeaders','New-AiRequestBody','Get-AiResponseText',
                    'Get-AiUsage','Get-AiModelList','Get-AiActiveProvider','New-AiProvider',
                    'ConvertTo-AiProvider','Test-AiOfficial','Resolve-AiError','Invoke-AiAnalysis',
                    'Update-AiProviderBar','Start-SigPass','Update-ItemSignature') {
        Ok "$fn" ($null -ne (Get-Command $fn -EA SilentlyContinue))
    }

    '--- 逻辑单测 ---'
    Ok '通配符转义: *'      ([Management.Automation.WildcardPattern]::Escape('*') -ne '*')
    Ok '通配符转义: [X]'    ([Management.Automation.WildcardPattern]::Escape('App [X]') -ne 'App [X]')
    Ok '签名中文化'         ((Get-SigText 'NotSigned') -eq '无签名')
    Ok '签名未知保持原样'   ((Get-SigText '未校验') -eq '未校验')
    Ok 'Undoable: Run删除'  (Test-RecordUndoable -Action 'delete' -Kind 'Run' -Extra @{})
    Ok 'Undoable: 服务删除=否' (-not (Test-RecordUndoable -Action 'delete' -Kind 'Service' -Extra @{}))
    Ok 'Undoable: lnk删除'  (Test-RecordUndoable -Action 'delete' -Kind 'Folder' -Extra @{Ext='.lnk'})
    Ok 'Undoable: 脚本删除=否' (-not (Test-RecordUndoable -Action 'delete' -Kind 'Folder' -Extra @{Ext='.vbs'}))
    $r = Convert-AiRedact "C:\Users\$env:USERNAME\app.exe" $true
    Ok "脱敏生效 ($r)"      ($r -notmatch [regex]::Escape($env:USERNAME))

    '--- 回滚白名单 ---'
    $bad = [pscustomobject]@{ Kind='Run'; Name='X'; Loc='HKLM:\SYSTEM\CurrentControlSet\Services\Evil'; Extra=@{} }
    $threw = $false
    try { Assert-JournalTarget $bad } catch { $threw = $true }
    Ok '拒绝非白名单注册表位置' $threw
    $good = [pscustomobject]@{ Kind='Run'; Name='X'; Loc=$RUN_LOCS[0].Reg; Extra=@{} }
    $threw2 = $false
    try { Assert-JournalTarget $good } catch { $threw2 = $true }
    Ok '接受白名单位置'        (-not $threw2)



    '--- 异步：后台枚举所需的函数源码可提取 ---'
    $src = Get-FunctionSource $script:EnumFns
    Ok "枚举函数源码长度 $([int]($src.Length/1024))KB" ($src.Length -gt 2000)
    foreach ($fn in $script:EnumFns) { if ($src -notmatch [regex]::Escape("function $fn")) { $script:fail++; "  [FAIL] 源码缺 $fn" } }
    Ok '11 个枚举函数全部可序列化' ($script:EnumFns.Count -eq 11)
    Ok '状态标志用哈希表承载(闭包可写)' ($script:Flags -is [hashtable])
    Ok 'DataGrid 已开启行虚拟化' ($UI.grid.EnableRowVirtualization)
    # 列虚拟化刻意关闭：只有 8 列，簿记开销比省下来的多（实测 478ms -> 212ms）
    Ok 'DataGrid 列虚拟化已关闭(有意为之)' (-not $UI.grid.EnableColumnVirtualization)

    '--- XAML：全部对话框可加载、命名控件可取 ---'
    $XSRC = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'BootScope.ps1'), [Text.Encoding]::UTF8)
    $PAL  = $P
    $blocks=[regex]::Matches($XSRC, "(?s)@'\r?\n(.*?)\r?\n'@") | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -match '<Window' }

$fail=0; $i=0
foreach($b in $blocks){
  $i++
  $x=$b.Replace('VERB','删除').Replace('TITLE','标题')
  foreach($k in $PAL.Keys){ $x=$x.Replace("@$k@",$PAL[$k]) }
  $title=([regex]::Match($x,'Title="([^"]*)"')).Groups[1].Value
  try {
    $w=[Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$x)))
    # 模板内部的 x:Name 按设计就不归 Window.FindName 管，先把模板段剔掉
    $flat = [regex]::Replace($x, '(?s)<ControlTemplate.*?</ControlTemplate>', '')
    $flat = [regex]::Replace($flat, '(?s)<DataTemplate.*?</DataTemplate>', '')
    $names=[regex]::Matches($flat,'x:Name="([^"]+)"')|ForEach-Object{$_.Groups[1].Value}
    $miss=@($names|Where-Object{ $null -eq $w.FindName($_) })
    if($miss.Count){ $script:fail++; "  [FAIL] XAML #$i 「$title」 FindName 找不到: $($miss -join ', ')" }
    else { }
    $w.Close()
  } catch {
    $script:fail++; "  [FAIL] XAML #$i 「$title」 加载失败: $($_.Exception.Message)"
  }
}
    Ok "共 $($blocks.Count) 段 XAML，全部加载成功" ($fail -eq 0 -and $blocks.Count -ge 5)

    '--- AI 多 provider：地址归一化 ---'
    $anth = @{ Protocol='anthropic'; BaseUrl='https://api.anthropic.com' }
    $oai  = @{ Protocol='openai';    BaseUrl='https://api.openai.com/v1' }
    Ok 'anthropic messages 端点' ((Get-AiEndpoint $anth 'messages') -eq 'https://api.anthropic.com/v1/messages')
    Ok 'anthropic models 端点'   ((Get-AiEndpoint $anth 'models')   -eq 'https://api.anthropic.com/v1/models')
    Ok 'openai chat 端点'        ((Get-AiEndpoint $oai  'messages') -eq 'https://api.openai.com/v1/chat/completions')
    foreach ($u in 'https://x.cn','https://x.cn/','https://x.cn/v1','https://x.cn/v1/') {
        $got = Get-AiEndpoint @{ Protocol='anthropic'; BaseUrl=$u } 'messages'
        Ok "地址 '$u' 归一化" ($got -eq 'https://x.cn/v1/messages')
    }
    Ok '空地址回落官方' ((Get-AiEndpoint @{ Protocol='anthropic'; BaseUrl='' } 'messages') -eq 'https://api.anthropic.com/v1/messages')
    Ok '官方端点识别'   (Test-AiOfficial $anth)
    Ok '中转站不算官方' (-not (Test-AiOfficial @{ Protocol='anthropic'; BaseUrl='https://relay.example.com' }))

    '--- AI 多 provider：请求头与请求体按协议分流 ---'
    $ha = Get-AiHeaders -Provider $anth -Key 'k1' -ForMessages
    Ok 'anthropic 用 x-api-key'      ($ha['x-api-key'] -eq 'k1')
    Ok 'anthropic 带 version 头'     ($ha['anthropic-version'] -eq '2023-06-01')
    Ok '官方端点带 fallback beta 头' ($ha.ContainsKey('anthropic-beta'))
    $hr = Get-AiHeaders -Provider @{ Protocol='anthropic'; BaseUrl='https://relay.example.com' } -Key 'k1' -ForMessages
    Ok '中转站不发 beta 头'          (-not $hr.ContainsKey('anthropic-beta'))
    $ho = Get-AiHeaders -Provider $oai -Key 'k2'
    Ok 'openai 用 Bearer'            ($ho['Authorization'] -eq 'Bearer k2')

    $ba = New-AiRequestBody -Provider @{ Protocol='anthropic'; BaseUrl='https://api.anthropic.com'; Model='m1'; Effort='high' } -System 'S' -UserText 'U' -Schema @{ type='object' }
    Ok 'anthropic 请求体有 system'      ($ba.system -eq 'S')
    Ok 'anthropic 用 output_config'     ($null -ne $ba.output_config -and $ba.output_config.format.type -eq 'json_schema')
    Ok 'anthropic 官方带 fallbacks'     ($ba.fallbacks -eq 'default')
    $br = New-AiRequestBody -Provider @{ Protocol='anthropic'; BaseUrl='https://relay.example.com'; Model='m1'; Effort='high' } -System 'S' -UserText 'U' -Schema @{ type='object' }
    Ok '中转站不带 fallbacks'           (-not $br.Contains('fallbacks'))
    $bo = New-AiRequestBody -Provider @{ Protocol='openai'; BaseUrl='https://api.openai.com/v1'; Model='m2' } -System 'S' -UserText 'U' -Schema @{ type='object' }
    Ok 'openai system 进 messages[0]'   ($bo.messages[0].role -eq 'system' -and $bo.messages[0].content -eq 'S')
    Ok 'openai 用 response_format'      ($bo.response_format.type -eq 'json_schema')
    Ok 'openai 不带 output_config'      (-not $bo.Contains('output_config'))

    '--- AI 多 provider：响应解析按协议分流 ---'
    $ra = [pscustomobject]@{ content=@([pscustomobject]@{type='text';text='{"a":1}'}); stop_reason='end_turn'; usage=[pscustomobject]@{input_tokens=11;output_tokens=22} }
    Ok 'anthropic 取 content[].text' ((Get-AiResponseText -Provider $anth -Resp $ra) -eq '{"a":1}')
    $ua = Get-AiUsage -Provider $anth -Resp $ra
    Ok 'anthropic 用量'              ($ua.In -eq 11 -and $ua.Out -eq 22)
    $ro = [pscustomobject]@{ choices=@([pscustomobject]@{message=[pscustomobject]@{content='{"b":2}'};finish_reason='stop'}); usage=[pscustomobject]@{prompt_tokens=33;completion_tokens=44} }
    Ok 'openai 取 choices[0].message' ((Get-AiResponseText -Provider $oai -Resp $ro) -eq '{"b":2}')
    $uo = Get-AiUsage -Provider $oai -Resp $ro
    Ok 'openai 用量'                  ($uo.In -eq 33 -and $uo.Out -eq 44)
    $refused = $false
    try { Get-AiResponseText -Provider $anth -Resp ([pscustomobject]@{ stop_reason='refusal'; stop_details=[pscustomobject]@{category='cyber'} }) } catch { $refused = $true }
    Ok 'anthropic 拒答会抛错' $refused

    '--- OpenAI Responses 协议（/v1/responses）---'
    $rsp = @{ Protocol='openai-responses'; BaseUrl='https://api.openai.com/v1'; Model='gpt-5'; Effort='' }
    Ok 'responses 端点'      ((Get-AiEndpoint $rsp 'messages') -eq 'https://api.openai.com/v1/responses')
    Ok 'responses models 端点' ((Get-AiEndpoint $rsp 'models')  -eq 'https://api.openai.com/v1/models')
    Ok 'responses 用 Bearer' ((Get-AiHeaders -Provider $rsp -Key 'k9')['Authorization'] -eq 'Bearer k9')

    $bd = New-AiRequestBody -Provider $rsp -System 'SYS' -UserText 'USR' -Schema @{ type='object' }
    Ok 'responses 用 input 数组'      ($bd.input[0].role -eq 'system' -and $bd.input[0].content -eq 'SYS')
    Ok 'responses 用户消息在 input[1]' ($bd.input[1].role -eq 'user' -and $bd.input[1].content -eq 'USR')
    Ok 'responses 用 max_output_tokens' ($bd.max_output_tokens -eq 16000 -and -not $bd.Contains('max_tokens'))
    Ok 'responses 结构化输出在 text.format' ($bd.text.format.type -eq 'json_schema')
    # 关键差异：Responses 的 name/schema/strict 是拍平的，不再套一层 json_schema
    Ok 'responses format 字段是拍平的' ($bd.text.format.name -eq 'startup_analysis' -and $bd.text.format.strict -eq $true -and $null -ne $bd.text.format.schema)
    Ok 'responses 无 json_schema 嵌套'  ($null -eq $bd.text.format.json_schema)
    Ok 'responses 不带 response_format' (-not $bd.Contains('response_format'))
    Ok 'responses 不带 messages'        (-not $bd.Contains('messages'))

    '--- 思考强度：留空即不发送（非推理模型会被参数噎住）---'
    Ok 'responses 未设 effort 不发 reasoning' (-not $bd.Contains('reasoning'))
    $bd2 = New-AiRequestBody -Provider @{ Protocol='openai-responses'; BaseUrl='https://x/v1'; Model='m'; Effort='high' } -System 'S' -UserText 'U' -Schema @{}
    Ok 'responses 设了 effort 发 reasoning.effort' ($bd2.reasoning.effort -eq 'high')
    $bc1 = New-AiRequestBody -Provider @{ Protocol='openai'; BaseUrl='https://x/v1'; Model='m'; Effort='' } -System 'S' -UserText 'U' -Schema @{}
    Ok 'chat 未设 effort 不发 reasoning_effort' (-not $bc1.Contains('reasoning_effort'))
    $bc2 = New-AiRequestBody -Provider @{ Protocol='openai'; BaseUrl='https://x/v1'; Model='m'; Effort='medium' } -System 'S' -UserText 'U' -Schema @{}
    Ok 'chat 设了 effort 发 reasoning_effort'  ($bc2.reasoning_effort -eq 'medium')
    $ba1 = New-AiRequestBody -Provider @{ Protocol='anthropic'; BaseUrl='https://x/v1'; Model='m'; Effort='' } -System 'S' -UserText 'U' -Schema @{}
    Ok 'anthropic 未设 effort 不发'  (-not $ba1.output_config.Contains('effort'))
    $ba2 = New-AiRequestBody -Provider @{ Protocol='anthropic'; BaseUrl='https://x/v1'; Model='m'; Effort='xhigh' } -System 'S' -UserText 'U' -Schema @{}
    Ok 'anthropic 设了 effort 发'    ($ba2.output_config.effort -eq 'xhigh')

    '--- Responses 响应解析：混合 output 数组 ---'
    # 推理模型会在 output 里插 reasoning 条目，必须先挑 type=message
    $rr = [pscustomobject]@{
        status='completed'; error=$null
        output=@(
            [pscustomobject]@{ type='reasoning'; summary=@() }
            [pscustomobject]@{ type='message'; role='assistant'; content=@(
                [pscustomobject]@{ type='output_text'; text='{"ok":1}'; annotations=@() }) }
        )
        usage=[pscustomobject]@{ input_tokens=77; output_tokens=88; total_tokens=165 }
    }
    Ok 'responses 跳过 reasoning 取 output_text' ((Get-AiResponseText -Provider $rsp -Resp $rr) -eq '{"ok":1}')
    $ur = Get-AiUsage -Provider $rsp -Resp $rr
    Ok 'responses 用量用 input/output_tokens' ($ur.In -eq 77 -and $ur.Out -eq 88)

    # 多个 output_text 分片应拼起来
    $rr2 = [pscustomobject]@{ status='completed'; output=@([pscustomobject]@{ type='message'; content=@(
        [pscustomobject]@{ type='output_text'; text='{"a"' }
        [pscustomobject]@{ type='output_text'; text=':1}' }) }) }
    Ok 'responses 多分片拼接' ((Get-AiResponseText -Provider $rsp -Resp $rr2) -eq '{"a":1}')

    # 只给顶层 output_text 便捷字段的兼容实现
    $rr3 = [pscustomobject]@{ status='completed'; output=@(); output_text='{"b":2}' }
    Ok 'responses 回退顶层 output_text' ((Get-AiResponseText -Provider $rsp -Resp $rr3) -eq '{"b":2}')

    # refusal
    $rr4 = [pscustomobject]@{ status='completed'; output=@([pscustomobject]@{ type='message'; content=@(
        [pscustomobject]@{ type='refusal'; refusal='我不能协助该请求' }) }) }
    $refThrew = $false
    try { Get-AiResponseText -Provider $rsp -Resp $rr4 } catch { $refThrew = ($_.Exception.Message -match '拒绝') }
    Ok 'responses refusal 会抛错' $refThrew

    # 截断
    $rr5 = [pscustomobject]@{ status='incomplete'; incomplete_details=[pscustomobject]@{ reason='max_output_tokens' }
                              output=@([pscustomobject]@{ type='message'; content=@(
                                  [pscustomobject]@{ type='output_text'; text='{"partial"' }) }) }
    $incThrew = $false
    try { Get-AiResponseText -Provider $rsp -Resp $rr5 } catch { $incThrew = ($_.Exception.Message -match 'incomplete') }
    Ok 'responses 截断会抛错（不返回半截 JSON）' $incThrew

    # 顶层 error
    $rr6 = [pscustomobject]@{ status='failed'; error=[pscustomobject]@{ message='model_not_found' }; output=@() }
    $errThrew = $false
    try { Get-AiResponseText -Provider $rsp -Resp $rr6 } catch { $errThrew = ($_.Exception.Message -match 'model_not_found') }
    Ok 'responses 顶层 error 会抛错' $errThrew

    '--- 三种协议互不串味 ---'
    Ok '协议清单有 3 种' ($script:AI_PROTOCOLS.Count -eq 3 -and ($script:AI_PROTOCOLS -contains 'openai-responses'))
    $pr = ConvertTo-AiProvider ([pscustomobject]@{ Protocol='openai-responses' })
    Ok 'responses 协议能被反序列化' ($pr.Protocol -eq 'openai-responses')
    $bad = ConvertTo-AiProvider ([pscustomobject]@{ Protocol='不存在的协议' })
    Ok '未知协议回落 anthropic'     ($bad.Protocol -eq 'anthropic')

    '--- AI 多 provider：配置读写与旧格式迁移 ---'
    $savedCfg = $script:AiCfgFile
    $script:AiCfgFile = Join-Path $env:TEMP "sm_aicfg_$PID.json"
    try {
        Remove-Item $script:AiCfgFile -Force -EA SilentlyContinue
        $c0 = Get-AiConfig
        Ok '无配置时给一条默认 provider' (@($c0.Providers).Count -eq 1)
        Ok '默认 provider 是 anthropic'  (@($c0.Providers)[0].Protocol -eq 'anthropic')
        Ok '默认已选中'                  ($c0.Active -eq @($c0.Providers)[0].Id)

        # 旧版单配置格式应被迁移
        '{"KeyEnc":"","Model":"claude-sonnet-5","Effort":"low","Redact":false,"Consented":true}' |
            Set-Content $script:AiCfgFile -Encoding UTF8
        $c1 = Get-AiConfig
        Ok '旧格式迁移成 1 条 provider' (@($c1.Providers).Count -eq 1)
        Ok '旧格式保留模型'             (@($c1.Providers)[0].Model -eq 'claude-sonnet-5')
        Ok '旧格式保留 effort'          (@($c1.Providers)[0].Effort -eq 'low')
        Ok '旧格式保留 Redact/同意'     ((-not $c1.Redact) -and $c1.Consented)

        # 多 provider 存取 + 切换
        $c1.Providers = @(@($c1.Providers)[0], (New-AiProvider -Name '中转' -Protocol 'openai' -BaseUrl 'https://r.cn/v1' -Model 'gpt-x'))
        $c1.Active = @($c1.Providers)[1].Id
        Save-AiConfig $c1
        $c2 = Get-AiConfig
        Ok '两条 provider 都存住了' (@($c2.Providers).Count -eq 2)
        Ok '启用项被记住'           ((Get-AiActiveProvider $c2).Name -eq '中转')
        Ok '协议/地址/模型往返一致' ((Get-AiActiveProvider $c2).Protocol -eq 'openai' -and (Get-AiActiveProvider $c2).BaseUrl -eq 'https://r.cn/v1' -and (Get-AiActiveProvider $c2).Model -eq 'gpt-x')
        # Active 指向不存在的 id 时应回落到第一条
        $c2.Active = 'nope'
        Save-AiConfig $c2
        Ok '无效 Active 回落第一条' ((Get-AiConfig).Active -eq @($c2.Providers)[0].Id)
    } finally {
        Remove-Item $script:AiCfgFile -Force -EA SilentlyContinue
        $script:AiCfgFile = $savedCfg
    }

    '--- 三种协议并列存在，可分别配置 ---'
    $trio = @(
        @{ Proto='anthropic';        Ep='https://x.cn/v1/messages';         Auth='x-api-key' }
        @{ Proto='openai';           Ep='https://x.cn/v1/chat/completions'; Auth='Authorization' }
        @{ Proto='openai-responses'; Ep='https://x.cn/v1/responses';        Auth='Authorization' }
    )
    foreach ($t in $trio) {
        $pv = @{ Protocol=$t.Proto; BaseUrl='https://x.cn'; Model='m'; Effort='' }
        Ok "$($t.Proto) 端点独立" ((Get-AiEndpoint $pv 'messages') -eq $t.Ep)
        Ok "$($t.Proto) 认证方式"  ((Get-AiHeaders -Provider $pv -Key 'k').ContainsKey($t.Auth))
        Ok "$($t.Proto) models 共用" ((Get-AiEndpoint $pv 'models') -eq 'https://x.cn/v1/models')
    }
    # 同一份配置里可以同时存两种 openai
    $savedC = $script:AiCfgFile
    $script:AiCfgFile = Join-Path $env:TEMP "sm_trio_$PID.json"
    try {
        $cfg = Get-AiConfig
        $cfg.Providers = @(
            (New-AiProvider -Name 'A' -Protocol 'anthropic'        -BaseUrl 'https://a.cn' -Model 'm1')
            (New-AiProvider -Name 'B' -Protocol 'openai'           -BaseUrl 'https://b.cn/v1' -Model 'm2')
            (New-AiProvider -Name 'C' -Protocol 'openai-responses' -BaseUrl 'https://b.cn/v1' -Model 'm2')
        )
        $cfg.Active = @($cfg.Providers)[2].Id
        Save-AiConfig $cfg
        $back = Get-AiConfig
        Ok '三套配置并存'       (@($back.Providers).Count -eq 3)
        Ok 'chat 与 responses 可同址并存' ((@($back.Providers)[1].BaseUrl -eq @($back.Providers)[2].BaseUrl) -and (@($back.Providers)[1].Protocol -ne @($back.Providers)[2].Protocol))
        Ok '启用的是 responses 那套' ((Get-AiActiveProvider $back).Protocol -eq 'openai-responses')
    } finally {
        Remove-Item $script:AiCfgFile -Force -EA SilentlyContinue
        $script:AiCfgFile = $savedC
    }

    '--- 404 时给出换协议的建议 ---'
    function Fake404 ($proto) {
        $ex  = New-Object Exception 'boom'
        $rec = New-Object Management.Automation.ErrorRecord $ex,'x','NotSpecified',$null
        # 拿不到真的 HttpResponse，这里只验证协议相关的建议文案接进去了
        Resolve-AiError $rec @{ Protocol=$proto; BaseUrl='https://x.cn' }
    }
    Ok 'openai 的错误里带端点'           ((Fake404 'openai') -match 'chat/completions')
    Ok 'openai-responses 的错误里带端点' ((Fake404 'openai-responses') -match '/v1/responses')

    '--- 自动探测所需的部件 ---'
    Ok 'AI_PROBE_BODY 已定义'   ($script:AI_PROBE_BODY -and $script:AI_PROBE_BODY -match 'foreach \(\$proto in')
    Ok '探测脚本命中即停'       ($script:AI_PROBE_BODY -match 'break')
    Ok '探测脚本逐协议记结果'   ($script:AI_PROBE_BODY -match 'Protocol=\$proto')

    '--- AI Key：DPAPI 往返 ---'
    $enc = Protect-AiKey 'sk-test-12345'
    Ok 'Key 加密后不是明文' ($enc -and $enc -ne 'sk-test-12345')
    Ok 'Key 能解回来'       ((Unprotect-AiKey $enc) -eq 'sk-test-12345')
    Ok '空 Key 不炸'        ((Unprotect-AiKey '') -eq '')

    '--- 计划任务：现在可编辑 ---'
    Ok 'Task 编辑可撤销'    (Test-RecordUndoable -Action 'edit' -Kind 'Task' -Extra @{})
    Ok 'Service 编辑仍不可撤销' (-not (Test-RecordUndoable -Action 'edit' -Kind 'Service' -Extra @{}))
    $okTask = $true
    try { Assert-JournalTarget ([pscustomobject]@{ Kind='Task'; Name='T'; Extra=@{ TaskName='T'; TaskPath='\' } }) } catch { $okTask = $false }
    Ok '普通任务通过白名单' $okTask
    $sysTask = $false
    try { Assert-JournalTarget ([pscustomobject]@{ Kind='Task'; Name='T'; Extra=@{ TaskName='T'; TaskPath='\Microsoft\Windows\Foo\' } }) } catch { $sysTask = $true }
    Ok '系统任务树被拒绝'   $sysTask
    $noName = $false
    try { Assert-JournalTarget ([pscustomobject]@{ Kind='Task'; Name='T'; Extra=@{ TaskName=''; TaskPath='\' } }) } catch { $noName = $true }
    Ok '缺任务名被拒绝'     $noName

    '--- 回归：通配符删除（真实注册表，专用测试键）---'
    $TK = 'HKCU:\SOFTWARE\__SM_WildcardRegression__'
    try {
        New-Item -Path $TK -Force | Out-Null
        # A. 名字含 [ ] 的值：旧代码 Remove-ItemProperty 匹配不到，静默删除失败
        Set-ItemProperty -Path $TK -Name 'App [X]' -Value 'v1' -Force
        Remove-RegValue -Path $TK -Name 'App [X]'
        $left = @((Get-Item $TK).GetValueNames())
        Ok '含[]的值确实被删除' ($left -notcontains 'App [X]')

        # B. 名字为 * 的值：旧代码会把整个键的所有值一起删光
        Set-ItemProperty -Path $TK -Name 'Keep1' -Value 'a' -Force
        Set-ItemProperty -Path $TK -Name 'Keep2' -Value 'b' -Force
        Set-ItemProperty -Path $TK -Name '*'     -Value 'evil' -Force
        Remove-RegValue -Path $TK -Name '*'
        $left = @((Get-Item $TK).GetValueNames())
        Ok '删除名为*的值不波及其他' (($left -contains 'Keep1') -and ($left -contains 'Keep2'))
        Ok '名为*的值本身已删除'     ($left -notcontains '*')
    } finally {
        Remove-Item -Path $TK -Recurse -Force -EA SilentlyContinue
    }

    '--- 回归：枚举返回值不得被包装 ---'
    $script:VerifySig = $false
    function __probe ($n) { @(Get-AllStartupItems) | Where-Object { $_.Name -eq $n } }
    $all = @(Get-AllStartupItems)
    if ($all.Count -gt 0) {
        $one = @(__probe $all[0].Name)
        Ok "按名过滤只返回该条 (得到 $($one.Count) 条)" ($one.Count -ge 1 -and $one.Count -lt $all.Count -and $one[0].Name -eq $all[0].Name)
    } else { Ok '枚举返回值形状（无条目可测，跳过）' $true }

    '--- 风险判定 ---'
    $rk = Get-RiskInfo -Target 'C:\Windows\System32\rundll32.exe' -SigStatus 'Valid' -ExistState 'yes' -Name 'X' -Kind 'Run' -Cmd 'rundll32 C:\Temp\evil.dll,Start'
    Ok "rundll32 不再判正常 ($($rk.Level))" ($rk.Level -ne 'normal')
    $rk2 = Get-RiskInfo -Target 'C:\App\a.exe' -SigStatus '未校验' -ExistState 'yes' -Name 'a' -Kind 'Run' -Cmd '"C:\App\a.exe"'
    Ok "未校验不谎称签名有效"  ($rk2.Note -notmatch '签名有效')
}
finally {
    Remove-Item $stub -Force -EA SilentlyContinue
}
""
if ($fail -gt 0) { "结果：$fail 项失败"; exit 1 } else { "结果：全部通过"; exit 0 }
