#Requires -Version 5.1
<#
    启视  BootScope
    https://github.com/<你的账号>/bootscope
    Windows 自启动项 增 / 删 / 改 / 查 工具

    覆盖位置：
      · 注册表 Run / RunOnce   HKCU · HKLM · WOW6432Node · HKU\S-1-5-18 · HKU\.DEFAULT
      · 启动文件夹             当前用户 · 所有用户
      · 计划任务               登录 / 开机触发
      · 服务                   自动启动
      · UWP / MSIX             windows.startupTask（当前用户）

    普通启动项使用 StartupApproved；UWP 启动任务使用 Windows 原生 SystemAppData 的 State 状态。
    所有删除操作先写入回滚日志，支持撤销。
#>
param(
    # 提权/STA 重启时由自己传入，防止提权始终失败时无限弹 UAC
    [switch]$Relaunched
)

# ══════════════════════════════════════════════════════════════════
#  0. 自提权 + 隐藏控制台
# ══════════════════════════════════════════════════════════════════
$ErrorActionPreference = 'Stop'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$isAdmin = Test-Admin
$isSta   = ([Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')

# WPF 要求 STA 单线程单元；pwsh 7 在某些宿主下默认 MTA，需带 -STA 重启。
if (-not $isAdmin -or -not $isSta) {
    Add-Type -AssemblyName System.Windows.Forms
    # 已经重启过一次还是不满足条件，说明重启这条路走不通（组策略拦截、
    # STA 检测异常等）。再启动一次只会无限弹 UAC，直接报错退出。
    if ($Relaunched) {
        [System.Windows.Forms.MessageBox]::Show(
            "重新启动后仍未取得所需环境，已停止重试。`n`n管理员权限：$isAdmin`nSTA 单线程单元：$isSta`n`n" +
            "请手动运行：`npwsh -NoProfile -STA -ExecutionPolicy Bypass -File `"<脚本路径>`"",
            '启视 BootScope', 'OK', 'Error') | Out-Null
        exit 1
    }
    $self = $PSCommandPath
    if (-not $self) { $self = $MyInvocation.MyCommand.Definition }
    $pwsh7 = 'C:\Program Files\PowerShell\7\pwsh.exe'
    # 不能用 $env:WINDIR —— 它可由 HKCU\Environment 覆盖，而下面紧接着就是
    # Start-Process -Verb RunAs，等于把攻击者指定的 exe 直接提权运行
    # （经典 windir UAC bypass）。SystemDirectory 由系统解析，不受用户环境影响。
    $ps51  = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $exe   = if (Test-Path $pwsh7) { $pwsh7 } else { $ps51 }
    $argv  = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
               '-File', "`"$self`"", '-Relaunched')

    try {
        if ($isAdmin) { Start-Process -FilePath $exe -ArgumentList $argv }          # 仅缺 STA
        else          { Start-Process -FilePath $exe -ArgumentList $argv -Verb RunAs }
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "本工具需要管理员权限才能修改系统自启动项。`n`n提权请求被取消或失败：`n$($_.Exception.Message)",
            '启视 BootScope', 'OK', 'Warning') | Out-Null
    }
    exit
}

try {
    Add-Type -Namespace Native -Name Win -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]   public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
    [Native.Win]::ShowWindow([Native.Win]::GetConsoleWindow(), 0) | Out-Null
} catch { }

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml, System.Windows.Forms

# ══════════════════════════════════════════════════════════════════
#  1. 常量与状态
# ══════════════════════════════════════════════════════════════════
$script:AppDir  = Join-Path $env:LOCALAPPDATA 'BootScope'
$script:Journal = Join-Path $script:AppDir 'rollback.json'
# 更名前叫 StartupManager。老目录里有回滚日志、AI 配置、被改成手动的服务清单，
# 不搬过来这些全都读不到 —— 只在新目录尚不存在时搬一次，之后互不干扰。
$legacyDir = Join-Path $env:LOCALAPPDATA 'StartupManager'
if (-not (Test-Path $script:AppDir) -and (Test-Path $legacyDir)) {
    try { Move-Item -LiteralPath $legacyDir -Destination $script:AppDir -Force -ErrorAction Stop } catch { }
}
if (-not (Test-Path $script:AppDir)) { New-Item -ItemType Directory -Path $script:AppDir -Force | Out-Null }

# 导出要带 BOM，否则 Excel 按 ANSI 解码、中文全乱码。但两代 PowerShell 的写法不同：
# PS7 的 'UTF8' 是无 BOM，要写 'utf8BOM'；5.1 没有 utf8BOM 这个值，它的 'UTF8' 本来就带 BOM。
$script:ENC_BOM = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }

# 5.1 默认还在用 TLS 1.0/1.1，直连 api.anthropic.com 会握手失败
if ($PSVersionTable.PSVersion.Major -lt 6) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
}

$script:SigCache = @{}
$script:Items    = @()      # 全量条目
$script:View     = @()      # 当前筛选后、绑定到表格的条目
$script:VerifySig = $true
$script:LoadErrors = @()    # 本次枚举中读取失败的位置，显示在统计条上
$script:JournalWarning = $null

# 被本工具从「自动」改成「手动」的服务。服务枚举默认只看 StartMode='Auto'，
# 禁用后条目就会从列表里蒸发、再也无法在界面里重新启用；记下来才能继续显示。
$script:SvcStateFile = Join-Path $script:AppDir 'managed-services.json'
function Get-ManagedServices {
    if (-not (Test-Path $script:SvcStateFile)) { return @() }
    try { return ,@(Get-Content $script:SvcStateFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return ,@() }
}
function Set-ManagedService {
    param([string]$Name, [bool]$Tracked)
    $cur = [System.Collections.Generic.List[string]]@(Get-ManagedServices | Where-Object { $_ })
    $hit = @($cur | Where-Object { $_ -ieq $Name })
    if ($Tracked -and $hit.Count -eq 0) { $cur.Add($Name) }
    elseif (-not $Tracked -and $hit.Count -gt 0) {
        $keep = @($cur | Where-Object { $_ -inotmatch "^$([regex]::Escape($Name))$" })
        $cur = [System.Collections.Generic.List[string]]$keep
    } else { return }
    try { ($cur | ConvertTo-Json -Depth 2) | Set-Content $script:SvcStateFile -Encoding UTF8 } catch { }
}

$RUN_LOCS = @(
    @{ Scope='HKCU';       Reg='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                  Ap='HKCU'; ApSub='Run';   Label='HKCU\Run' }
    @{ Scope='HKCU-Once';  Reg='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';              Ap=$null;  ApSub=$null;   Label='HKCU\RunOnce' }
    @{ Scope='HKCU32';     Reg='HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';      Ap='HKCU'; ApSub='Run32'; Label='HKCU\WOW64\Run' }
    @{ Scope='HKLM';       Reg='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                  Ap='HKLM'; ApSub='Run';   Label='HKLM\Run' }
    @{ Scope='HKLM-Once';  Reg='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';              Ap=$null;  ApSub=$null;   Label='HKLM\RunOnce' }
    @{ Scope='HKLM32';     Reg='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';      Ap='HKLM'; ApSub='Run32'; Label='HKLM\WOW64\Run' }
    @{ Scope='HKLM32-Once';Reg='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce';  Ap=$null;  ApSub=$null;   Label='HKLM\WOW64\RunOnce' }
    @{ Scope='SYSTEM';     Reg='Registry::HKEY_USERS\S-1-5-18\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Ap=$null; ApSub=$null; Label='SYSTEM账户\Run' }
    @{ Scope='DEFAULT';    Reg='Registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Ap=$null; ApSub=$null; Label='默认用户模板\Run' }
)

$FOLDER_LOCS = @(
    @{ Scope='User';   Path=[Environment]::GetFolderPath('Startup');       Ap='HKCU'; Label='启动文件夹(当前用户)' }
    @{ Scope='Common'; Path=[Environment]::GetFolderPath('CommonStartup'); Ap='HKLM'; Label='启动文件夹(所有用户)' }
)

# ══════════════════════════════════════════════════════════════════
#  2. 工具函数
# ══════════════════════════════════════════════════════════════════
function Resolve-Target {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return @{ Path=''; Args='' } }
    $c = $Cmd.Trim()
    if ($c.StartsWith('"')) {
        $i = $c.IndexOf('"', 1)
        if ($i -gt 0) { return @{ Path=$c.Substring(1, $i-1); Args=$c.Substring($i+1).Trim() } }
    }
    $m = [regex]::Match($c, '^(.*?\.(?:exe|com|bat|cmd|vbs|vbe|js|ps1|scr|dll))(?:\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return @{ Path=$m.Groups[1].Value; Args=$c.Substring($m.Groups[1].Value.Length).Trim() } }
    $sp = $c.IndexOf(' ')
    if ($sp -gt 0) { return @{ Path=$c.Substring(0, $sp); Args=$c.Substring($sp+1) } }
    return @{ Path=$c; Args='' }
}

function Expand-Path { param([string]$P) if ($P) { [Environment]::ExpandEnvironmentVariables($P) } else { '' } }

# 判定目标文件是否存在。必须区分「确实缺失」与「无权读取」——
# 有些服务把自己装在 ProgramData 下并对普通用户设了 deny ACE，这类目录会让
# Test-Path 抛 Access denied；若当成缺失，就会把正在运行的服务误报为失效残留。
# 同时把裸文件名（powershell.exe）按 PATH 解析成完整路径。
function Resolve-ExistState {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return @{ State='na'; Path='' } }
    $p = $Path.Trim('"')
    if ($p -notmatch '[\\/]') {
        try {
            $c = @(Get-Command $p -CommandType Application -ErrorAction Stop)[0]
            if ($c) { $p = $c.Source }
        } catch { return @{ State='no'; Path=$Path } }
    }
    try {
        if (Test-Path -LiteralPath $p -PathType Leaf -ErrorAction Stop) { return @{ State='yes'; Path=$p } }
        return @{ State='no'; Path=$p }
    } catch {
        if ($_.Exception -is [System.UnauthorizedAccessException] -or
            $_.Exception.Message -match 'denied|拒绝访问') { return @{ State='denied'; Path=$p } }
        return @{ State='no'; Path=$p }
    }
}

function Get-Sig {
    param([string]$Path)
    if (-not $script:VerifySig) { return @{ Status='未校验'; Signer='' } }
    if ([string]::IsNullOrWhiteSpace($Path)) { return @{ Status='—'; Signer='' } }
    $k = $Path.ToLower()
    if ($script:SigCache.ContainsKey($k)) { return $script:SigCache[$k] }
    $r = @{ Status='—'; Signer='' }
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $r.Status = [string]$s.Status
            if ($s.SignerCertificate) {
                $cn = $s.SignerCertificate.Subject -replace '^CN=("?)([^",]+)\1.*', '$2'
                $r.Signer = $cn.Trim()
            }
        }
    } catch { $r.Status = '校验失败' }
    $script:SigCache[$k] = $r
    return $r
}

function Get-ApprovedState {
    param([string]$Hive, [string]$Sub, [string]$Name)
    if (-not $Hive) { return $true }
    $p = "${Hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$Sub"
    try {
        if (Test-Path $p) {
            $k = Get-Item $p
            if ($k.GetValueNames() -contains $Name) {
                $b = $k.GetValue($Name)
                # 首字节偶数 = 启用，奇数 = 禁用（Windows 原生约定）
                return (($b[0] -band 1) -eq 0)
            }
        }
    } catch { }
    return $true   # 无记录 => 默认启用
}

function Set-ApprovedState {
    param([string]$Hive, [string]$Sub, [string]$Name, [bool]$Enabled)
    $p = "${Hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$Sub"
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    if ($Enabled) {
        $bytes = [byte[]]@(2,0,0,0, 0,0,0,0, 0,0,0,0)
    } else {
        $ft = [BitConverter]::GetBytes([DateTime]::Now.ToFileTime())
        $bytes = [byte[]]@(3,0,0,0) + $ft
    }
    Set-ItemProperty -Path $p -Name $Name -Value $bytes -Type Binary -Force
}

# Remove-ItemProperty 的 -Name 走通配符匹配，这在删除注册表启动项时有两个后果：
#   · 名为「*」的值（恶意软件会这么干）会连带删光整个 Run 键，而回滚日志只记了一条
#   · 名含「[ ]」的值（Adobe ARM [Startup] 之类真实存在的名字）匹配不到，
#     删除静默失败但返回成功，界面报「已删除」而条目还在
# 所有删除路径一律走这里。注意 Set-ItemProperty -Name 反而是字面量语义，不能转义。
function Remove-RegValue {
    param([string]$Path, [string]$Name, [switch]$Quiet)
    $esc = [Management.Automation.WildcardPattern]::Escape($Name)
    if ($Quiet) { Remove-ItemProperty -Path $Path -Name $esc -Force -ErrorAction SilentlyContinue }
    else        { Remove-ItemProperty -Path $Path -Name $esc -Force }
}

# StartupApproved 键路径在删除/编辑/恢复多处重复拼接，收敛到一处
function Get-ApprovedKeyPath {
    param([string]$Hive, [string]$Sub)
    if (-not $Hive) { return $null }
    "${Hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$Sub"
}

# 回滚日志是 %LOCALAPPDATA% 下的普通 JSON 文件，同一用户的中完整性进程可以改写它。
# 而「撤销」会以管理员身份把记录里的 Loc / Extra.File 原样写回系统 —— 若不校验，
# 一个被篡改的日志就能让用户点一次撤销就往 HKLM\Services 或全局启动文件夹里写东西。
# 因此恢复前必须确认目标确实是本工具自己枚举的那些位置。
function Assert-JournalTarget {
    param($r)
    if ([string]$r.Kind -eq 'Task') {
        # 计划任务不落在注册表/文件白名单里，单独校验：必须有名字，且不能指向系统任务树
        if ([string]::IsNullOrWhiteSpace([string]$r.Extra.TaskName)) { throw '回滚记录缺少任务名，已拒绝恢复' }
        if ([string]$r.Extra.TaskPath -like '\Microsoft\Windows\*') { throw '回滚记录指向系统计划任务，已拒绝恢复' }
        return
    }
    switch ([string]$r.Kind) {
        'Run' {
            if ($RUN_LOCS.Reg -notcontains [string]$r.Loc) {
                throw "回滚记录指向的注册表位置不在本工具管理范围内，已拒绝恢复：$($r.Loc)"
            }
        }
        'Folder' {
            $f = [string]$r.Extra.File
            if (-not $f) { throw '回滚记录缺少文件路径，已拒绝恢复' }
            $dir = $null
            try { $dir = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($f)).TrimEnd('\') } catch { }
            if (-not $dir) { throw "回滚记录的文件路径无法解析，已拒绝恢复：$f" }
            $ok = $false
            foreach ($L in $FOLDER_LOCS) {
                if (-not $L.Path) { continue }
                $known = $null
                try { $known = [IO.Path]::GetFullPath($L.Path).TrimEnd('\') } catch { continue }
                if ($known -and $dir.Equals($known, [StringComparison]::OrdinalIgnoreCase)) { $ok = $true; break }
            }
            if (-not $ok) { throw "回滚记录指向的目录不是启动文件夹，已拒绝恢复：$f" }
        }
        default { throw "回滚记录的类型无法自动恢复：$($r.Kind)" }
    }
    if ([string]::IsNullOrWhiteSpace([string]$r.Name)) { throw '回滚记录缺少条目名称，已拒绝恢复' }
}

function Get-RiskInfo {
    param([string]$Target, [string]$SigStatus, [string]$ExistState, [string]$Name, [string]$Kind, [string]$Cmd)
    $notes = New-Object System.Collections.Generic.List[string]
    $lvl = 'normal'

    # 「文件不存在」以前会在这里直接 return，跳过后面全部规则。后果是
    # rundll32 xxx.dll,Start 这类命令被 Resolve-Target 解析出一个不存在的路径后，
    # 一个活着的持久化被标成「无害残留」，还会被「所有残留项」一键勾选。
    # 现在改成：先记下残留，继续跑完所有规则，最后取较严重的那个等级。
    $stale = ($ExistState -eq 'no')
    if ($stale) { $notes.Add('目标文件不存在 —— 可能是失效残留，也可能是命令行未被正确解析，删除前请核对完整命令') }
    if ($ExistState -eq 'denied') { $notes.Add('所在目录受 ACL 保护，未能读取该文件（不代表缺失）') }

    $t   = if ($Target) { $Target.ToLowerInvariant() } else { '' }
    $ext = try { [IO.Path]::GetExtension($t) } catch { '' }
    $isScript = $ext -in @('.vbs','.vbe','.bat','.cmd','.ps1','.js','.jse','.wsf')
    $isBinary = $ext -in @('.exe','.dll','.com','.scr')
    # 三态而非两态：'Valid' 才是真的验过；未校验 / 无权读取只是「不知道」，
    # 以前把它们和 Valid 一起当成「签名没问题」，等于给关掉签名校验或设了
    # deny-read ACL 的样本发免检通行证。
    $sigKnownBad  = ($SigStatus -notin @('Valid','未校验','—','校验失败'))
    $sigUnknown   = ($SigStatus -in @('未校验','—','校验失败')) -or ($ExistState -eq 'denied')
    $bad = $sigKnownBad -or $sigUnknown

    # 启动文件夹的物理路径本身就在 AppData\Roaming\Microsoft\Windows\… 之下，
    # 不能算「伪装成微软目录」。
    $inStartupFolder = ($t -match '\\start menu\\programs\\startup\\')

    if ($isScript) {
        $lvl = 'warning'
        $notes.Add('脚本文件（无数字签名属正常）—— 实际风险取决于脚本内容，请确认来源')
    } elseif ($sigKnownBad) {
        $lvl = 'warning'; $notes.Add("数字签名：$SigStatus")
    } elseif ($sigUnknown -and $ExistState -ne 'na') {
        $notes.Add($(if ($SigStatus -eq '未校验') { '未校验数字签名（已在界面关闭校验）' } else { "未能校验数字签名：$SigStatus" }))
    }

    # 解释器 + 脚本参数：真正决定行为的是脚本，不是解释器本身
    if ($t -match '\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$') {
        if ($lvl -eq 'normal') { $lvl = 'warning' }
        # 先匹配带引号的路径（脚本路径常含空格），失败再退回无引号匹配
        $sm = [regex]::Match($Cmd, '"([^"]+\.(?:ps1|vbs|vbe|bat|cmd|js|wsf|dll|scr))"', 'IgnoreCase')
        if (-not $sm.Success) { $sm = [regex]::Match($Cmd, '([^\s",]+\.(?:ps1|vbs|vbe|bat|cmd|js|wsf|dll|scr))', 'IgnoreCase') }
        if ($sm.Success) { $notes.Add("经系统解释器执行脚本：$($sm.Groups[1].Value) —— 实际行为由该脚本决定") }
        else             { $notes.Add('通过系统解释器启动 —— 请核对完整命令行') }
    }

    if ($isBinary -and $bad -and -not $inStartupFolder -and $t -match '\\appdata\\(roaming|local)\\microsoft\\') {
        # 签名确实无效 → 危险；只是没验成 → 关注（提示用户去开校验），不静默放行
        if ($sigKnownBad) { $lvl = 'critical'; $notes.Add('位于微软目录内却无有效签名 —— 典型的名称伪装手法') }
        elseif ($lvl -ne 'critical') { $lvl = 'warning'; $notes.Add('位于微软目录内且签名未经确认 —— 建议开启签名校验后复查') }
    }
    if ($t -match '^[a-z]:\\users\\public\\') {
        if ($lvl -eq 'normal') { $lvl = 'warning' }
        $notes.Add('位于所有用户可写目录，任何低权限进程都能替换该文件')
    }
    if ($t -match '\\(temp|tmp)\\' -or $t -match '\\windows\\temp\\') {
        $lvl = 'critical'; $notes.Add('位于临时目录 —— 正规软件不会从这里自启动')
    }
    if ($isBinary -and $bad -and $t -match '\\programdata\\') {
        if ($lvl -eq 'normal') { $lvl = 'warning' }
        $notes.Add('ProgramData 默认允许普通用户写入')
    }
    if ($Name -match '^(svchost|rundll32|csrss|lsass|explorer|winlogon|services|taskhost)(\.exe)?$' -and
        $t -notmatch '\\windows\\(system32|syswow64)\\') {
        $lvl = 'critical'; $notes.Add('使用系统进程名但不在 System32 —— 高度可疑')
    }

    # 残留只在没有更严重发现时才作为最终等级；critical / warning 优先级都高于 stale
    if ($stale -and $lvl -eq 'normal') { $lvl = 'stale' }

    if ($notes.Count -eq 0) {
        $notes.Add($(if ($sigUnknown) { '路径正常；签名未经校验' } else { '签名有效，路径正常' }))
    }
    return @{ Level=$lvl; Note=($notes -join '；') }
}

# ── 条目类型 ──────────────────────────────────────────────────────
# 签名校验是刷新耗时的大头，所以分两趟：先不校验把列表铺出来，再后台逐个填。
# 第二趟要在条目已经绑在表格上之后改它的「签名 / 签署者 / 风险」——
# PSCustomObject 不实现 INotifyPropertyChanged，改了界面不会动，只能整表重绑，
# 那会丢掉滚动位置和选中行。所以条目改用一个实现了变更通知的真类型。
# 顺带也解决了原先「程序化改 Sel 后必须重绑 ItemsSource」的老问题。
$script:HasInpc = $false
try {
    Add-Type -TypeDefinition @'
using System.ComponentModel;
public class SmItem : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;
    private void P(string n) { var h = PropertyChanged; if (h != null) h(this, new PropertyChangedEventArgs(n)); }

    // 枚举完就不再变的字段
    public string Name { get; set; }
    public string Command { get; set; }
    public string Target { get; set; }
    public string Arguments { get; set; }
    public string Kind { get; set; }
    public string Scope { get; set; }
    public string Label { get; set; }
    public string Loc { get; set; }
    public bool   Enabled { get; set; }
    public string StateText { get; set; }
    public bool   CanToggle { get; set; }
    public bool   CanEdit { get; set; }
    public bool   CanDelete { get; set; }
    public bool   Exists { get; set; }
    public string ExistState { get; set; }   // yes / no / denied / na，重算风险时要用
    public string ExistText { get; set; }
    public object Extra { get; set; }

    // 界面存活期间会被改动的字段，必须发通知
    private bool _sel;
    public bool Sel { get { return _sel; } set { if (_sel != value) { _sel = value; P("Sel"); } } }

    private string _signer = "";
    public string Signer { get { return _signer; } set { _signer = value; P("Signer"); } }

    private string _sigStatus = "";
    public string SigStatus { get { return _sigStatus; } set { _sigStatus = value; P("SigStatus"); } }

    private string _sigText = "";
    public string SigText { get { return _sigText; } set { _sigText = value; P("SigText"); } }

    private string _risk = "normal";
    public string Risk { get { return _risk; } set { _risk = value; P("Risk"); } }

    private string _riskText = "";
    public string RiskText { get { return _riskText; } set { _riskText = value; P("RiskText"); } }

    private string _riskCell = "";
    public string RiskCell { get { return _riskCell; } set { _riskCell = value; P("RiskCell"); } }

    private int _riskRank = 3;
    public int RiskRank { get { return _riskRank; } set { _riskRank = value; P("RiskRank"); } }

    private string _riskNote = "";
    public string RiskNote { get { return _riskNote; } set { _riskNote = value; P("RiskNote"); } }

    private string _aiVerdict = "";
    public string AiVerdict { get { return _aiVerdict; } set { _aiVerdict = value; P("AiVerdict"); } }

    private object _aiReport;
    public object AiReport { get { return _aiReport; } set { _aiReport = value; P("AiReport"); } }
}
'@ -ReferencedAssemblies @(
        [System.ComponentModel.INotifyPropertyChanged].Assembly.Location,
        [object].Assembly.Location
    )
    $script:HasInpc = $true
} catch {
    # 编译不出来也能跑，只是退回「一趟到底」的旧行为，没有渐进填充
    $script:HasInpc = $false
}

$RISK_TEXT = @{ critical='危险'; warning='关注'; stale='残留'; normal='正常' }
$RISK_RANK = @{ critical=0; warning=1; stale=2; normal=3 }
# 四种风险的行底色在浅色主题下亮度差不到 3%，实际几乎分辨不出，
# 且选中行的背景会把它整个盖掉。加一个字形前缀，让风险不依赖颜色也能读出来。
$RISK_GLYPH = @{ critical='⛔'; warning='⚠'; stale='○'; normal='✓' }

# 签名状态原本直接显示 .NET 的英文枚举（NotSigned / HashMismatch / …），
# 是整个中文界面里唯一的英文，且非技术用户看不懂。
$SIG_TEXT = @{
    'Valid'                  = '有效'
    'NotSigned'              = '无签名'
    'HashMismatch'           = '哈希不符'
    'NotTrusted'             = '不受信任'
    'UnknownError'           = '未知错误'
    'NotSupportedFileFormat' = '不支持的格式'
    'Incompatible'           = '不兼容'
}
function Get-SigText {
    param([string]$Status)
    if ([string]::IsNullOrEmpty($Status)) { return '' }
    if ($SIG_TEXT.ContainsKey($Status)) { return $SIG_TEXT[$Status] }
    return $Status   # 未校验 / — / 校验失败 本来就是中文
}

function New-Item2 {
    param($Name,$Cmd,$Kind,$Scope,$Label,$Loc,$Enabled,$CanToggle,$CanEdit,$CanDelete,$Extra)
    $rt = Resolve-Target $Cmd
    $es = Resolve-ExistState (Expand-Path $rt.Path)
    # Resolve-Target 的非贪婪正则会把「rundll32 evil.dll,Start」整段当成路径
    # （`.*?\.dll` 跨过了空格），解析出的路径当然不存在，于是一个活着的持久化
    # 被判成失效残留。解析结果不存在且含空格时，退回只取第一个词再试一次。
    if ($es.State -eq 'no' -and $rt.Path -match '\s') {
        $first = ($rt.Path -split '\s+')[0]
        if ($first) {
            $es2 = Resolve-ExistState (Expand-Path $first)
            if ($es2.State -ne 'no') {
                $es = $es2
                $rt = @{ Path=$first; Args=$Cmd.Substring([Math]::Min($Cmd.Length, $Cmd.IndexOf($first) + $first.Length)).Trim() }
            }
        }
    }
    $tp = $es.Path                    # 可能已由 PATH 解析成完整路径
    $ex = ($es.State -eq 'yes')
    $sg = if ($es.State -eq 'yes') { Get-Sig $tp } else { @{ Status='—'; Signer='' } }
    $rk = Get-RiskInfo -Target $tp -SigStatus $sg.Status -ExistState $es.State -Name $Name -Kind $Kind -Cmd $Cmd
    $f = [ordered]@{
        Sel        = $false          # 复选框勾选状态（双向绑定）
        Name       = $Name
        Command    = $Cmd
        Target     = $tp
        Arguments  = $rt.Args
        Kind       = $Kind
        Scope      = $Scope
        Label      = $Label
        Loc        = $Loc
        Enabled    = $Enabled
        StateText  = $(if ($Enabled) { '已启用' } else { '已禁用' })
        CanToggle  = $CanToggle
        CanEdit    = $CanEdit
        CanDelete  = $CanDelete
        Signer     = $sg.Signer
        SigStatus  = $sg.Status
        SigText    = (Get-SigText $sg.Status)
        Exists     = $ex
        ExistState = $es.State       # 后台补签名后要用它重算风险
        ExistText  = $(switch ($es.State) { 'yes' { '存在' } 'no' { '文件不存在' } 'denied' { '无权读取（ACL 保护）' } default { '—' } })
        Risk       = $rk.Level
        RiskText   = $RISK_TEXT[$rk.Level]
        RiskCell   = "$($RISK_GLYPH[$rk.Level]) $($RISK_TEXT[$rk.Level])"
        RiskRank   = $RISK_RANK[$rk.Level]
        RiskNote   = $rk.Note
        AiVerdict  = ''              # AI 分析结论（列表里显示摘要）
        AiReport   = $null           # AI 分析全文，供详情面板展开
        Extra      = $Extra
    }
    # 字段清单只写一份：有 SmItem 就用带变更通知的真类型，没有就退回 PSCustomObject
    if ($script:HasInpc) {
        $o = [SmItem]::new()
        foreach ($k in $f.Keys) { $o.$k = $f[$k] }
        return $o
    }
    return [pscustomobject]$f
}

# ══════════════════════════════════════════════════════════════════
#  3. 查 —— 枚举
# ══════════════════════════════════════════════════════════════════
# 进度上报。前台跑时 $global:SM_PROGRESS 不存在，整个函数就是空操作；
# 后台 Runspace 里注入一个 synchronized hashtable，UI 线程的定时器直接读它。
function Set-Progress {
    param([string]$Stage, [int]$Done = -1, [int]$Total = -1)
    $p = $global:SM_PROGRESS
    if ($null -eq $p) { return }
    if ($Stage) { $p['Stage'] = $Stage }
    if ($Done  -ge 0) { $p['Done']  = $Done }
    if ($Total -ge 0) { $p['Total'] = $Total }
}

# UWP / MSIX 的 windows.startupTask 不在传统 Run 键或启动文件夹里。
# Windows 为当前用户记录启动状态的位置通常是：
# HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\<PackageFamilyName>\<TaskId>
# 只枚举存在 State 的已注册任务，避免把所有已安装商店应用都误当成启动项。
function Get-UwpStartupItems {
    param(
        [System.Collections.Generic.List[object]]$Output,
        [System.Collections.Generic.List[string]]$Errors
    )

    $root = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData'
    Set-Progress -Stage '读取 UWP 启动任务' -Done $Output.Count
    if (-not (Test-Path -LiteralPath $root)) { return }

    # Get-AppxPackage 用于把 PackageFamilyName 映射到安装位置；仅读取当前用户注册的包。
    $packages = @{}
    try {
        if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                try { Import-Module Appx -UseWindowsPowerShell -ErrorAction Stop } catch { }
            } else {
                try { Import-Module Appx -ErrorAction Stop } catch { }
            }
        }
        if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
            $Errors.Add('UWP 启动任务：当前 PowerShell 环境无法调用 Get-AppxPackage，已跳过 UWP 扫描。')
            return
        }
        foreach ($pkg in @(Get-AppxPackage -ErrorAction Stop)) {
            if ($pkg.PackageFamilyName) { $packages[[string]$pkg.PackageFamilyName] = $pkg }
        }
    } catch {
        $Errors.Add("UWP 启动任务：读取已安装应用失败：$($_.Exception.Message)")
        return
    }

    # Get-StartApps 提供 Windows 开始菜单中用户看到的本地化名称。
    # 不直接把 40459File-New-Project.EarTrumpet 之类内部包名放进主列表。
    $startNames = @{}
    try {
        if (-not (Get-Command Get-StartApps -ErrorAction SilentlyContinue)) {
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                try { Import-Module StartLayout -UseWindowsPowerShell -ErrorAction Stop } catch { }
            } else {
                try { Import-Module StartLayout -ErrorAction Stop } catch { }
            }
        }
        if (Get-Command Get-StartApps -ErrorAction SilentlyContinue) {
            foreach ($entry in @(Get-StartApps -ErrorAction Stop)) {
                $appId = [string]$entry.AppID
                $display = [string]$entry.Name
                if ($appId -and $display) { $startNames[$appId.ToLowerInvariant()] = $display.Trim() }
            }
        }
    } catch { }

    $explorer = Join-Path ([Environment]::GetFolderPath('Windows')) 'explorer.exe'
    try {
        foreach ($packageKey in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            $pfn = [string]$packageKey.PSChildName
            if (-not $packages.ContainsKey($pfn)) { continue }
            $pkg = $packages[$pfn]
            $taskKeys = @(Get-ChildItem -LiteralPath (Join-Path $root $pfn) -ErrorAction SilentlyContinue)
            if ($taskKeys.Count -eq 0) { continue }

            if (-not $pkg.InstallLocation) {
                $Errors.Add("UWP 启动任务 → $($pkg.Name)：安装位置为空，无法解析启动任务名称。")
                continue
            }
            $manifestPath = Join-Path ([string]$pkg.InstallLocation) 'AppxManifest.xml'
            if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
                $Errors.Add("UWP 启动任务 → $($pkg.Name)：找不到应用清单，无法解析启动任务名称。")
                continue
            }

            # 先用自动识别 BOM 的 StreamReader 检查清单是否真的声明了 windows.startupTask。
            # 某些系统 MSIX（例如 Microsoft.LanguageExperiencePackzh-CN）也会在
            # SystemAppData 下留下状态子键，但它们的清单不是启动任务清单，不应解析、更不应
            # 作为“读取失败”报告。StreamReader 会正确处理 UTF-8 BOM/无 BOM 文件。
            $manifestText = ''
            try {
                $textReader = New-Object System.IO.StreamReader($manifestPath, $true)
                try { $manifestText = $textReader.ReadToEnd() } finally { $textReader.Dispose() }
            } catch {
                $Errors.Add("UWP 启动任务 → $($pkg.Name)：无法读取应用清单文本：$($_.Exception.Message)")
                continue
            }
            if ($manifestText -notmatch '(?i)Category\s*=\s*["'']windows\.startupTask["'']') {
                continue
            }

            # TaskId -> 清单中的 AppId、显示名；清单只对存在运行状态键的包解析一次。
            # XmlReader 按 XML 声明/BOM 识别编码；禁止 DTD/外部实体，避免读取外部资源。
            $taskInfo = @{}
            $manifestReader = $null
            try {
                $xmlSettings = New-Object System.Xml.XmlReaderSettings
                $xmlSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
                $xmlSettings.XmlResolver = $null
                $manifestReader = [System.Xml.XmlReader]::Create($manifestPath, $xmlSettings)
                $manifest = New-Object System.Xml.XmlDocument
                $manifest.XmlResolver = $null
                $manifest.Load($manifestReader)
                $appNodes = $manifest.SelectNodes("/*[local-name()='Package']/*[local-name()='Applications']/*[local-name()='Application']")
                foreach ($appNode in $appNodes) {
                    $appId = [string]$appNode.GetAttribute('Id')
                    $visual = $appNode.SelectSingleNode("./*[local-name()='VisualElements']")
                    $appDisplayName = if ($visual) { [string]$visual.GetAttribute('DisplayName') } else { '' }
                    $fullAppId = if ($pfn -and $appId) { "$pfn!$appId" } else { '' }
                    $startName = if ($fullAppId -and $startNames.ContainsKey($fullAppId.ToLowerInvariant())) { [string]$startNames[$fullAppId.ToLowerInvariant()] } else { '' }

                    $extensions = $appNode.SelectNodes("./*[local-name()='Extensions']/*[local-name()='Extension' and @Category='windows.startupTask']")
                    foreach ($extension in $extensions) {
                        $startupNode = $extension.SelectSingleNode(".//*[local-name()='StartupTask']")
                        if (-not $startupNode) { continue }
                        $taskId = [string]$startupNode.GetAttribute('TaskId')
                        if (-not $taskId) { continue }
                        $taskDisplay = [string]$startupNode.GetAttribute('DisplayName')
                        $taskInfo[$taskId.ToLowerInvariant()] = @{
                            TaskId = $taskId; AppId = $appId; AppName = $startName
                            AppDisplayName = $appDisplayName; TaskDisplayName = $taskDisplay
                        }
                    }
                }
            } catch {
                # 前置检查已确认清单声明了 windows.startupTask；此时解析失败才是真正的
                # 启动任务清单错误，应该显示在窗口中，便于定位问题。
                $Errors.Add("UWP 启动任务 → $($pkg.Name)：读取启动任务清单失败：$($_.Exception.Message)")
                continue
            } finally {
                if ($manifestReader) { $manifestReader.Dispose() }
            }

            foreach ($taskKey in $taskKeys) {
                $taskId = [string]$taskKey.PSChildName
                $infoKey = $taskId.ToLowerInvariant()
                if (-not $taskInfo.ContainsKey($infoKey)) { continue }
                $taskPath = Join-Path (Join-Path $root $pfn) $taskId
                try {
                    $stateData = Get-ItemProperty -LiteralPath $taskPath -Name State -ErrorAction Stop
                    if ($null -eq $stateData.State) { continue }
                    $state = [int]$stateData.State
                    # StartupTaskState：0=Disabled、1=DisabledByUser、2=Enabled、3=DisabledByPolicy；
                    # 某些 Windows 版本/策略实现还会出现 4=EnabledByPolicy。
                    if ($state -notin @(0,1,2,3,4)) { $Errors.Add("UWP 启动任务 → $($pkg.Name)\$taskId：未知状态值 $state。"); continue }
                    $info = $taskInfo[$infoKey]

                    $friendly = [string]$info.AppName
                    if (-not $friendly -or $friendly -match '^(?i:ms-resource:)|^@') {
                        $friendly = [string]$info.TaskDisplayName
                    }
                    if (-not $friendly -or $friendly -match '^(?i:ms-resource:)|^@') {
                        $friendly = [string]$info.AppDisplayName
                    }
                    if (-not $friendly -or $friendly -match '^(?i:ms-resource:)|^@') {
                        $friendly = [string]$pkg.Name
                        # 对常见的数字发布者前缀包名做降噪：40459File-New-Project.EarTrumpet -> EarTrumpet。
                        if ($friendly -match '^\d+[^.]*\.(.+)$') { $friendly = $Matches[1] }
                        $friendly = $friendly -replace '\.', ' '
                    }
                    if ([string]::IsNullOrWhiteSpace($friendly)) { $friendly = $pfn }
                    $friendly = $friendly.Trim()

                    $launchId = if ($info.AppId) { "$pfn!$($info.AppId)" } else { "$pfn!App" }
                    $cmd = '"' + $explorer + '" shell:AppsFolder\' + $launchId
                    # UWP 的状态切换交给 Windows“启动应用”设置；策略控制状态不可直接切换。
                    $canToggle = ($state -notin @(3,4))
                    $extra = @{
                        PackageName = [string]$pkg.Name
                        PackageFamilyName = $pfn
                        PackageFullName = [string]$pkg.PackageFullName
                        ApplicationId = [string]$info.AppId
                        TaskId = $taskId
                        StartupState = $state
                        RegistryPath = $taskPath
                    }
                    $item = New-Item2 -Name $friendly -Cmd $cmd -Kind 'UWP' -Scope '当前用户' `
                        -Label 'UWP / MSIX 启动任务' -Loc $taskPath -Enabled ($state -in @(2,4)) `
                        -CanToggle $canToggle -CanEdit $false -CanDelete $false -Extra $extra
                    $Output.Add($item)
                } catch {
                    $Errors.Add("UWP 启动任务 → $($pkg.Name)\$taskId：$($_.Exception.Message)")
                }
            }
        }
    } catch {
        $Errors.Add("UWP 启动任务：枚举注册状态失败：$($_.Exception.Message)")
    }
}

function Get-AllStartupItems {
    param([bool]$IncludeMsServices = $false)
    $out  = New-Object System.Collections.Generic.List[object]
    $errs = New-Object System.Collections.Generic.List[string]
    Set-Progress -Stage '读取注册表 Run 键' -Done 0 -Total 0

    # try 必须包在每一条上，而不是整个循环外面：$ErrorActionPreference='Stop' 下
    # 任何一条 New-Item2 抛错（Get-Command / Test-Path / 签名校验都可能抛），
    # 循环外的 catch 会让该位置**剩余的全部条目**一起消失，界面看起来完全正常。
    # 对一个用来排查持久化的工具来说这是最坏的失败模式，必须逐条隔离并计数。

    # ── 注册表 Run 系列 ──
    foreach ($L in $RUN_LOCS) {
        try {
            if (-not (Test-Path $L.Reg)) { continue }
            $k = $null
            try {
                $k = Get-Item $L.Reg
                $names = @($k.GetValueNames())
            } finally { if ($k -is [IDisposable]) { $k.Dispose() } }
            foreach ($n in $names) {
                if ([string]::IsNullOrEmpty($n)) { continue }
                try {
                    $kk = Get-Item $L.Reg
                    try { $v = [string]$kk.GetValue($n) } finally { if ($kk -is [IDisposable]) { $kk.Dispose() } }
                    $en = Get-ApprovedState -Hive $L.Ap -Sub $L.ApSub -Name $n
                    $out.Add((New-Item2 -Name $n -Cmd $v -Kind 'Run' -Scope $L.Scope -Label $L.Label `
                        -Loc $L.Reg -Enabled $en -CanToggle ([bool]$L.Ap) -CanEdit $true -CanDelete $true `
                        -Extra @{ Ap=$L.Ap; ApSub=$L.ApSub }))
                } catch { $errs.Add("$($L.Label) → $n : $($_.Exception.Message)") }
            }
        } catch { $errs.Add("$($L.Label) : $($_.Exception.Message)") }
    }

    # ── 启动文件夹 ──
    Set-Progress -Stage '读取启动文件夹' -Done $out.Count
    $shell = New-Object -ComObject WScript.Shell
    try {
        foreach ($L in $FOLDER_LOCS) {
            try {
                if (-not $L.Path -or -not (Test-Path $L.Path)) { continue }
                foreach ($f in Get-ChildItem -LiteralPath $L.Path -File -Force) {
                    try {
                        if ($f.Name -eq 'desktop.ini') { continue }
                        $cmd = $f.FullName
                        if ($f.Extension -ieq '.lnk') {
                            $lnk = $null
                            try {
                                $lnk = $shell.CreateShortcut($f.FullName)
                                $cmd = if ($lnk.Arguments) { "`"$($lnk.TargetPath)`" $($lnk.Arguments)" } else { "`"$($lnk.TargetPath)`"" }
                            } catch {
                                $errs.Add("$($L.Label) → $($f.Name) : 快捷方式解析失败")
                            } finally {
                                if ($lnk) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($lnk) }
                            }
                        }
                        $en = Get-ApprovedState -Hive $L.Ap -Sub 'StartupFolder' -Name $f.Name
                        $out.Add((New-Item2 -Name $f.Name -Cmd $cmd -Kind 'Folder' -Scope $L.Scope -Label $L.Label `
                            -Loc $f.FullName -Enabled $en -CanToggle $true -CanEdit $true -CanDelete $true `
                            -Extra @{ Ap=$L.Ap; ApSub='StartupFolder'; File=$f.FullName; Ext=$f.Extension }))
                    } catch { $errs.Add("$($L.Label) → $($f.Name) : $($_.Exception.Message)") }
                }
            } catch { $errs.Add("$($L.Label) : $($_.Exception.Message)") }
        }
    } finally {
        if ($shell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
    }

    # ── 计划任务（登录 / 开机触发）──
    Set-Progress -Stage '读取计划任务' -Done $out.Count
    try {
        foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
            try {
                $trg = @($t.Triggers | Where-Object { $_.CimClass.CimClassName -match 'Logon|Boot' })
                if ($trg.Count -eq 0) { continue }
                if ($t.TaskPath -like '\Microsoft\Windows\*') { continue }   # 系统任务默认折叠
                $act = @($t.Actions | ForEach-Object {
                    $a = [string]$_.Execute
                    if ($_.Arguments) { "`"$a`" $($_.Arguments)" } else { $a }
                }) -join ' | '
                if (-not $act.Trim()) { $act = '(COM 处理程序)' }
                $kinds = ($trg | ForEach-Object { if ($_.CimClass.CimClassName -match 'Boot') {'开机'} else {'登录'} } | Select-Object -Unique) -join '+'
                $out.Add((New-Item2 -Name $t.TaskName -Cmd $act -Kind 'Task' -Scope $kinds `
                    -Label "计划任务($kinds 触发)" -Loc ($t.TaskPath + $t.TaskName) `
                    -Enabled ($t.State -ne 'Disabled') -CanToggle $true -CanEdit $true -CanDelete $true `
                    -Extra @{ TaskName=$t.TaskName; TaskPath=$t.TaskPath; Desc=$t.Description; Author=$t.Author }))
            } catch { $errs.Add("计划任务 → $($t.TaskName) : $($_.Exception.Message)") }
        }
    } catch { $errs.Add("计划任务 : $($_.Exception.Message)") }

    # ── 服务 ──
    # 只列 StartMode='Auto' 会让「禁用」变成单向死路：改成 Manual 后条目从列表消失，
    # 界面里再也无法重新启用。把本工具管过的服务一并带出来，Enabled 反映真实 StartMode。
    Set-Progress -Stage '读取服务' -Done $out.Count
    try {
        $managed = @(Get-ManagedServices)
        foreach ($s in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
            try {
                $isAuto = ($s.StartMode -eq 'Auto')
                $isMine = ($managed -contains $s.Name)
                if (-not $isAuto -and -not $isMine) { continue }
                $pn = [string]$s.PathName
                if (-not $IncludeMsServices) {
                    $rt = Resolve-Target $pn
                    $tp = (Expand-Path $rt.Path).ToLowerInvariant()
                    if ($tp -match '\\windows\\(system32|syswow64)\\(svchost|lsass|spoolsv|searchindexer|sppsvc)\.exe$') { continue }
                }
                $mode = switch ([string]$s.StartMode) { 'Auto' {'自动'} 'Manual' {'手动'} 'Disabled' {'已禁用'} default { [string]$s.StartMode } }
                $out.Add((New-Item2 -Name $s.Name -Cmd $pn -Kind 'Service' -Scope $s.StartName `
                    -Label "服务($mode·$($s.State))" -Loc "HKLM\SYSTEM\CurrentControlSet\Services\$($s.Name)" `
                    -Enabled $isAuto -CanToggle $true -CanEdit $false -CanDelete $true `
                    -Extra @{ SvcName=$s.Name; Display=$s.DisplayName; State=$s.State; Account=$s.StartName; StartMode=[string]$s.StartMode }))
            } catch { $errs.Add("服务 → $($s.Name) : $($_.Exception.Message)") }
        }
    } catch { $errs.Add("服务 : $($_.Exception.Message)") }

    # ── UWP / MSIX StartupTask ──
    try { Get-UwpStartupItems -Output $out -Errors $errs }
    catch { $errs.Add("UWP 启动任务：$($_.Exception.Message)") }

    Set-Progress -Stage '整理结果' -Done $out.Count
    $script:LoadErrors = @($errs)
    # 注意：这里**不能**写 `return ,$out.ToArray()`。加逗号会让函数只输出一个
    # 「装着数组的对象」，调用方 `@(Get-AllStartupItems) | Where-Object {...}`
    # 拿到的 $_ 就是整个数组，$_.Name 变成全部名称的集合，过滤条件恒真 ——
    # 结果是「找一条」返回全部条目，后续删除/改名会打到别的启动项上。
    # 调用方一律用 @() 包裹来处理单元素情形（Load-Items 已经这么做）。
    return $out.ToArray()
}

# ══════════════════════════════════════════════════════════════════
#  4. 回滚日志
# ══════════════════════════════════════════════════════════════════
# 哪些记录「撤销上一步」真的能还原。计划任务 / 服务的删除、脚本文件的删除、
# 快捷方式的编辑都恢复不了 —— 提前标出来，避免它们占住「上一步」的位置，
# 让真正可撤销的操作被顶掉。
function Test-RecordUndoable {
    param([string]$Action, [string]$Kind, $Extra)
    switch ($Action) {
        'delete' {
            switch ($Kind) {
                'Run'    { return $true }
                'Folder' { return ([string]$Extra.Ext -ieq '.lnk') }
                default  { return $false }
            }
        }
        'edit' { return ($Kind -in @('Run','Task')) }
    }
    return $false
}

function New-JournalRecord {
    param($Item, [string]$Action, [string]$Batch = '', [string]$NewName = '')
    [pscustomobject]@{
        Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Action = $Action
        Batch = $Batch          # 同一次批量操作共用一个批次号，供整批撤销
        Name = $Item.Name; Command = $Item.Command; Kind = $Item.Kind
        Scope = $Item.Scope; Loc = $Item.Loc; Enabled = $Item.Enabled
        NewName = $NewName      # 改名时的新键名，撤销要把它删掉，否则新旧两条同时开机启动
        Undoable = (Test-RecordUndoable -Action $Action -Kind $Item.Kind -Extra $Item.Extra)
        Extra = $Item.Extra
    }
}

# 读取原始日志。解析失败时**不能**当成空数组返回给写入方 ——
# 那会让下一次写入用一条新记录覆盖掉整个历史。这里返回 $null 表示「损坏」，
# 由调用方决定是另存还是中止。
function Read-JournalRaw {
    if (-not (Test-Path $script:Journal)) { return ,@() }
    try {
        $txt = Get-Content $script:Journal -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($txt)) { return ,@() }
        return ,@($txt | ConvertFrom-Json)
    } catch { return $null }
}

function Read-Journal {
    $r = Read-JournalRaw
    if ($null -eq $r) { return ,@() }
    return ,$r
}

$script:JOURNAL_MAX = 2000   # 超出后从最旧的开始丢弃，避免日志无上限增长

# 一次读、一次写。批量删除 50 项原本是 50 次全量 JSON 往返（O(n²)）。
function Write-JournalRecords {
    param([object[]]$Records)
    if (-not $Records -or $Records.Count -eq 0) { return }
    $all = Read-JournalRaw
    if ($null -eq $all) {
        # 日志损坏：另存备份后重新开始，既不覆盖丢失历史，也不阻塞本次操作
        $bak = "$script:Journal.corrupt-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        try { Move-Item -LiteralPath $script:Journal -Destination $bak -Force } catch { }
        $all = @()
        $script:JournalWarning = "回滚日志此前已损坏，已另存为 $bak 并重新开始记录 —— 该时间点之前的操作不再可撤销。"
    }
    $all = @($all) + @($Records)
    if ($all.Count -gt $script:JOURNAL_MAX) { $all = @($all[($all.Count - $script:JOURNAL_MAX)..($all.Count - 1)]) }
    ($all | ConvertTo-Json -Depth 6) | Set-Content $script:Journal -Encoding UTF8
}

function Write-Journal {
    param($Item, [string]$Action, [string]$Batch = '', [string]$NewName = '')
    Write-JournalRecords -Records @((New-JournalRecord -Item $Item -Action $Action -Batch $Batch -NewName $NewName))
}

# 取「上一步」——若末条属于某个批次，则整批一起返回，避免删 9 项要点 9 次撤销
function Get-LastJournalGroup {
    $all = Read-Journal
    if ($all.Count -eq 0) { return @() }
    $last = $all[-1]
    if ([string]::IsNullOrEmpty($last.Batch)) { return @($last) }
    return @($all | Where-Object { $_.Batch -eq $last.Batch })
}

function Pop-JournalGroup {
    param([int]$Count = 1)
    $all = Read-Journal
    if ($all.Count -le $Count) { Remove-Item $script:Journal -Force -ErrorAction SilentlyContinue; return }
    ($all[0..($all.Count - $Count - 1)] | ConvertTo-Json -Depth 6) | Set-Content $script:Journal -Encoding UTF8
}

# ══════════════════════════════════════════════════════════════════
#  5. 增 / 删 / 改
# ══════════════════════════════════════════════════════════════════
function Add-StartupItem {
    # 注意：参数名不可叫 $Args —— 它与 PowerShell 自动变量 $args 冲突，会导致绑定失效。
    param([string]$Kind, [string]$Scope, [string]$Name, [string]$Exe, [string]$Arguments)
    $cmd = if ($Arguments) { "`"$Exe`" $Arguments" } else { "`"$Exe`"" }
    switch ($Kind) {
        'Run' {
            $L = $RUN_LOCS | Where-Object { $_.Scope -eq $Scope } | Select-Object -First 1
            if (-not $L) { throw "未知的注册表位置：$Scope" }
            if (-not (Test-Path $L.Reg)) { New-Item -Path $L.Reg -Force | Out-Null }
            Set-ItemProperty -Path $L.Reg -Name $Name -Value $cmd -Type String -Force
            if ($L.Ap) { Set-ApprovedState -Hive $L.Ap -Sub $L.ApSub -Name $Name -Enabled $true }
        }
        'Folder' {
            $L = $FOLDER_LOCS | Where-Object { $_.Scope -eq $Scope } | Select-Object -First 1
            if (-not $L) { throw "未知的启动文件夹：$Scope" }
            $lnkPath = Join-Path $L.Path "$Name.lnk"
            $sh = New-Object -ComObject WScript.Shell
            $lnk = $sh.CreateShortcut($lnkPath)
            $lnk.TargetPath = $Exe
            if ($Arguments) { $lnk.Arguments = $Arguments }
            $lnk.WorkingDirectory = Split-Path $Exe -Parent
            $lnk.Save()
        }
        'Task' {
            $a = if ($Arguments) { New-ScheduledTaskAction -Execute $Exe -Argument $Arguments }
                 else             { New-ScheduledTaskAction -Execute $Exe }
            $t = New-ScheduledTaskTrigger -AtLogOn
            $p = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
            $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
            Register-ScheduledTask -TaskName $Name -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
        }
        default { throw "不支持新建该类型：$Kind" }
    }
}

function Remove-StartupItem {
    # SkipJournal：批量删除时由调用方一次性预写全部记录（仍在任何破坏性操作之前），
    # 避免每删一项就整文件读写一遍日志。
    param($Item, [string]$Batch = '', [switch]$SkipJournal)
    if (-not $SkipJournal) { Write-Journal -Item $Item -Action 'delete' -Batch $Batch }
    switch ($Item.Kind) {
        'Run' {
            Remove-RegValue -Path $Item.Loc -Name $Item.Name
            $ap = Get-ApprovedKeyPath -Hive $Item.Extra.Ap -Sub $Item.Extra.ApSub
            if ($ap -and (Test-Path $ap)) { Remove-RegValue -Path $ap -Name $Item.Name -Quiet }
        }
        'Folder'  {
            # 送回收站而非直接抹除：回滚日志只能重建 .lnk，脚本文件的内容重建不出来，
            # 回收站是这类文件唯一的第二道防线。
            try {
                Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
                [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile(
                    $Item.Extra.File,
                    [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
                    [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
            } catch {
                Remove-Item -LiteralPath $Item.Extra.File -Force   # 回收站不可用时退回硬删
            }
        }
        'Task'    { Unregister-ScheduledTask -TaskName $Item.Extra.TaskName -TaskPath $Item.Extra.TaskPath -Confirm:$false }
        'Service' {
            if ($Item.Extra.State -eq 'Running') { Stop-Service -Name $Item.Extra.SvcName -Force -ErrorAction SilentlyContinue }
            & "$([Environment]::SystemDirectory)\sc.exe" delete $Item.Extra.SvcName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "sc.exe delete 返回 $LASTEXITCODE（受保护的服务无法删除）" }
            Set-ManagedService -Name $Item.Extra.SvcName -Tracked $false
        }
        'UWP' { throw 'UWP 启动任务由应用程序清单注册，不能单独删除；请使用启用/禁用，或通过 Windows 设置卸载应用。' }
    }
}

function Set-UwpStartupTaskEnabled {
    param($Item, [bool]$Enabled)

    # Windows Task Manager/Startup Settings store UWP StartupTask state at:
    # HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\<PFN>\<TaskId>\State
    # StartupApproved is for classic Run/StartupFolder entries; it is not the state store for UWP StartupTask.
    $pfn = [string]$Item.Extra.PackageFamilyName
    $taskId = [string]$Item.Extra.TaskId
    if ([string]::IsNullOrWhiteSpace($pfn) -or [string]::IsNullOrWhiteSpace($taskId)) {
        throw 'UWP 启动项缺少 PackageFamilyName 或 TaskId，已拒绝修改。'
    }

    $rootSubKey = 'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData'
    $subKey = $rootSubKey + '\' + $pfn + '\' + $taskId
    $baseKey = $null
    $key = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::CurrentUser,
            [Microsoft.Win32.RegistryView]::Default)
        $key = $baseKey.OpenSubKey($subKey, $true)
        if ($null -eq $key) { throw "找不到 UWP 启动状态注册表项：HKCU\$subKey" }
        if (@($key.GetValueNames()) -notcontains 'State') {
            throw "UWP 启动状态项中不存在 State 值：HKCU\$subKey"
        }

        $current = [int]$key.GetValue('State', -1)
        if ($current -in @(3, 4)) {
            throw '此 UWP 启动任务由系统策略管理，不能由当前用户切换。'
        }
        if ($current -notin @(0, 1, 2)) {
            throw "UWP 启动任务状态值异常 ($current)，为避免破坏状态已停止修改。"
        }

        # StartupTaskState: 0=Disabled, 1=DisabledByUser, 2=Enabled,
        # 3=DisabledByPolicy, 4=EnabledByPolicy. Task Manager's user-off state is 1.
        $target = if ($Enabled) { 2 } else { 1 }
        if ($current -ne $target) {
            if (-not $Enabled) {
                # Keep the timestamp value in the same location used by Windows for a user-disabled task.
                $key.SetValue('LastDisabledTime', [long]([DateTime]::UtcNow.ToFileTime()),
                    [Microsoft.Win32.RegistryValueKind]::QWord)
            }
            $key.SetValue('State', [int]$target, [Microsoft.Win32.RegistryValueKind]::DWord)
            $key.Flush()
        }

        $actual = [int]$key.GetValue('State', -1)
        if ($actual -ne $target) {
            throw "UWP 启动状态写入后验证失败：期望 $target，实际 $actual。"
        }
    } finally {
        if ($key) { $key.Dispose() }
        if ($baseKey) { $baseKey.Dispose() }
    }
}

function Set-StartupItemEnabled {
    param($Item, [bool]$Enabled)
    switch ($Item.Kind) {
        'Run'    { if (-not $Item.Extra.Ap) { throw '该位置不支持启用/禁用开关，只能删除' }
                   Set-ApprovedState -Hive $Item.Extra.Ap -Sub $Item.Extra.ApSub -Name $Item.Name -Enabled $Enabled }
        'Folder' { Set-ApprovedState -Hive $Item.Extra.Ap -Sub 'StartupFolder' -Name $Item.Name -Enabled $Enabled }
        'Task'   { if ($Enabled) { Enable-ScheduledTask  -TaskName $Item.Extra.TaskName -TaskPath $Item.Extra.TaskPath | Out-Null }
                   else          { Disable-ScheduledTask -TaskName $Item.Extra.TaskName -TaskPath $Item.Extra.TaskPath | Out-Null } }
        'Service'{ $m = if ($Enabled) { 'Automatic' } else { 'Manual' }
                   Set-Service -Name $Item.Extra.SvcName -StartupType $m
                   # 记住被我们改成手动的服务，否则下次刷新它就从列表里消失了
                   Set-ManagedService -Name $Item.Extra.SvcName -Tracked (-not $Enabled) }
        'UWP' {
            Set-UwpStartupTaskEnabled -Item $Item -Enabled $Enabled
        }
    }
}

function Update-StartupItem {
    param($Item, [string]$NewName, [string]$NewCmd)
    Write-Journal -Item $Item -Action 'edit' -NewName $NewName
    $renamed = ($NewName -ne $Item.Name)

    switch ($Item.Kind) {
        'Run' {
            # 必须在删除旧记录之前读取实时启用状态：
            #   · 不能信任传入对象缓存的 Enabled（「先禁用再编辑」会被悄悄重新启用）
            #   · 也不能在 Remove 之后再读（记录已消失，会退回默认「启用」）
            $live = $true
            if ($Item.Extra.Ap) {
                $live = Get-ApprovedState -Hive $Item.Extra.Ap -Sub $Item.Extra.ApSub -Name $Item.Name
            }
            if ($renamed) {
                Remove-RegValue -Path $Item.Loc -Name $Item.Name
                $ap = Get-ApprovedKeyPath -Hive $Item.Extra.Ap -Sub $Item.Extra.ApSub
                if ($ap -and (Test-Path $ap)) { Remove-RegValue -Path $ap -Name $Item.Name -Quiet }
            }
            Set-ItemProperty -Path $Item.Loc -Name $NewName -Value $NewCmd -Type String -Force
            if ($Item.Extra.Ap) {
                Set-ApprovedState -Hive $Item.Extra.Ap -Sub $Item.Extra.ApSub -Name $NewName -Enabled $live
            }
        }
        'Folder' {
            if ($Item.Extra.Ext -ine '.lnk') {
                throw '仅支持编辑快捷方式(.lnk)。脚本文件请用「定位文件」打开后直接编辑其内容。'
            }
            # StartupApproved\StartupFolder 以「文件名」为键，改名时必须把状态迁移过去
            $live = Get-ApprovedState -Hive $Item.Extra.Ap -Sub 'StartupFolder' -Name $Item.Name

            $rt   = Resolve-Target $NewCmd
            $tgt  = Expand-Path $rt.Path
            $sh   = New-Object -ComObject WScript.Shell
            $lnk  = $sh.CreateShortcut($Item.Extra.File)
            $lnk.TargetPath = $tgt
            $lnk.Arguments  = $rt.Args
            if ($tgt) {
                $parent = Split-Path $tgt -Parent
                if ($parent) { $lnk.WorkingDirectory = $parent }
            }
            $lnk.Save()

            if ($renamed) {
                $leaf = if ($NewName -match '\.lnk$') { $NewName } else { "$NewName.lnk" }
                Rename-Item -LiteralPath $Item.Extra.File -NewName $leaf -Force
                $ap = Get-ApprovedKeyPath -Hive $Item.Extra.Ap -Sub 'StartupFolder'
                if ($ap -and (Test-Path $ap)) { Remove-RegValue -Path $ap -Name $Item.Name -Quiet }
                Set-ApprovedState -Hive $Item.Extra.Ap -Sub 'StartupFolder' -Name $leaf -Enabled $live
            }
        }
        'Task' {
            $tp = [string]$Item.Extra.TaskPath
            if ($tp -like '\Microsoft\Windows\*') { throw '系统计划任务不允许在此修改。' }
            $t = Get-ScheduledTask -TaskName $Item.Extra.TaskName -TaskPath $tp -ErrorAction Stop
            # 多动作任务在这里只能整体替换成一条，会丢掉其余动作 —— 明确拒绝
            if (@($t.Actions).Count -gt 1) {
                throw "该任务有 $(@($t.Actions).Count) 个动作，在此编辑会丢掉其余动作。请用「打开位置」在任务计划程序中修改。"
            }
            $rt  = Resolve-Target $NewCmd
            $exe = Expand-Path $rt.Path
            if (-not $exe) { throw '命令为空。' }
            $act = if ($rt.Args) { New-ScheduledTaskAction -Execute $exe -Argument $rt.Args }
                   else          { New-ScheduledTaskAction -Execute $exe }
            if ($renamed) {
                # 任务名就是标识，改名只能「按同一份定义在新名下重建，再注销旧的」。
                # 顺序不能反：先建后删，中途失败也不会把原任务弄丢。
                Register-ScheduledTask -TaskName $NewName -TaskPath $tp -Action $act `
                    -Trigger $t.Triggers -Principal $t.Principal -Settings $t.Settings -Force | Out-Null
                Unregister-ScheduledTask -TaskName $Item.Extra.TaskName -TaskPath $tp -Confirm:$false
            } else {
                Set-ScheduledTask -TaskName $Item.Extra.TaskName -TaskPath $tp -Action $act | Out-Null
            }
        }
        default { throw "「$($Item.Label)」类型不支持在此编辑。" }
    }
}

function Restore-JournalRecord {
    param($r)
    # 恢复会以管理员身份按记录内容写系统，日志文件本身却是可被篡改的普通文件 ——
    # 先确认目标在本工具管理的位置白名单内。
    Assert-JournalTarget $r
    if ($r.Action -eq 'delete') {
        switch ($r.Kind) {
            'Run' {
                if (-not (Test-Path $r.Loc)) { New-Item -Path $r.Loc -Force | Out-Null }
                Set-ItemProperty -Path $r.Loc -Name $r.Name -Value $r.Command -Type String -Force
                if ($r.Extra.Ap) { Set-ApprovedState -Hive $r.Extra.Ap -Sub $r.Extra.ApSub -Name $r.Name -Enabled ([bool]$r.Enabled) }
            }
            'Folder' {
                if ($r.Extra.Ext -ine '.lnk') {
                    throw "脚本文件的内容无法自动恢复：$($r.Extra.File)（请查回收站）"
                }
                $rt  = Resolve-Target $r.Command
                $tgt = Expand-Path $rt.Path
                $sh  = New-Object -ComObject WScript.Shell
                $lnk = $sh.CreateShortcut($r.Extra.File)
                $lnk.TargetPath = $tgt
                $lnk.Arguments  = $rt.Args
                if ($tgt) { $p = Split-Path $tgt -Parent; if ($p) { $lnk.WorkingDirectory = $p } }
                $lnk.Save()
                Set-ApprovedState -Hive $r.Extra.Ap -Sub 'StartupFolder' -Name $r.Name -Enabled ([bool]$r.Enabled)
            }
            default { throw "计划任务 / 服务的删除无法自动撤销（需手动重建）" }
        }
        return
    }
    if ($r.Action -eq 'edit') {
        if ($r.Kind -eq 'Task') {
            $tp  = [string]$r.Extra.TaskPath
            $new = [string]$r.NewName
            $rt  = Resolve-Target $r.Command
            $exe = Expand-Path $rt.Path
            $act = if ($rt.Args) { New-ScheduledTaskAction -Execute $exe -Argument $rt.Args }
                   else          { New-ScheduledTaskAction -Execute $exe }
            if ($new -and $new -ne [string]$r.Name) {
                # 改过名：拿改名后那个任务的定义，在原名下重建，再把新名注销
                $cur = Get-ScheduledTask -TaskName $new -TaskPath $tp -ErrorAction Stop
                Register-ScheduledTask -TaskName $r.Name -TaskPath $tp -Action $act `
                    -Trigger $cur.Triggers -Principal $cur.Principal -Settings $cur.Settings -Force | Out-Null
                Unregister-ScheduledTask -TaskName $new -TaskPath $tp -Confirm:$false
            } else {
                Set-ScheduledTask -TaskName $r.Name -TaskPath $tp -Action $act | Out-Null
            }
            return
        }
        if ($r.Kind -eq 'Run') {
            if (-not (Test-Path $r.Loc)) { New-Item -Path $r.Loc -Force | Out-Null }
            # 改名的撤销必须先删掉新键，否则新旧两条会同时留在 Run 里一起开机启动
            $new = [string]$r.NewName
            if ($new -and $new -ne [string]$r.Name) {
                Remove-RegValue -Path $r.Loc -Name $new -Quiet
                $apk = Get-ApprovedKeyPath -Hive $r.Extra.Ap -Sub $r.Extra.ApSub
                if ($apk -and (Test-Path $apk)) { Remove-RegValue -Path $apk -Name $new -Quiet }
            }
            Set-ItemProperty -Path $r.Loc -Name $r.Name -Value $r.Command -Type String -Force
            # 删除的撤销会还原启用/禁用状态，编辑的撤销此前漏了这一步
            if ($r.Extra.Ap) { Set-ApprovedState -Hive $r.Extra.Ap -Sub $r.Extra.ApSub -Name $r.Name -Enabled ([bool]$r.Enabled) }
            return
        }
        throw "该类型的编辑无法自动撤销"
    }
    throw "未知的日志动作：$($r.Action)"
}

# 撤销失败 / 本就不可撤销的记录不能随出栈一起丢掉 —— 那是这些条目仅存的备份。
# 单独落到 unrecoverable.json，用户至少还能照着手工重建。
function Save-UnrecoverableRecords {
    param([object[]]$Records)
    if (-not $Records -or $Records.Count -eq 0) { return $null }
    $path = Join-Path $script:AppDir 'unrecoverable.json'
    $all = @()
    if (Test-Path $path) { try { $all = @(Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $all = @() } }
    $all = @($all) + @($Records)
    try { ($all | ConvertTo-Json -Depth 6) | Set-Content $path -Encoding UTF8; return $path } catch { return $null }
}

function Undo-LastAction {
    $grp = Get-LastJournalGroup
    if ($grp.Count -eq 0) { throw '回滚日志为空，没有可撤销的操作' }

    $done = 0
    $errs = New-Object System.Collections.Generic.List[string]
    $lost = New-Object System.Collections.Generic.List[object]
    # 倒序还原：与删除顺序相反，语义上更接近「逐步回退」
    for ($i = $grp.Count - 1; $i -ge 0; $i--) {
        try { Restore-JournalRecord $grp[$i]; $done++ }
        catch {
            $errs.Add("$($grp[$i].Name)：$($_.Exception.Message)")
            $lost.Add($grp[$i])
        }
    }
    # 整批出栈，否则会卡在同一批反复重试；但失败项先存档，不能凭空消失
    $saved = Save-UnrecoverableRecords -Records $lost.ToArray()
    Pop-JournalGroup -Count $grp.Count

    $msg = if ($grp.Count -eq 1 -and $errs.Count -eq 0) { "已撤销：$($grp[0].Name)" }
           else { "已撤销该批次 $($grp.Count) 项中的 $done 项" }
    if ($errs.Count) {
        $msg += "`n`n以下 $($errs.Count) 项无法自动恢复：`n" + ($errs -join "`n")
        if ($saved) { $msg += "`n`n这些条目的原始记录已存档到：`n$saved`n（可照此手工重建）" }
    }
    return $msg
}

# ══════════════════════════════════════════════════════════════════
#  6. 配色（跟随系统主题）
# ══════════════════════════════════════════════════════════════════
$light = 1
try {
    $tv = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -ErrorAction Stop
    if ($null -ne $tv.AppsUseLightTheme) { $light = [int]$tv.AppsUseLightTheme }
} catch { }

if ($light -eq 1) {
    $P = @{ Ground='#F5F5FA'; Surface='#FFFFFF'; Surface2='#FAFAFC'; Surface3='#F0EFF7'
            Ink='#16151F'; Ink2='#3E3C51'; Muted='#5E5B73'; Line='#E3E1EE'; Line2='#CFCCE0'
            Accent='#4A3FBF'; AccentSoft='#EEECFB'; AccentInk='#FFFFFF'
            Crit='#C01A3A'; Warn='#C08400'; Stale='#6A5D9E'; Ok='#00875A'
            CritBg='#FBEBEF'; WarnBg='#FAF3E3'; StaleBg='#F0EEF9'; OkBg='#E4F3EC'; RowAlt='#FAFAFD' }
} else {
    $P = @{ Ground='#0E0D14'; Surface='#191823'; Surface2='#1E1D29'; Surface3='#252334'
            Ink='#E9E8F2'; Ink2='#C2BFD4'; Muted='#918EA8'; Line='#2B2939'; Line2='#3B3850'
            Accent='#8B80F0'; AccentSoft='#221F3A'; AccentInk='#0E0D14'
            Crit='#E05B6B'; Warn='#C98500'; Stale='#7E71B8'; Ok='#199E70'
            CritBg='#2C1620'; WarnBg='#2A2011'; StaleBg='#211E32'; OkBg='#0D231B'; RowAlt='#1C1B27' }
}

# ══════════════════════════════════════════════════════════════════
#  7. XAML 界面
# ══════════════════════════════════════════════════════════════════
$xamlRaw = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="启视 · BootScope" Height="800" Width="1320" MinHeight="600" MinWidth="1000"
        WindowStartupLocation="CenterScreen" Background="@Ground@"
        FontFamily="Microsoft YaHei UI, Segoe UI" FontSize="13">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Background" Value="@Surface@"/>
      <Setter Property="Foreground" Value="@Ink@"/>
      <Setter Property="BorderBrush" Value="@Line2@"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="13,7"/>
      <Setter Property="Margin" Value="0,0,7,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" CornerRadius="6" Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="@Surface3@"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="bd" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="@Accent@"/>
      <Setter Property="Foreground" Value="@AccentInk@"/>
      <Setter Property="BorderBrush" Value="@Accent@"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="Danger" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="@CritBg@"/>
      <Setter Property="Foreground" Value="@Crit@"/>
      <Setter Property="BorderBrush" Value="@Crit@"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="@Surface@"/>
      <Setter Property="Foreground" Value="@Ink@"/>
      <Setter Property="BorderBrush" Value="@Line2@"/>
      <Setter Property="Padding" Value="7,6"/>
      <Setter Property="CaretBrush" Value="@Ink@"/>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Background" Value="@Surface@"/>
      <Setter Property="Foreground" Value="@Ink@"/>
      <Setter Property="BorderBrush" Value="@Line2@"/>
      <Setter Property="Padding" Value="7,5"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="@Ink2@"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="@Surface@"/>
      <Setter Property="Foreground" Value="@Ink@"/>
      <Setter Property="BorderBrush" Value="@Line@"/>
      <Setter Property="RowBackground" Value="@Surface@"/>
      <Setter Property="AlternatingRowBackground" Value="@RowAlt@"/>
      <Setter Property="HorizontalGridLinesBrush" Value="@Line@"/>
      <Setter Property="VerticalGridLinesBrush" Value="Transparent"/>
      <Setter Property="RowHeight" Value="32"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="@Surface3@"/>
      <Setter Property="Foreground" Value="@Muted@"/>
      <Setter Property="BorderBrush" Value="@Line@"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
      <Setter Property="Padding" Value="9,7"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="9,0"/>
      <Setter Property="Foreground" Value="@Ink@"/>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="@AccentSoft@"/>
          <Setter Property="Foreground" Value="@Ink@"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <!-- 表格全部为固定像素列且无 TextTrimming：超长的中文名和命令行是硬裁切，
         既没有省略号也没有 ToolTip，配合详情面板就可能完全看不到全文。 -->
    <!-- 短的定值列（状态/风险/签名/AI 结论）不会被截断，不需要 ToolTip 绑定。
         每格一个绑定看着不起眼，但它是上屏那一帧布局成本的一部分。 -->
    <Style x:Key="CellPlain" TargetType="TextBlock">
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="CellTrim" TargetType="TextBlock" BasedOn="{StaticResource CellPlain}">
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
      <Setter Property="ToolTip" Value="{Binding RelativeSource={RelativeSource Self}, Path=Text}"/>
    </Style>
  </Window.Resources>

  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>   <!-- 0 标题 -->
      <RowDefinition Height="Auto"/>   <!-- 1 统计 -->
      <RowDefinition Height="Auto"/>   <!-- 2 筛选 -->
      <RowDefinition Height="Auto"/>   <!-- 3 勾选栏 -->
      <RowDefinition Height="*"/>      <!-- 4 主表 -->
      <RowDefinition Height="Auto"/>   <!-- 5 详情 -->
      <RowDefinition Height="Auto"/>   <!-- 6 操作栏 -->
    </Grid.RowDefinitions>

    <!-- 标题栏 -->
    <Grid Grid.Row="0" Margin="0,0,0,12">
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="启视" FontSize="23" FontWeight="Bold" Foreground="@Ink@" VerticalAlignment="Center"/>
        <TextBlock Text="BootScope" FontSize="12" Foreground="@Muted@" Margin="8,0,0,3" VerticalAlignment="Bottom"/>
        <Border Background="@OkBg@" BorderBrush="@Ok@" BorderThickness="1" CornerRadius="4" Padding="7,2" Margin="12,0,0,0" VerticalAlignment="Center">
          <TextBlock Text="管理员" FontSize="11" FontWeight="SemiBold" Foreground="@Ok@"/>
        </Border>
        <TextBlock x:Name="lblHost" FontSize="12" Foreground="@Muted@" Margin="12,0,0,0" VerticalAlignment="Center"/>
        <TextBlock x:Name="lblBusy" FontSize="12.5" FontWeight="SemiBold" Foreground="@Accent@" Margin="14,0,0,0" VerticalAlignment="Center"/>
      </StackPanel>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <CheckBox x:Name="chkSig" Content="校验数字签名" IsChecked="True" Margin="0,0,14,0"
                  ToolTip="关闭可显著加快刷新（跳过 Authenticode 校验与可能的 CRL 联网）"/>
        <CheckBox x:Name="chkMs" Content="含系统托管服务" Margin="0,0,14,0"
                  ToolTip="勾选后一并列出 svchost / lsass / spoolsv / SearchIndexer / sppsvc 承载的服务"/>
        <Button x:Name="btnRefresh" Content="刷新 (F5)" Style="{StaticResource Primary}"/>
      </StackPanel>
    </Grid>

    <!-- 统计条 -->
    <Border Grid.Row="1" Background="@Surface@" BorderBrush="@Line@" BorderThickness="1" CornerRadius="8" Padding="14,11" Margin="0,0,0,10">
      <StackPanel>
        <StackPanel Orientation="Horizontal" x:Name="panStats"/>
        <!-- 枚举失败过去是裸 catch 静默吞掉的，列表看起来完整但其实缺了东西 -->
        <TextBlock x:Name="lblWarn" FontSize="12" Foreground="@Warn@" TextWrapping="Wrap"
                   Margin="0,9,0,0" Visibility="Collapsed" Cursor="Hand"/>
      </StackPanel>
    </Border>

    <!-- 筛选栏 -->
    <Grid Grid.Row="2" Margin="0,0,0,10">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="txtSearch" Grid.Column="0" Margin="0,0,8,0" ToolTip="搜索名称 / 命令 / 路径 / 签署者"/>
      <ComboBox x:Name="cboKind"  Grid.Column="1" Width="150" Margin="0,0,8,0"/>
      <ComboBox x:Name="cboRisk"  Grid.Column="2" Width="120" Margin="0,0,8,0"/>
      <ComboBox x:Name="cboState" Grid.Column="3" Width="120"/>
    </Grid>

    <!-- 勾选栏 -->
    <Border Grid.Row="3" Background="@Surface3@" BorderBrush="@Line@" BorderThickness="1" CornerRadius="7" Padding="11,7" Margin="0,0,0,8">
      <Grid>
        <StackPanel Orientation="Horizontal">
          <TextBlock Text="批量勾选" Foreground="@Muted@" FontSize="12" VerticalAlignment="Center" Margin="0,0,10,0"/>
          <Button x:Name="btnSelAll"  Content="全选筛选结果" Padding="10,4" FontSize="12"/>
          <Button x:Name="btnSelNone" Content="清空"         Padding="10,4" FontSize="12"/>
          <Button x:Name="btnSelInv"  Content="反选"         Padding="10,4" FontSize="12"/>
          <Border Width="1" Background="@Line2@" Margin="6,2,12,2"/>
          <TextBlock Text="快捷：" Foreground="@Muted@" FontSize="12" VerticalAlignment="Center" Margin="0,0,7,0"/>
          <Button x:Name="btnSelStale" Content="所有残留项"   Padding="10,4" FontSize="12"/>
          <Button x:Name="btnSelRisk"  Content="危险 + 关注"  Padding="10,4" FontSize="12"/>
        </StackPanel>
        <TextBlock x:Name="lblSel" HorizontalAlignment="Right" VerticalAlignment="Center"
                   FontSize="12.5" FontWeight="SemiBold" Foreground="@Accent@"/>
      </Grid>
    </Border>

    <!-- 主表 -->
    <!-- 行虚拟化：51 条只实例化 13 行，是上屏那一帧的关键。
         列虚拟化反而要关：只有 8 列，它的簿记开销比省下来的多
         —— 实测开启时重绑 + 布局 478ms，关闭后 212ms。 -->
    <DataGrid Grid.Row="4" x:Name="grid" AutoGenerateColumns="False" IsReadOnly="True"
              CanUserAddRows="False" CanUserResizeRows="False" SelectionMode="Extended"
              GridLinesVisibility="Horizontal" HeadersVisibility="Column"
              ScrollViewer.HorizontalScrollBarVisibility="Auto"
              ScrollViewer.CanContentScroll="True"
              EnableRowVirtualization="True" EnableColumnVirtualization="False"
              VirtualizingPanel.IsVirtualizing="True"
              VirtualizingPanel.VirtualizationMode="Recycling">
      <DataGrid.Columns>
        <DataGridTemplateColumn Header="勾选" Width="52" CanUserSort="False" SortMemberPath="Sel">
          <DataGridTemplateColumn.CellTemplate>
            <DataTemplate>
              <CheckBox IsChecked="{Binding Sel, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"
                        HorizontalAlignment="Center" VerticalAlignment="Center"
                        ToolTip="勾选后，删除 / 启用禁用 将作用于所有勾选项"/>
            </DataTemplate>
          </DataGridTemplateColumn.CellTemplate>
        </DataGridTemplateColumn>
        <DataGridTextColumn Header="状态"   Binding="{Binding StateText}" Width="62"  SortMemberPath="StateText" ElementStyle="{StaticResource CellPlain}"/>
        <DataGridTextColumn Header="风险"   Binding="{Binding RiskCell}"  Width="72"  SortMemberPath="RiskRank"  ElementStyle="{StaticResource CellPlain}"/>
        <DataGridTextColumn Header="名称"   Binding="{Binding Name}"      Width="200" MinWidth="120" ElementStyle="{StaticResource CellTrim}"/>
        <DataGridTextColumn Header="类型"   Binding="{Binding Label}"     Width="150" MinWidth="90"  ElementStyle="{StaticResource CellTrim}"/>
        <DataGridTextColumn Header="命令"   Binding="{Binding Command}"   Width="*"   MinWidth="200" FontFamily="Consolas" ElementStyle="{StaticResource CellTrim}"/>
        <DataGridTextColumn Header="AI 结论" Binding="{Binding AiVerdict}" Width="120" MinWidth="70" ElementStyle="{StaticResource CellPlain}"/>
        <DataGridTextColumn Header="签署者" Binding="{Binding Signer}"    Width="150" MinWidth="80"  ElementStyle="{StaticResource CellTrim}"/>
        <DataGridTextColumn Header="签名"   Binding="{Binding SigText}"   Width="84"  SortMemberPath="SigStatus" ElementStyle="{StaticResource CellPlain}"/>
      </DataGrid.Columns>
      <DataGrid.RowStyle>
        <Style TargetType="DataGridRow">
          <Setter Property="Foreground" Value="@Ink@"/>
          <Style.Triggers>
            <DataTrigger Binding="{Binding Risk}" Value="critical"><Setter Property="Background" Value="@CritBg@"/></DataTrigger>
            <DataTrigger Binding="{Binding Risk}" Value="warning"><Setter Property="Background" Value="@WarnBg@"/></DataTrigger>
            <DataTrigger Binding="{Binding Risk}" Value="stale"><Setter Property="Background" Value="@StaleBg@"/></DataTrigger>
            <DataTrigger Binding="{Binding Enabled}" Value="False"><Setter Property="Opacity" Value="0.55"/></DataTrigger>
          </Style.Triggers>
        </Style>
      </DataGrid.RowStyle>
    </DataGrid>

    <!-- 详情 -->
    <Border Grid.Row="5" Background="@Surface2@" BorderBrush="@Line@" BorderThickness="1" CornerRadius="8" Padding="14,11" Margin="0,10,0,10">
      <ScrollViewer MaxHeight="132" VerticalScrollBarVisibility="Auto">
        <StackPanel x:Name="panDetail">
          <TextBlock Text="选中一行查看详情" Foreground="@Muted@"/>
        </StackPanel>
      </ScrollViewer>
    </Border>

    <!-- 操作栏 -->
    <Grid Grid.Row="6">
      <StackPanel Orientation="Horizontal">
        <Button x:Name="btnNew"    Content="新建"      Style="{StaticResource Primary}"/>
        <Button x:Name="btnEdit"   Content="编辑"/>
        <Button x:Name="btnToggle" Content="启用 / 禁用"/>
        <Button x:Name="btnDel"    Content="删除"      Style="{StaticResource Danger}"/>
        <Separator Width="12" Background="Transparent"/>
        <Button x:Name="btnLocate" Content="定位文件"/>
        <Button x:Name="btnReg"    Content="打开位置"/>
        <Separator Width="12" Background="Transparent"/>
        <Button x:Name="btnAi"     Content="AI 分析" Style="{StaticResource Primary}"
                ToolTip="把选中条目的元数据发送给 AI 进行研判（需先配置 API Key）"/>
        <ComboBox x:Name="cboAi" Width="148" Margin="0,0,7,0" Padding="7,4" DisplayMemberPath="Name"
                  Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" VerticalAlignment="Center"/>
        <Button x:Name="btnAiCfg"  Content="⚙" Padding="9,7" ToolTip="AI 设置：多套配置、自定义地址、获取模型"/>
      </StackPanel>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="btnUndo"   Content="撤销上一步"/>
        <Button x:Name="btnExport" Content="导出快照"/>
      </StackPanel>
    </Grid>
  </Grid>
</Window>
'@

$xaml = $xamlRaw
foreach ($k in $P.Keys) { $xaml = $xaml.Replace("@$k@", $P[$k]) }

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$win = [Windows.Markup.XamlReader]::Load($reader)

$UI = @{}
foreach ($n in 'lblHost','lblBusy','lblWarn','chkSig','chkMs','btnRefresh','panStats','txtSearch','cboKind','cboRisk','cboState',
                'grid','panDetail','btnNew','btnEdit','btnToggle','btnDel','btnLocate','btnReg','btnUndo','btnExport',
                'btnAi','btnAiCfg','cboAi','btnSelAll','btnSelNone','btnSelInv','btnSelStale','btnSelRisk','lblSel') {
    $UI[$n] = $win.FindName($n)
}

# 800×1320 是 DIP：1920×1080 @150% 缩放的工作区只有 1280×~690 DIP，
# 窗口会比屏幕还大。按实际工作区钳一下。
$wa = [System.Windows.SystemParameters]::WorkArea
if ($win.Width  -gt $wa.Width)  { $win.Width  = [Math]::Max(900, $wa.Width  - 60) }
if ($win.Height -gt $wa.Height) { $win.Height = [Math]::Max(560, $wa.Height - 60) }
if ($win.MinWidth  -gt $wa.Width)  { $win.MinWidth  = $wa.Width  - 20 }
if ($win.MinHeight -gt $wa.Height) { $win.MinHeight = $wa.Height - 20 }

# 带上脚本文件的修改时间。改了代码但忘了重开窗口时，一眼就能看出跑的是旧实例
# —— 代码早在启动时就加载进内存了，改文件对已经跑着的进程没有任何影响。
$script:BuildStamp = try {
    $sp = $PSCommandPath; if (-not $sp) { $sp = $MyInvocation.MyCommand.Path }
    (Get-Item -LiteralPath $sp).LastWriteTime.ToString('MM-dd HH:mm')
} catch { '?' }
$UI.lblHost.Text = "$env:COMPUTERNAME \ $env:USERNAME   ·   构建 $script:BuildStamp"
$UI.lblHost.ToolTip = "主程序文件的修改时间。`n若你刚改过代码但这里还是旧时间，说明当前跑的是改动前启动的实例，关掉重开即可。"
$UI.cboKind.ItemsSource  = @('全部类型','注册表 Run','启动文件夹','计划任务','服务','UWP 启动任务')
$UI.cboRisk.ItemsSource  = @('全部风险','危险','关注','残留','正常')
$UI.cboState.ItemsSource = @('全部状态','已启用','已禁用')
$UI.cboKind.SelectedIndex = 0; $UI.cboRisk.SelectedIndex = 0; $UI.cboState.SelectedIndex = 0

# ══════════════════════════════════════════════════════════════════
#  8. 界面逻辑
# ══════════════════════════════════════════════════════════════════
function Show-Msg {
    param([string]$Text, [string]$Title = '启视', [string]$Icon = 'Information')
    [System.Windows.MessageBox]::Show($Text, $Title, 'OK', $Icon) | Out-Null
}
function Confirm-Msg {
    param([string]$Text, [string]$Title = '请确认')
    ([System.Windows.MessageBox]::Show($Text, $Title, 'YesNo', 'Warning')) -eq 'Yes'
}

# MessageBox 不能滚动。批量操作的失败清单原本是整段无上限塞进去的，
# 几十项时后面的内容直接看不到 —— 截断并注明还剩多少。
function Format-ErrList {
    param($Errors, [int]$Max = 12)
    $a = @($Errors)
    if ($a.Count -eq 0) { return '' }
    $t = ($a | Select-Object -First $Max) -join "`n"
    if ($a.Count -gt $Max) { $t += "`n… 以及另外 $($a.Count - $Max) 项（完整清单见回滚日志目录）" }
    return $t
}

function Add-Stat {
    param([string]$Label, [string]$Value, [string]$Color)
    $sp = New-Object Windows.Controls.StackPanel
    $sp.Margin = '0,0,26,0'
    $t1 = New-Object Windows.Controls.TextBlock
    $t1.Text = $Label; $t1.FontSize = 11
    $t1.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($P.Muted)
    $t2 = New-Object Windows.Controls.TextBlock
    $t2.Text = $Value; $t2.FontSize = 20; $t2.FontWeight = 'Bold'
    $t2.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($Color)
    $sp.AddChild($t1); $sp.AddChild($t2)
    $UI.panStats.AddChild($sp)
}

function Update-Stats {
    $UI.panStats.Children.Clear()
    $all = $script:Items
    Add-Stat '条目总数'  ([string]$all.Count)                                          $P.Ink
    Add-Stat '开机生效'  ([string](@($all | Where-Object Enabled).Count))              $P.Accent
    Add-Stat '已禁用'    ([string](@($all | Where-Object { -not $_.Enabled }).Count))  $P.Muted
    Add-Stat '危险'      ([string](@($all | Where-Object Risk -eq 'critical').Count))  $P.Crit
    Add-Stat '关注'      ([string](@($all | Where-Object Risk -eq 'warning').Count))   $P.Warn
    Add-Stat '残留'      ([string](@($all | Where-Object Risk -eq 'stale').Count))     $P.Stale
    Add-Stat '正常'      ([string](@($all | Where-Object Risk -eq 'normal').Count))    $P.Ok
}

function Apply-Filter {
    # 重排会替换 ItemsSource，默认会清空高亮行。签名补填结束后要重新按风险排序，
    # 那时用户很可能正选着某一行，所以按对象身份把选中项还原回去。
    $keepSel = @($UI.grid.SelectedItems)
    $q  = $UI.txtSearch.Text
    $kd = [string]$UI.cboKind.SelectedItem
    $rk = [string]$UI.cboRisk.SelectedItem
    $st = [string]$UI.cboState.SelectedItem
    $v = $script:Items
    if ($kd -and $kd -ne '全部类型') {
        $map = @{ '注册表 Run'='Run'; '启动文件夹'='Folder'; '计划任务'='Task'; '服务'='Service'; 'UWP 启动任务'='UWP' }
        $v = @($v | Where-Object { $_.Kind -eq $map[$kd] })
    }
    if ($rk -and $rk -ne '全部风险') { $v = @($v | Where-Object { $_.RiskText -eq $rk }) }
    if ($st -and $st -ne '全部状态') { $v = @($v | Where-Object { $_.StateText -eq $st }) }
    if ($q) {
        $ql = $q.ToLower()
        $v = @($v | Where-Object {
            "$($_.Name) $($_.Command) $($_.Target) $($_.Signer) $($_.Label) $($_.Loc)".ToLower().Contains($ql)
        })
    }
    $script:View = @($v | Sort-Object RiskRank, @{E={-[int]$_.Enabled}}, Kind, Name)
    $UI.grid.ItemsSource = $script:View
    if ($keepSel.Count -gt 0) {
        $set = New-Object 'System.Collections.Generic.HashSet[object]'
        foreach ($x in $keepSel) { [void]$set.Add($x) }
        foreach ($v2 in $script:View) { if ($set.Contains($v2)) { [void]$UI.grid.SelectedItems.Add($v2) } }
    }
    Update-SelCount
}

# ── 批量勾选 ──────────────────────────────────────────────────────
# SmItem 实现了 INotifyPropertyChanged，改 Sel 会自动刷新复选框，不必重绑。
# 只有退回 PSCustomObject 的降级路径才需要那套「置 null 再赋值」的老办法
# —— 它会顺带清掉高亮行和滚动位置，能不用就不用。
function Refresh-Grid {
    if ($script:HasInpc) { return }
    $UI.grid.ItemsSource = $null
    $UI.grid.ItemsSource = $script:View
}

function Get-Checked { @($script:Items | Where-Object { $_.Sel }) }

# 操作目标：优先用勾选项；没有勾选时退回到高亮行（Ctrl/Shift 点选依然可用）
function Get-TargetItems {
    $c = Get-Checked
    if ($c.Count -gt 0) { return $c }
    return @($UI.grid.SelectedItems)
}

function Update-SelCount {
    $n = (Get-Checked).Count
    $v = @($script:View).Count
    $t = $script:Items.Count
    $UI.lblSel.Text = if ($n -gt 0) { "已勾选 $n 项  ·  当前筛选 $v / $t" } else { "当前筛选 $v / $t 项" }
}

function Set-ViewSelection { param([bool]$On)
    foreach ($i in $script:View) { $i.Sel = $On }
    Refresh-Grid; Update-SelCount
}

function Invert-ViewSelection {
    foreach ($i in $script:View) { $i.Sel = -not $i.Sel }
    Refresh-Grid; Update-SelCount
}

# 按条件跨筛选勾选：先清空全部，再勾中命中项，并把筛选重置为「全部」以便一眼看全
function Select-ByPredicate { param([scriptblock]$Pred, [string]$What)
    foreach ($i in $script:Items) { $i.Sel = $false }
    $hit = @($script:Items | Where-Object $Pred)
    foreach ($i in $hit) { $i.Sel = $true }
    $UI.cboKind.SelectedIndex = 0; $UI.cboRisk.SelectedIndex = 0; $UI.cboState.SelectedIndex = 0
    $UI.txtSearch.Text = ''
    Apply-Filter
    if ($hit.Count -eq 0) { Show-Msg "没有找到$What。" '无匹配' 'Information' }
}

# ── 后台执行器 ──────────────────────────────────────────────────
# 枚举（逐文件 Authenticode + Get-ScheduledTask + Win32_Service）和 AI 请求
# 都是秒级到十几秒的活。放在 UI 线程上窗口就是「未响应」。这里统一丢进独立
# Runspace，用 DispatcherTimer 轮询完成状态并回到 UI 线程交付结果。
#
# 不用 Start-Job：那是独立进程 + 序列化，几十个对象来回一趟比干活还慢，
# 而且 PSCustomObject 会被反序列化成死数据，丢掉方法与类型。
# 同进程 Runspace 传的是活对象引用，零拷贝。

$script:BgJobs = New-Object System.Collections.Generic.List[object]

# 注意：DispatcherTimer 的回调必须用 GetNewClosure() 才能捕获 $keep / $cfg / $prog
# 这些自由变量。但闭包有个陷阱 —— 闭包里**读** $script:X 正常，**写** $script:X
# 却写进闭包自己的模块作用域，外面根本看不到。所以「是否正在加载」这类要跨回调
# 传递的状态一律放进这个哈希表：改哈希表条目是「读变量 + 索引赋值」，闭包里有效。
$script:Flags = @{ LoadRunning = $false; AiRunning = $false; SigDone = $true }

# 直接从已加载的函数取源码，避免在后台脚本里重复维护一份逻辑
function Get-FunctionSource {
    param([string[]]$Names)
    ($Names | ForEach-Object {
        $c = Get-Command $_ -CommandType Function -ErrorAction Stop
        "function $($c.Name) {`r`n$($c.Definition)`r`n}"
    }) -join "`r`n"
}

function Start-BgWork {
    param(
        [string]$Body,                 # 在后台运行的脚本文本
        [string[]]$Functions = @(),    # 需要一并带过去的函数名
        [hashtable]$Vars = @{},        # 注入后台的变量
        [scriptblock]$OnDone,          # UI 线程回调：接收 (结果, 错误文本)
        [scriptblock]$OnTick           # UI 线程回调：轮询期间刷新进度，可选
    )
    # WScript.Shell 解析 .lnk 需要 STA
    $rs = [runspacefactory]::CreateRunspace([initialsessionstate]::CreateDefault())
    $rs.ApartmentState = 'STA'
    $rs.ThreadOptions  = 'ReuseThread'
    $rs.Open()
    foreach ($k in $Vars.Keys) { $rs.SessionStateProxy.SetVariable($k, $Vars[$k]) }

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $src = (Get-FunctionSource $Functions) + "`r`n" + $Body
    [void]$ps.AddScript($src)
    $handle = $ps.BeginInvoke()

    $timer = New-Object Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(120)
    $job = [pscustomobject]@{
        PS = $ps; RS = $rs; Handle = $handle; Timer = $timer
        OnDone = $OnDone; OnTick = $OnTick; Done = $false
    }
    $script:BgJobs.Add($job)

    # 回调必须是闭包才能捕获 $job；但闭包里**不要**直接动 $script: 集合 ——
    # 交给下面这个普通函数去收尾，函数的 $script: 语义才是我们要的。
    $timer.Add_Tick({
        try {
            if ($job.OnTick) { try { & $job.OnTick } catch { } }
            if (-not $job.Handle.IsCompleted) { return }
            $job.Timer.Stop()
            if ($job.Done) { return }
            $job.Done = $true

            $out = $null; $err = $null
            try { $out = $job.PS.EndInvoke($job.Handle) }
            catch { $err = $_.Exception.Message }
            if (-not $err) {
                try {
                    if ($job.PS.HadErrors -and $job.PS.Streams.Error.Count) {
                        $err = (@($job.PS.Streams.Error) | ForEach-Object { $_.ToString() }) -join "`n"
                    }
                } catch { }
            }
            Unregister-BgJob $job
            & $job.OnDone $out $err
        } catch {
            # 兜底：这里再挂就没人接了，静默失败会表现成「一直转圈不出结果」
            try { Unregister-BgJob $job } catch { }
            try { Show-Msg "后台任务收尾失败：`n$($_.Exception.Message)" '错误' 'Error' } catch { }
        }
    }.GetNewClosure())
    $timer.Start()
    return $job
}

# 闭包里对 $script: 变量的**写入**会落进闭包自己的模块作用域，外面看不到。
# 所以所有「回到空闲状态」的动作都收敛成普通函数，由闭包调用。
function Set-LoadIdle {
    $script:Flags['LoadRunning'] = $false
    Set-LoadLock $false
    Set-Busy ''
}
function Set-AiIdle {
    $script:Flags['AiRunning'] = $false
    Set-LoadLock $false
    Set-Busy ''
}

# 释放资源并把任务移出登记表。必须是普通函数：闭包里对 $script: 集合的操作不可靠。
function Unregister-BgJob {
    param($Job)
    if ($null -eq $Job) { return }
    try { $Job.Timer.Stop() } catch { }
    try { $Job.PS.Dispose() } catch { }
    try { $Job.RS.Dispose() } catch { }
    for ($i = $script:BgJobs.Count - 1; $i -ge 0; $i--) {
        if ([object]::ReferenceEquals($script:BgJobs[$i], $Job)) { $script:BgJobs.RemoveAt($i) }
    }
}

# 窗口关掉时把还在跑的后台任务清干净，否则 Runspace 线程会吊住进程不退出
function Stop-AllBgWork {
    try { if ($script:SigTimer) { $script:SigTimer.Stop() } } catch { }
    try {
        if ($null -eq $script:BgJobs) { return }
        $snapshot = @()
        try { $snapshot = $script:BgJobs.ToArray() } catch { return }
        foreach ($j in $snapshot) {
            if ($null -eq $j) { continue }
            try { $j.Timer.Stop() } catch { }
            try { $j.PS.Stop() }    catch { }
            try { $j.PS.Dispose() } catch { }
            try { $j.RS.Dispose() } catch { }
        }
        try { $script:BgJobs.Clear() } catch { }
    } catch { }
}

# 兜底用：极少数需要在同步流程里让界面喘口气的地方
function Sync-UI {
    $frame = New-Object Windows.Threading.DispatcherFrame
    $win.Dispatcher.BeginInvoke(
        [Windows.Threading.DispatcherPriority]::Background,
        [Windows.Threading.DispatcherOperationCallback]{ param($f) $f.Continue = $false; $null },
        $frame) | Out-Null
    [Windows.Threading.Dispatcher]::PushFrame($frame)
}

# 不再泵 Dispatcher：重活已经在后台 Runspace 里，UI 线程本来就是空闲的，
# 在事件处理器里 PushFrame 反而会引入重入。
function Set-Busy {
    param([string]$Text)
    $UI.lblBusy.Text = $Text
    $win.Cursor = if ($Text) { 'Wait' } else { 'Arrow' }
}

function Show-LoadWarnings {
    $msgs = New-Object System.Collections.Generic.List[string]
    if ($script:JournalWarning) { $msgs.Add($script:JournalWarning); $script:JournalWarning = $null }
    $n = @($script:LoadErrors).Count
    if ($n -gt 0) { $msgs.Add("有 $n 处启动位置未能读取，列表可能不完整 —— 点此查看详情。") }
    if ($msgs.Count) {
        $UI.lblWarn.Text = ($msgs -join '  ')
        $UI.lblWarn.Visibility = 'Visible'
    } else {
        $UI.lblWarn.Visibility = 'Collapsed'
    }
}

# 枚举期间要禁掉的控件：列表还没到位，这些操作没有意义
$script:LOAD_LOCK = @('btnRefresh','chkSig','chkMs','btnNew','btnEdit','btnToggle','btnDel',
                      'btnLocate','btnReg','btnAi','btnUndo','btnExport',
                      'btnSelAll','btnSelNone','btnSelInv','btnSelStale','btnSelRisk')
function Set-LoadLock {
    param([bool]$Busy)
    foreach ($n in $script:LOAD_LOCK) { if ($UI[$n]) { $UI[$n].IsEnabled = -not $Busy } }
}

# 后台枚举完成后回到 UI 线程做的收尾。前台同步路径也走这里，两条路只有取数方式不同。
function Complete-ItemLoad {
    param($NewItems, $Errors, $Keep, $Ai)
    $script:Items = @($NewItems)
    $script:LoadErrors = @($Errors)
    foreach ($i in $script:Items) {
        $k = "$($i.Kind)|$($i.Loc)|$($i.Name)"
        if ($Keep -and $Keep.ContainsKey($k)) { $i.Sel = $true }
        if ($Ai   -and $Ai.ContainsKey($k))   { $i.AiVerdict = $Ai[$k].AiVerdict; $i.AiReport = $Ai[$k].AiReport }
    }
    Update-Stats
    Apply-Filter
    Show-LoadWarnings
    Show-Detail
}

# ── 第二趟：后台逐个补签名 ────────────────────────────────────────
# 后台只算不改：结果丢进并发队列，由 UI 线程取出后写回条目。
# 绝不能让后台线程直接改已经绑在表格上的对象 —— 那会触发跨线程更新异常。
$script:SigQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
$script:SigMap   = @{}
$script:SigProg  = $null
$script:SigJob   = $null

$script:SIG_BODY = @'
$ErrorActionPreference = 'Stop'
foreach ($p in $SM_Paths) {
    $st = '—'; $sn = ''
    try {
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
            $st = [string]$s.Status
            if ($s.SignerCertificate) {
                $cn = $s.SignerCertificate.Subject -replace '^CN=("?)([^",]+)\1.*', '$2'
                $sn = $cn.Trim()
            }
        }
    } catch { $st = '校验失败' }
    $SM_QUEUE.Enqueue([pscustomobject]@{ Path = $p; Status = $st; Signer = $sn })
    $SM_PROGRESS['Done'] = [int]$SM_PROGRESS['Done'] + 1
}
'@

# 签名到位后风险等级可能变（无签名的 AppData 可执行文件会从「正常」升到「危险」），
# 所以要连风险一起重算。这些属性都带变更通知，赋值即刷新对应单元格与整行底色。
function Update-ItemSignature {
    param($Item, [string]$Status, [string]$Signer)
    $Item.SigStatus = $Status
    $Item.SigText   = Get-SigText $Status
    $Item.Signer    = $Signer
    $rk = Get-RiskInfo -Target $Item.Target -SigStatus $Status -ExistState $Item.ExistState `
                       -Name $Item.Name -Kind $Item.Kind -Cmd $Item.Command
    $Item.Risk     = $rk.Level
    $Item.RiskText = $RISK_TEXT[$rk.Level]
    $Item.RiskCell = "$($RISK_GLYPH[$rk.Level]) $($RISK_TEXT[$rk.Level])"
    $Item.RiskRank = $RISK_RANK[$rk.Level]
    $Item.RiskNote = $rk.Note
}

function Stop-SigPass {
    $script:Flags['SigDone'] = $true
    if ($script:SigTimer) { try { $script:SigTimer.Stop() } catch { } }
    if ($script:SigJob) { Unregister-BgJob $script:SigJob; $script:SigJob = $null }
    $script:SigQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    $script:SigMap   = @{}
    $script:SigProg  = $null
}

function Start-SigPass {
    Stop-SigPass
    if (-not $script:HasInpc) { return }   # 没有变更通知就没法渐进填充

    $map = @{}
    foreach ($i in $script:Items) {
        if ($i.ExistState -ne 'yes' -or -not $i.Target) { continue }
        $k = $i.Target.ToLowerInvariant()
        if (-not $map.ContainsKey($k)) { $map[$k] = New-Object System.Collections.Generic.List[object] }
        $map[$k].Add($i)
        $i.SigText = '校验中…'
    }
    if ($map.Count -eq 0) { return }
    $script:SigMap = $map
    $paths = @($map.Values | ForEach-Object { $_[0].Target })

    $script:SigProg = [hashtable]::Synchronized(@{ Done = 0; Total = $paths.Count })
    $script:Flags['SigDone'] = $false
    Set-Busy "校验数字签名… 0 / $($paths.Count)"
    $script:SigTimer.Start()
    $script:SigJob = Start-BgWork -Body $script:SIG_BODY -Vars @{
        SM_Paths    = [string[]]$paths
        SM_QUEUE    = $script:SigQueue
        SM_PROGRESS = $script:SigProg
    } -OnDone { param($r, $e) Set-SigDone }
}

# 后台跑完不等于填完 —— 队列里可能还有没取的，交给排空定时器收尾
function Set-SigDone { $script:Flags['SigDone'] = $true }

# UI 线程排空队列。每次限量，避免一口气写几百个属性把这一帧撑爆。
$script:SigTimer = New-Object Windows.Threading.DispatcherTimer
$script:SigTimer.Interval = [TimeSpan]::FromMilliseconds(150)
$script:SigTimer.Add_Tick({
    try {
        $n = 0
        $rec = $null
        while ($n -lt 250 -and $script:SigQueue.TryDequeue([ref]$rec)) {
            $k = ([string]$rec.Path).ToLowerInvariant()
            if ($script:SigMap.ContainsKey($k)) {
                foreach ($it in $script:SigMap[$k]) { Update-ItemSignature $it $rec.Status $rec.Signer }
            }
            $n++
        }
        if ($script:SigProg -and -not $script:Flags['SigDone']) {
            Set-Busy "校验数字签名… $($script:SigProg['Done']) / $($script:SigProg['Total'])"
        }
        if ($script:Flags['SigDone'] -and $script:SigQueue.Count -eq 0) {
            $script:SigTimer.Stop()
            Update-Stats
            Apply-Filter     # 签名到位后风险变了，这时才重新排序（中途排会让行乱跳）
            Set-Busy ''
        }
    } catch {
        try { $script:SigTimer.Stop(); Set-Busy '' } catch { }
    }
})

$script:EnumFns = @('Set-Progress','Resolve-Target','Expand-Path','Resolve-ExistState','Get-Sig',
                    'Get-SigText','Get-ApprovedState','Get-RiskInfo','New-Item2',
                    'Get-ManagedServices','Get-UwpStartupItems','Get-AllStartupItems')

$script:ENUM_BODY = @'
$ErrorActionPreference = 'Stop'
$script:VerifySig    = $SM_VerifySig
$script:SigCache     = @{}
$script:LoadErrors   = @()
$script:SvcStateFile = $SM_SvcStateFile
# 条目是在这个 Runspace 里造的。不把这个标志带过来，New-Item2 会走降级分支
# 返回 PSCustomObject，回到 UI 后就没有变更通知，签名根本填不进界面。
# SmItem 是 Add-Type 编译进本进程 AppDomain 的，所有 Runspace 都能解析。
$script:HasInpc      = $SM_HasInpc
$items = Get-AllStartupItems -IncludeMsServices $SM_IncludeMs
[pscustomobject]@{ Items = @($items); Errors = @($script:LoadErrors) }
'@

# Sync：仅供自测使用。界面上一律走异步，否则枚举期间窗口就是「未响应」。
function Load-Items {
    param([switch]$Sync)

    # 刷新期间再点刷新直接忽略，避免叠加多个 Runspace
    if ($script:Flags['LoadRunning'] -and -not $Sync) { return }
    # 上一轮的签名补填作废：它填的是即将被替换掉的那批对象
    Stop-SigPass

    # 勾选状态与 AI 结论在重建对象后会丢失，先按「类型|位置|名称」记下来，加载完恢复
    $keep = @{}; $ai = @{}
    foreach ($i in $script:Items) {
        $k = "$($i.Kind)|$($i.Loc)|$($i.Name)"
        if ($i.Sel)      { $keep[$k] = $true }
        if ($i.AiReport) { $ai[$k]   = $i }
    }
    $verify = if ($UI -and $UI.chkSig) { [bool]$UI.chkSig.IsChecked } else { $script:VerifySig }
    $incMs  = if ($UI -and $UI.chkMs)  { [bool]$UI.chkMs.IsChecked }  else { $false }

    if ($Sync) {
        $script:VerifySig = $verify
        $script:SigCache.Clear()
        $items = Get-AllStartupItems -IncludeMsServices $incMs
        Complete-ItemLoad -NewItems $items -Errors $script:LoadErrors -Keep $keep -Ai $ai
        return
    }

    $script:Flags['LoadRunning'] = $true
    Set-LoadLock $true
    Set-Busy '正在枚举启动项…'

    # 第一趟不做签名校验 —— 那是刷新耗时的大头，先把列表铺出来。
    # 校验留给第二趟在后台逐个补（需要条目类型支持变更通知才能渐进填充）。
    #
    # 注意 $hasInpc 必须先落成局部变量：下面的回调是在本函数内部创建的闭包，
    # 而闭包里 $script:X 会去查闭包自己的模块作用域，读不到外面的值（会是 $null）。
    # 不带限定符的变量（如 $UI）反而能被 GetNewClosure 捕获。
    $hasInpc = $script:HasInpc
    $phase1Verify = if ($hasInpc) { $false } else { $verify }

    # 后台线程写、UI 线程读，必须是 synchronized 的
    $prog = [hashtable]::Synchronized(@{ Stage='启动中'; Done=0; Total=0 })

    Start-BgWork -Body $script:ENUM_BODY -Functions $script:EnumFns -Vars @{
        SM_VerifySig    = $phase1Verify
        SM_IncludeMs    = $incMs
        SM_HasInpc      = $script:HasInpc
        SM_SvcStateFile = $script:SvcStateFile
        SM_PROGRESS     = $prog
        RUN_LOCS        = $RUN_LOCS
        FOLDER_LOCS     = $FOLDER_LOCS
        RISK_TEXT       = $RISK_TEXT
        RISK_RANK       = $RISK_RANK
        RISK_GLYPH      = $RISK_GLYPH
        SIG_TEXT        = $SIG_TEXT
    } -OnTick {
        $n = [int]$prog['Done']
        $UI.lblBusy.Text = if ($n -gt 0) { "$($prog['Stage'])… 已发现 $n 项" } else { "$($prog['Stage'])…" }
    }.GetNewClosure() -OnDone {
        param($result, $err)
        try {
            if ($err) {
                Show-Msg "枚举启动项失败：`n$err" '错误' 'Error'
                return
            }
            $r = @($result)[0]
            Complete-ItemLoad -NewItems $r.Items -Errors $r.Errors -Keep $keep -Ai $ai
        } finally { Set-LoadIdle }
        # 列表这时已经在界面上了，才开始后台补签名
        if ($verify -and $hasInpc) { Start-SigPass }
    }.GetNewClosure() | Out-Null
}

function Add-DetailLine {
    param([string]$Label, [string]$Value, [string]$Color = $null)
    if (-not $Value) { return }
    $g = New-Object Windows.Controls.Grid
    $c1 = New-Object Windows.Controls.ColumnDefinition; $c1.Width = '78'
    $c2 = New-Object Windows.Controls.ColumnDefinition; $c2.Width = '*'
    $g.ColumnDefinitions.Add($c1); $g.ColumnDefinitions.Add($c2)
    $bc = [Windows.Media.BrushConverter]::new()
    $a = New-Object Windows.Controls.TextBlock
    $a.Text = $Label; $a.FontSize = 12; $a.Foreground = $bc.ConvertFromString($P.Muted)
    [Windows.Controls.Grid]::SetColumn($a, 0)
    $b = New-Object Windows.Controls.TextBlock
    $b.Text = $Value; $b.FontSize = 12.5; $b.TextWrapping = 'Wrap'
    $b.Foreground = $bc.ConvertFromString($(if ($Color) { $Color } else { $P.Ink2 }))
    if ($Label -in @('命令','路径','位置')) { $b.FontFamily = New-Object Windows.Media.FontFamily 'Consolas' }
    [Windows.Controls.Grid]::SetColumn($b, 1)
    $g.AddChild($a); $g.AddChild($b)
    $g.Margin = '0,0,0,3'
    $UI.panDetail.AddChild($g)
}

function Show-Detail {
    $UI.panDetail.Children.Clear()
    $chk = Get-Checked
    $hi  = @($UI.grid.SelectedItems)

    # 以前是「有勾选就只显示批量汇总」——结果勾了一项之后就再也点不出单行详情，
    # 而单行详情是唯一能看到完整命令行和风险依据的地方。改成高亮行优先：
    # 高亮了就看高亮的，没高亮才回落到勾选汇总。
    $sel = if ($hi.Count -gt 0) { $hi } elseif ($chk.Count -gt 0) { $chk } else { @() }

    if ($sel.Count -eq 0) {
        Add-DetailLine '' '点一行查看详情；勾选左侧复选框可批量操作' $P.Muted; return
    }
    if ($sel.Count -gt 1) {
        $src = if ($hi.Count -gt 1) { '已选中行' } else { '已勾选' }
        $brk = ($sel | Group-Object Kind | Sort-Object Count -Descending | ForEach-Object {
            "$(switch($_.Name){'Run'{'注册表 Run'}'Folder'{'启动文件夹'}'Task'{'计划任务'}'Service'{'服务'}default{$_.Name}}) $($_.Count)"
        }) -join ' · '
        Add-DetailLine $src "$($sel.Count) 个条目" $P.Accent
        Add-DetailLine '构成' $brk
        Add-DetailLine '风险' (($sel | Group-Object RiskText | Sort-Object Name | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ' · ')
        $noTgl = @($sel | Where-Object { -not $_.CanToggle }).Count
        $hard  = @($sel | Where-Object { $_.Kind -in @('Task','Service') }).Count
        $note = New-Object System.Collections.Generic.List[string]
        $note.Add('可批量执行：删除、启用/禁用')
        if ($noTgl) { $note.Add("其中 $noTgl 项不支持启用/禁用开关（只能删除）") }
        if ($hard)  { $note.Add("其中 $hard 项删除后无法自动撤销") }
        Add-DetailLine '说明' ($note -join '；')
        return
    }
    $i = $sel[0]
    $rc = switch ($i.Risk) { 'critical' { $P.Crit } 'warning' { $P.Warn } 'stale' { $P.Stale } default { $P.Ok } }
    Add-DetailLine '名称' "$($i.Name)   [$($i.StateText)]"
    Add-DetailLine '命令' $i.Command
    Add-DetailLine '路径' $(if ($i.Target) { "$($i.Target)   [$($i.ExistText)]" } else { '—' })
    Add-DetailLine '位置' $i.Loc
    Add-DetailLine '签名' $(if ($i.Signer) { "$($i.SigStatus) — $($i.Signer)" } else { $i.SigStatus })
    Add-DetailLine '风险' "$($i.RiskText) — $($i.RiskNote)" $rc
    if ($i.Kind -eq 'Task' -and $i.Extra.Desc)    { Add-DetailLine '任务说明' $i.Extra.Desc }
    if ($i.Kind -eq 'Service')                    { Add-DetailLine '服务' "$($i.Extra.Display) · 账户 $($i.Extra.Account) · 当前 $($i.Extra.State)" }
    if ($i.Kind -eq 'UWP') {
        Add-DetailLine 'UWP 包' ([string]$i.Extra.PackageName)
        Add-DetailLine '启动任务 ID' ([string]$i.Extra.TaskId)
        Add-DetailLine '应用 ID' ([string]$i.Extra.ApplicationId)
        if ([int]$i.Extra.StartupState -eq 3) { Add-DetailLine '限制' '系统策略已禁用此任务' }
        elseif ([int]$i.Extra.StartupState -eq 4) { Add-DetailLine '限制' '系统策略已启用此任务，可能无法由用户关闭' }
    }
    $caps = @()
    if ($i.Kind -eq 'UWP') { $caps += '通过 Windows 原生启动任务状态切换' }
    elseif ($i.CanToggle) { $caps += '可启用/禁用' }
    elseif ($i.CanDelete) { $caps += '不支持开关（可删除）' }
    else { $caps += '不支持启用/禁用或删除' }
    if ($i.CanEdit)   { $caps += '可编辑' }      else { $caps += '不可在此编辑' }
    if ($i.CanDelete) { $caps += '可删除' } else { $caps += '不可删除' }
    Add-DetailLine '可操作' ($caps -join ' · ')
    if ($i.AiReport) {
        $ac = switch -Wildcard ($i.AiVerdict) { '恶意*' { $P.Crit } '可疑*' { $P.Warn } '未知*' { $P.Stale } default { $P.Ok } }
        Add-DetailLine 'AI 判断' "$($i.AiReport.Badge) · $($i.AiReport.Need)" $ac
        Add-DetailLine 'AI 说明' "$($i.AiReport.Identity)  $($i.AiReport.Advice)"
    }
    if ($chk.Count -gt 0 -and $hi.Count -gt 0) {
        Add-DetailLine '批量' "另有 $($chk.Count) 项处于勾选状态 —— 删除 / 启用禁用 会作用于那 $($chk.Count) 项，而不是当前高亮行" $P.Accent
    }
}

# ── 批量删除确认对话框 ──
# MessageBox 无法滚动，几十项时只能截断显示；批量删除必须让用户看到完整清单。
function Show-BatchConfirm {
    param($Items, [string]$Verb = '删除', [bool]$Danger = $true, [string]$Extra = '')

    $raw = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="确认批量VERB" Height="520" Width="740" ResizeMode="CanResize"
        WindowStartupLocation="CenterOwner" Background="@Ground@"
        FontFamily="Microsoft YaHei UI, Segoe UI" FontSize="13">
  <Grid Margin="18">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0" x:Name="bHead" FontSize="17" FontWeight="Bold" Foreground="@Ink@" Margin="0,0,0,4"/>
    <TextBlock Grid.Row="1" x:Name="bSum"  FontSize="12.5" Foreground="@Muted@" Margin="0,0,0,11" TextWrapping="Wrap"/>

    <Border Grid.Row="2" Background="@Surface@" BorderBrush="@Line@" BorderThickness="1" CornerRadius="7">
      <DataGrid x:Name="bGrid" AutoGenerateColumns="False" IsReadOnly="True" HeadersVisibility="Column"
                CanUserAddRows="False" GridLinesVisibility="Horizontal" BorderThickness="0"
                Background="@Surface@" Foreground="@Ink@" RowBackground="@Surface@"
                AlternatingRowBackground="@RowAlt@" HorizontalGridLinesBrush="@Line@"
                VerticalGridLinesBrush="Transparent" RowHeight="27">
        <DataGrid.Columns>
          <DataGridTextColumn Header="风险" Binding="{Binding RiskText}" Width="52"/>
          <DataGridTextColumn Header="名称" Binding="{Binding Name}"     Width="205"/>
          <DataGridTextColumn Header="类型" Binding="{Binding Label}"    Width="160"/>
          <DataGridTextColumn Header="命令" Binding="{Binding Command}"  Width="*" FontFamily="Consolas"/>
        </DataGrid.Columns>
        <DataGrid.ColumnHeaderStyle>
          <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="@Surface3@"/><Setter Property="Foreground" Value="@Muted@"/>
            <Setter Property="BorderBrush" Value="@Line@"/><Setter Property="BorderThickness" Value="0,0,0,1"/>
            <Setter Property="Padding" Value="8,6"/><Setter Property="HorizontalContentAlignment" Value="Left"/>
          </Style>
        </DataGrid.ColumnHeaderStyle>
        <DataGrid.CellStyle>
          <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="8,0"/>
            <Setter Property="Foreground" Value="@Ink@"/>
          </Style>
        </DataGrid.CellStyle>
      </DataGrid>
    </Border>

    <Border Grid.Row="3" x:Name="bWarnBox" Background="@WarnBg@" BorderBrush="@Warn@" BorderThickness="1"
            CornerRadius="6" Padding="11,8" Margin="0,11,0,0" Visibility="Collapsed">
      <TextBlock x:Name="bWarn" FontSize="12" Foreground="@Warn@" TextWrapping="Wrap"/>
    </Border>

    <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <!-- 确认按钮刻意不设 IsDefault：这是破坏性操作，不该按一下回车就执行 -->
      <Button x:Name="bOk" Content="确认VERB" Padding="20,7" Margin="0,0,8,0" FontWeight="SemiBold"
              Background="@CritBg@" Foreground="@Crit@" BorderBrush="@Crit@" Cursor="Hand"/>
      <Button x:Name="bNo" Content="取消" Padding="20,7" IsCancel="True"
              Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"/>
    </StackPanel>
  </Grid>
</Window>
'@
    $x = $raw.Replace('VERB', $Verb)
    foreach ($k in $P.Keys) { $x = $x.Replace("@$k@", $P[$k]) }
    $d = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$x)))
    $d.Owner = $win

    $d.FindName('bHead').Text = "即将$Verb $($Items.Count) 个自启动项"
    $brk = ($Items | Group-Object Kind | Sort-Object Count -Descending |
            ForEach-Object { "$(switch($_.Name){'Run'{'注册表 Run'}'Folder'{'启动文件夹'}'Task'{'计划任务'}'Service'{'服务'}default{$_.Name}}) $($_.Count)" }) -join ' · '
    $rsk = ($Items | Group-Object RiskText | Sort-Object Name | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ' · '
    $d.FindName('bSum').Text = "构成：$brk`n风险：$rsk"
    $d.FindName('bGrid').ItemsSource = @($Items)

    $w = New-Object System.Collections.Generic.List[string]
    if ($Verb -eq '删除') {
        $hard = @($Items | Where-Object { $_.Kind -in @('Task','Service') })
        $scr  = @($Items | Where-Object { $_.Kind -eq 'Folder' -and $_.Extra.Ext -ine '.lnk' })
        if ($hard.Count) { $w.Add("其中 $($hard.Count) 项是计划任务 / 服务 —— 删除后无法用「撤销上一步」自动恢复，需手动重建。") }
        if ($scr.Count)  { $w.Add("其中 $($scr.Count) 项是启动文件夹里的脚本文件 —— 文件内容无法自动恢复，请先确认已有备份。") }
    }
    if ($Extra) { $w.Add($Extra) }
    if (-not $Danger) {
        # 切换启用状态不是破坏性操作，别用删除那套红色按钮吓人
        $b = $d.FindName('bOk')
        $bc = [Windows.Media.BrushConverter]::new()
        $b.Background = $bc.ConvertFromString($P.Accent)
        $b.Foreground = $bc.ConvertFromString($P.AccentInk)
        $b.BorderBrush = $bc.ConvertFromString($P.Accent)
    }
    if ($w.Count) {
        $d.FindName('bWarn').Text = ($w -join "`n")
        $d.FindName('bWarnBox').Visibility = 'Visible'
    }

    $d.FindName('bOk').Add_Click({ $d.DialogResult = $true;  $d.Close() })
    # bNo 已经是 IsCancel，WPF 会自行把 DialogResult 置 false 并关窗；
    # 这里再设一次会在窗口关闭后抛 InvalidOperationException。
    return ($d.ShowDialog() -eq $true)
}

# ── 新建 / 编辑对话框 ──
function Show-ItemDialog {
    param([string]$Mode, $Item)

    $dlgRaw = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="TITLE" Height="336" Width="620" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" Background="@Ground@"
        FontFamily="Microsoft YaHei UI, Segoe UI" FontSize="13">
  <Grid Margin="18">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <Grid.ColumnDefinitions><ColumnDefinition Width="86"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>

    <TextBlock Grid.Row="0" Grid.Column="0" Text="位置" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,10"/>
    <ComboBox  Grid.Row="0" Grid.Column="1" Grid.ColumnSpan="2" x:Name="dLoc" Margin="0,0,0,10"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Padding="7,5"/>

    <TextBlock Grid.Row="1" Grid.Column="0" Text="名称" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,10"/>
    <TextBox   Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="2" x:Name="dName" Margin="0,0,0,10"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Padding="7,6" CaretBrush="@Ink@"/>

    <TextBlock Grid.Row="2" Grid.Column="0" Text="程序" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,10"/>
    <TextBox   Grid.Row="2" Grid.Column="1" x:Name="dExe" Margin="0,0,7,10" FontFamily="Consolas"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Padding="7,6" CaretBrush="@Ink@"/>
    <Button    Grid.Row="2" Grid.Column="2" x:Name="dBrowse" Content="浏览…" Margin="0,0,0,10" Padding="13,6"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"/>

    <TextBlock Grid.Row="3" Grid.Column="0" Text="参数" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,10"/>
    <TextBox   Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="2" x:Name="dArgs" Margin="0,0,0,10" FontFamily="Consolas"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Padding="7,6" CaretBrush="@Ink@"/>

    <Border Grid.Row="4" Grid.ColumnSpan="3" Background="@Surface2@" BorderBrush="@Line@" BorderThickness="1"
            CornerRadius="6" Padding="11,9" Margin="0,2,0,0">
      <TextBlock x:Name="dHint" TextWrapping="Wrap" FontSize="12" Foreground="@Muted@"/>
    </Border>

    <StackPanel Grid.Row="6" Grid.ColumnSpan="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="dOk" Content="确定" Padding="20,7" Margin="0,0,8,0" FontWeight="SemiBold" IsDefault="True"
              Background="@Accent@" Foreground="@AccentInk@" BorderBrush="@Accent@" Cursor="Hand"/>
      <Button x:Name="dCancel" Content="取消" Padding="20,7" IsCancel="True"
              Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"/>
    </StackPanel>
  </Grid>
</Window>
'@
    $dx = $dlgRaw.Replace('TITLE', $(if ($Mode -eq 'new') { '新建自启动项' } else { '编辑自启动项' }))
    foreach ($k in $P.Keys) { $dx = $dx.Replace("@$k@", $P[$k]) }
    $dlg = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$dx)))
    $dlg.Owner = $win

    $dLoc=$dlg.FindName('dLoc'); $dName=$dlg.FindName('dName'); $dExe=$dlg.FindName('dExe')
    $dArgs=$dlg.FindName('dArgs'); $dHint=$dlg.FindName('dHint')
    $dOk=$dlg.FindName('dOk'); $dCancel=$dlg.FindName('dCancel'); $dBrowse=$dlg.FindName('dBrowse')

    $LOCOPTS = [ordered]@{
        '注册表 Run — 当前用户 (HKCU)'      = @{ Kind='Run';    Scope='HKCU'   }
        '注册表 Run — 所有用户 (HKLM)'      = @{ Kind='Run';    Scope='HKLM'   }
        '注册表 Run — 32位 (HKLM\WOW64)'    = @{ Kind='Run';    Scope='HKLM32' }
        '启动文件夹 — 当前用户'             = @{ Kind='Folder'; Scope='User'   }
        '启动文件夹 — 所有用户'             = @{ Kind='Folder'; Scope='Common' }
        '计划任务 — 登录时触发(最高权限)'   = @{ Kind='Task';   Scope='Logon'  }
    }
    $dLoc.ItemsSource = @($LOCOPTS.Keys)
    $dLoc.SelectedIndex = 0

    if ($Mode -eq 'edit') {
        $dLoc.IsEnabled = $false
        $lab = switch ($Item.Kind) {
            'Run'    { "注册表 Run — $($Item.Scope)" }
            'Folder' { "启动文件夹 — $($Item.Scope)" }
            'Task'   { "计划任务 — $($Item.Extra.TaskPath)$($Item.Extra.TaskName)" }
            default  { $Item.Label }
        }
        $dLoc.ItemsSource = @($lab); $dLoc.SelectedIndex = 0
        $dName.Text = $Item.Name
        $rt = Resolve-Target $Item.Command
        $dExe.Text = $rt.Path; $dArgs.Text = $rt.Args
        $undoable = Test-RecordUndoable -Action 'edit' -Kind $Item.Kind -Extra $Item.Extra
        $dHint.Text = "编辑将直接写入：$($Item.Loc)`n" + $(if ($undoable) {
            '原值已记入回滚日志，可用「撤销上一步」还原。'
        } else {
            '注意：该类型的编辑无法用「撤销上一步」还原，改前请自行确认。'
        })
        if ($Item.Kind -eq 'Task') {
            $dHint.Text += "`n改名会以同一份触发器 / 权限 / 设置在新名下重建任务，再注销旧任务。"
        }
    } else {
        $dHint.Text = "HKCU 只影响当前用户，无需重启即生效。HKLM 影响所有用户。`n计划任务以最高权限运行，可绕过 UAC 提示。"
    }

    $dBrowse.Add_Click({
        $ofd = New-Object Microsoft.Win32.OpenFileDialog
        $ofd.Filter = '可执行文件与脚本|*.exe;*.bat;*.cmd;*.vbs;*.ps1|所有文件|*.*'
        if ($ofd.ShowDialog()) {
            $dExe.Text = $ofd.FileName
            if (-not $dName.Text) { $dName.Text = [IO.Path]::GetFileNameWithoutExtension($ofd.FileName) }
        }
    })

    $script:dlgResult = $null
    $dOk.Add_Click({
        if (-not $dName.Text.Trim()) { Show-Msg '请填写名称。' '缺少信息' 'Warning'; return }
        if (-not $dExe.Text.Trim())  { Show-Msg '请填写程序路径。' '缺少信息' 'Warning'; return }
        $exe = [Environment]::ExpandEnvironmentVariables($dExe.Text.Trim())
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
            if (-not (Confirm-Msg "路径不存在：`n$exe`n`n仍然继续？")) { return }
        }
        $script:dlgResult = @{
            Loc  = [string]$dLoc.SelectedItem
            Name = $dName.Text.Trim()
            Exe  = $dExe.Text.Trim()
            Args = $dArgs.Text.Trim()
        }
        $dlg.DialogResult = $true; $dlg.Close()
    })
    # dCancel 是 IsCancel，交给 WPF 处理，勿重复设置 DialogResult

    if ($dlg.ShowDialog() -ne $true) { return $null }
    $r = $script:dlgResult
    if ($Mode -eq 'new') {
        $o = $LOCOPTS[$r.Loc]
        $r.Kind = $o.Kind; $r.Scope = $o.Scope
    }
    return $r
}

# ══════════════════════════════════════════════════════════════════
#  8b. AI 分析（Claude Messages API，直连 REST，无 SDK）
# ══════════════════════════════════════════════════════════════════
$script:AiCfgFile = Join-Path $script:AppDir 'ai-config.json'
$script:AI_BATCH  = 8        # 每次请求最多几条，避免单次输出撞上 max_tokens
$script:AI_VERSION   = '2023-06-01'
$script:AI_PROTOCOLS = @('anthropic','openai','openai-responses')

# 预设：新建配置时的起点。自定义中转站选对应协议后改地址即可。
$script:AI_PRESETS = [ordered]@{
    'Anthropic 官方'     = @{ Protocol='anthropic'; BaseUrl='https://api.anthropic.com'; Model='claude-opus-5' }
    'Anthropic 兼容中转' = @{ Protocol='anthropic'; BaseUrl='';                          Model='claude-opus-5' }
    'OpenAI 兼容(chat)'  = @{ Protocol='openai';           BaseUrl='https://api.openai.com/v1'; Model='' }
    'OpenAI 兼容(responses)' = @{ Protocol='openai-responses'; BaseUrl='https://api.openai.com/v1'; Model='' }
}

# API Key 用 DPAPI 加密后落盘（绑定当前 Windows 用户，换机器/换账号都解不开）。
# 明文只在内存里存在于一次请求的生命周期内。
function Protect-AiKey {
    param([string]$Plain)
    if (-not $Plain) { return '' }
    ConvertFrom-SecureString (ConvertTo-SecureString $Plain -AsPlainText -Force)
}
function Unprotect-AiKey {
    param([string]$Enc)
    if (-not $Enc) { return '' }
    try { [Net.NetworkCredential]::new('', (ConvertTo-SecureString $Enc)).Password } catch { '' }
}

function New-AiProvider {
    param([string]$Name = '新建配置', [string]$Protocol = 'anthropic',
          [string]$BaseUrl = 'https://api.anthropic.com', [string]$Model = 'claude-opus-5')
    [ordered]@{
        Id       = [guid]::NewGuid().ToString('N').Substring(0, 8)
        Name     = $Name
        Protocol = $Protocol
        BaseUrl  = $BaseUrl
        KeyEnc   = ''
        Model    = $Model
        Effort   = 'high'
    }
}

# JSON 反序列化出来的是 PSCustomObject，统一转成有序哈希表，字段缺失时给默认值
function ConvertTo-AiProvider {
    param($o)
    [ordered]@{
        Id       = $(if ($o.Id)   { [string]$o.Id }   else { [guid]::NewGuid().ToString('N').Substring(0, 8) })
        Name     = $(if ($o.Name) { [string]$o.Name } else { '未命名' })
        Protocol = $(if ([string]$o.Protocol -in $script:AI_PROTOCOLS) { [string]$o.Protocol } else { 'anthropic' })
        BaseUrl  = [string]$o.BaseUrl
        KeyEnc   = [string]$o.KeyEnc
        Model    = [string]$o.Model
        Effort   = $(if ($o.Effort) { [string]$o.Effort } else { 'high' })
    }
}

function Get-AiConfig {
    $d = [ordered]@{ Active = ''; Providers = @(); Redact = $true; Consented = $false }
    if (Test-Path $script:AiCfgFile) {
        try {
            $j = Get-Content $script:AiCfgFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($null -ne $j.Redact)    { $d.Redact    = [bool]$j.Redact }
            if ($null -ne $j.Consented) { $d.Consented = [bool]$j.Consented }
            if ($j.Providers) {
                $d.Providers = @($j.Providers | ForEach-Object { ConvertTo-AiProvider $_ })
                $d.Active    = [string]$j.Active
            } elseif ($j.KeyEnc -or $j.Model) {
                # 旧版单配置格式，迁移成一条 provider
                $p = New-AiProvider -Name 'Anthropic 官方'
                $p.KeyEnc = [string]$j.KeyEnc
                if ($j.Model)  { $p.Model  = [string]$j.Model }
                if ($j.Effort) { $p.Effort = [string]$j.Effort }
                $d.Providers = @($p); $d.Active = $p.Id
            }
        } catch { }
    }
    if (@($d.Providers).Count -eq 0) {
        $p = New-AiProvider -Name 'Anthropic 官方'
        $d.Providers = @($p); $d.Active = $p.Id
    }
    if (-not (@($d.Providers) | Where-Object { $_.Id -eq $d.Active })) { $d.Active = @($d.Providers)[0].Id }
    return $d
}

function Save-AiConfig {
    param($Cfg)
    $out = [ordered]@{
        Active    = [string]$Cfg.Active
        Redact    = [bool]$Cfg.Redact
        Consented = [bool]$Cfg.Consented
        Providers = @($Cfg.Providers)
    }
    ($out | ConvertTo-Json -Depth 6) | Set-Content $script:AiCfgFile -Encoding UTF8
}

function Get-AiActiveProvider {
    param($Cfg)
    $p = @($Cfg.Providers) | Where-Object { $_.Id -eq $Cfg.Active } | Select-Object -First 1
    if (-not $p) { $p = @($Cfg.Providers)[0] }
    return $p
}

# 环境变量作为兜底：provider 自己没填 Key 时才用，方便不想落盘的场景
function Get-AiKey {
    param($Provider)
    $k = Unprotect-AiKey $Provider.KeyEnc
    if ($k) { return $k }
    if ($Provider.Protocol -eq 'openai') { return [string]$env:OPENAI_API_KEY }
    return [string]$env:ANTHROPIC_API_KEY
}

# 地址一律归一化成以 /v1 结尾，两种协议的路径都从这里派生 ——
# 用户填 https://x.com、https://x.com/ 还是 https://x.com/v1 都能用
function Get-AiEndpoint {
    param($Provider, [string]$What = 'messages')
    $b = ([string]$Provider.BaseUrl).Trim().TrimEnd('/')
    if (-not $b) { $b = $(if ($Provider.Protocol -eq 'openai') { 'https://api.openai.com/v1' } else { 'https://api.anthropic.com' }) }
    if ($b -notmatch '/v1$') { $b = "$b/v1" }
    if ($What -eq 'models') { return "$b/models" }
    switch ($Provider.Protocol) {
        'openai'           { return "$b/chat/completions" }
        'openai-responses' { return "$b/responses" }
        default            { return "$b/messages" }
    }
}

function Test-AiOfficial {
    param($Provider)
    (Get-AiEndpoint $Provider 'messages') -match '^https://api\.anthropic\.com/'
}

function Get-AiHeaders {
    param($Provider, [string]$Key, [switch]$ForMessages)
    if ($Provider.Protocol -like 'openai*') { return @{ 'Authorization' = "Bearer $Key" } }
    $h = @{ 'x-api-key' = $Key; 'anthropic-version' = $script:AI_VERSION }
    # 服务端 fallback 是官方端点的特性，中转站多半不认这个 beta 头，只对官方发
    if ($ForMessages -and (Test-AiOfficial $Provider)) { $h['anthropic-beta'] = 'server-side-fallback-2026-07-01' }
    return $h
}

function New-AiRequestBody {
    param($Provider, [string]$System, [string]$UserText, $Schema)

    # 思考强度留空表示「不发送」—— 非推理模型收到这个参数会直接报错，
    # 所以对两种 openai 协议都是显式 opt-in。
    $eff = [string]$Provider.Effort
    $sendEff = $eff -and $eff -ne '(不发送)'

    if ($Provider.Protocol -eq 'openai-responses') {
        # Responses API：结构化输出在 text.format，且 name/schema/strict 是**拍平**的，
        # 不像 Chat Completions 那样再套一层 json_schema 对象。
        $b = [ordered]@{
            model = $Provider.Model
            input = @(
                [ordered]@{ role = 'system'; content = $System }
                [ordered]@{ role = 'user';   content = $UserText }
            )
            max_output_tokens = 16000
            text = [ordered]@{
                format = [ordered]@{
                    type   = 'json_schema'
                    name   = 'startup_analysis'
                    schema = $Schema
                    strict = $true
                }
            }
        }
        if ($sendEff) { $b['reasoning'] = [ordered]@{ effort = $eff } }
        return $b
    }
    if ($Provider.Protocol -eq 'openai') {
        $b = [ordered]@{
            model      = $Provider.Model
            max_tokens = 16000
            messages   = @(
                [ordered]@{ role = 'system'; content = $System }
                [ordered]@{ role = 'user';   content = $UserText }
            )
            response_format = [ordered]@{
                type = 'json_schema'
                json_schema = [ordered]@{ name = 'startup_analysis'; strict = $true; schema = $Schema }
            }
        }
        if ($sendEff) { $b['reasoning_effort'] = $eff }
        return $b
    }
    $b = [ordered]@{
        model      = $Provider.Model
        max_tokens = 16000
        system     = $System
        messages   = @([ordered]@{ role = 'user'; content = $UserText })
        output_config = [ordered]@{ format = [ordered]@{ type = 'json_schema'; schema = $Schema } }
    }
    if ($sendEff) { $b.output_config['effort'] = $eff }
    if (Test-AiOfficial $Provider) { $b['fallbacks'] = 'default' }
    return $b
}

function Get-AiResponseText {
    param($Provider, $Resp)
    if ($Provider.Protocol -eq 'openai-responses') {
        # output 是个混合数组：推理模型还会插入 type=reasoning 的条目，
        # 必须先挑出 type=message，再从它的 content 里取 type=output_text。
        if ($Resp.error) { throw "服务返回错误：$([string]$Resp.error.message)" }
        $parts = @(@($Resp.output) | Where-Object { $_.type -eq 'message' } |
                   ForEach-Object { $_.content } | Where-Object { $_ })
        $ref = @($parts | Where-Object { $_.type -eq 'refusal' })
        if ($ref.Count) { throw "模型拒绝了这次请求：$([string]$ref[0].refusal)" }
        if ($Resp.status -eq 'incomplete') {
            throw "输出被截断（status=incomplete，原因：$([string]$Resp.incomplete_details.reason)）。请减少一次分析的条目数。"
        }
        $t = (@($parts | Where-Object { $_.type -eq 'output_text' } | ForEach-Object { [string]$_.text }) -join '')
        # 有些兼容实现只给顶层的 output_text 便捷字段
        if (-not $t -and $Resp.output_text) { $t = [string]$Resp.output_text }
        return $t
    }
    if ($Provider.Protocol -eq 'openai') {
        $t  = [string]$Resp.choices[0].message.content
        $fr = [string]$Resp.choices[0].finish_reason
        if (-not $t -and $fr -eq 'content_filter') { throw '内容被服务端安全策略拦截（finish_reason=content_filter）。' }
        return $t
    }
    if ($Resp.stop_reason -eq 'refusal') {
        throw "模型拒绝了这次请求（stop_reason=refusal，类别：$($Resp.stop_details.category)）。请减少一次分析的条目数或换一批条目重试。"
    }
    return (@($Resp.content | Where-Object { $_.type -eq 'text' } | ForEach-Object { $_.text }) -join '')
}

function Get-AiUsage {
    param($Provider, $Resp)
    # Chat Completions 用 prompt/completion_tokens；
    # Responses API 和 Anthropic 恰好都用 input/output_tokens。
    if ($Provider.Protocol -eq 'openai') {
        return @{ In = [int]$Resp.usage.prompt_tokens; Out = [int]$Resp.usage.completion_tokens }
    }
    return @{ In = [int]$Resp.usage.input_tokens; Out = [int]$Resp.usage.output_tokens }
}

# 两种协议共用的错误解读
function Resolve-AiError {
    param($ErrRecord, $Provider)
    $detail = $null
    if ($ErrRecord.ErrorDetails -and $ErrRecord.ErrorDetails.Message) {
        try {
            $j = $ErrRecord.ErrorDetails.Message | ConvertFrom-Json
            $detail = $(if ($j.error.message) { [string]$j.error.message } else { [string]$ErrRecord.ErrorDetails.Message })
        } catch { $detail = [string]$ErrRecord.ErrorDetails.Message }
    }
    $code = try { [int]$ErrRecord.Exception.Response.StatusCode } catch { 0 }
    # 404 在 OpenAI 家族里八成是「这个服务只实现了另一套端点」，直接把建议给出来
    $alt = switch ([string]$Provider.Protocol) {
        'openai'           { '（该服务可能只提供 Responses API —— 把「协议」改成 openai-responses 试试，或点「自动探测」）' }
        'openai-responses' { '（该服务可能只提供 Chat Completions —— 把「协议」改成 openai 试试，或点「自动探测」）' }
        default            { '' }
    }
    $hint = switch ($code) {
        401 { '（API Key 无效或已撤销）' }
        403 { '（该 Key 无权访问此模型）' }
        404 { $(if ($alt) { $alt } else { '（地址不对或该模型不存在 —— 检查「地址」一栏）' }) }
        429 { '（触发速率限制，稍后再试）' }
        400 { '（请求被拒绝，通常是模型名或参数不被该服务支持）' }
        0   { '（连不上服务器 —— 检查地址、网络或代理）' }
        default { '' }
    }
    "调用失败 HTTP $code $hint`n端点：$(Get-AiEndpoint $Provider 'messages')`n$detail"
}

# 拉取模型清单。两种协议的 /v1/models 返回格式基本一致（data[].id）
function Get-AiModelList {
    param($Provider, [string]$Key)
    $url = Get-AiEndpoint $Provider 'models'
    try {
        $r = Invoke-RestMethod -Uri $url -Method Get -Headers (Get-AiHeaders $Provider $Key) -TimeoutSec 60
    } catch {
        throw (Resolve-AiError $_ $Provider)
    }
    $ids = @()
    if ($r.data)            { $ids = @($r.data   | ForEach-Object { [string]$_.id }) }
    elseif ($r.models)      { $ids = @($r.models | ForEach-Object { [string]$_.id }) }
    elseif ($r -is [array]) { $ids = @($r        | ForEach-Object { [string]$_.id }) }
    return @($ids | Where-Object { $_ } | Sort-Object -Unique)
}

# 命令行里经常夹着用户名、主机名、完整用户目录。默认脱敏后再出网。
function Convert-AiRedact {
    param([string]$Text, [bool]$On)
    if (-not $On -or [string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    $up = [Environment]::GetFolderPath('UserProfile')
    if ($up) { $t = $t -replace [regex]::Escape($up), '%USERPROFILE%' }
    if ($env:USERNAME)     { $t = $t -replace [regex]::Escape($env:USERNAME), '<USER>' }
    if ($env:COMPUTERNAME) { $t = $t -replace [regex]::Escape($env:COMPUTERNAME), '<HOST>' }
    return $t
}

# 只发元数据，绝不读取、更不上传任何文件内容
function Get-AiItemPayload {
    param($Item, [bool]$Redact)
    $o = [ordered]@{
        name       = Convert-AiRedact $Item.Name $Redact
        type       = $Item.Label
        location   = Convert-AiRedact $Item.Loc $Redact
        command    = Convert-AiRedact $Item.Command $Redact
        target     = Convert-AiRedact $Item.Target $Redact
        file_state = $Item.ExistText
        signer     = $Item.Signer
        signature  = $Item.SigStatus
        enabled    = [bool]$Item.Enabled
        local_risk = "$($Item.RiskText) — $($Item.RiskNote)"
    }
    if ($Item.Kind -eq 'Service') {
        $o['service_display'] = $Item.Extra.Display
        $o['service_account'] = $Item.Extra.Account
    }
    if ($Item.Kind -eq 'Task') {
        $o['task_author'] = Convert-AiRedact ([string]$Item.Extra.Author) $Redact
        $o['task_desc']   = Convert-AiRedact ([string]$Item.Extra.Desc) $Redact
    }
    if ($Item.Kind -eq 'UWP') {
        $o['uwp_package_name'] = Convert-AiRedact ([string]$Item.Extra.PackageName) $Redact
        $o['uwp_package_family'] = Convert-AiRedact ([string]$Item.Extra.PackageFamilyName) $Redact
        $o['uwp_task_id'] = Convert-AiRedact ([string]$Item.Extra.TaskId) $Redact
        $o['uwp_application_id'] = Convert-AiRedact ([string]$Item.Extra.ApplicationId) $Redact
    }
    $o
}

$script:AI_SCHEMA = [ordered]@{
    type = 'object'
    properties = [ordered]@{
        results = [ordered]@{
            type = 'array'
            items = [ordered]@{
                type = 'object'
                properties = [ordered]@{
                    name            = [ordered]@{ type='string'; description='与输入条目完全一致的名称' }
                    identity        = [ordered]@{ type='string'; description='这个程序是什么、属于哪个软件、由谁发布' }
                    verdict         = [ordered]@{ type='string'; enum=@('malicious','suspicious','unknown','legitimate') }
                    confidence      = [ordered]@{ type='string'; enum=@('high','medium','low') }
                    necessity       = [ordered]@{ type='string'; enum=@('essential','useful','optional','unnecessary') }
                    findings        = [ordered]@{ type='array'; items=[ordered]@{ type='string' }; description='具体依据，每条一句话' }
                    recommendation  = [ordered]@{ type='string'; description='给用户的一句话建议' }
                    safe_to_disable = [ordered]@{ type='boolean' }
                    safe_to_delete  = [ordered]@{ type='boolean' }
                }
                required = @('name','identity','verdict','confidence','necessity','findings','recommendation','safe_to_disable','safe_to_delete')
                additionalProperties = $false
            }
        }
        summary = [ordered]@{ type='string'; description='对这一批条目的整体判断，2-4 句' }
    }
    required = @('results','summary')
    additionalProperties = $false
}

$script:AI_SYSTEM = @'
你是 Windows 自启动项安全分析专家，正在协助用户审查本机的开机启动配置。

用户会给你一批启动项的元数据（名称、注册表位置或文件路径、命令行、数字签名状态、
签署者、目标文件是否存在、以及本地静态规则给出的初步风险判断）。注意：路径和命令行
可能已做脱敏处理，%USERPROFILE% / <USER> / <HOST> 是占位符，不要把它们当成可疑特征。

请逐条判断，并遵守以下原则：

1. 先识别身份。说清楚这是什么软件的组件、正常情况下由谁发布、装在哪里才算合理。
   认不出来就直接说认不出来，verdict 用 unknown，不要编造一个听起来合理的来源。
2. 签名是重要但不充分的证据。有效签名只说明文件未被篡改且发布者身份可查，
   不代表软件本身有价值或值得开机自启；无签名也不等于恶意（大量正规小工具、
   脚本、开源程序都没有签名）。
3. 重点关注这些真正的危险信号：用系统进程名却不在 System32；位于 Temp / AppData /
   ProgramData 等任何低权限进程可写的目录；通过 rundll32 / mshta / regsvr32 /
   powershell -enc 等系统程序间接执行载荷；命令行里有 base64、隐藏窗口、下载执行；
   名称与实际路径不匹配；服务路径含空格却未加引号（可被劫持提权）。
4. 区分「安全性」和「必要性」。很多签名有效的正规软件（更新器、云盘、聊天工具、
   驱动面板）完全合法但没必要开机自启 —— 这类应判 legitimate，necessity 给
   optional 或 unnecessary，并在建议里说明关掉它的影响。
5. safe_to_disable / safe_to_delete 要保守。凡是涉及安全软件、驱动、系统组件、
   或者你无法确认身份的条目，safe_to_delete 一律给 false，并在建议里说明原因。
   两者含义不同：禁用通常可逆，删除往往不可逆。
6. findings 写具体证据，不要写「建议谨慎」这类空话。你不确定的地方要明说不确定，
   宁可给 unknown + low confidence，也不要给一个自信的错误结论。

全部输出使用简体中文（verdict / confidence / necessity 这三个字段除外，
它们必须原样使用 schema 里规定的英文枚举值）。
'@

# 单次请求。两种协议（Anthropic Messages / OpenAI Chat Completions）在这里分流，
# 具体的地址、请求头、请求体、响应解析都由上面那组 Get-Ai* 函数按 provider 决定。
# Anthropic 官方端点会额外带上服务端 fallback（安全分类器拒答时自动换备用模型重跑）；
# 中转站不发这个 beta 头，因为它们多半不认。
function Invoke-AiAnalysis {
    param($Provider, [string]$ApiKey, [object[]]$Payloads)

    $userText = "请分析以下 $($Payloads.Count) 个 Windows 自启动项：`n`n" +
                (($Payloads | ConvertTo-Json -Depth 6))

    $body  = New-AiRequestBody -Provider $Provider -System $script:AI_SYSTEM -UserText $userText -Schema $script:AI_SCHEMA
    $json  = $body | ConvertTo-Json -Depth 40
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $url   = Get-AiEndpoint $Provider 'messages'
    $hdrs  = Get-AiHeaders -Provider $Provider -Key $ApiKey -ForMessages

    try {
        $resp = Invoke-RestMethod -Uri $url -Method Post -Headers $hdrs `
                    -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 300
    } catch {
        throw (Resolve-AiError $_ $Provider)
    }

    $txt = Get-AiResponseText -Provider $Provider -Resp $resp
    if (-not $txt) { throw '服务返回了空内容。' }
    # 有些中转站会把 JSON 包在 ```json 围栏里，先剥掉
    $txt = $txt.Trim()
    if ($txt.StartsWith('```')) { $txt = ($txt -replace '^```[a-zA-Z]*\s*', '' -replace '\s*```$', '').Trim() }
    $data = $null
    try { $data = $txt | ConvertFrom-Json }
    catch { throw "无法解析返回的 JSON（该服务可能不支持结构化输出）：`n$($txt.Substring(0, [Math]::Min(400, $txt.Length)))" }

    $u = Get-AiUsage -Provider $Provider -Resp $resp
    return [pscustomobject]@{
        Data  = $data
        Model = $(if ($resp.model) { [string]$resp.model } else { [string]$Provider.Model })
        Usage = [pscustomobject]@{ input_tokens = $u.In; output_tokens = $u.Out }
    }
}

$script:AI_VERDICT_TEXT = @{ malicious='恶意'; suspicious='可疑'; unknown='未知'; legitimate='合法' }
$script:AI_NEED_TEXT    = @{ essential='必需'; useful='有用'; optional='可选'; unnecessary='无必要' }

# 要一并带进后台 Runspace 的函数。协议分流全靠这几个。
$script:AiFns = @('Get-AiEndpoint','Test-AiOfficial','Get-AiHeaders','New-AiRequestBody',
                  'Get-AiResponseText','Get-AiUsage','Resolve-AiError','Invoke-AiAnalysis','Get-AiModelList')

# 逐个协议试一遍，命中即停。用来回答「这个地址到底该选哪个协议」。
$script:AI_PROBE_BODY = @'
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 6) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
}
$script:AI_VERSION   = $SM_Version
$script:AI_SYSTEM    = $SM_System
$script:AI_SCHEMA    = $SM_Schema
$script:AI_PROTOCOLS = $SM_Protocols

$out = New-Object System.Collections.Generic.List[object]
$hit = $null
foreach ($proto in @($SM_Order)) {
    $pv = @{}
    foreach ($k in @($SM_Provider.Keys)) { $pv[$k] = $SM_Provider[$k] }
    $pv['Protocol'] = $proto
    $rec = [ordered]@{ Protocol=$proto; Endpoint=(Get-AiEndpoint $pv 'messages'); Ok=$false; Error=''; Model='' }
    $SM_PROGRESS['Stage'] = "探测 $proto"
    try {
        $r = Invoke-AiAnalysis -Provider $pv -ApiKey $SM_Key -Payloads @($SM_Probe)
        $rec.Ok = $true
        $rec.Model = [string]$r.Model
        $out.Add([pscustomobject]$rec)
        $hit = $proto
        break
    } catch {
        $rec.Error = [string]$_.Exception.Message
        $out.Add([pscustomobject]$rec)
    }
}
[pscustomobject]@{ Hit = $hit; Results = @($out) }
'@

# 后台批量分析。整个批次循环都在 Runspace 里跑，UI 线程只在结束时收一次结果。
$script:AI_BODY = @'
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 6) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
}
$script:AI_VERSION   = $SM_Version
$script:AI_SYSTEM    = $SM_System
$script:AI_SCHEMA    = $SM_Schema
$script:AI_PROTOCOLS = $SM_Protocols

$rows = New-Object System.Collections.Generic.List[object]
$sums = New-Object System.Collections.Generic.List[string]
$errs = New-Object System.Collections.Generic.List[string]
$inTok = 0; $outTok = 0; $model = ''
$batches = @($SM_Batches)
for ($b = 0; $b -lt $batches.Count; $b++) {
    $SM_PROGRESS['Stage'] = "AI 分析中 第 $($b + 1)/$($batches.Count) 批"
    $SM_PROGRESS['Done']  = $b
    try {
        $r = Invoke-AiAnalysis -Provider $SM_Provider -ApiKey $SM_Key -Payloads @($batches[$b])
        $model   = $r.Model
        $inTok  += [int]$r.Usage.input_tokens
        $outTok += [int]$r.Usage.output_tokens
        foreach ($x in @($r.Data.results)) { $rows.Add($x) }
        if ($r.Data.summary) { $sums.Add([string]$r.Data.summary) }
    } catch {
        $errs.Add("第 $($b + 1) 批：$($_.Exception.Message)")
    }
}
[pscustomobject]@{ Rows=@($rows); Sums=@($sums); Errors=@($errs); In=$inTok; Out=$outTok; Model=$model }
'@

# ── AI 设置对话框 ──
# 多套配置并存，顶部下拉切换；每套各有协议 / 地址 / Key / 模型。
function Show-AiConfigDialog {
    $cfg = Get-AiConfig
    $raw = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AI 设置" Height="620" Width="720" ResizeMode="CanResize" MinHeight="560" MinWidth="640"
        WindowStartupLocation="CenterOwner" Background="@Ground@"
        FontFamily="Microsoft YaHei UI, Segoe UI" FontSize="13">
  <Grid Margin="18">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <Grid.ColumnDefinitions><ColumnDefinition Width="76"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>

    <!-- 配置切换 -->
    <TextBlock Grid.Row="0" Grid.Column="0" Text="配置" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,9"/>
    <ComboBox  Grid.Row="0" Grid.Column="1" x:Name="aList" Margin="0,0,7,9" Padding="7,5"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" DisplayMemberPath="Name"/>
    <StackPanel Grid.Row="0" Grid.Column="2" Orientation="Horizontal" Margin="0,0,0,9">
      <Button x:Name="aNew"  Content="新建" Padding="11,5" Margin="0,0,5,0" Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"/>
      <Button x:Name="aCopy" Content="复制" Padding="11,5" Margin="0,0,5,0" Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"/>
      <Button x:Name="aDel"  Content="删除" Padding="11,5" Background="@CritBg@" Foreground="@Crit@" BorderBrush="@Crit@" Cursor="Hand"/>
    </StackPanel>

    <Border Grid.Row="1" Grid.ColumnSpan="3" Height="1" Background="@Line@" Margin="0,0,0,11"/>

    <TextBlock Grid.Row="2" Grid.Column="0" Text="名称" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,9"/>
    <TextBox   Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="2" x:Name="aName" Margin="0,0,0,9" Padding="7,6"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" CaretBrush="@Ink@"/>

    <TextBlock Grid.Row="3" Grid.Column="0" Text="协议" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,9"/>
    <ComboBox  Grid.Row="3" Grid.Column="1" x:Name="aProto" Margin="0,0,7,9" Padding="7,5"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@"/>
    <ComboBox  Grid.Row="3" Grid.Column="2" x:Name="aPreset" Width="150" Margin="0,0,0,9" Padding="7,5"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" ToolTip="套用预设地址"/>

    <TextBlock Grid.Row="4" Grid.Column="0" Text="地址" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,9"/>
    <TextBox   Grid.Row="4" Grid.Column="1" x:Name="aUrl" Margin="0,0,7,9" Padding="7,6" FontFamily="Consolas"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" CaretBrush="@Ink@"/>
    <Button    Grid.Row="4" Grid.Column="2" x:Name="aProbe" Content="自动探测" Padding="11,6" Margin="0,0,0,9"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"
               ToolTip="用这个地址和 Key 依次试三种协议，命中即停，并把「协议」自动设成能用的那个"/>

    <TextBlock Grid.Row="5" Grid.Column="0" Text="API Key" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,9"/>
    <PasswordBox Grid.Row="5" Grid.Column="1" Grid.ColumnSpan="2" x:Name="aKey" Margin="0,0,0,9" Padding="7,6"
                 Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@"/>

    <TextBlock Grid.Row="6" Grid.Column="0" Text="模型" Foreground="@Muted@" VerticalAlignment="Center" Margin="0,0,0,9"/>
    <ComboBox  Grid.Row="6" Grid.Column="1" x:Name="aModel" Margin="0,0,7,9" Padding="7,5" IsEditable="True"
               Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@"/>
    <StackPanel Grid.Row="6" Grid.Column="2" Orientation="Horizontal" Margin="0,0,0,9">
      <Button x:Name="aFetch" Content="获取模型" Padding="11,5" Margin="0,0,5,0" Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"/>
      <ComboBox x:Name="aEffort" Width="86" Padding="7,5" Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" ToolTip="思考强度。anthropic 发 output_config.effort；openai 发 reasoning_effort；openai-responses 发 reasoning.effort。非推理模型请选「(不发送)」"/>
    </StackPanel>

    <Border Grid.Row="7" Grid.ColumnSpan="3" Background="@WarnBg@" BorderBrush="@Warn@" BorderThickness="1"
            CornerRadius="6" Padding="12,10" Margin="0,2,0,0">
      <ScrollViewer VerticalScrollBarVisibility="Auto">
        <StackPanel>
          <CheckBox x:Name="aRedact" Margin="0,0,0,8" Foreground="@Ink@"
                    Content="发送前脱敏（把用户名 / 主机名 / 用户目录替换成占位符）"/>
          <TextBlock Text="这项功能会把数据发送到你配置的服务器" FontWeight="SemiBold" Foreground="@Warn@" Margin="0,0,0,5"/>
          <TextBlock x:Name="aInfo" TextWrapping="Wrap" FontSize="12" Foreground="@Ink2@"/>
        </StackPanel>
      </ScrollViewer>
    </Border>

    <StackPanel Grid.Row="8" Grid.ColumnSpan="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,13,0,0">
      <Button x:Name="aTest" Content="测试连接" Padding="16,7" Margin="0,0,8,0"
              Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"/>
      <Button x:Name="aOk" Content="保存并启用" Padding="20,7" Margin="0,0,8,0" FontWeight="SemiBold" IsDefault="True"
              Background="@Accent@" Foreground="@AccentInk@" BorderBrush="@Accent@" Cursor="Hand"/>
      <Button x:Name="aNo" Content="取消" Padding="20,7" IsCancel="True"
              Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"/>
    </StackPanel>
  </Grid>
</Window>
'@
    $x = $raw
    foreach ($k in $P.Keys) { $x = $x.Replace("@$k@", $P[$k]) }
    $d = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$x)))
    $d.Owner = $win

    $c = @{}
    foreach ($n in 'aList','aNew','aCopy','aDel','aName','aProto','aPreset','aUrl','aProbe','aKey',
                   'aModel','aFetch','aEffort','aRedact','aInfo','aTest','aOk','aNo') { $c[$n] = $d.FindName($n) }

    # 编辑中的副本：取消就整个丢弃，不动磁盘上的配置
    $work = [System.Collections.Generic.List[object]]@(@($cfg.Providers) | ForEach-Object { ConvertTo-AiProvider ([pscustomobject]$_) })
    $state = @{ Idx = 0; Loading = $false }

    $c.aProto.ItemsSource  = $script:AI_PROTOCOLS
    $c.aEffort.ItemsSource = @('(不发送)','low','medium','high','xhigh','max')
    $c.aPreset.ItemsSource = @('套用预设…') + @($script:AI_PRESETS.Keys)
    $c.aPreset.SelectedIndex = 0
    $c.aRedact.IsChecked = [bool]$cfg.Redact
    $c.aInfo.Text = @"
每次分析会发送所选条目的元数据：名称、启动位置、命令行、目标路径、数字签名状态与签署者、
文件是否存在、以及本地规则给出的初步风险判断。不会发送任何文件内容或你没选中的启动项。

API Key 用 Windows DPAPI 加密后保存在 $($script:AiCfgFile)，只有当前 Windows 账户能解密。
留空则回退到环境变量（anthropic 协议读 ANTHROPIC_API_KEY，openai 协议读 OPENAI_API_KEY）。

地址填到域名即可，程序会自动补 /v1。三种协议对应的端点：
  anthropic          -> /v1/messages
  openai             -> /v1/chat/completions        （Chat Completions）
  openai-responses   -> /v1/responses               （Responses API）
不确定该选哪个就填好地址和模型，点「自动探测」—— 会依次真发一次请求，命中即停并自动回填。
"@

    # 表单 <-> 当前 provider 的双向同步
    function Sync-ToForm {
        $state.Loading = $true
        try {
            $pv = $work[$state.Idx]
            $c.aName.Text          = $pv.Name
            $c.aProto.SelectedItem = $pv.Protocol
            $c.aUrl.Text           = $pv.BaseUrl
            $c.aKey.Password       = (Unprotect-AiKey $pv.KeyEnc)
            $c.aModel.ItemsSource  = @($pv.Model) | Where-Object { $_ }
            $c.aModel.Text         = $pv.Model
            $c.aEffort.SelectedItem = $(if ($pv.Effort) { $pv.Effort } else { '(不发送)' })
            if (-not $c.aEffort.SelectedItem) { $c.aEffort.SelectedIndex = 0 }
            # 三种协议都能带思考强度，只是字段不同（output_config.effort /
            # reasoning_effort / reasoning.effort）。非推理模型请选「(不发送)」。
            $c.aEffort.IsEnabled = $true
            $c.aDel.IsEnabled    = ($work.Count -gt 1)
        } finally { $state.Loading = $false }
    }
    function Sync-FromForm {
        if ($state.Loading) { return }
        $pv = $work[$state.Idx]
        $pv.Name     = $c.aName.Text.Trim()
        $pv.Protocol = [string]$c.aProto.SelectedItem
        $pv.BaseUrl  = $c.aUrl.Text.Trim()
        $pv.KeyEnc   = $(if ($c.aKey.Password) { Protect-AiKey $c.aKey.Password } else { '' })
        $pv.Model    = ([string]$c.aModel.Text).Trim()
        $ef = [string]$c.aEffort.SelectedItem
        $pv.Effort = $(if ($ef -eq '(不发送)') { '' } else { $ef })
    }
    function Reload-List {
        $state.Loading = $true
        try {
            $c.aList.ItemsSource = $null
            $c.aList.ItemsSource = @($work | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Id = $_.Id } })
            $c.aList.SelectedIndex = $state.Idx
        } finally { $state.Loading = $false }
    }

    $state.Idx = [Math]::Max(0, [array]::IndexOf(@($work | ForEach-Object { $_.Id }), [string]$cfg.Active))
    Reload-List
    Sync-ToForm

    $c.aList.Add_SelectionChanged({
        if ($state.Loading -or $c.aList.SelectedIndex -lt 0) { return }
        Sync-FromForm
        $state.Idx = $c.aList.SelectedIndex
        Sync-ToForm
    })
    # 名称改了要同步到下拉里
    $c.aName.Add_LostFocus({ if (-not $state.Loading) { Sync-FromForm; Reload-List } })
    $c.aProto.Add_SelectionChanged({
        if ($state.Loading) { return }
        Sync-FromForm
    })
    $c.aPreset.Add_SelectionChanged({
        if ($state.Loading -or $c.aPreset.SelectedIndex -le 0) { return }
        $k = [string]$c.aPreset.SelectedItem
        $ps = $script:AI_PRESETS[$k]
        if ($ps) {
            $c.aProto.SelectedItem = $ps.Protocol
            $c.aUrl.Text           = $ps.BaseUrl
            if ($ps.Model) { $c.aModel.Text = $ps.Model }
            if (-not $c.aName.Text -or $c.aName.Text -eq '新建配置') { $c.aName.Text = $k }
            Sync-FromForm; Reload-List
        }
        $c.aPreset.SelectedIndex = 0
    })

    $c.aNew.Add_Click({
        Sync-FromForm
        $work.Add((New-AiProvider))
        $state.Idx = $work.Count - 1
        Reload-List; Sync-ToForm
        $c.aName.Focus() | Out-Null; $c.aName.SelectAll()
    })
    $c.aCopy.Add_Click({
        Sync-FromForm
        $src = $work[$state.Idx]
        $cp  = ConvertTo-AiProvider ([pscustomobject]$src)
        $cp.Id   = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $cp.Name = "$($src.Name) 副本"
        $work.Add($cp)
        $state.Idx = $work.Count - 1
        Reload-List; Sync-ToForm
    })
    $c.aDel.Add_Click({
        if ($work.Count -le 1) { Show-Msg '至少要保留一套配置。' '提示' 'Warning'; return }
        if (-not (Confirm-Msg "删除配置「$($work[$state.Idx].Name)」？")) { return }
        $work.RemoveAt($state.Idx)
        $state.Idx = [Math]::Max(0, $state.Idx - 1)
        Reload-List; Sync-ToForm
    })

    # 一次构造好的探针载荷，探测和测试连接共用
    $script:AiProbePayload = [ordered]@{
        name='TestEntry'; type='注册表 Run'; location='HKCU:\...\Run'
        command='"C:\Windows\System32\notepad.exe"'; target='C:\Windows\System32\notepad.exe'
        file_state='存在'; signer='Microsoft Windows'; signature='Valid'
        enabled=$true; local_risk='正常 — 签名有效，路径正常'
    }

    # 自动探测：三种协议依次试，命中即停并回填「协议」
    $c.aProbe.Add_Click({
        Sync-FromForm
        $pv  = ConvertTo-AiProvider ([pscustomobject]$work[$state.Idx])
        $key = Get-AiKey $pv
        if (-not $key)      { Show-Msg '请先填写 API Key（或设置对应的环境变量）。' '缺少信息' 'Warning'; return }
        if (-not $pv.Model) { Show-Msg '请先填写模型（探测要真发一次请求）。' '缺少信息' 'Warning'; return }
        # 当前选中的协议排第一，其余按常见程度排后面
        $order = @($pv.Protocol) + @($script:AI_PROTOCOLS | Where-Object { $_ -ne $pv.Protocol })
        $c.aProbe.IsEnabled = $false; $c.aProbe.Content = '探测中…'
        $pg = [hashtable]::Synchronized(@{ Stage='探测中'; Done=0; Total=$order.Count })
        Start-BgWork -Body $script:AI_PROBE_BODY -Functions $script:AiFns -Vars @{
            SM_Provider  = $pv
            SM_Key       = $key
            SM_Probe     = $script:AiProbePayload
            SM_Order     = [string[]]$order
            SM_Version   = $script:AI_VERSION
            SM_System    = $script:AI_SYSTEM
            SM_Schema    = $script:AI_SCHEMA
            SM_Protocols = $script:AI_PROTOCOLS
            SM_PROGRESS  = $pg
        } -OnDone {
            param($result, $err)
            try {
                if ($err) { Show-Msg $err '探测失败' 'Error'; return }
                $r = @($result)[0]
                $lines = @($r.Results | ForEach-Object {
                    if ($_.Ok) { "✓ $($_.Protocol)`n   $($_.Endpoint)`n   应答模型：$($_.Model)" }
                    else       { "✗ $($_.Protocol)`n   $($_.Endpoint)`n   $($_.Error -split "`n" | Select-Object -First 1)" }
                })
                if ($r.Hit) {
                    $c.aProto.SelectedItem = [string]$r.Hit
                    Sync-FromForm
                    Show-Msg ("探测完成，已把「协议」设为 $($r.Hit)。`n`n" + ($lines -join "`n`n")) '探测成功'
                } else {
                    Show-Msg ("三种协议都没走通：`n`n" + ($lines -join "`n`n")) '探测失败' 'Error'
                }
            } finally { $c.aProbe.IsEnabled = $true; $c.aProbe.Content = '自动探测' }
        }.GetNewClosure() | Out-Null
    })

    # 获取模型：走后台，别卡住对话框
    $c.aFetch.Add_Click({
        Sync-FromForm
        $pv  = ConvertTo-AiProvider ([pscustomobject]$work[$state.Idx])
        $key = Get-AiKey $pv
        if (-not $key) { Show-Msg '请先填写 API Key（或设置对应的环境变量）。' '缺少信息' 'Warning'; return }
        $c.aFetch.IsEnabled = $false; $c.aFetch.Content = '获取中…'
        $body = @'
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 6) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
}
$script:AI_VERSION = $SM_Version
[pscustomobject]@{ Models = @(Get-AiModelList -Provider $SM_Provider -Key $SM_Key) }
'@
        Start-BgWork -Body $body -Functions $script:AiFns -Vars @{
            SM_Provider = $pv; SM_Key = $key; SM_Version = $script:AI_VERSION
        } -OnDone {
            param($result, $err)
            try {
                if ($err) { Show-Msg $err '获取模型失败' 'Error'; return }
                $ms = @(@($result)[0].Models)
                if ($ms.Count -eq 0) { Show-Msg '该服务没有返回任何模型。可以直接在「模型」框里手填。' '没有模型' 'Warning'; return }
                $cur = [string]$c.aModel.Text
                $c.aModel.ItemsSource = $ms
                if ($cur -and ($ms -contains $cur)) { $c.aModel.SelectedItem = $cur } else { $c.aModel.Text = $cur }
                $c.aModel.IsDropDownOpen = $true
                Show-Msg "拉到 $($ms.Count) 个模型，已填进下拉列表。" '获取成功'
            } finally { $c.aFetch.IsEnabled = $true; $c.aFetch.Content = '获取模型' }
        }.GetNewClosure() | Out-Null
    })

    $c.aTest.Add_Click({
        Sync-FromForm
        $pv  = ConvertTo-AiProvider ([pscustomobject]$work[$state.Idx])
        $key = Get-AiKey $pv
        if (-not $key)   { Show-Msg '请先填写 API Key（或设置对应的环境变量）。' '缺少信息' 'Warning'; return }
        if (-not $pv.Model) { Show-Msg '请先填写或选择模型。' '缺少信息' 'Warning'; return }
        $c.aTest.IsEnabled = $false; $c.aTest.Content = '测试中…'
        $probe = [object[]]@(, [object[]]@($script:AiProbePayload))
        $pg = [hashtable]::Synchronized(@{ Stage='测试中'; Done=0; Total=1 })
        Start-BgWork -Body $script:AI_BODY -Functions $script:AiFns -Vars @{
            SM_Provider  = $pv
            SM_Key       = $key
            SM_Batches   = $probe
            SM_Version   = $script:AI_VERSION
            SM_System    = $script:AI_SYSTEM
            SM_Schema    = $script:AI_SCHEMA
            SM_Protocols = $script:AI_PROTOCOLS
            SM_PROGRESS  = $pg
        } -OnDone {
            param($result, $err)
            try {
                if ($err) { Show-Msg $err '测试失败' 'Error'; return }
                $r = @($result)[0]
                if (@($r.Errors).Count) { Show-Msg (@($r.Errors) -join "`n") '测试失败' 'Error'; return }
                Show-Msg ("连接成功。`n`n端点：{0}`n应答模型：{1}`n输入 {2} tok · 输出 {3} tok" -f `
                          (Get-AiEndpoint $pv 'messages'), $r.Model, $r.In, $r.Out) '测试通过'
            } finally { $c.aTest.IsEnabled = $true; $c.aTest.Content = '测试连接' }
        }.GetNewClosure() | Out-Null
    })

    $script:aiCfgResult = $null
    $c.aOk.Add_Click({
        Sync-FromForm
        foreach ($pv in $work) { if (-not $pv.Name) { $pv.Name = '未命名' } }
        $script:aiCfgResult = [ordered]@{
            Active    = $work[$state.Idx].Id      # 当前编辑的这套就是启用的那套
            Providers = @($work)
            Redact    = [bool]$c.aRedact.IsChecked
            Consented = $true
        }
        $d.DialogResult = $true; $d.Close()
    })
    # aNo 是 IsCancel，交给 WPF 处理

    if ($d.ShowDialog() -ne $true) { return $null }
    Save-AiConfig $script:aiCfgResult
    Update-AiProviderBar
    return $script:aiCfgResult
}

# ── AI 分析结果窗口 ──
function Show-AiReport {
    param([object[]]$Rows, [string]$Summary, [string]$Meta)
    $raw = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AI 分析结果" Height="620" Width="1000" ResizeMode="CanResize"
        WindowStartupLocation="CenterOwner" Background="@Ground@"
        FontFamily="Microsoft YaHei UI, Segoe UI" FontSize="13">
  <Grid Margin="18">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0" x:Name="rHead" FontSize="17" FontWeight="Bold" Foreground="@Ink@" Margin="0,0,0,6"/>
    <Border Grid.Row="1" Background="@AccentSoft@" BorderBrush="@Accent@" BorderThickness="1"
            CornerRadius="6" Padding="12,9" Margin="0,0,0,11">
      <TextBlock x:Name="rSum" TextWrapping="Wrap" FontSize="12.5" Foreground="@Ink@"/>
    </Border>

    <Border Grid.Row="2" Background="@Surface@" BorderBrush="@Line@" BorderThickness="1" CornerRadius="7">
      <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="4">
        <ItemsControl x:Name="rList" Margin="10">
          <ItemsControl.ItemTemplate>
            <DataTemplate>
              <Border Background="@Surface2@" BorderBrush="@Line@" BorderThickness="1" CornerRadius="6"
                      Padding="13,11" Margin="0,0,0,9">
                <StackPanel>
                  <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                    <Border Background="{Binding Bg}" BorderBrush="{Binding Fg}" BorderThickness="1"
                            CornerRadius="4" Padding="7,2" Margin="0,0,9,0">
                      <TextBlock Text="{Binding Badge}" FontSize="11.5" FontWeight="Bold" Foreground="{Binding Fg}"/>
                    </Border>
                    <TextBlock Text="{Binding Name}" FontWeight="Bold" FontSize="14" Foreground="@Ink@" VerticalAlignment="Center"/>
                    <TextBlock Text="{Binding Need}" FontSize="11.5" Foreground="@Muted@" Margin="10,0,0,0" VerticalAlignment="Center"/>
                  </StackPanel>
                  <TextBlock Text="{Binding Identity}" TextWrapping="Wrap" FontSize="12.5" Foreground="@Ink2@" Margin="0,0,0,5"/>
                  <TextBlock Text="{Binding Findings}" TextWrapping="Wrap" FontSize="12" Foreground="@Muted@" Margin="0,0,0,5"/>
                  <TextBlock Text="{Binding Advice}" TextWrapping="Wrap" FontSize="12.5" FontWeight="SemiBold" Foreground="@Ink@"/>
                  <TextBlock Text="{Binding Ops}" TextWrapping="Wrap" FontSize="11.5" Foreground="@Muted@" Margin="0,5,0,0"/>
                </StackPanel>
              </Border>
            </DataTemplate>
          </ItemsControl.ItemTemplate>
        </ItemsControl>
      </ScrollViewer>
    </Border>

    <Grid Grid.Row="3" Margin="0,12,0,0">
      <TextBlock x:Name="rMeta" FontSize="11.5" Foreground="@Muted@" VerticalAlignment="Center"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="rCopy" Content="复制为文本" Padding="16,7" Margin="0,0,8,0"
                Background="@Surface@" Foreground="@Ink@" BorderBrush="@Line2@" Cursor="Hand"/>
        <Button x:Name="rOk" Content="关闭" Padding="22,7" IsDefault="True" IsCancel="True"
                Background="@Accent@" Foreground="@AccentInk@" BorderBrush="@Accent@" Cursor="Hand"/>
      </StackPanel>
    </Grid>
  </Grid>
</Window>
'@
    $x = $raw
    foreach ($k in $P.Keys) { $x = $x.Replace("@$k@", $P[$k]) }
    $d = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$x)))
    $d.Owner = $win
    $d.FindName('rHead').Text = "AI 分析结果 · 共 $($Rows.Count) 项"
    $d.FindName('rSum').Text  = $Summary
    $d.FindName('rMeta').Text = $Meta
    $d.FindName('rList').ItemsSource = @($Rows)
    $d.FindName('rCopy').Add_Click({
        $txt = "AI 分析结果`n$Meta`n`n整体判断：$Summary`n`n" +
               (($Rows | ForEach-Object {
                   "【$($_.Badge)】$($_.Name)  $($_.Need)`n$($_.Identity)`n$($_.Findings)`n建议：$($_.Advice)`n$($_.Ops)`n"
               }) -join "`n")
        try { Set-Clipboard -Value $txt; Show-Msg '已复制到剪贴板。' } catch { Show-Msg "复制失败：$($_.Exception.Message)" '错误' 'Error' }
    })
    $d.FindName('rOk').Add_Click({ $d.Close() })
    $d.ShowDialog() | Out-Null
}

# 主界面上的配置下拉：显示全部配置，选中即切换（立刻落盘）
function Update-AiProviderBar {
    if (-not $UI -or -not $UI.cboAi) { return }
    $script:Flags['AiBarLoading'] = $true
    try {
        $cfg = Get-AiConfig
        $ids = @($cfg.Providers | ForEach-Object { [string]$_.Id })
        $UI.cboAi.ItemsSource = @($cfg.Providers | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Id = $_.Id } })
        $UI.cboAi.SelectedIndex = [Math]::Max(0, [array]::IndexOf($ids, [string]$cfg.Active))
        $p = Get-AiActiveProvider $cfg
        $mdl = $(if ($p.Model) { $p.Model } else { '（未选择）' })
        $UI.cboAi.ToolTip = "当前配置：$($p.Name)`n协议：$($p.Protocol)`n端点：$(Get-AiEndpoint $p 'messages')`n模型：$mdl`n`n下拉可一键切换"
    } catch {
        $UI.cboAi.ToolTip = 'AI 配置读取失败'
    } finally {
        $script:Flags['AiBarLoading'] = $false
    }
}

function Invoke-AiOnItems {
    param([object[]]$Items)

    $cfg  = Get-AiConfig
    $prov = Get-AiActiveProvider $cfg
    if (-not (Get-AiKey $prov) -or -not $cfg.Consented) {
        Show-Msg "首次使用需要先配置 API Key，并确认发送内容。`n`n即将打开「AI 设置」。" 'AI 分析' 'Information'
        if (-not (Show-AiConfigDialog)) { return }
        $cfg  = Get-AiConfig
        $prov = Get-AiActiveProvider $cfg
        if (-not (Get-AiKey $prov)) { return }
    }
    $key = Get-AiKey $prov
    if (-not $prov.Model) { Show-Msg "配置「$($prov.Name)」还没有选择模型。请在「⚙」里填写或点「获取模型」。" '缺少模型' 'Warning'; return }

    if ($Items.Count -gt 40) {
        if (-not (Confirm-Msg "当前目标有 $($Items.Count) 项，将分 $([Math]::Ceiling($Items.Count / $script:AI_BATCH)) 次请求发送，耗时和费用都不低。`n`n继续？")) { return }
    }

    # 载荷在 UI 线程构造（很便宜，且要读条目对象），HTTP 请求全部丢到后台。
    # Invoke-RestMethod 单次最长阻塞 300 秒，绝不能放在 UI 线程上。
    $byName = @{}
    foreach ($i in $Items) { $byName[$i.Name] = $i }

    $batches = New-Object System.Collections.Generic.List[object]
    for ($b = 0; $b -lt $Items.Count; $b += $script:AI_BATCH) {
        $n = [Math]::Min($script:AI_BATCH, $Items.Count - $b)
        $chunk = @($Items[$b..($b + $n - 1)])
        $batches.Add([object[]]@($chunk | ForEach-Object { Get-AiItemPayload -Item $_ -Redact ([bool]$cfg.Redact) }))
    }

    # 同样的原因：闭包里读不到 $script:，先落成局部变量
    $vmap = $script:AI_VERDICT_TEXT
    $nmap = $script:AI_NEED_TEXT
    $script:Flags['AiRunning'] = $true
    Set-LoadLock $true
    Set-Busy 'AI 分析中…'
    $prog = [hashtable]::Synchronized(@{ Stage='AI 分析中'; Done=0; Total=$batches.Count })

    Start-BgWork -Body $script:AI_BODY -Functions $script:AiFns -Vars @{
        SM_Provider  = $prov
        SM_Key       = $key
        SM_Batches   = [object[]]$batches.ToArray()
        SM_Version   = $script:AI_VERSION
        SM_System    = $script:AI_SYSTEM
        SM_Schema    = $script:AI_SCHEMA
        SM_Protocols = $script:AI_PROTOCOLS
        SM_PROGRESS  = $prog
    } -OnTick {
        $UI.lblBusy.Text = "$($prog['Stage'])（共 $($prog['Total']) 批）"
    }.GetNewClosure() -OnDone {
        param($result, $err)
        try {
            if ($err) { Show-Msg "AI 分析失败：`n$err" '错误' 'Error'; return }
            $r = @($result)[0]

            # 呈现层（配色）留在 UI 线程做，后台只负责拿数据
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($x in @($r.Rows)) {
                $v  = [string]$x.verdict
                $vt = if ($vmap.ContainsKey($v)) { $vmap[$v] } else { $v }
                $ct = switch ([string]$x.confidence) { 'high' {'高置信'} 'medium' {'中置信'} 'low' {'低置信'} default { '' } }
                $nt = if ($nmap.ContainsKey([string]$x.necessity)) { $nmap[[string]$x.necessity] } else { [string]$x.necessity }
                $fg = switch ($v) { 'malicious' { $P.Crit } 'suspicious' { $P.Warn } 'unknown' { $P.Stale } default { $P.Ok } }
                $bg = switch ($v) { 'malicious' { $P.CritBg } 'suspicious' { $P.WarnBg } 'unknown' { $P.StaleBg } default { $P.OkBg } }
                $row = [pscustomobject]@{
                    Name     = [string]$x.name
                    Badge    = "$vt · $ct"
                    Need     = "开机必要性：$nt"
                    Identity = [string]$x.identity
                    Findings = (@($x.findings) | ForEach-Object { "· $_" }) -join "`n"
                    Advice   = "建议：$([string]$x.recommendation)"
                    Ops      = "可安全禁用：$(if ($x.safe_to_disable) {'是'} else {'否'})    ·    可安全删除：$(if ($x.safe_to_delete) {'是'} else {'否'})"
                    Fg = $fg; Bg = $bg
                }
                $rows.Add($row)
                # 结论写回主表，刷新时按 Kind|Loc|Name 保留
                $it = $byName[[string]$x.name]
                if ($it) { $it.AiVerdict = "$vt·$nt"; $it.AiReport = $row }
            }
            Refresh-Grid; Show-Detail

            $errList = @($r.Errors)
            if ($rows.Count -eq 0) {
                Show-Msg "没有得到任何分析结果。`n`n$($errList -join "`n`n")" 'AI 分析失败' 'Error'
                return
            }
            $meta = "模型 $($r.Model) · 输入 $($r.In) tok · 输出 $($r.Out) tok" +
                    $(if ($cfg.Redact) { ' · 已脱敏' } else { ' · 未脱敏' })
            $summary = (@($r.Sums) -join '  ')
            if ($errList.Count) { $summary += "`n`n（有 $($errList.Count) 批请求失败：" + ($errList -join '；') + '）' }
            Show-AiReport -Rows $rows.ToArray() -Summary $summary -Meta $meta
        } finally { Set-AiIdle }
    }.GetNewClosure() | Out-Null
}

# ══════════════════════════════════════════════════════════════════
#  9. 事件绑定
# ══════════════════════════════════════════════════════════════════
# 事件处理器里抛出的异常会逃到 Dispatcher，而控制台是隐藏的 ——
# 用户看到的就是程序凭空消失。所有处理器统一走这里。
function Invoke-Guarded {
    param([scriptblock]$Body, [string]$What = '操作')
    try { & $Body }
    catch { Show-Msg "$What 失败：`n$($_.Exception.Message)" '错误' 'Error' }
}
$win.Dispatcher.Add_UnhandledException({
    param($s, $e)
    $e.Handled = $true
    try { Show-Msg "发生未处理的错误：`n$($e.Exception.Message)`n`n程序会继续运行，建议刷新后重试。" '错误' 'Error' } catch { }
})

$UI.btnRefresh.Add_Click({ Invoke-Guarded { Load-Items } '刷新' })
$UI.chkSig.Add_Click({ Invoke-Guarded { Load-Items } '刷新' })
$UI.chkMs.Add_Click({ Invoke-Guarded { Load-Items } '刷新' })
$UI.cboKind.Add_SelectionChanged({ Invoke-Guarded { Apply-Filter } '筛选' })
$UI.cboRisk.Add_SelectionChanged({ Invoke-Guarded { Apply-Filter } '筛选' })
$UI.cboState.Add_SelectionChanged({ Invoke-Guarded { Apply-Filter } '筛选' })
$UI.grid.Add_SelectionChanged({ Invoke-Guarded { Show-Detail } '显示详情' })

# 搜索框每敲一个字符原本都会全量重新过滤 + 四键排序 + 重绑 ItemsSource，
# 几百条时逐字卡顿。加 220ms 去抖。
$script:SearchTimer = New-Object Windows.Threading.DispatcherTimer
$script:SearchTimer.Interval = [TimeSpan]::FromMilliseconds(220)
$script:SearchTimer.Add_Tick({ $script:SearchTimer.Stop(); Invoke-Guarded { Apply-Filter } '筛选' })
$UI.txtSearch.Add_TextChanged({ $script:SearchTimer.Stop(); $script:SearchTimer.Start() })

# 枚举失败详情
$UI.lblWarn.Add_MouseLeftButtonUp({
    $e = @($script:LoadErrors)
    if ($e.Count -eq 0) { return }
    $show = @($e | Select-Object -First 25)
    $t = ($show -join "`n")
    if ($e.Count -gt 25) { $t += "`n… 以及另外 $($e.Count - 25) 处" }
    Show-Msg "以下启动位置未能读取，列表可能不完整：`n`n$t" '读取失败的位置' 'Warning'
})

# ── 键盘 ──
# 原本全文没有一个 IsDefault / IsCancel / 快捷键，表格里的复选框连 Tab 都到不了。
$win.Add_KeyDown({
    param($s, $e)
    $ctrl = ([Windows.Input.Keyboard]::Modifiers -band [Windows.Input.ModifierKeys]::Control)
    switch ($e.Key) {
        'F5'     { $UI.btnRefresh.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Primitives.ButtonBase]::ClickEvent))); $e.Handled = $true }
        'Delete' {
            if (-not $UI.txtSearch.IsKeyboardFocusWithin) {
                $UI.btnDel.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Primitives.ButtonBase]::ClickEvent))); $e.Handled = $true
            }
        }
        'F'      { if ($ctrl) { $UI.txtSearch.Focus() | Out-Null; $UI.txtSearch.SelectAll(); $e.Handled = $true } }
        'Escape' {
            if ($UI.txtSearch.Text) { $UI.txtSearch.Text = '' } else { $UI.grid.UnselectAll() }
            $e.Handled = $true
        }
    }
})

$UI.btnNew.Add_Click({
    $r = Show-ItemDialog -Mode 'new'
    if (-not $r) { return }
    try {
        Add-StartupItem -Kind $r.Kind -Scope $r.Scope -Name $r.Name -Exe $r.Exe -Arguments $r.Args
        Load-Items
        Show-Msg "已新建：$($r.Name)`n位置：$($r.Loc)"
    } catch { Show-Msg "新建失败：`n$($_.Exception.Message)" '错误' 'Error' }
})

$UI.btnSelAll.Add_Click({  Set-ViewSelection $true })
$UI.btnSelNone.Add_Click({ foreach ($i in $script:Items) { $i.Sel = $false }; Refresh-Grid; Update-SelCount })
$UI.btnSelInv.Add_Click({  Invert-ViewSelection })
$UI.btnSelStale.Add_Click({ Select-ByPredicate { $_.Risk -eq 'stale' } '失效残留项' })
$UI.btnSelRisk.Add_Click({  Select-ByPredicate { $_.Risk -in @('critical','warning') } '危险或需关注的条目' })

# 复选框的 Checked/Unchecked 会从单元格模板向上冒泡到 DataGrid，
# 在这里统一接住以刷新计数标签（无需给每个 CheckBox 单独挂事件）
$UI.grid.AddHandler(
    [Windows.Controls.Primitives.ToggleButton]::CheckedEvent,
    [Windows.RoutedEventHandler]{ Update-SelCount; Show-Detail })
$UI.grid.AddHandler(
    [Windows.Controls.Primitives.ToggleButton]::UncheckedEvent,
    [Windows.RoutedEventHandler]{ Update-SelCount; Show-Detail })

$UI.btnEdit.Add_Click({
    $sel = Get-TargetItems
    if ($sel.Count -ne 1) { Show-Msg "编辑一次只能处理一个条目（当前目标 $($sel.Count) 个）。" '提示' 'Warning'; return }
    $i = $sel[0]
    if (-not $i.CanEdit) {
        $why = if ($i.Kind -eq 'UWP') { 'UWP 启动任务的信息来自应用清单，不能像注册表 Run 项那样改名或改命令。' }
               elseif ($i.Kind -eq 'Service') { '服务的可执行文件路径改起来风险高（改错会导致服务无法启动，且本工具无法可靠回滚），请用 sc config 手工修改。' }
               else { '此类型不支持直接编辑。' }
        Show-Msg ("「$($i.Label)」类型不支持在此编辑。`n`n$why") '不支持' 'Warning'
        return
    }
    $r = Show-ItemDialog -Mode 'edit' -Item $i
    if (-not $r) { return }
    try {
        $cmd = if ($r.Args) { "`"$($r.Exe)`" $($r.Args)" } else { "`"$($r.Exe)`"" }
        Update-StartupItem -Item $i -NewName $r.Name -NewCmd $cmd
        Load-Items
        Show-Msg "已更新：$($r.Name)"
    } catch { Show-Msg "编辑失败：`n$($_.Exception.Message)" '错误' 'Error' }
})

$UI.btnToggle.Add_Click({ Invoke-Guarded {
    $selected = Get-TargetItems
    if ($selected.Count -eq 0) { Show-Msg '请先勾选或选中条目。' '提示' 'Warning'; return }

    if ($selected.Count -gt 1) {
        $on  = @($selected | Where-Object { $_.Enabled }).Count
        $off = $selected.Count - $on
        $note = "本工具内切换：已启用的 $on 项将被禁用，已禁用的 $off 项将被重新启用。UWP 启动任务使用 Windows 原生 State 状态；策略锁定项会报告失败。"
        if (-not (Show-BatchConfirm -Items $selected -Verb '切换' -Danger $false -Extra $note)) { return }
    }

    $ok = 0; $errs = New-Object System.Collections.Generic.List[string]
    foreach ($i in $selected) {
        if (-not $i.CanToggle) { $errs.Add("$($i.Name)：$($i.Label) 不支持启用/禁用（可能受系统策略限制）"); continue }
        try {
            Set-StartupItemEnabled -Item $i -Enabled (-not $i.Enabled)
            $ok++
        } catch { $errs.Add("$($i.Name)：$($_.Exception.Message)") }
    }
    Load-Items
    $m = "已切换 $ok 项。"
    if ($errs.Count) { $m += "`n`n未处理 $($errs.Count) 项：`n" + (Format-ErrList $errs) }
    Show-Msg $m
} '启用/禁用' })

$UI.btnDel.Add_Click({ Invoke-Guarded {
    $requested = Get-TargetItems
    if ($requested.Count -eq 0) { Show-Msg '请先勾选条目，或在表格里选中行。' '提示' 'Warning'; return }
    $blocked = @($requested | Where-Object { -not $_.CanDelete })
    $sel = @($requested | Where-Object { $_.CanDelete })
    if ($sel.Count -eq 0) {
        Show-Msg ("所选的 $($blocked.Count) 项都不支持删除。UWP 启动任务由应用清单注册，请使用启用/禁用；需要移除应用时请到 Windows 设置中卸载。") '不支持删除' 'Warning'
        return
    }
    $extraWarning = if ($blocked.Count -gt 0) { "将跳过 $($blocked.Count) 项不支持删除的条目：" + (($blocked | Select-Object -ExpandProperty Name) -join '、') } else { '' }
    if (-not (Show-BatchConfirm -Items $sel -Verb '删除' -Extra $extraWarning)) { return }

    # 同一次批量删除共用一个批次号，「撤销上一步」可整批还原
    $batch = if ($sel.Count -gt 1) { [guid]::NewGuid().ToString('N') } else { '' }
    # 日志一次性预写：仍然全部在任何破坏性操作之前，但把 N 次全文件读写降到 1 次
    Write-JournalRecords -Records @($sel | ForEach-Object { New-JournalRecord -Item $_ -Action 'delete' -Batch $batch })

    $ok = 0; $errs = New-Object System.Collections.Generic.List[string]
    foreach ($i in $sel) {
        try { Remove-StartupItem -Item $i -Batch $batch -SkipJournal; $ok++ }
        catch { $errs.Add("$($i.Name)：$($_.Exception.Message)") }
    }
    Load-Items
    $undoable = @($sel | Where-Object { Test-RecordUndoable -Action 'delete' -Kind $_.Kind -Extra $_.Extra }).Count
    $m = "已删除 $ok / $($sel.Count) 项。"
    if ($blocked.Count -gt 0) { $m += "`n`n已跳过 $($blocked.Count) 项不支持删除的条目：" + (($blocked | Select-Object -ExpandProperty Name) -join '、') }
    if ($ok -gt 0) {
        $m += if ($undoable -eq 0) { "`n`n这些条目无法用「撤销上一步」恢复（计划任务 / 服务 / 脚本文件），需手动重建。" }
              elseif ($undoable -lt $ok) { "`n`n其中 $undoable 项可用「撤销上一步」还原，其余 $($ok - $undoable) 项需手动重建。" }
              elseif ($batch) { "`n`n这 $ok 项属于同一批次，点「撤销上一步」可一次性整批还原。" }
              else { "`n`n可点「撤销上一步」还原。" }
    }
    if ($errs.Count) { $m += "`n`n失败 $($errs.Count) 项：`n" + (Format-ErrList $errs) }
    Show-Msg $m
} '删除' })

# 进程是管理员且继承用户 PATH，调系统程序一律用绝对路径
$SYS  = [Environment]::SystemDirectory
$EXPL = Join-Path ([Environment]::GetFolderPath('Windows')) 'explorer.exe'

$UI.btnLocate.Add_Click({ Invoke-Guarded {
    $sel = Get-TargetItems
    if ($sel.Count -ne 1) { Show-Msg "「定位文件」一次只能处理一个条目（当前目标 $($sel.Count) 个）。" '提示' 'Warning'; return }
    $t = $sel[0].Target
    if ($sel[0].Kind -eq 'UWP') { Start-Process 'ms-settings:startupapps'; return }
    if ($t -and (Test-Path -LiteralPath $t)) { Start-Process $EXPL "/select,`"$t`"" }
    else { Show-Msg "目标文件不存在：`n$t" '找不到文件' 'Warning' }
} '定位文件' })

$UI.btnReg.Add_Click({ Invoke-Guarded {
    $sel = Get-TargetItems
    if ($sel.Count -ne 1) { Show-Msg "「打开位置」一次只能处理一个条目（当前目标 $($sel.Count) 个）。" '提示' 'Warning'; return }
    $i = $sel[0]
    switch ($i.Kind) {
        'Run' {
            $p = $i.Loc -replace '^HKCU:', 'HKEY_CURRENT_USER' -replace '^HKLM:', 'HKEY_LOCAL_MACHINE' -replace '^Registry::', ''
            Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit' -Name LastKey -Value $p -Force -ErrorAction SilentlyContinue
            Start-Process (Join-Path ([Environment]::GetFolderPath('Windows')) 'regedit.exe')
        }
        'Folder'  { Start-Process $EXPL "/select,`"$($i.Extra.File)`"" }
        'Task'    { Start-Process (Join-Path $SYS 'taskschd.msc') }
        'Service' { Start-Process (Join-Path $SYS 'services.msc') }
        'UWP'     { Start-Process 'ms-settings:startupapps' }
    }
} '打开位置' })

# ── AI 分析 ──
$UI.btnAi.Add_Click({ Invoke-Guarded {
    $sel = Get-TargetItems
    if ($sel.Count -eq 0) { Show-Msg '请先勾选条目，或在表格里选中行。' '提示' 'Warning'; return }
    Invoke-AiOnItems -Items $sel
} 'AI 分析' })

$UI.btnAiCfg.Add_Click({ Invoke-Guarded { Show-AiConfigDialog | Out-Null } 'AI 设置' })

# 一键切换：选中即生效并落盘，不用进设置对话框
$UI.cboAi.Add_SelectionChanged({
    if ($script:Flags['AiBarLoading'] -or $UI.cboAi.SelectedIndex -lt 0) { return }
    Invoke-Guarded {
        $sel = $UI.cboAi.SelectedItem
        if (-not $sel) { return }
        $cfg = Get-AiConfig
        if ([string]$cfg.Active -eq [string]$sel.Id) { return }
        $cfg.Active = [string]$sel.Id
        Save-AiConfig $cfg
        Update-AiProviderBar
        Set-Busy ''
    } '切换 AI 配置'
})

$UI.btnUndo.Add_Click({ Invoke-Guarded {
    $grp = Get-LastJournalGroup
    if ($grp.Count -eq 0) { Show-Msg '回滚日志为空，没有可撤销的操作。' '提示' 'Warning'; return }
    $act = switch ($grp[0].Action) { 'delete' { '删除' } 'edit' { '编辑' } default { $grp[0].Action } }
    # 旧记录没有 Undoable 字段，按类型现算一次，避免升级后判断失真
    $no = @($grp | Where-Object {
        if ($null -ne $_.Undoable) { -not $_.Undoable }
        else { -not (Test-RecordUndoable -Action $_.Action -Kind $_.Kind -Extra $_.Extra) }
    })
    $msg = if ($grp.Count -eq 1) {
        "撤销这一步？`n`n时间：$($grp[0].Time)`n动作：$act`n条目：$($grp[0].Name)`n位置：$($grp[0].Loc)"
    } else {
        $list = ($grp | Select-Object -First 15 | ForEach-Object { "  · $($_.Name)" }) -join "`n"
        if ($grp.Count -gt 15) { $list += "`n  … 以及另外 $($grp.Count - 15) 项" }
        "撤销上一批操作？`n`n时间：$($grp[0].Time)`n动作：批量$act，共 $($grp.Count) 项`n`n$list"
    }
    # 撤销会把整批出栈。哪些恢复不了，必须在点下去之前就说清楚。
    if ($no.Count -gt 0) {
        $msg += "`n`n注意：其中 $($no.Count) 项无法自动恢复（计划任务 / 服务 / 脚本文件 / 快捷方式编辑）。" +
                "`n撤销后这批记录会移出回滚日志，原始信息将存档到 unrecoverable.json 供手工重建。"
    }
    if (-not (Confirm-Msg $msg)) { return }
    $m = Undo-LastAction
    Load-Items
    Show-Msg $m
} '撤销' })

$UI.btnExport.Add_Click({ Invoke-Guarded {
    $sfd = New-Object Microsoft.Win32.SaveFileDialog
    $sfd.Filter = 'CSV 表格|*.csv|JSON 快照|*.json'
    $sfd.FileName = "启动项快照_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    if (-not $sfd.ShowDialog()) { return }
    # PS7 的 -Encoding UTF8 是**无 BOM**，Excel 会按 ANSI 解码，中文全乱码。
    # 主程序就是用 pwsh7 启动的，所以这个坑必中 —— 导出一律带 BOM。
    if ($sfd.FileName -match '\.json$') {
        ($script:Items | Select-Object Name,Command,Target,Kind,Scope,Label,Loc,Enabled,Signer,SigStatus,Exists,Risk,RiskNote,AiVerdict |
            ConvertTo-Json -Depth 5) | Set-Content $sfd.FileName -Encoding $script:ENC_BOM
    } else {
        $script:Items | Select-Object @{N='名称';E={$_.Name}}, @{N='状态';E={$_.StateText}},
            @{N='风险';E={$_.RiskText}}, @{N='类型';E={$_.Label}}, @{N='命令';E={$_.Command}},
            @{N='目标路径';E={$_.Target}}, @{N='文件状态';E={$_.ExistText}},
            @{N='签署者';E={$_.Signer}}, @{N='签名状态';E={$_.SigText}},
            @{N='AI 结论';E={$_.AiVerdict}},
            @{N='位置';E={$_.Loc}}, @{N='风险说明';E={$_.RiskNote}} |
            Export-Csv $sfd.FileName -NoTypeInformation -Encoding $script:ENC_BOM
    }
    Show-Msg "已导出 $($script:Items.Count) 条到：`n$($sfd.FileName)"
} '导出' })

$UI.grid.Add_MouseDoubleClick({ $UI.btnLocate.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) })

# ══════════════════════════════════════════════════════════════════
#  10. 启动
# ══════════════════════════════════════════════════════════════════
# 首次枚举原本在 ShowDialog() 之前跑，而控制台已被隐藏 ——
# UAC 过后屏幕上几十秒什么都没有，用户会以为没启动、反复双击拉起多个实例。
# 改成窗口渲染完成后再枚举，先让界面出来。
# DataGrid 的第一次绑定要连带解析行/单元格模板、加载 Consolas 与雅黑字体、
# JIT 掉一大堆 WPF 代码 —— 实测冷绑约 900ms，热绑只要 200ms。
# 拿一行空占位先把这些一次性成本走掉，之后真实数据上屏就是热路径。
# UpdateLayout 是同步的，绑定与清空在同一个调度周期内完成，屏幕上不会闪出这一行。
function Initialize-GridWarmup {
    try {
        $probe = New-Item2 -Name '' -Cmd '' -Kind 'Run' -Scope '' -Label '' -Loc '' `
                           -Enabled $true -CanToggle $false -CanEdit $false -CanDelete $false -Extra @{}
        $UI.grid.ItemsSource = @($probe)
        $UI.grid.UpdateLayout()
    } catch { } finally {
        $UI.grid.ItemsSource = $null
    }
}

$win.Add_ContentRendered({
    # Load-Items 现在是异步的：立刻返回，界面可交互，结果到位后自行刷新
    Invoke-Guarded { Update-AiProviderBar; Initialize-GridWarmup; Load-Items } '加载启动项'
})
# 还在跑的后台 Runspace 不清掉，进程不会退出
$win.Add_Closed({ Stop-AllBgWork })
$win.ShowDialog() | Out-Null
Stop-AllBgWork