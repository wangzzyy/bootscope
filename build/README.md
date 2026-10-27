# BootScopeTray（启视 BootScope）

Windows 托盘前端 + PowerShell 启动项管理脚本。托盘菜单用于按分组启用/禁用启动项、打开原有主窗口、管理当前用户开机启动，以及可选安装/移除永久管理员后台。

> 本说明描述本项目 v16 的当前实现。修改权限流程时，请同时检查 `Program.cs`、`BootScope_grouped_clickfix_v26_cli.ps1`、`BootScopeTray.csproj` 和本 README，避免只改 UI 而保留脚本二次提权逻辑。

## 1. 基本功能

- **分组启停**：托盘菜单显示 `groups.json` 中的分组名称、成员数和启用状态；点击分组切换启用/禁用。
- **主窗口**：通过“显示主窗口”打开 PowerShell 脚本提供的原有图形界面；双击托盘图标也可打开。
- **开机启动**：通过当前用户注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 管理托盘自启动。普通托盘按普通权限启动。
- **可选永久管理员后台**：用户主动选择“设置永久管理员后台”并确认一次 UAC 后，创建登录触发的最高权限计划任务；后续操作通过本机命名管道请求后台，通常不再为每次操作弹 UAC。
- **撤销授权**：菜单“取消永久管理员授权”删除计划任务并尝试停止后台。
- **异常保护**：后台通信使用有限重试和超时；启停后查询实际状态验证，不会为了验证结果而再次执行启停；取消 UAC 时托盘保持运行。
- **自定义图标与资源释放**：托盘优先使用 EXE 中嵌入的 `bootscope.ico`；退出时释放托盘图标和菜单资源。

## 2. 权限流程（重要）

### 未设置永久管理员后台

- 普通托盘不因启动本身请求管理员权限，也不会在每次启动时强制安装后台。
- 点击分组启用/禁用时，由 `BootScopeTray.exe` 使用 Windows `runas` 启动一次性管理员操作进程（参数 `--elevated-action`）。因此 UAC 对话框应针对本程序，而不是先针对 `powershell.exe`。
- 一次性管理员进程再以普通子进程方式启动 PowerShell CLI；脚本调用使用 `-NoElevation`，防止脚本内部再次弹 UAC。
- “显示主窗口”使用 `--elevated-open-main` 走 Windows 标准 UAC 流程。
- 用户取消 UAC 时，不执行该次管理员操作，托盘继续运行。

### 已设置永久管理员后台

- “设置永久管理员后台”通过一次 UAC 确认创建任务计划程序任务，任务名格式为 `BootScopeTrayElevated_<当前用户 SID>`，触发器为当前用户登录（`ONLOGON`），运行级别为最高权限。
- 后台常驻进程使用命名管道等待托盘请求。管道名基于当前用户 SID 生成；访问控制仅授予当前用户 SID，不授予 `Everyone`。
- 后台仅接受固定操作：`ping`、`shutdown`、`open-main`、`enable`、`disable`。不接受任意 shell/PowerShell 命令。
- 安装流程会等待后台启动并进行 `ping` 握手；仅创建任务但后台未就绪不能视为安装成功。
- 普通进程启动时若管理员托盘已响应握手，会退出以避免重复托盘图标。若后台任务不存在或无法启动，普通托盘应继续运行。
- 托盘“退出”只退出当前托盘进程；永久后台任务默认保留。要撤销常驻授权，请使用“取消永久管理员授权”。

## 3. 环境要求

- Windows 10/11（需要使用 Windows 托盘、UAC、注册表和任务计划程序）。
- .NET 8 SDK，用于编译；发布目标为 `net8.0-windows`、`win-x64`。
- Windows PowerShell 5.1（系统通常自带）。
- `BootScope_grouped_clickfix_v26_cli.ps1` 必须与 EXE 位于同一目录；分组配置文件为同目录的 `groups.json`。

## 4. 编译和首次运行

1. 解压项目到固定目录，例如 `G:\bootscope-master\BootScope`。如果已有配置，先备份 `groups.json`。
2. 在项目根目录打开 PowerShell，执行：

   ```powershell
   .\build.ps1
   ```

3. 编译产物位于 `publish\win-x64\BootScopeTray.exe`。构建脚本会复制 CLI 脚本；若项目根目录存在 `groups.json`，也会复制到发布目录。
4. 第一次运行时检查分组菜单。若提示找不到 `groups.json`，请将自己的配置复制到 `publish\win-x64\groups.json`，或在主窗口中建立并保存分组后重新启动托盘。
5. 右键托盘图标使用菜单：
   - **分组启停**：点击某个分组切换状态。
   - **显示主窗口**：打开启动项管理主界面。
   - **开机启动**：添加/移除当前用户 Run 项。
   - **设置永久管理员后台（首次需确认 UAC）**：选择性启用常驻后台。
   - **取消永久管理员授权**：移除后台任务。
   - **退出**：关闭托盘界面；不等同于移除永久管理员后台。

建议先在未安装永久后台时测试分组操作：应该只出现一次针对 `BootScopeTray.exe` 的 UAC；再选择安装永久后台，验证安装后操作通过后台执行。


## 6. 权限后台实现要点（用于复现/维护）

- EXE 入口按命令行分流：`--elevated-server` 启动常驻后台；`--install-elevated-task` / `--uninstall-elevated-task` 安装或移除任务；`--elevated-action <enable|disable> --group <分组名>` 执行一次性管理员操作；`--elevated-open-main` 打开管理员主窗口。
- 需要一次性 UAC 时，调用当前 EXE 的 `ProcessStartInfo`，设置 `UseShellExecute = true`、`Verb = "runas"`，并传入专用参数。不要直接对 `powershell.exe` 使用 `runas`，也不要让脚本在此流程中再次自提权。
- PowerShell CLI 子进程使用 `-NoProfile`、`-ExecutionPolicy Bypass`、UTF-8 输出设置，并通过参数传入动作和分组名；不得将用户输入拼接成任意 PowerShell 命令。
- 常驻后台使用 `NamedPipeServerStreamAcl.Create` 创建命名管道，只设置当前用户 SID 的 DACL，不设置需要额外特权的 SACL/强制完整性标签。请求使用 JSON 行协议；操作白名单限制为固定动作。
- 命名管道连接失败时可重试连接/启动已存在的计划任务，但**请求发出后不能自动重发启停动作**，以免响应超时导致重复切换。
- 操作返回后查询 `status`，将实际状态与目标状态比较；即使某些子进程退出码异常，只要只读状态确认已达到目标，也应按成功处理。
- 所有长时间等待都应有超时和取消处理；取消 UAC 不应关闭普通托盘。

## 7. 日志和故障排查

- 后台日志：`%LOCALAPPDATA%\BootScopeTray\backend.log`。
- 若提示后台连接超时，先检查任务计划程序中 `BootScopeTrayElevated_<SID>` 任务是否存在、是否正在运行，以及任务操作路径是否指向当前 EXE。
- 若移动了程序目录，旧任务可能仍指向旧路径；请先“取消永久管理员授权”，再从新位置重新设置。
- 若操作成功却显示失败，刷新托盘菜单并检查最终状态；将 `backend.log` 和完整错误信息一并保留用于诊断。
- 若构建报 `NU1102`，检查 NuGet 源和项目中的 `System.IO.Pipes.AccessControl` 依赖版本；当前项目文件引用 `5.0.0`。

## 8. 已知限制与验证说明

- 永久管理员后台是当前用户登录触发的最高权限计划任务，不是 Windows 服务，也不是绕过 UAC 的系统级授权。首次设置需要 UAC；撤销时若当前托盘已在管理员权限下运行，可直接移除，否则会请求 UAC。
- 本项目的启停行为会改变 Windows 启动项状态，请先备份配置并确认分组成员。
- 本次打包/文档编辑环境无法实际运行 Windows WinForms、UAC 和任务计划程序验证。发布前必须在目标 Windows 机器上运行 `build.ps1` 并完成实际测试；不能仅凭源码或 ZIP 存在就视为编译通过。
