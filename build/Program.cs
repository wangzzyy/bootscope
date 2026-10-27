using System.Diagnostics;
using System.Text.Json;
using System.Text;
using System.Threading;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Windows.Forms;
using Microsoft.Win32;

namespace BootScopeTray;

internal static class Program
{
    private static Process? _elevatedMainWindowProcess;
    [STAThread]
    private static void Main(string[] args)
    {
        // UAC 提权时提升的是本程序 EXE，而不是直接提升 powershell.exe，
        // 这样 Windows 的 UAC 对话框会显示 BootScopeTray。
        if (args.Length > 0 && args[0].Equals("--elevated-server", StringComparison.OrdinalIgnoreCase))
        {
            if (args.Length < 2) { Environment.ExitCode = 2; return; }
            ApplicationConfiguration.Initialize();
            Environment.ExitCode = RunElevatedServer(args[1]);
            return;
        }
        if (args.Length > 0 && args[0].Equals("--install-elevated-task", StringComparison.OrdinalIgnoreCase))
        {
            Environment.ExitCode = InstallElevatedTask();
            return;
        }
        if (args.Length > 0 && args[0].Equals("--uninstall-elevated-task", StringComparison.OrdinalIgnoreCase))
        {
            Environment.ExitCode = UninstallElevatedTask();
            return;
        }
        if (args.Length > 0 && args[0].Equals("--elevated-action", StringComparison.OrdinalIgnoreCase))
        {
            Environment.ExitCode = RunElevatedAction(args);
            return;
        }
        if (args.Length > 0 && args[0].Equals("--elevated-open-main", StringComparison.OrdinalIgnoreCase))
        {
            Environment.ExitCode = RunElevatedMainWindow();
            return;
        }

        // 若管理员托盘已经接管，普通权限启动实例立即退出，避免两个托盘图标。
        // 开机启动时任务计划程序和 Run 项可能存在启动先后竞态；后续由普通托盘的定时探测兜底。
        try
        {
            string response = SendPipeRequestSync(StablePipeName(), new PipeRequest("ping", ""), 250);
            var reply = JsonSerializer.Deserialize<PipeReply>(response);
            if (reply?.ExitCode == 0) return;
        }
        catch { }

        using var mutex = new Mutex(true, "Local\\BootScopeTray.SingleInstance.v1", out bool firstInstance);
        if (!firstInstance)
        {
            MessageBox.Show("启视托盘已经在运行。请从系统托盘图标打开菜单。", "启视托盘", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        ApplicationConfiguration.Initialize();
        Application.Run(new TrayContext());
    }


    internal static string StablePipeName()
    {
        string sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("无法获取当前 Windows 用户 SID。");
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(sid));
        return "BootScopeTrayElevated_" + Convert.ToHexString(hash.AsSpan(0, 12));
    }

    private static string ElevatedTaskName()
    {
        string sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("无法获取当前 Windows 用户 SID。");
        return "BootScopeTrayElevated_" + sid.Replace('-', '_');
    }

    private static int InstallElevatedTask()
    {
        try
        {
            string exe = Environment.ProcessPath ?? throw new InvalidOperationException("无法获取程序路径。");
            string taskName = ElevatedTaskName();
            string pipeName = StablePipeName();
            // /TR 必须将 EXE 路径用双引号包裹，才能支持安装目录含空格。
            string taskCommand = "\"" + exe + "\" --elevated-server " + pipeName;
            int createCode = RunSchtasks("/Create", "/TN", taskName, "/SC", "ONLOGON", "/TR", taskCommand, "/RL", "HIGHEST", "/IT", "/F");
            if (createCode != 0) return createCode;
            // 安装后立即启动；之后每次用户登录由任务计划程序自动启动。
            int runCode = RunSchtasks("/Run", "/TN", taskName);
            if (runCode != 0) return runCode;
            // schtasks /Run 只表示已提交启动请求，不代表后台已经创建命名管道。
            // 等待后台实际就绪并完成 ping 握手，避免错误显示“设置成功”。
            Exception? lastError = null;
            DateTime deadline = DateTime.UtcNow.AddSeconds(15);
            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    string response = SendPipeRequestSync(pipeName, new PipeRequest("ping", ""), 1200);
                    var reply = JsonSerializer.Deserialize<PipeReply>(response);
                    if (reply?.ExitCode == 0) return 0;
                    lastError = new IOException("管理员后台 ping 握手返回无效结果。");
                }
                catch (Exception ex) { lastError = ex; }
                Thread.Sleep(500);
            }
            LogBackendError("安装后后台未就绪", lastError ?? new TimeoutException("后台在 15 秒内未启动。"));
            return 12;
        }
        catch { return 10; }
    }

    internal static int UninstallElevatedTask()
    {
        try
        {
            string taskName = ElevatedTaskName();
            // 先尝试通知当前后台退出，再删除登录触发任务。
            try { SendPipeRequestSync(StablePipeName(), new PipeRequest("shutdown", ""), 1200); } catch { }
            int code = RunSchtasks("/Delete", "/TN", taskName, "/F");
            return code;
        }
        catch { return 10; }
    }

    private static int RunSchtasks(params string[] args)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false)
        };
        foreach (string arg in args) process.StartInfo.ArgumentList.Add(arg);
        process.Start();
        if (!process.WaitForExit(4000))
        {
            try { process.Kill(true); } catch { }
            return 1460; // ERROR_TIMEOUT
        }
        return process.ExitCode;
    }

    internal static string PingElevatedServer(string pipeName, int timeoutMs) =>
        SendPipeRequestSync(pipeName, new PipeRequest("ping", ""), timeoutMs);

    private static string SendPipeRequestSync(string pipeName, PipeRequest request, int timeoutMs)
    {
        using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
        client.Connect(timeoutMs);
        using var reader = new StreamReader(client, new UTF8Encoding(false), false, 4096, leaveOpen: true);
        using var writer = new StreamWriter(client, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
        writer.WriteLine(JsonSerializer.Serialize(request));
        return reader.ReadLine() ?? throw new IOException("管理员后台未返回握手结果。");
    }

    private static void LogBackendError(string context, Exception ex)
    {
        try
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BootScopeTray");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "backend.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}: {ex}\r\n", new UTF8Encoding(false));
        }
        catch { }
    }

    internal static int RunTaskForCurrentUser() => RunSchtasks("/Run", "/TN", ElevatedTaskName());

    // 查询是否已明确安装永久管理员任务。未安装时普通托盘只在当前权限下执行 CLI，
    // 不尝试连接命名管道、不启动任务，也不请求 UAC。
    internal static bool IsElevatedTaskInstalled() => RunSchtasks("/Query", "/TN", ElevatedTaskName()) == 0;

    private static int RunElevatedAction(string[] args)
    {
        try
        {
            string? action = null;
            string? group = null;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i].Equals("--group", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) group = args[++i];
                else if (action is null) action = args[i];
            }
            if (string.IsNullOrWhiteSpace(action) || string.IsNullOrWhiteSpace(group)) return 2;
            return ExecuteCliAction(action, group).ExitCode;
        }
        catch { return 10; }
    }

    // 由任务计划程序在用户登录时以最高权限启动的常驻后台；普通权限托盘通过受限命名管道发送操作。
    private static int RunElevatedServer(string pipeName)
    {
        TrayContext? elevatedTray = null;
        using var dispatcher = new Control();
        _ = dispatcher.Handle; // 创建隐藏窗口句柄，供后台线程安全通知 UI 线程退出。
        try
        {
            elevatedTray = new TrayContext(elevatedMode: true);
            Task server = Task.Run(() => RunElevatedPipeLoop(pipeName, dispatcher, elevatedTray));
            Application.Run(elevatedTray);
            try { dispatcher.Dispose(); } catch { }
            return 0;
        }
        catch (Exception ex)
        {
            LogBackendError("管理员托盘启动异常", ex);
            try { elevatedTray?.Dispose(); } catch { }
            return 11;
        }
    }

    private static void RunElevatedPipeLoop(string pipeName, Control dispatcher, TrayContext elevatedTray)
    {
        try
        {
            while (true)
            {
                // 只设置当前登录用户的 DACL，不设置 SACL/强制完整性标签。
                // 写入 SACL 需要 SeSecurityPrivilege；普通管理员令牌通常没有启用该特权，
                // 会导致 NamedPipeServerStreamAcl.Create 抛出“客户端没有所需的特权”。
                // 管道仍仅向当前用户 SID 授权，不授予 Everyone/Authenticated Users。
                string userSid = WindowsIdentity.GetCurrent().User?.Value
                    ?? throw new InvalidOperationException("无法获取当前 Windows 用户 SID。");
                var pipeSecurity = new PipeSecurity();
                pipeSecurity.SetSecurityDescriptorSddlForm(
                    $"D:(A;;GA;;;{userSid})", AccessControlSections.Access);
                using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, pipeSecurity);
                pipe.WaitForConnection();
                using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, leaveOpen: true);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
                string? line = reader.ReadLine();
                if (string.IsNullOrWhiteSpace(line)) continue;
                PipeRequest? request;
                try { request = JsonSerializer.Deserialize<PipeRequest>(line); }
                catch { writer.WriteLine(JsonSerializer.Serialize(new PipeReply(2, "", "无法解析管理员操作请求。"))); continue; }
                if (request is null) continue;
                if (string.Equals(request.Action, "ping", StringComparison.OrdinalIgnoreCase))
                {
                    writer.WriteLine(JsonSerializer.Serialize(new PipeReply(0, "ready", "")));
                    continue;
                }
                if (string.Equals(request.Action, "shutdown", StringComparison.OrdinalIgnoreCase))
                {
                    writer.WriteLine(JsonSerializer.Serialize(new PipeReply(0, "", "管理员托盘正在退出。")));
                    try
                    {
                        dispatcher.BeginInvoke((Action)(() =>
                        {
                            elevatedTray.ExitApplication();
                            Application.ExitThread();
                        }));
                    }
                    catch { }
                    return;
                }
                if (string.Equals(request.Action, "open-main", StringComparison.OrdinalIgnoreCase))
                {
                    var mainReply = new PipeReply(RunElevatedMainWindow(), "", "");
                    writer.WriteLine(JsonSerializer.Serialize(mainReply));
                    continue;
                }
                string requestedAction = request.Action ?? "";
                string requestedGroup = request.Group ?? "";
                if (!(requestedAction.Equals("enable", StringComparison.OrdinalIgnoreCase) ||
                      requestedAction.Equals("disable", StringComparison.OrdinalIgnoreCase)) ||
                    string.IsNullOrWhiteSpace(requestedGroup) || requestedGroup.Length > 200)
                {
                    writer.WriteLine(JsonSerializer.Serialize(new PipeReply(2, "", "请求的管理员操作不在允许范围内。")));
                    continue;
                }
                var reply = ExecuteCliAction(requestedAction, requestedGroup);
                writer.WriteLine(JsonSerializer.Serialize(reply));
            }
        }
        catch (Exception ex) { LogBackendError("管理员后台服务异常退出", ex); }
    }

    private static PipeReply ExecuteCliAction(string action, string group)
    {
        try
        {
            string script = Path.Combine(AppContext.BaseDirectory, "BootScope.ps1");
            if (!File.Exists(script)) return new PipeReply(3, "", "找不到脚本：" + script);
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = new UTF8Encoding(false),
                StandardErrorEncoding = new UTF8Encoding(false)
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-ExecutionPolicy"); psi.ArgumentList.Add("Bypass");
            // Windows PowerShell 5.1 在重定向输出时可能使用系统代码页；在子进程内显式切换 UTF-8，
            // 避免中文错误消息乱码。路径/参数使用 PowerShell 单引号转义，不拼接可执行任意代码的输入。
            string command = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); " +
                "$OutputEncoding = [Console]::OutputEncoding; & " + QuotePowerShellArg(script) +
                " -TrayAction " + QuotePowerShellArg(action) + " -Group " + QuotePowerShellArg(group);
            psi.ArgumentList.Add("-Command"); psi.ArgumentList.Add(command);
            using var child = Process.Start(psi);
            if (child is null) return new PipeReply(4, "", "无法启动 PowerShell CLI。");
            Task<string> stdoutTask = child.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = child.StandardError.ReadToEndAsync();
            child.WaitForExit();
            string stdout = stdoutTask.GetAwaiter().GetResult();
            string stderr = stderrTask.GetAwaiter().GetResult();
            int exitCode = child.ExitCode;
            // 脚本可能已经成功修改状态并输出 ok:true JSON，但 PowerShell 宿主仍以 1 退出。
            // 结构化结果优先于宿主退出码，避免出现“操作成功却弹失败”的误报。
            if (TryReadCliJsonOk(stdout, out bool jsonOk) && jsonOk) exitCode = 0;
            return new PipeReply(exitCode, stdout, stderr);
        }
        catch (Exception ex) { return new PipeReply(10, "", ex.ToString()); }
    }


    private static string QuotePowerShellArg(string value) => "'" + value.Replace("'", "''") + "'";

    private static bool TryReadCliJsonOk(string output, out bool ok)
    {
        ok = false;
        if (string.IsNullOrWhiteSpace(output)) return false;
        foreach (string line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Reverse())
        {
            try
            {
                using var doc = JsonDocument.Parse(line.Trim());
                if (doc.RootElement.ValueKind != JsonValueKind.Object ||
                    !doc.RootElement.TryGetProperty("ok", out var property) ||
                    (property.ValueKind != JsonValueKind.True && property.ValueKind != JsonValueKind.False))
                    continue;
                ok = property.ValueKind == JsonValueKind.True;
                return true;
            }
            catch (JsonException) { }
        }
        return false;
    }

    private static int RunElevatedMainWindow()
    {
        try
        {
            string script = Path.Combine(AppContext.BaseDirectory, "BootScope.ps1");
            if (!File.Exists(script)) return 3;
            if (_elevatedMainWindowProcess is not null)
            {
                try
                {
                    if (!_elevatedMainWindowProcess.HasExited)
                    {
                        _elevatedMainWindowProcess.Refresh();
                        if (_elevatedMainWindowProcess.MainWindowHandle != IntPtr.Zero)
                            NativeMethods.ShowWindow(_elevatedMainWindowProcess.MainWindowHandle, NativeMethods.SW_RESTORE);
                        return 0;
                    }
                }
                catch { }
                try { _elevatedMainWindowProcess.Dispose(); } catch { }
                _elevatedMainWindowProcess = null;
            }
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-STA");
            psi.ArgumentList.Add("-ExecutionPolicy"); psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-File"); psi.ArgumentList.Add(script);
            _elevatedMainWindowProcess = Process.Start(psi);
            return _elevatedMainWindowProcess is null ? 4 : 0;
        }
        catch { return 10; }
    }

    private static class NativeMethods
    {
        internal const int SW_RESTORE = 9;
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        internal static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }

}

internal sealed record PipeRequest(string? Action, string? Group);
internal sealed record PipeReply(int ExitCode, string Stdout, string Stderr);

internal sealed class TrayContext : ApplicationContext
{
    private readonly NotifyIcon _tray;
    private readonly Icon _trayIcon;
    private readonly ContextMenuStrip _menu = new();
    private readonly ToolStripMenuItem _groupsRoot = new("分组启停");
    private readonly ToolStripMenuItem _showMain = new("显示主窗口");
    private readonly ToolStripMenuItem _startup = new("开机启动") { CheckOnClick = false };
    private readonly ToolStripMenuItem _installAdmin = new("设置永久管理员后台（首次需确认 UAC）");
    private readonly ToolStripMenuItem _removeAdmin = new("取消永久管理员授权");
    private readonly ToolStripMenuItem _exit = new("退出");
    private const string StartupRunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string StartupValueName = "BootScopeTray";
    private readonly string _baseDir = AppContext.BaseDirectory;
    private Process? _mainWindowProcess;
    private readonly string _pipeName = Program.StablePipeName();
    private readonly bool _elevatedMode;
    private readonly System.Windows.Forms.Timer? _takeoverTimer;
    private bool _takeoverCheckInProgress;
    private DateTime _nextTaskStartAttemptUtc = DateTime.MinValue;
    private bool _busy;

    private string ScriptPath => Path.Combine(_baseDir, "BootScope.ps1");
    private string GroupsPath => Path.Combine(_baseDir, "groups.json");

    public TrayContext(bool elevatedMode = false)
    {
        _elevatedMode = elevatedMode;
        _menu.Items.Add(_groupsRoot);
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add(_showMain);
        _menu.Items.Add(_startup);
        if (!_elevatedMode) _menu.Items.Add(_installAdmin);
        _menu.Items.Add(_removeAdmin);
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add(_exit);
        _menu.Opening += (_, _) => { RefreshGroupsMenu(); RefreshStartupMenu(); };
        _showMain.Click += (_, _) => ShowMainWindow();
        _startup.Click += (_, _) => ToggleStartup();
        _installAdmin.Click += (_, _) => InstallAdminBackend();
        _removeAdmin.Click += (_, _) => RemoveAdminBackend();
        _exit.Click += (_, _) => ExitApplication();

        // 由 TrayContext 持有图标，退出时在 NotifyIcon 释放后统一释放句柄。
        _trayIcon = LoadTrayIcon();
        _tray = new NotifyIcon
        {
            // 优先使用嵌入 EXE 的 BootScope 自定义图标，避免显示通用程序图标。
            Icon = _trayIcon,
            Text = "启视 BootScope 分组托盘",
            ContextMenuStrip = _menu,
            Visible = true
        };
        _tray.DoubleClick += (_, _) => ShowMainWindow();
        _tray.BalloonTipTitle = "启视 BootScope";
        _tray.BalloonTipText = "托盘已启动。右键图标可控制启动项分组。";
        _tray.BalloonTipIcon = ToolTipIcon.Info;
        _tray.ShowBalloonTip(2500);
        RefreshGroupsMenu();
        RefreshStartupMenu();

        // 普通权限实例用于首次安装/故障恢复。若登录时管理员计划任务稍晚启动，
        // 一旦管理员实例成功监听管道，普通实例自动退出，把托盘留给管理员实例。
        if (!_elevatedMode)
        {
            _takeoverTimer = new System.Windows.Forms.Timer { Interval = 2000 };
            _takeoverTimer.Tick += async (_, _) => await CheckForElevatedTakeoverAsync();
            _takeoverTimer.Start();
        }
    }

    private async Task CheckForElevatedTakeoverAsync()
    {
        if (_elevatedMode || _takeoverCheckInProgress || _resourcesDisposed) return;
        _takeoverCheckInProgress = true;
        try
        {
            // 第一步：若管理员后台已运行且管道可用，确认握手成功后才退出普通托盘。
            if (await IsElevatedBackendReadyAsync())
            {
                ExitApplication();
                return;
            }

            // 未设置永久管理员后台时，不尝试启动任务；普通托盘继续保持可用。
            bool taskInstalled = await Task.Run(() => Program.IsElevatedTaskInstalled());
            if (!taskInstalled) return;

            // 第二步：后台未就绪时，自动尝试运行已授权的计划任务。
            // 限制尝试频率，避免任务启动失败时频繁调用 schtasks。
            if (DateTime.UtcNow < _nextTaskStartAttemptUtc) return;
            _nextTaskStartAttemptUtc = DateTime.UtcNow.AddSeconds(10);
            int runCode;
            try
            {
                runCode = await Task.Run(() => Program.RunTaskForCurrentUser());
            }
            catch
            {
                return; // 未安装授权任务或任务计划程序不可用：保留普通托盘，避免托盘消失。
            }
            if (runCode != 0) return;

            // schtasks /Run 只代表提交启动请求。轮询管道，只有管理员托盘真正就绪后才退出。
            for (int i = 0; i < 10 && !_resourcesDisposed; i++)
            {
                await Task.Delay(400);
                if (await IsElevatedBackendReadyAsync())
                {
                    ExitApplication();
                    return;
                }
            }
        }
        catch
        {
            // 后台启动或握手失败时，普通托盘继续工作，下一轮定时器会再尝试。
        }
        finally { _takeoverCheckInProgress = false; }
    }

    private async Task<bool> IsElevatedBackendReadyAsync()
    {
        try
        {
            string response = await Task.Run(() => Program.PingElevatedServer(_pipeName, 500));
            var reply = JsonSerializer.Deserialize<PipeReply>(response);
            return reply?.ExitCode == 0 && string.Equals(reply.Stdout, "ready", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static Icon LoadTrayIcon()
    {
        try
        {
            string? exePath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(exePath))
            {
                Icon? icon = Icon.ExtractAssociatedIcon(exePath);
                if (icon is not null) return icon;
            }
        }
        catch { }
        return SystemIcons.Application;
    }

    private void RefreshStartupMenu()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRunKey, writable: false);
            string? command = key?.GetValue(StartupValueName) as string;
            _startup.Checked = !string.IsNullOrWhiteSpace(command) &&
                command.Contains(Path.GetFileName(Environment.ProcessPath ?? "BootScopeTray.exe"), StringComparison.OrdinalIgnoreCase);
            _startup.ToolTipText = _startup.Checked ? "已加入当前用户开机启动" : "点击后加入当前用户开机启动";
        }
        catch (Exception ex)
        {
            _startup.Checked = false;
            _startup.ToolTipText = "无法读取开机启动状态：" + ex.Message;
        }
    }

    private void ToggleStartup()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(StartupRunKey, writable: true);
            if (key is null) throw new InvalidOperationException("无法打开当前用户的开机启动注册表项。");
            if (_startup.Checked)
            {
                key.DeleteValue(StartupValueName, throwOnMissingValue: false);
                _tray.BalloonTipText = "已取消开机启动。";
            }
            else
            {
                string exePath = Environment.ProcessPath ?? throw new InvalidOperationException("无法获取当前程序路径。");
                key.SetValue(StartupValueName, "\"" + exePath + "\"", RegistryValueKind.String);
                _tray.BalloonTipText = "已加入开机启动。登录 Windows 时将以普通权限启动；只有执行需要管理员权限的操作时才会请求 UAC。";
            }
            _tray.BalloonTipTitle = "启视 BootScope";
            _tray.BalloonTipIcon = ToolTipIcon.Info;
            _tray.ShowBalloonTip(2500);
        }
        catch (Exception ex)
        {
            MessageBox.Show("设置开机启动失败：\n" + ex.Message, "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { RefreshStartupMenu(); }
    }

    private void RefreshGroupsMenu()
    {
        // Clear() 只会移除菜单项，不保证释放每个旧 ToolStripItem；先逐个 Dispose，
        // 避免每次打开菜单/操作分组时不断累积事件处理器和 UI 资源。
        foreach (ToolStripItem oldItem in _groupsRoot.DropDownItems.Cast<ToolStripItem>().ToArray())
        {
            _groupsRoot.DropDownItems.Remove(oldItem);
            oldItem.Dispose();
        }
        if (!File.Exists(GroupsPath))
        {
            var missing = new ToolStripMenuItem("未找到 groups.json") { Enabled = false };
            _groupsRoot.DropDownItems.Add(missing);
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(GroupsPath, Encoding.UTF8));
            if (!doc.RootElement.TryGetProperty("groups", out var groups) || groups.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("groups.json 缺少 groups 数组");

            var entries = groups.EnumerateArray()
                .Where(g => g.TryGetProperty("name", out var n) && !string.IsNullOrWhiteSpace(n.GetString()))
                .OrderBy(g => g.TryGetProperty("order", out var o) && o.TryGetInt32(out var order) ? order : int.MaxValue)
                .ToList();

            foreach (var g in entries)
            {
                string name = g.GetProperty("name").GetString()!;
                bool enabled = g.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.True;
                int count = g.TryGetProperty("items", out var its) && its.ValueKind == JsonValueKind.Array ? its.GetArrayLength() : 0;
                var item = new ToolStripMenuItem($"{name} ({count})")
                {
                    CheckOnClick = false,
                    Checked = enabled,
                    CheckState = enabled ? CheckState.Checked : CheckState.Unchecked,
                    ToolTipText = enabled ? "当前启用；点击可禁用" : "当前禁用；点击可启用",
                    Tag = name
                };
                item.Click += async (_, _) => await ToggleGroupAsync(name, !item.Checked);
                _groupsRoot.DropDownItems.Add(item);
            }
            if (entries.Count == 0)
                _groupsRoot.DropDownItems.Add(new ToolStripMenuItem("没有分组") { Enabled = false });
        }
        catch (Exception ex)
        {
            _groupsRoot.DropDownItems.Add(new ToolStripMenuItem("读取分组失败") { Enabled = false });
            _groupsRoot.DropDownItems.Add(new ToolStripMenuItem(ex.Message) { Enabled = false });
        }
    }

    private async Task ToggleGroupAsync(string groupName, bool enable)
    {
        if (_busy) return;
        _busy = true;
        SetMenuEnabled(false);
        try
        {
            var result = await RunCliAsync(enable ? "enable" : "disable", groupName);
            if (!result.Ok)
            {
                MessageBox.Show(result.Message, "分组操作失败", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            else
            {
                _tray.BalloonTipTitle = "启视 BootScope";
                _tray.BalloonTipText = $"分组“{groupName}”已{(enable ? "启用" : "禁用")}。";
                _tray.BalloonTipIcon = ToolTipIcon.Info;
                _tray.ShowBalloonTip(1800);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "分组操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            RefreshGroupsMenu();
            SetMenuEnabled(true);
            _busy = false;
        }
    }

    private void SetMenuEnabled(bool enabled)
    {
        _groupsRoot.Enabled = enabled;
        _showMain.Enabled = enabled;
        _startup.Enabled = enabled;
        _installAdmin.Enabled = enabled;
        _removeAdmin.Enabled = enabled;
        _exit.Enabled = enabled;
    }

    private async Task<CliResult> RunCliAsync(string action, string group)
    {
        if (!File.Exists(ScriptPath)) return new(false, "找不到脚本：" + ScriptPath);

        // Windows PowerShell 5.1 的重定向输出编码可能不是 UTF-8。
        // 在子进程中显式设置控制台输出编码，避免中文错误信息乱码。
        async Task<(int ExitCode, string Stdout, string Stderr)> InvokeAsync(string requestedAction)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                WorkingDirectory = _baseDir,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = new UTF8Encoding(false),
                StandardErrorEncoding = new UTF8Encoding(false)
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-ExecutionPolicy"); psi.ArgumentList.Add("Bypass");
            string command = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $OutputEncoding = [Console]::OutputEncoding; & "
                + QuotePowerShell(ScriptPath)
                + " -TrayAction " + QuotePowerShell(requestedAction)
                + " -Group " + QuotePowerShell(group)
                + " -NoElevation";
            psi.ArgumentList.Add("-Command"); psi.ArgumentList.Add(command);

            using var process = new Process { StartInfo = psi };
            process.Start();
            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = process.StandardError.ReadToEndAsync();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            try { await process.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException)
            {
                try { process.Kill(true); } catch { }
                return (-1, "", "操作超时（20 秒），已终止子进程以避免托盘长时间无响应。");
            }
            return (process.ExitCode, await stdoutTask, await stderrTask);
        }

        static string QuotePowerShell(string value) => "'" + value.Replace("'", "''") + "'";

        async Task<CliResult> InvokeElevatedAsync(string requestedAction, string requestedGroup)
        {
            try
            {
                PipeReply reply = await SendElevatedRequestAsync(requestedAction, requestedGroup);
                string details = GetReadableDetails(reply.Stdout, reply.Stderr);
                if (reply.ExitCode != 0)
                {
                    // 某些 PowerShell 5.1/启动项操作会在实际修改成功后仍返回退出码 1，
                    // 且 stderr 可能因系统代码页出现乱码。先只读查询最终状态；若目标状态已达成，
                    // 以实际状态为准，不弹“操作失败”。不会重发 enable/disable 操作。
                    if (requestedAction.Equals("enable", StringComparison.OrdinalIgnoreCase) ||
                        requestedAction.Equals("disable", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            var verify = await InvokeAsync("status");
                            bool expected = requestedAction.Equals("enable", StringComparison.OrdinalIgnoreCase);
                            if (verify.ExitCode == 0 && TryReadStatus(verify.Stdout, out bool actual) && actual == expected)
                                return new(true, "分组状态已确认；已忽略 PowerShell 的异常退出码。");
                        }
                        catch { /* 保留原始错误用于诊断 */ }
                    }
                    // 优先解析脚本 JSON，展示失败成员及原因，而不是只显示笼统的退出代码。
                    string friendly = FormatCliFailure(reply.Stdout, reply.Stderr, reply.ExitCode);
                    return new(false, friendly);
                }
                if (!string.IsNullOrWhiteSpace(details))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(details.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Last());
                        if (doc.RootElement.TryGetProperty("ok", out var okProp) && okProp.ValueKind == JsonValueKind.False)
                        {
                            string message = doc.RootElement.TryGetProperty("message", out var msg) ? msg.ToString() : "脚本返回操作失败。";
                            if (doc.RootElement.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array)
                            {
                                var failures = items.EnumerateArray().Where(x => x.TryGetProperty("ok", out var itemOk) && itemOk.ValueKind == JsonValueKind.False)
                                    .Select(x => (x.TryGetProperty("name", out var n) ? n.ToString() : "启动项") + "：" + (x.TryGetProperty("message", out var m) ? m.ToString() : "操作失败"));
                                string failureText = string.Join("\n", failures);
                                if (!string.IsNullOrWhiteSpace(failureText)) message += "\n" + failureText;
                            }
                            return new(false, message);
                        }
                    }
                    catch { }
                }
                return new(true, "管理员操作已完成。");
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                return new(false, "你取消了 UAC 提权，分组状态未更改。");
            }
            catch (Exception ex) { return new(false, "管理员操作失败：" + ex.Message); }
        }

        try
        {
            // 未配置永久管理员后台：先尝试在普通权限下执行。只有普通权限失败且状态未达成时，
            // 才通过当前 EXE 的 runas 启动一次性管理员操作进程，让 Windows 正常显示 UAC。
            bool taskInstalled = await Task.Run(() => Program.IsElevatedTaskInstalled());
            if (!taskInstalled)
            {
                // 未安装永久后台时，不要先启动 PowerShell 再由脚本自行提权：
                // 这种两段式流程可能先弹出 powershell.exe 的 UAC，再弹一次本程序的 UAC。
                // 直接由 BootScopeTray.exe 使用 runas 启动一次性管理员操作进程，确保只有一层 UAC，
                // UAC 对话框显示本程序名称；提权进程内部再以普通子进程方式调用 PowerShell。
                int elevatedExitCode;
                try
                {
                    elevatedExitCode = await StartOnDemandElevatedActionAsync(action, group);
                }
                catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
                {
                    return new(false, "你取消了 Windows 权限申请，分组状态未更改。");
                }
                catch (Exception ex)
                {
                    return new(false, "无法启动管理员操作：" + ex.Message);
                }

                // 只读查询确认结果，不重复发送启停操作。
                bool expectedLocal = action.Equals("enable", StringComparison.OrdinalIgnoreCase);
                try
                {
                    var verify = await InvokeAsync("status");
                    if (verify.ExitCode == 0 && TryReadStatus(verify.Stdout, out bool actual) && actual == expectedLocal)
                        return new(true, "分组状态已确认。");
                }
                catch { }

                return new(false, elevatedExitCode == 0
                    ? "管理员操作已结束，但无法确认分组最终状态。请刷新菜单后检查。"
                    : $"管理员操作失败（代码 {elevatedExitCode}）。请检查分组配置及启动项状态。");
            }

            // 只有已安装永久管理员任务时，才通过受限管道调用管理员后台。
            var operation = await InvokeElevatedAsync(action, group);
            if (!operation.Ok)
                return operation;

            // 不能只依赖提权子进程的退出码；查询实际状态确认操作是否生效。
            var status = await InvokeAsync("status");
            bool expectedEnabled = action.Equals("enable", StringComparison.OrdinalIgnoreCase);
            if (status.ExitCode == 0 && TryReadStatus(status.Stdout, out bool actualEnabled) &&
                actualEnabled == expectedEnabled)
            {
                return new(true, "分组状态已确认。");
            }

            string safeDetails = GetReadableDetails(status.Stderr, status.Stdout);
            return new(false, string.IsNullOrWhiteSpace(safeDetails)
                ? $"管理员操作已启动，但未能确认分组已{(expectedEnabled ? "启用" : "禁用")}。请重新打开托盘菜单检查状态。"
                : safeDetails);
        }
        catch (Exception ex)
        {
            return new(false, ex.Message);
        }
    }

    private async Task<int> StartOnDemandElevatedActionAsync(string action, string group)
    {
        string exe = Environment.ProcessPath ?? throw new InvalidOperationException("无法获取程序路径。");
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            WorkingDirectory = _baseDir,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden
        };
        psi.ArgumentList.Add("--elevated-action");
        psi.ArgumentList.Add(action);
        psi.ArgumentList.Add("--group");
        psi.ArgumentList.Add(group);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("无法启动管理员操作进程。");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(180));
        try { await process.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(true); } catch { }
            throw new TimeoutException("管理员操作超过 180 秒，已终止操作进程。");
        }
        return process.ExitCode;
    }

    private static string FormatCliFailure(string stdout, string stderr, int exitCode)
    {
        string line = (stdout ?? "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            string message = root.TryGetProperty("message", out var msg) ? msg.ToString() : "分组脚本执行失败。";
            if (root.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array)
            {
                var failures = items.EnumerateArray()
                    .Where(x => x.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.False)
                    .Select(x => (x.TryGetProperty("name", out var name) ? name.ToString() : "启动项") + "：" +
                                 (x.TryGetProperty("message", out var detail) ? detail.ToString() : "操作失败"));
                string failureText = string.Join("\n", failures);
                if (!string.IsNullOrWhiteSpace(failureText)) message += "\n" + failureText;
            }
            return $"管理员操作失败（代码 {exitCode}）：\n{message}";
        }
        catch
        {
            string details = GetReadableDetails(stdout, stderr);
            return $"管理员操作失败（代码 {exitCode}）。" +
                (string.IsNullOrWhiteSpace(details) ? "\n未收到脚本错误详情；请检查 groups.json 和启动项路径。" : "\n" + details);
        }
    }

    private static bool TryReadOk(string output, out bool ok, out string message)
    {
        ok = false; message = "";
        string line = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            ok = root.TryGetProperty("ok", out var prop) && prop.ValueKind == JsonValueKind.True;
            message = root.TryGetProperty("message", out var msg) && msg.ValueKind == JsonValueKind.String ? msg.GetString() ?? "" : "";
            return true;
        }
        catch { return false; }
    }

    private static bool TryReadStatus(string output, out bool enabled)
    {
        enabled = false;
        string line = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (!root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True) return false;
            if (!root.TryGetProperty("enabled", out var en) || (en.ValueKind != JsonValueKind.True && en.ValueKind != JsonValueKind.False)) return false;
            enabled = en.ValueKind == JsonValueKind.True;
            return true;
        }
        catch { return false; }
    }

    private static string GetReadableDetails(params string?[] candidates)
    {
        foreach (string? candidate in candidates)
        {
            string value = (candidate ?? "").Trim();
            if (value.Length == 0) continue;
            // 避免把明显的乱码原样展示给用户。
            int replacementCount = value.Count(ch => ch == '\uFFFD');
            if (replacementCount > 0 || value.Contains("锟斤拷", StringComparison.Ordinal)) continue;
            return value.Length > 1200 ? value[..1200] : value;
        }
        return "";
    }

    private async void ShowMainWindow()
    {
        if (!File.Exists(ScriptPath))
        {
            MessageBox.Show("找不到主窗口脚本：\n" + ScriptPath, "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        try
        {
            if (!await Task.Run(() => Program.IsElevatedTaskInstalled()))
            {
                // 没有永久后台时，打开主窗口同样走 Windows 标准 UAC 流程。
                string exe = Environment.ProcessPath ?? throw new InvalidOperationException("无法获取程序路径。");
                var psi = new ProcessStartInfo { FileName = exe, WorkingDirectory = _baseDir, UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
                psi.ArgumentList.Add("--elevated-open-main");
                using var proc = Process.Start(psi) ?? throw new InvalidOperationException("无法启动管理员主窗口进程。");
                await proc.WaitForExitAsync();
                if (proc.ExitCode != 0)
                    MessageBox.Show("无法打开主窗口（代码 " + proc.ExitCode + "）。", "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                var result = await SendElevatedRequestAsync("open-main", "");
                if (result.ExitCode != 0)
                {
                    string details = GetReadableDetails(result.Stdout, result.Stderr);
                    MessageBox.Show("无法打开主窗口：" + (string.IsNullOrWhiteSpace(details) ? "错误代码 " + result.ExitCode : "\n" + details),
                        "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // 用户取消 UAC；托盘仍保持普通权限运行。
        }
        catch (Exception ex)
        {
            MessageBox.Show("无法打开主窗口：\n" + ex.Message, "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async Task<PipeReply> SendElevatedRequestAsync(string action, string group)
    {
        Exception? lastError = null;
        NamedPipeClientStream? connectedClient = null;
        // 先建立连接，再发送一次操作请求。连接失败时可重试；请求发出后不自动重发，
        // 避免启停操作在响应超时时被重复执行。
        for (int attempt = 0; attempt < 12; attempt++)
        {
            var client = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                await client.ConnectAsync(1200);
                connectedClient = client;
                break;
            }
            catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException)
            {
                lastError = ex;
                client.Dispose();
                if (attempt == 0)
                {
                    // 任务已存在时此命令只会请求其启动，不会再次弹出 UAC。
                    try
                    {
                        int runCode = await Task.Run(() => Program.RunTaskForCurrentUser());
                        if (runCode != 0) lastError = new IOException("无法启动管理员后台计划任务，schtasks 退出代码：" + runCode, ex);
                    }
                    catch (Exception runEx) { lastError = runEx; }
                }
                await Task.Delay(650);
            }
        }
        if (connectedClient is null)
        {
            LogClientBackendError("连接永久管理员后台失败", lastError);
            throw new IOException("已检测到永久管理员后台连接失败。请检查任务计划程序中的 BootScopeTrayElevated 任务是否正在运行；详细错误已记录到 %LOCALAPPDATA%\\BootScopeTray\\backend.log。最后错误：" + lastError?.Message, lastError);
        }

        using (connectedClient)
        using (var reader = new StreamReader(connectedClient, new UTF8Encoding(false), false, 4096, leaveOpen: true))
        using (var writer = new StreamWriter(connectedClient, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true })
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new PipeRequest(action, group)));
            // 请求一旦发出不自动重发，避免切换分组被重复执行。
            string? line = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(180));
            if (string.IsNullOrWhiteSpace(line)) throw new IOException("管理员后台已连接，但没有返回操作结果。详情已记录到 %LOCALAPPDATA%\\BootScopeTray\\backend.log。");
            return JsonSerializer.Deserialize<PipeReply>(line) ?? new PipeReply(10, "", "管理员后台返回空结果。");
        }
    }

    private static void LogClientBackendError(string context, Exception? ex)
    {
        try
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BootScopeTray");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "backend.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}: {ex}\r\n", new UTF8Encoding(false));
        }
        catch { }
    }

    private async void InstallAdminBackend()
    {
        try
        {
            string exe = Environment.ProcessPath ?? throw new InvalidOperationException("无法获取程序路径。");
            var psi = new ProcessStartInfo { FileName = exe, WorkingDirectory = _baseDir, UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            psi.ArgumentList.Add("--install-elevated-task");
            using var proc = Process.Start(psi) ?? throw new InvalidOperationException("无法启动管理员安装程序。");
            await proc.WaitForExitAsync();
            if (proc.ExitCode == 0)
            {
                MessageBox.Show("管理员权限托盘已启动并接管托盘图标；普通权限实例将退出。以后登录 Windows 时会自动启动。", "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Information);
                // 由提升后的实例接管托盘与菜单，普通权限实例不再保留第二个图标。
                ExitApplication();
            }
            else
                MessageBox.Show("设置管理员后台失败（代码 " + proc.ExitCode + "）。请确认你有管理员权限，并检查任务计划程序服务是否可用。", "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223) { }
        catch (Exception ex) { MessageBox.Show("设置管理员后台失败：\n" + ex.Message, "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private async void RemoveAdminBackend()
    {
        var confirm = MessageBox.Show("将删除永久管理员后台任务。之后分组启停和打开主窗口将要求重新设置授权。是否继续？", "启视 BootScope", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (confirm != DialogResult.Yes) return;
        try
        {
            int exitCode;
            if (_elevatedMode)
            {
                // 管理员托盘已经提权，直接删除任务并通过本机管道通知自身退出，不再二次请求 UAC。
                exitCode = await Task.Run(() => Program.UninstallElevatedTask());
            }
            else
            {
                string exe = Environment.ProcessPath ?? throw new InvalidOperationException("无法获取程序路径。");
                var psi = new ProcessStartInfo { FileName = exe, WorkingDirectory = _baseDir, UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
                psi.ArgumentList.Add("--uninstall-elevated-task");
                using var proc = Process.Start(psi) ?? throw new InvalidOperationException("无法启动管理员卸载程序。");
                await proc.WaitForExitAsync();
                exitCode = proc.ExitCode;
            }
            if (exitCode == 0) MessageBox.Show("永久管理员后台任务已删除。", "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else MessageBox.Show("删除管理员后台失败（代码 " + exitCode + "）。", "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223) { }
        catch (Exception ex) { MessageBox.Show("删除管理员后台失败：\n" + ex.Message, "启视 BootScope", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private bool _resourcesDisposed;

    internal void ExitApplication()
    {
        // ApplicationContext 不依赖调用方是否显式 Dispose；退出时主动释放托盘、菜单、图标和进程句柄。
        Dispose();
        ExitThread();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_resourcesDisposed)
        {
            _resourcesDisposed = true;
            try { _takeoverTimer?.Stop(); _takeoverTimer?.Dispose(); } catch { }
            try { _tray.Visible = false; } catch { }
            _tray.Dispose();
            _menu.Dispose();
            _trayIcon.Dispose();
            try { _mainWindowProcess?.Dispose(); } catch { }
            _mainWindowProcess = null;
            // 管理员实例自身承载托盘与命名管道；退出托盘时该实例一并结束。
        }
        base.Dispose(disposing);
    }

    private sealed record CliResult(bool Ok, string Message);

}
