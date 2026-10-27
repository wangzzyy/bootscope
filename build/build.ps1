# 在 Windows + .NET 8 SDK 环境运行。默认生成 win-x64 文件夹。
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw '未找到 dotnet。请先安装 .NET 8 SDK：https://dotnet.microsoft.com/download/dotnet/8.0'
}
$cliScript = Join-Path (Split-Path -Parent $root) 'BootScope.ps1'
if (-not (Test-Path $cliScript)) {
    throw '缺少同级文件 BootScope.ps1。请确认它位于项目文件夹的上一级目录。'
}
dotnet publish (Join-Path $root 'BootScopeTray.csproj') -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o (Join-Path $root 'publish\win-x64')
if ($LASTEXITCODE -ne 0) { throw "dotnet publish 失败，退出代码：$LASTEXITCODE" }
$exePath = Join-Path $root 'publish\win-x64\BootScopeTray.exe'
if (-not (Test-Path $exePath)) { throw '发布失败：没有生成 BootScopeTray.exe。' }
Copy-Item $cliScript (Join-Path $root 'publish\win-x64\BootScope.ps1') -Force
if (Test-Path (Join-Path $root 'groups.json')) {
    Copy-Item (Join-Path $root 'groups.json') (Join-Path $root 'publish\win-x64\groups.json') -Force
} else {
    Write-Warning '本目录没有 groups.json。请把你现有的 groups.json 手动复制到 publish\win-x64，避免丢失现有分组配置。'
}
if (-not (Test-Path (Join-Path $root 'publish\win-x64\BootScopeTray.exe'))) { throw '发布失败：最终 EXE 不存在。' }
Write-Host "完成：$root\publish\win-x64\BootScopeTray.exe" -ForegroundColor Green
