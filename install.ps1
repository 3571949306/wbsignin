<#
.SYNOPSIS
    wbsignin Windows 一键安装脚本（零第三方依赖）
.EXAMPLE
    irm https://raw.githubusercontent.com/3571949306/wbsignin/main/install.ps1 | iex
    .\install.ps1 -InstallTask
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [string]$HomeDir = "",
    [string]$Branch = "main",
    [string]$RepoUrl = "https://github.com/3571949306/wbsignin.git",
    [string]$Passphrase = "",
    [switch]$InstallTask,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

function Say([string]$msg) { Write-Host $msg }
function Die([string]$msg) { Write-Host "`n[x] $msg" -ForegroundColor Red; exit 1 }

# 1. 查找 Python 3.8+
Say "== 1/5 检查 Python 环境 =="
$PyExe = $null
$PyPrefixArgs = @()

foreach ($cmdName in @("python", "python3")) {
    $cmd = Get-Command $cmdName -ErrorAction SilentlyContinue
    if ($cmd) {
        & $cmd.Source -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $PyExe = $cmd.Source
            break
        }
    }
}
if (-not $PyExe) {
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        & $pyLauncher.Source -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $PyExe = (& $pyLauncher.Source -3 -c "import sys; print(sys.executable)")
        }
    }
}
if (-not $PyExe) {
    Die "未检测到 Python 3.8+，请先安装 Python（https://www.python.org/downloads/）。"
}
$PyVer = & $PyExe -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
Say "  Python $PyVer ($PyExe)"

# 2. 确定源码目录
Say "== 2/5 准备程序源码 =="
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$InsideRepo = (Test-Path (Join-Path $ScriptRoot "pyproject.toml")) -and (Test-Path (Join-Path $ScriptRoot "wbsignin\__init__.py"))

if (-not $InstallDir) {
    if ($InsideRepo) {
        $InstallDir = $ScriptRoot
    } else {
        $InstallDir = Join-Path $env:USERPROFILE ".local\share\wbsignin"
    }
}

if ($InsideRepo -and ($InstallDir -eq $ScriptRoot)) {
    Say "  使用当前仓库目录: $InstallDir"
} elseif ($InsideRepo) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    foreach ($sub in @("wbsignin", "tools", "tests")) {
        Copy-Item -Recurse -Force (Join-Path $ScriptRoot $sub) $InstallDir
    }
    foreach ($f in @("pyproject.toml", "README.md", "LICENSE", "install.ps1", "install.sh")) {
        $fp = Join-Path $ScriptRoot $f
        if (Test-Path $fp) { Copy-Item -Force $fp $InstallDir }
    }
    Say "  已复制源码至: $InstallDir"
} else {
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if ($gitCmd -and (Test-Path (Join-Path $InstallDir ".git"))) {
        Say "  更新已有仓库: $InstallDir"
        & $gitCmd.Source -C $InstallDir pull --ff-only
    } elseif ($gitCmd) {
        New-Item -ItemType Directory -Force -Path (Split-Path $InstallDir -Parent) | Out-Null
        Say "  克隆仓库: $RepoUrl ($Branch) -> $InstallDir"
        & $gitCmd.Source clone --depth 1 --branch $Branch $RepoUrl $InstallDir
        if ($LASTEXITCODE -ne 0) { Die "git clone 失败" }
    } else {
        $zipUrl = "https://github.com/3571949306/wbsignin/archive/refs/heads/$Branch.zip"
        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wbsignin_" + [System.Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
        try {
            $zipFile = Join-Path $tmpDir "src.zip"
            Say "  下载源码压缩包: $zipUrl"
            Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
            Expand-Archive -Path $zipFile -DestinationPath $tmpDir -Force
            $extracted = Get-ChildItem -Path $tmpDir -Directory | Select-Object -First 1
            if (-not $extracted) { Die "压缩包解压失败" }
            if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
            New-Item -ItemType Directory -Force -Path (Split-Path $InstallDir -Parent) | Out-Null
            Move-Item -Path $extracted.FullName -Destination $InstallDir
        } finally {
            Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
        }
    }
}

# 3. 准备状态目录与主密码
Say "== 3/5 配置凭据库主密码 =="
if (-not $HomeDir) {
    $HomeDir = if ($env:WBSIGNIN_HOME) { $env:WBSIGNIN_HOME } else { Join-Path $env:USERPROFILE ".wbsignin" }
}
New-Item -ItemType Directory -Force -Path $HomeDir | Out-Null
$EnvFile = Join-Path $HomeDir "vault.env"

$EffPass = $Passphrase
if (-not $EffPass) { $EffPass = $env:WBSIGNIN_PASSPHRASE }
if (-not $EffPass -and (Test-Path $EnvFile)) {
    foreach ($line in Get-Content $EnvFile -Encoding UTF8) {
        if ($line -match '^WBSIGNIN_PASSPHRASE=(.+)$') {
            $EffPass = $Matches[1].Trim()
            Say "  复用现有主密码配置: $EnvFile"
            break
        }
    }
}
if (-not $EffPass) {
    if ($NonInteractive) {
        $EffPass = & $PyExe -c "import secrets; print(secrets.token_urlsafe(18))"
        Say "  已自动生成随机主密码并写入 vault.env"
    } else {
        $s1 = Read-Host "  设置凭据库主密码（至少 8 位）" -AsSecureString
        $s2 = Read-Host "  再输入一次确认" -AsSecureString
        $b1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s1))
        $b2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s2))
        if ($b1 -ne $b2) { Die "两次输入不一致" }
        $EffPass = $b1
    }
}
if ($EffPass.Length -lt 8) { Die "主密码至少 8 位" }

$envText = "WBSIGNIN_HOME=$HomeDir`nWBSIGNIN_PASSPHRASE=$EffPass`n"
[System.IO.File]::WriteAllText($EnvFile, $envText, (New-Object System.Text.UTF8Encoding($false)))
try {
    $acl = Get-Acl $EnvFile
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
        "FullControl",
        "Allow"
    )
    $acl.SetAccessRule($rule)
    Set-Acl -Path $EnvFile -AclObject $acl
} catch {
    Write-Warning "收紧 vault.env 文件权限失败: $_"
}
Say "  凭据环境已写入: $EnvFile"

# 4. 安装 CLI 包装器并加入用户 PATH
Say "== 4/5 安装 wbsignin 命令行入口 =="
$BinDir = Join-Path $env:USERPROFILE ".local\bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$CmdPath = Join-Path $BinDir "wbsignin.cmd"

$CmdContent = @"
@echo off
setlocal
if "%WBSIGNIN_HOME%"=="" set "WBSIGNIN_HOME=$HomeDir"
set "PYTHONPATH=$InstallDir;%PYTHONPATH%"
if "%WBSIGNIN_PASSPHRASE%"=="" if exist "%WBSIGNIN_HOME%\vault.env" (
  for /f "usebackq tokens=1,* delims==" %%A in ("%WBSIGNIN_HOME%\vault.env") do (
    if /i "%%A"=="WBSIGNIN_PASSPHRASE" set "WBSIGNIN_PASSPHRASE=%%B"
    if /i "%%A"=="WBSIGNIN_HOME" set "WBSIGNIN_HOME=%%B"
  )
)
"$PyExe" -m wbsignin %*
"@
Set-Content -Path $CmdPath -Value $CmdContent -Encoding ASCII

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$PathParts = if ($UserPath) { $UserPath -split ";" } else { @() }
if ($PathParts -notcontains $BinDir) {
    $NewPath = if ($UserPath) { "$UserPath;$BinDir" } else { $BinDir }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    $env:Path = "$env:Path;$BinDir"
    Say "  已将 $BinDir 加入用户 PATH"
}
Say "  CLI 命令已安装: $CmdPath"

# 5. 自检 + 可选计划任务
Say "== 5/5 运行环境自检 =="
& $CmdPath doctor

if ($InstallTask) {
    Say ""
    Say "创建 Windows 每日定时签到任务（08:17 与 10:17）..."
    $Action = New-ScheduledTaskAction -Execute $CmdPath -Argument "signin --quiet"
    $Trig1 = New-ScheduledTaskTrigger -Daily -At "08:17"
    $Trig2 = New-ScheduledTaskTrigger -Daily -At "10:17"
    $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName "wbsignin-daily" -Action $Action -Trigger @($Trig1, $Trig2) -Settings $Settings -Force | Out-Null
    Say "  已注册计划任务: wbsignin-daily"
}

Say ""
Say "== 安装完成 =="
Say "常用命令："
Say "  wbsignin accounts          # 查看账号"
Say "  wbsignin signin            # 立即签到全部账号"
Say "  wbsignin credit            # 查看积分/额度与到期时间"
Say "  wbsignin web               # 启动本地 Web 控制台 (http://127.0.0.1:8787)"
Say ""
Say "快速导入本机已登录客户端凭据："
Say "  python `"$InstallDir\tools\pull_doubao_cookie.py`" --local"
Say "  python `"$InstallDir\tools\pull_qoder_cred.py`" --local"
