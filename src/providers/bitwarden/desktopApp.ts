import { Platform } from "obsidian";

const BUNDLE_ID = "com.bitwarden.desktop";

interface ChildProcessModule {
  execFile(
    file: string,
    args: string[],
    options: { encoding: "utf8"; timeout: number; windowsHide: boolean },
    callback: (error: Error | null, stdout: string) => void,
  ): void;
}

function requireDesktopModule<T>(id: string): T {
  const req = (window as unknown as { require: (id: string) => unknown }).require;
  return req(id) as T;
}

function runCommand(file: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const childProcess = requireDesktopModule<ChildProcessModule>("child_process");
    childProcess.execFile(file, args, { encoding: "utf8", timeout: 8_000, windowsHide: true }, (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout.trim());
    });
  });
}

const WINDOWS_LOOKUP = String.raw`
$ErrorActionPreference = 'Stop'
$app = $null
if (Get-Command Get-StartApps -ErrorAction SilentlyContinue) {
  $app = Get-StartApps -ErrorAction SilentlyContinue | Where-Object {
    $_.AppID -eq '${BUNDLE_ID}' -or
    $_.AppID -match '^8bitSolutionsLLC\.bitwardendesktop_[a-z0-9]{13}!bitwardendesktop$'
  } | Select-Object -First 1
}

$exe = $null
if (-not $app) {
  $roots = @(
    (Join-Path $env:LOCALAPPDATA 'Programs')
    $env:ProgramFiles
    [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $env:ProgramW6432
  )
  $exe = $roots | Where-Object { $_ } | ForEach-Object {
    Join-Path $_ 'Bitwarden\Bitwarden.exe'
  } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
`;

const WINDOWS_OPEN = String.raw`
if ($app) {
  Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList ('shell:AppsFolder\' + $app.AppID)
} elseif ($exe) {
  Start-Process -FilePath $exe
} else {
  exit 1
}
`;

async function runWindowsCommand(script: string): Promise<string> {
  const { env } = requireDesktopModule<{ env: { SystemRoot?: string } }>("process");
  if (!env.SystemRoot) throw new Error("Windows system folder is unavailable");
  return runCommand(`${env.SystemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`, [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_LOOKUP + script,
  ]);
}

export async function hasBitwardenDesktop(): Promise<boolean> {
  if (!Platform.isDesktopApp) return false;
  try {
    if (Platform.isWin) {
      return (await runWindowsCommand("\nif ($app -or $exe) { 'installed' }")) === "installed";
    }
    if (!Platform.isMacOS) return false;
    const installed = await runCommand("/usr/bin/osascript", [
      "-l", "JavaScript",
      "-e", 'ObjC.import("AppKit");',
      "-e", `!$.NSWorkspace.sharedWorkspace.URLForApplicationWithBundleIdentifier("${BUNDLE_ID}").isNil();`,
    ]);
    return installed === "true";
  } catch {
    return false;
  }
}

export async function openBitwardenDesktop(): Promise<void> {
  if (Platform.isWin) {
    await runWindowsCommand(WINDOWS_OPEN);
  } else {
    await runCommand("/usr/bin/open", ["-b", BUNDLE_ID]);
  }
}
