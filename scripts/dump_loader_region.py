#!/usr/bin/env python3
"""
Dump the full 514 KB Stage 1 region of ImplantLoader.exe — both halves.

pe-sieve /shellc 3 dumped only the R-X executable half (248 KB at
0x7ffa730a7000). The RW data half above it holds the resolved-API pointer
table that every indirect CALL in the code half jumps to. To analyze the
license-check protocol we need both halves.

Strategy: VirtualQueryEx-walk the process; find every MEM_PRIVATE region
whose first 32 bytes match the known Stage 1 signature; dump the whole
contiguous AllocationBase range.

Run from an elevated shell — the loader is UAC-elevated.

Usage:
    python dump_full_region.py            # auto-watch for ImplantLoader.exe
    python dump_full_region.py --pid N    # scan a specific PID
    python dump_full_region.py --addr 0x7ffa730a7000  # dump from a known base
"""
from __future__ import annotations
import argparse, ctypes, ctypes.wintypes as w, struct, sys, time, hashlib
from pathlib import Path

# ---------------- Win32 ABI ----------------
PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFO= 0x1000

MEM_COMMIT  = 0x00001000
MEM_FREE    = 0x00010000
MEM_PRIVATE = 0x00020000
MEM_MAPPED  = 0x00040000
MEM_IMAGE   = 0x01000000

PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD             = 0x100

K32 = ctypes.WinDLL("kernel32", use_last_error=True)
ADV = ctypes.WinDLL("advapi32", use_last_error=True)

# ---------------- SeDebugPrivilege helpers ----------------
TOKEN_QUERY              = 0x0008
TOKEN_ADJUST_PRIVILEGES  = 0x0020
SE_PRIVILEGE_ENABLED     = 0x00000002

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", w.DWORD), ("HighPart", ctypes.c_long)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", w.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", w.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]

ADV.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
ADV.OpenProcessToken.restype = w.BOOL
ADV.LookupPrivilegeValueW.argtypes = [w.LPCWSTR, w.LPCWSTR, ctypes.POINTER(LUID)]
ADV.LookupPrivilegeValueW.restype = w.BOOL
ADV.AdjustTokenPrivileges.argtypes = [w.HANDLE, w.BOOL,
                                       ctypes.POINTER(TOKEN_PRIVILEGES),
                                       w.DWORD, ctypes.c_void_p, ctypes.c_void_p]
ADV.AdjustTokenPrivileges.restype = w.BOOL

def enable_se_debug() -> bool:
    h_token = w.HANDLE()
    h_proc = K32.GetCurrentProcess()
    if not ADV.OpenProcessToken(h_proc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                 ctypes.byref(h_token)):
        return False
    luid = LUID()
    if not ADV.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        return False
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    ok = ADV.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp),
                                    ctypes.sizeof(tp), None, None)
    err = ctypes.get_last_error()
    K32.CloseHandle(h_token)
    # AdjustTokenPrivileges returns nonzero even when the privilege wasn't
    # granted; GetLastError == ERROR_NOT_ALL_ASSIGNED (1300) indicates that.
    return bool(ok) and err == 0


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", w.DWORD),
        ("__align",           w.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             w.DWORD),
        ("Protect",           w.DWORD),
        ("Type",              w.DWORD),
        ("__pad",             w.DWORD),
    ]


K32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
K32.OpenProcess.restype = w.HANDLE

K32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p,
                                ctypes.POINTER(MEMORY_BASIC_INFORMATION64),
                                ctypes.c_size_t]
K32.VirtualQueryEx.restype = ctypes.c_size_t

K32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]
K32.ReadProcessMemory.restype = w.BOOL


def prot_to_str(p: int) -> str:
    base = {
        PAGE_NOACCESS: "---", PAGE_READONLY: "R--", PAGE_READWRITE: "RW-",
        PAGE_WRITECOPY: "WC-", PAGE_EXECUTE: "--X", PAGE_EXECUTE_READ: "R-X",
        PAGE_EXECUTE_READWRITE: "RWX", PAGE_EXECUTE_WRITECOPY: "WCX",
    }.get(p & ~PAGE_GUARD, f"?{p:#x}")
    return base + ("+G" if p & PAGE_GUARD else "")


# First 32 bytes of the known Stage 1 dump (from process_17508 / process_58560)
STAGE1_SIG = bytes.fromhex(
    "20e852220200eb9ff60591e204000274964c8b4b084c8d0584f40300ba160000"
)


def find_pid_by_name(name: str) -> int | None:
    """Find PID via PowerShell — works without admin if same user."""
    import subprocess
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-Process -Name '{name}' -ErrorAction SilentlyContinue | Select-Object -First 1).Id"],
            text=True, errors="replace", timeout=5,
        ).strip()
        return int(out) if out and out.isdigit() else None
    except Exception:
        return None


def read_mem(h: int, addr: int, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)()
    nread = ctypes.c_size_t(0)
    ok = K32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size,
                                ctypes.byref(nread))
    if not ok or nread.value == 0:
        return b""
    return bytes(buf[:nread.value])


def walk_regions(h: int):
    addr = 0
    end  = 0x0000_7FFF_FFFF_FFFF
    mbi = MEMORY_BASIC_INFORMATION64()
    while addr < end:
        sz = K32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                 ctypes.byref(mbi), ctypes.sizeof(mbi))
        if sz == 0: break
        yield (
            mbi.BaseAddress or 0,
            mbi.AllocationBase or 0,
            mbi.RegionSize,
            mbi.State, mbi.Protect, mbi.Type,
            mbi.AllocationProtect,
        )
        nxt = (mbi.BaseAddress or 0) + mbi.RegionSize
        if nxt <= addr: break
        addr = nxt


def is_committed_priv(state: int, type_: int) -> bool:
    return (state == MEM_COMMIT) and (type_ == MEM_PRIVATE)

def is_executable(protect: int) -> bool:
    return bool(protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))

def type_name(t: int) -> str:
    return {MEM_PRIVATE: "PRIV", MEM_MAPPED: "MAPD", MEM_IMAGE: "IMG"}.get(t, f"?{t:#x}")


def coalesce_alloc(h: int, target_alloc: int):
    """Find all regions sharing the same AllocationBase, return (start, total_size, [subregions])."""
    subs = []
    for (ba, ab, sz, st, pr, ty, ap) in walk_regions(h):
        if ab == target_alloc and st == MEM_COMMIT:
            subs.append((ba, sz, pr))
    if not subs: return None
    subs.sort()
    start = subs[0][0]
    end   = subs[-1][0] + subs[-1][1]
    return start, end - start, subs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--pname", default="ImplantLoader")
    ap.add_argument("--addr", type=lambda s: int(s, 0), default=None,
                    help="Specific base address (e.g. 0x7ffa730a7000) to dump")
    ap.add_argument("--sig", action="store_true",
                    help="Auto-find region whose first 32 bytes match the known Stage 1 signature")
    ap.add_argument("--out", type=Path,
                    default=Path(r"./workspace/implant_live_dumps"))
    ap.add_argument("--wait", action="store_true",
                    help="Poll until pname appears (use when relaunching the loader)")
    ap.add_argument("--delay-ms", type=int, default=2500,
                    help="After detecting the PID, wait this long before scanning. "
                         "VMP loaders take ~2s to unpack Stage 1 — too-early scans miss it.")
    ap.add_argument("--retry", type=int, default=4,
                    help="If signature not found, re-scan every 500 ms up to this many times.")
    args = ap.parse_args()

    # Resolve PID
    pid = args.pid
    if not pid:
        if args.wait:
            print(f"[wait] polling for {args.pname}.exe ...")
            for _ in range(600):  # up to 30 s
                pid = find_pid_by_name(args.pname)
                if pid: break
                time.sleep(0.05)
        else:
            pid = find_pid_by_name(args.pname)
    if not pid:
        print(f"[!] {args.pname}.exe not running. Launch it and try again.")
        return 2
    print(f"[+] target PID = {pid}")

    # Enable SeDebugPrivilege — admin tokens have it but it starts disabled,
    # and VMP'd processes reject OpenProcess without it.
    if enable_se_debug():
        print(f"[+] SeDebugPrivilege enabled.")
    else:
        err = ctypes.get_last_error()
        print(f"[!] could not enable SeDebugPrivilege (Win32 error {err}). "
              f"You probably need to run this from an elevated shell.")

    # Wait for VMP to unpack Stage 1 before scanning. The first scan we ran
    # only saw the still-encrypted main image (no Stage 1 mapped region) —
    # pe-sieve's prior successful scan took 2.3 s, so 2.5 s is the floor.
    if args.delay_ms > 0:
        print(f"[wait] sleeping {args.delay_ms} ms to let the loader unpack Stage 1 ...")
        time.sleep(args.delay_ms / 1000.0)

    # Open process — fall back through lower access masks if the protector
    # rejects PROCESS_VM_READ | PROCESS_QUERY_INFORMATION.
    access_attempts = [
        ("VM_READ|QUERY_INFO", PROCESS_VM_READ | PROCESS_QUERY_INFORMATION),
        ("VM_READ|QUERY_LIMITED", PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFO),
        ("VM_READ only", PROCESS_VM_READ),
        ("ALL_ACCESS", 0x001F0FFF),
    ]
    h = None
    for label, mask in access_attempts:
        h = K32.OpenProcess(mask, False, pid)
        if h:
            print(f"[+] OpenProcess({label}) handle={h:#x}")
            break
        err = ctypes.get_last_error()
        print(f"[*] OpenProcess({label}) failed, Win32 error {err}")
    if not h:
        print(f"[!] all OpenProcess access masks denied.")
        print(f"    Likely the loader has an OB_PRE_OPERATION_CALLBACK kernel hook")
        print(f"    stripping access rights. Use Process Hacker (KProcessHacker driver)")
        print(f"    or x64dbg with kernel-level dumping.")
        return 3

    # Decide target allocation base
    target_alloc = None
    if args.addr:
        target_alloc = args.addr
    else:
        # Auto-find by signature — scan ALL committed executable regions
        # (the prior Stage 1 was MEM_MAPPED with PAGE_EXECUTE_WRITECOPY, not
        # MEM_PRIVATE, so we can't filter on type).
        diag = []
        for attempt in range(args.retry + 1):
            print(f"[scan] attempt {attempt+1}/{args.retry+1}: walking all committed executable regions ...")
            scanned = 0
            diag = []  # reset each attempt
            candidates = []  # (size, base, alloc, prot, type, head) for fallback
            for (ba, ab, sz, st, pr, ty, ap2) in walk_regions(h):
                if st != MEM_COMMIT: continue
                if not is_executable(pr): continue
                scanned += 1
                head = read_mem(h, ba, 32)
                diag.append((ba, ab, sz, pr, ty, head))
                # Signature match
                if head == STAGE1_SIG:
                    target_alloc = ab
                    print(f"[hit] signature match at {ba:#x} (alloc base {ab:#x}, size {sz:#x}, prot {prot_to_str(pr)}, type {type_name(ty)})")
                    break
                # Fallback candidate: non-IMAGE region in the Stage 1 size band (100KB..1MB)
                # with first byte NOT in the 0xCC padding range — i.e. real code, not module-prologue padding.
                if (ty != MEM_IMAGE and 0x40000 <= sz <= 0x100000
                        and head and head[0] != 0xCC and head != b"\x00" * 32):
                    candidates.append((sz, ba, ab, pr, ty, head))
            if target_alloc: break
            # No signature hit; show fallback candidates from this attempt
            if candidates:
                print(f"[fallback] {len(candidates)} non-image region(s) in the Stage 1 size band:")
                for (sz, ba, ab, pr, ty, head) in sorted(candidates, reverse=True)[:10]:
                    print(f"    {ba:#014x}  alloc={ab:#014x}  size={sz:#x}  prot={prot_to_str(pr)}  type={type_name(ty)}  first16={head[:16].hex()}")
            if attempt < args.retry:
                print(f"[retry] no Stage 1 signature yet, sleeping 500 ms...")
                time.sleep(0.5)
        if not target_alloc:
            print(f"[!] no region matched the Stage 1 signature out of {scanned} candidates.")
            print(f"[diag] all executable committed regions in this process:")
            print(f"       {'base':>14}  {'allocbase':>14}  {'size':>10}  prot  type  first16")
            # Sort by size desc; the implant is one of the bigger non-image ones
            for (ba, ab, sz, pr, ty, head) in sorted(diag, key=lambda x: -x[2])[:30]:
                print(f"       {ba:#014x}  {ab:#014x}  {sz:>#10x}  {prot_to_str(pr):>4s}  {type_name(ty):>4s}  {head[:16].hex()}")
            # Persist diag so we can re-pick offline
            args.out.mkdir(parents=True, exist_ok=True)
            diag_path = args.out / f"region_diag_pid{pid}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            with diag_path.open("w") as f:
                f.write(f"# ImplantLoader region diagnostic, pid={pid}\n")
                for (ba, ab, sz, pr, ty, head) in sorted(diag, key=lambda x: -x[2]):
                    f.write(f"{ba:#014x} alloc={ab:#014x} size={sz:#x} "
                            f"prot={prot_to_str(pr)} type={type_name(ty)} first32={head.hex()}\n")
            print(f"[diag] wrote {diag_path}")
            print(f"    Possibilities: (a) loader hasn't unpacked yet — re-run with --wait,")
            print(f"    (b) new VMP layout — pick a region from the diag above and re-run with --addr <base>,")
            print(f"    (c) loader exited — try again.")
            return 4

    # Coalesce the whole AllocationBase region
    info = coalesce_alloc(h, target_alloc)
    if not info:
        print(f"[!] no committed pages at AllocationBase {target_alloc:#x}")
        return 5
    start, total, subs = info
    print(f"[region] AllocationBase = {target_alloc:#x}")
    print(f"         total committed = {total:#x} bytes across {len(subs)} subregion(s):")
    for (ba, sz, pr) in subs:
        print(f"           {ba:#018x}  size={sz:#x}  prot={prot_to_str(pr)}")

    # Read the whole thing
    print(f"[read] reading {total:#x} bytes from {start:#x} ...")
    chunks = []
    for (ba, sz, pr) in subs:
        if pr & (PAGE_GUARD | PAGE_NOACCESS):
            print(f"  skipping {ba:#x}+{sz:#x} (guard / noaccess)")
            chunks.append((ba, b"\x00" * sz))
            continue
        data = read_mem(h, ba, sz)
        if len(data) != sz:
            print(f"  partial read at {ba:#x}: {len(data)}/{sz}")
        chunks.append((ba, data))

    # Assemble into one contiguous blob (with zero padding for gaps)
    full = bytearray()
    cur = start
    for (ba, data) in chunks:
        if ba > cur:
            full.extend(b"\x00" * (ba - cur))
        full.extend(data)
        cur = ba + len(data)

    # Write artifact
    args.out.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = args.out / f"stage1_full_{target_alloc:x}_{ts}.bin"
    out.write_bytes(bytes(full))
    print(f"[done] wrote {len(full):,} bytes -> {out}")
    print(f"       sha256 = {hashlib.sha256(full).hexdigest()}")
    # Quick body diff vs prior 248 KB R-X-only dump
    prior_shc = Path(r"./workspace/implant_live_dumps/process_17508/7ffa730a7000.shc")
    if prior_shc.exists():
        shc = prior_shc.read_bytes()
        head_match = full[:len(shc)] == shc
        print(f"       first {len(shc):,} bytes match prior pe-sieve dump: {head_match}")
        if head_match:
            print(f"       NEW data (above the R-X half) = {len(full) - len(shc):,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
