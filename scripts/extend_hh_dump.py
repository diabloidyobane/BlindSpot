#!/usr/bin/env python3
"""
Companion to hollows_hunter: extend any new <addr>.shc dump by reading the
RW data half from the live loader process and appending it on disk.

HH /loop reliably catches Stage 1's R-X executable half. The RW data half
above offset 0x3e000 holds the resolved-API pointer table. HH won't dump
it (pe-sieve only dumps executable pages by default). This script watches
the HH output dir for new .shc files, parses the heap address from the
filename, opens the (still-alive) loader process, and reads bytes
addr+RX_SIZE..addr+TOTAL_SIZE into <name>.full.bin next to the original.

Run from an admin terminal in PARALLEL with hollows_hunter /loop.
"""
from __future__ import annotations
import argparse, ctypes, ctypes.wintypes as w, struct, sys, time, hashlib, re
from pathlib import Path

# Reuse the Win32 plumbing + privilege code from the walker
sys.path.insert(0, str(Path(__file__).parent))
import importlib.util
spec = importlib.util.spec_from_file_location("dfr", str(Path(__file__).parent / "dump_full_region.py"))
dfr = importlib.util.module_from_spec(spec); spec.loader.exec_module(dfr)

DUMP_DIR = Path(r"./workspace/implant_live_dumps")
HEX_RE = re.compile(r"^([0-9a-fA-F]{8,16})\.(?:shc|dll)$")


def find_pid(name: str = "ImplantLoader") -> int | None:
    return dfr.find_pid_by_name(name)


def already_extended(shc: Path) -> bool:
    return shc.with_suffix(shc.suffix + ".full.bin").exists()


def parse_addr(shc: Path) -> int | None:
    m = HEX_RE.match(shc.name)
    if not m: return None
    try: return int(m.group(1), 16)
    except ValueError: return None


def extend_one(shc: Path, pid: int) -> bool:
    """Walk the AllocationBase neighborhood of the .shc's address via VirtualQueryEx,
    read every committed subregion, and write <name>.full.bin with the contiguous blob.
    Also enumerates SIBLING regions (allocations at completely different addresses)
    that may hold matching code / data for the cheat — writes them as <name>.sibling_<addr>.bin.
    """
    addr = parse_addr(shc)
    if addr is None:
        print(f"  skip (can't parse address): {shc.name}")
        return False
    h = dfr.K32.OpenProcess(
        dfr.PROCESS_VM_READ | dfr.PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        err = ctypes.get_last_error()
        print(f"  OpenProcess(pid={pid}) failed Win32 err {err}")
        return False
    try:
        # Find this region's AllocationBase
        mbi = dfr.MEMORY_BASIC_INFORMATION64()
        sz = dfr.K32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
        if sz == 0:
            print(f"  VirtualQueryEx({hex(addr)}) failed")
            return False
        alloc_base = mbi.AllocationBase or addr
        print(f"  base={hex(addr)} alloc_base={hex(alloc_base)} "
              f"state={mbi.State:#x} type={mbi.Type:#x} prot={mbi.Protect:#x}")

        # Walk every subregion sharing this AllocationBase
        info = dfr.coalesce_alloc(h, alloc_base)
        if not info:
            print(f"  no committed pages at alloc_base {hex(alloc_base)}")
            return False
        start, total, subs = info
        print(f"  coalesced: start={hex(start)} total={hex(total)} subs={len(subs)}")
        for (ba, ssz, pr) in subs:
            print(f"    {hex(ba)} +{hex(ssz)} prot={dfr.prot_to_str(pr)}")

        # If this is a system DLL (MEM_IMAGE) > 16 MB, DON'T dump the whole
        # allocation — HH was just flagging a hooked function inside an
        # otherwise-legit module. Dump a 64-page window around the actual
        # suspicious address instead.
        is_image = (mbi.Type == 0x1000000)  # MEM_IMAGE
        big_image = is_image and total > 16 * 1024 * 1024
        if big_image:
            window = 0x40000  # 256 KB centered on the suspicious address
            ws = max(start, (addr - window // 2) & ~0xFFF)
            we = min(start + total, ws + window)
            print(f"  big-image: writing 256 KB window around addr instead "
                  f"of {total:#x}-byte whole DLL")
            data = dfr.read_mem(h, ws, we - ws)
            out = shc.with_suffix(shc.suffix + ".window.bin")
            out.write_bytes(data)
            print(f"  -> {out.name}  ({len(data):,} bytes)  "
                  f"sha256={hashlib.sha256(data).hexdigest()[:24]}...")
            return True

        # Read all subregions of this allocation into one contiguous blob
        full = bytearray()
        cur = start
        for (ba, ssz, pr) in subs:
            if ba > cur:
                full.extend(b"\x00" * (ba - cur))
            if pr & (dfr.PAGE_GUARD | dfr.PAGE_NOACCESS):
                full.extend(b"\x00" * ssz)
            else:
                data = dfr.read_mem(h, ba, ssz)
                if len(data) != ssz:
                    print(f"    partial read at {hex(ba)}: {len(data)}/{ssz}")
                full.extend(data)
            cur = ba + ssz

        # Sanity: if the .shc is the same as what we just read (R-X half at top),
        # great — we wrote the full thing. If alloc_base != addr the .shc was a
        # subregion; output is still the full allocation.
        out = shc.with_suffix(shc.suffix + ".full.bin")
        out.write_bytes(bytes(full))
        sha = hashlib.sha256(full).hexdigest()
        print(f"  -> {out.name}  ({len(full):,} bytes)  sha256={sha[:24]}...")

        return True
    finally:
        dfr.K32.CloseHandle(h)


def dump_all_private_executable(pid: int, out_dir: Path) -> int:
    """Side-quest: walk EVERY MEM_PRIVATE+exec or MEM_MAPPED+exec region in the
    process and dump those whose first bytes don't look like a system module.
    These are the candidates for the cheat's code allocation that lives ALONGSIDE
    the data heap. Returns count dumped."""
    h = dfr.K32.OpenProcess(
        dfr.PROCESS_VM_READ | dfr.PROCESS_QUERY_INFORMATION, False, pid)
    if not h: return 0
    n = 0
    try:
        seen_alloc = set()
        for (ba, ab, ssz, st, pr, ty, ap2) in dfr.walk_regions(h):
            if st != 0x1000: continue           # MEM_COMMIT
            if not dfr.is_executable(pr): continue
            if ab in seen_alloc: continue
            seen_alloc.add(ab)
            # Skip clearly-system regions: type=IMG that have a head matching
            # the CC-padded prologue style + a 1-page tail page (Windows DLLs)
            head = dfr.read_mem(h, ba, 32)
            if ty == 0x1000000:  # MEM_IMAGE
                continue
            # Coalesce and dump
            info = dfr.coalesce_alloc(h, ab)
            if not info: continue
            start, total, subs = info
            if total < 0x10000 or total > 0x10_000_000:  # 64 KB .. 16 MB
                continue
            full = bytearray()
            cur = start
            for (sba, sz_, pr_) in subs:
                if sba > cur:
                    full.extend(b"\x00" * (sba - cur))
                if pr_ & (dfr.PAGE_GUARD | dfr.PAGE_NOACCESS):
                    full.extend(b"\x00" * sz_)
                else:
                    full.extend(dfr.read_mem(h, sba, sz_))
                cur = sba + sz_
            out = out_dir / f"sidequest_{ab:x}_{total:x}_pid{pid}.bin"
            out.write_bytes(bytes(full))
            print(f"  side-quest dump: {out.name} ({total:,} bytes, head={head[:16].hex()})")
            n += 1
    finally:
        dfr.K32.CloseHandle(h)
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=DUMP_DIR,
                    help="HH output dir to watch")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="Stop watching after this many seconds")
    ap.add_argument("--once", action="store_true",
                    help="Process existing files once and exit (no watch loop)")
    args = ap.parse_args()

    if not dfr.enable_se_debug():
        print(f"[!] could not enable SeDebugPrivilege (err {ctypes.get_last_error()}).")
        print(f"    Re-run from an elevated terminal.")
        return 2

    print(f"[+] watching {args.dir} for new <addr>.shc files (timeout {args.timeout}s)")
    print(f"    Run hollows_hunter64.exe /loop in parallel; or use the existing")
    print(f"    catch_implant.bat in another admin window.")
    print()

    seen = set()
    # On startup, mark already-extended files as 'seen' so we don't re-process
    for shc in args.dir.rglob("*.shc"):
        if already_extended(shc):
            seen.add(shc)

    start = time.time()
    while time.time() - start < args.timeout:
        new = []
        for shc in args.dir.rglob("*.shc"):
            if shc in seen: continue
            if already_extended(shc): seen.add(shc); continue
            new.append(shc)

        if new:
            pid = find_pid("ImplantLoader")
            print(f"[+] {len(new)} new .shc file(s); current loader PID: {pid}")
            for shc in new:
                print(f" extend {shc.name}")
                if pid is None:
                    print(f"  warning: loader is not running; can't read.")
                    seen.add(shc)
                    continue
                ok = extend_one(shc, pid)
                if ok:
                    seen.add(shc)
            # Once we've extended at least one .shc successfully, also dump
            # all other non-image executable regions in this PID — those are
            # the candidates for the matching code allocation of the cheat.
            if pid is not None and any(s in seen for s in new):
                out_dir = (next(iter(new))).parent
                print(f"[side-quest] dumping all non-image executable allocations in pid {pid}...")
                n = dump_all_private_executable(pid, out_dir)
                print(f"[side-quest] {n} additional region(s) dumped")

        if args.once: break
        time.sleep(0.2)

    print("[+] done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
