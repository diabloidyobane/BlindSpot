#!/usr/bin/env python3
"""
Dump a fresh copy of the the implant implant from a live TheDivision2.exe
and diff against the previously reconstructed copy.

Background (from the user's own implant_paper.md):
  the implant is manually mapped into TheDivision2.exe as MEM_PRIVATE +RWX
  with the first 0x1000 bytes zeroed (header wipe). pe-sieve cannot
  recover a PE header so it tags the dump '<addr>.shc' under
  implanted_shc, not implanted_pe.  HollowsHunter or pe-sieve with
  /shellc 3 /imp 3 /data 3 will find it. Body size on May 27 was
  2,854,912 bytes; expect the same shape (~2.7-3.0 MB) on a fresh run.

This script:
  1. Locates pe-sieve64.exe on disk.
  2. Finds TheDivision2.exe pid.
  3. Runs pe-sieve with aggressive shellcode + import + data scan.
  4. Picks the dumped .shc that matches the the implant size profile.
  5. Reports the bytes-after-header (offset 0x1000+) hash and a diff
     against C:\\Users\\Jon\\Desktop\\_TD2_RE\\implant_reconstructed.dll.

Usage:
    python dump_implant_fresh.py
        --> writes to .\\implant_dump_<timestamp>\\process_<pid>\\

Add --pid <N> to scan a specific process instead.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import os
import subprocess
import sys
from pathlib import Path

PE_SIEVE = Path(r"./workspace/_RE_Tools/pe-sieve64.exe")
PRIOR_DLL = Path(r"./workspace/implant_reconstructed.dll")
DESKTOP = Path(r"./workspace")

# Heuristics — what counts as a the implant-candidate dump.
IMPLANT_MIN = 2_500_000   # ~2.5 MB
IMPLANT_MAX = 3_200_000   # ~3.2 MB
HEADER_WIPE_LEN = 0x1000    # the implant wipes the first page


def find_pid(name: str = "TheDivision2.exe") -> int | None:
    """Find the PID of a running process by exact image name."""
    try:
        out = subprocess.check_output(
            ["tasklist", "/fi", f"IMAGENAME eq {name}", "/fo", "csv", "/nh"],
            text=True, errors="replace",
        ).strip()
    except Exception as e:
        print(f"[!] tasklist failed: {e}", file=sys.stderr)
        return None
    if not out or "No tasks" in out:
        return None
    # CSV: "TheDivision2.exe","6888","Console","1","246,392 K"
    first = out.splitlines()[0]
    parts = [p.strip('"') for p in first.split('","')]
    if len(parts) < 2: return None
    try: return int(parts[1])
    except ValueError: return None


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hamming_after_header(a: bytes, b: bytes, skip: int = HEADER_WIPE_LEN) -> tuple[int, int]:
    """Bytewise difference count for two blobs after skipping their wiped header."""
    n = min(len(a) - skip, len(b) - skip)
    if n <= 0:
        return (0, 0)
    a_tail = a[skip:skip + n]
    b_tail = b[skip:skip + n]
    diffs = sum(1 for x, y in zip(a_tail, b_tail) if x != y)
    return diffs, n


def run_pe_sieve(pid: int, out_dir: Path) -> int:
    """
    Run pe-sieve with the full implant + thread-callstack pass.

    Why /threads matters for the implant specifically: the paper notes
    the implant uses thread hijacking (OpenThread/SetThreadContext) and
    has no Win32StartAddress inside the implant. A region-only scan
    must rank by size + private + no-mapped-file. /threads adds a
    second, independent positive signal: any thread whose call stack
    has a return address inside the suspicious region is flagged with
    SUS_RET / SUS_CALLSTACK_SHC / SUS_CALLS_INTEGRITY, and that frame
    is the live entry point inside the implant.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(PE_SIEVE),
        "/pid", str(pid),
        "/shellc", "3",     # aggressive shellcode detection (catches header-wiped manual maps)
        "/imp", "3",        # full IAT recovery + autosearch
        "/data", "3",       # scan non-executable too (catches the IAT table inside the implant)
        "/threads",         # walk thread callstacks; catches sleeping/hijacked threads in the implant
        "/dmode", "3",      # dump as virtual image
        "/dir", str(out_dir),
        "/quiet",
    ]
    print(f"[+] {' '.join(cmd)}")
    rc = subprocess.call(cmd)
    print(f"[+] pe-sieve exit code: {rc}")
    return rc


def parse_thread_findings(scan_dir: Path) -> list[dict]:
    """
    Extract thread-scan findings from scan_report.json.
    Returns a list of {thread_id, susp_addr, module, area_start, area_size, indicators}.
    These are the live entry points where the implant is being called from.
    """
    import json
    report = scan_dir / "scan_report.json"
    if not report.exists():
        return []
    try:
        data = json.loads(report.read_text(errors="replace"))
    except Exception:
        return []
    findings = []
    for scan in data.get("scans", []):
        ts = scan.get("thread_scan")
        if not ts: continue
        info = ts.get("thread_info", {})
        findings.append({
            "thread_id": ts.get("thread_id"),
            "indicators": ts.get("indicators", []),
            "susp_addr": ts.get("susp_addr"),
            "module": ts.get("module"),
            "area_start": ts.get("stats", {}).get("area_start"),
            "area_size": ts.get("stats", {}).get("area_size"),
            "entropy": ts.get("stats", {}).get("entropy"),
            "state": info.get("state"),
            "callstack_frames": info.get("callstack", {}).get("frames", []),
            "last_sysc": info.get("last_sysc"),
        })
    return findings


def pick_implant(scan_dir: Path) -> Path | None:
    """Return the dumped .shc/.dll that fits the the implant size profile."""
    candidates = []
    for f in scan_dir.rglob("*"):
        if f.is_file() and f.suffix.lower() in (".shc", ".dll") and not f.name.endswith(".imports.txt"):
            sz = f.stat().st_size
            if IMPLANT_MIN <= sz <= IMPLANT_MAX:
                candidates.append((sz, f))
    if not candidates:
        return None
    # If multiple match, prefer the .shc one (the implant is wiped → tagged .shc)
    candidates.sort(key=lambda x: (x[1].suffix != ".shc", -x[0]))
    return candidates[0][1]


def main() -> int:
    ap = argparse.ArgumentParser(description="Fresh the implant dump + diff vs prior reconstructed")
    ap.add_argument("--pid", type=int, default=None, help="Override PID (default: find TheDivision2.exe)")
    ap.add_argument("--out", type=Path, default=None, help="Override output dir")
    ap.add_argument("--prior", type=Path, default=PRIOR_DLL,
                    help="Prior reconstructed DLL to diff against")
    args = ap.parse_args()

    if not PE_SIEVE.exists():
        print(f"[!] pe-sieve64.exe not found at {PE_SIEVE}", file=sys.stderr)
        return 2

    pid = args.pid or find_pid("TheDivision2.exe")
    if not pid:
        print("[!] TheDivision2.exe not running.")
        print("    Launch the game + ImplantLoader.exe first, complete the")
        print("    license / OK step, give it a few seconds to map the implant,")
        print("    then re-run this script.")
        return 3

    print(f"[+] Target PID: {pid} (TheDivision2.exe)")
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.out or (DESKTOP / f"implant_dump_{ts}")
    run_pe_sieve(pid, out_dir)

    scan_dir = out_dir / f"process_{pid}"
    if not scan_dir.exists():
        # pe-sieve sometimes flattens; fall back to out_dir
        scan_dir = out_dir
    print(f"[+] Scan output: {scan_dir}")

    # Report any thread-scan findings BEFORE picking the region dump — those
    # give us the live entry-point RIPs inside the implant.
    findings = parse_thread_findings(scan_dir)
    if findings:
        print()
        print(f"[threads] {len(findings)} suspicious thread(s) with SUS_RET / SUS_CALLSTACK_SHC:")
        for i, f in enumerate(findings, 1):
            tid = f["thread_id"]
            inds = ",".join(f["indicators"])
            area = f["area_start"]
            sz = f["area_size"]
            sa = f["susp_addr"]
            ent = f["entropy"]
            sysc = f["last_sysc"] or "?"
            print(f"  #{i} tid={tid} state={f['state']} last_sysc={sysc}")
            print(f"      indicators={inds}")
            print(f"      susp_addr=0x{sa}  area=0x{area}+0x{sz}  entropy={ent}")
            frames = f["callstack_frames"]
            if frames:
                # Show top 6 frames; the suspicious one is typically the lowest module-less RIP
                print(f"      top callstack frames ({len(frames)}):")
                for fr in frames[:6]:
                    print(f"        {fr}")
        print()

    divt = pick_implant(scan_dir)
    if not divt:
        print("[!] No file in the the implant size band "
              f"({IMPLANT_MIN:,}-{IMPLANT_MAX:,} bytes) was dumped.")
        print("    Possibilities: (a) loader hasn't mapped yet — wait + retry,")
        print("    (b) the cheat shape changed substantially,")
        print("    (c) pe-sieve missed it (try hollows_hunter64.exe instead).")
        if findings:
            print()
            print("    Thread-scan findings above ARE positive evidence of an implant —")
            print("    even without a region dump, the susp_addr is the live entry point.")
            print("    Try the VirtualQuery walker from implant_paper.md to extract the body.")
        return 4

    # If we have both: cross-reference. Does any thread-scan area overlap our pick?
    if findings:
        try:
            pick_addr = int(divt.stem.split(".")[0], 16)
        except ValueError:
            pick_addr = None
        for f in findings:
            try:
                a_start = int(f["area_start"], 16) if f["area_start"] else None
                a_size = int(f["area_size"], 16) if f["area_size"] else None
            except (ValueError, TypeError):
                continue
            if a_start is None or pick_addr is None: continue
            if a_start <= pick_addr <= a_start + (a_size or 0):
                print(f"[xref] thread tid={f['thread_id']} call-stack confirms the picked "
                      f"region is being actively executed (susp_addr=0x{f['susp_addr']}).")
                break

    new_bytes = divt.read_bytes()
    print(f"[+] Picked: {divt.name}  ({len(new_bytes):,} bytes)")
    print(f"    sha256        = {sha256(new_bytes)}")
    print(f"    first 16 bytes = {new_bytes[:16].hex()}")
    print(f"    sha256 of body (after 0x1000 wipe) = "
          f"{sha256(new_bytes[HEADER_WIPE_LEN:])}")

    # Also show the imports file if pe-sieve produced one
    imp_file = divt.with_suffix(divt.suffix + ".imports.txt")
    if imp_file.exists():
        ips = imp_file.read_text(errors="replace").splitlines()
        print(f"    imports file = {imp_file.name}  ({len(ips)} lines)")

    if not args.prior.exists():
        print(f"[!] Prior reconstructed DLL not found: {args.prior}")
        return 0

    prior_bytes = args.prior.read_bytes()
    diffs, n = hamming_after_header(new_bytes, prior_bytes)
    pct = (diffs / n * 100) if n else 0.0
    print()
    print(f"[diff] new vs {args.prior.name}")
    print(f"  new_size   = {len(new_bytes):,}")
    print(f"  prior_size = {len(prior_bytes):,}")
    print(f"  body bytes compared = {n:,}")
    print(f"  bytes differ = {diffs:,}  ({pct:.2f}%)")
    if diffs == 0 and len(new_bytes) == len(prior_bytes):
        print("  -> IDENTICAL body. No new version since the last dump.")
    elif pct < 0.5:
        print("  -> Near-identical (only relocation/import-table fixups differ).")
    elif pct < 5:
        print("  -> Minor change (point patches, hotfix-shape).")
    else:
        print("  -> Substantial change. New build / new features. Re-analyze.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
