"""
scan_exec_private.py — list every MEM_PRIVATE region with an executable
protection (PAGE_EXECUTE*, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE).

A manual-mapped DLL always has at least one RX region (its .text). Even if
the loader wiped every PE/MZ byte out of the headers, the code section
itself still has to be executable — you can't run from non-X pages.

If we see suspicious RX private regions of reasonable size (>= ~0x8000),
those are strong implant candidates. A "clean" process has very few RX
private regions: JITs, some shims, maybe a dozen. Most executable mappings
are MEM_IMAGE (real DLLs loaded by the Windows loader).

Usage:
    python scan_exec_private.py --pid 24468
"""

import argparse
import ctypes
import os
import struct
import sys
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
MEM_COMMIT                = 0x1000
MEM_PRIVATE               = 0x20000
PAGE_EXECUTE              = 0x10
PAGE_EXECUTE_READ         = 0x20
PAGE_EXECUTE_READWRITE    = 0x40
PAGE_EXECUTE_WRITECOPY    = 0x80
EXEC_MASK                 = (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
PAGE_GUARD                = 0x100
PAGE_NOACCESS             = 0x01


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       ctypes.c_void_p),
        ('AllocationBase',    ctypes.c_void_p),
        ('AllocationProtect', wintypes.DWORD),
        ('__alignment1',      wintypes.DWORD),
        ('RegionSize',        ctypes.c_size_t),
        ('State',             wintypes.DWORD),
        ('Protect',           wintypes.DWORD),
        ('Type',              wintypes.DWORD),
        ('__alignment2',      wintypes.DWORD),
    ]


kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                                    ctypes.c_size_t]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return bytes(buf.raw[:n.value]) if ok else None


def entropy(data):
    """Shannon entropy, normalized to 0..8."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    import math
    H = 0.0
    for c in counts:
        if c:
            p = c / n
            H -= p * math.log2(p)
    return H


def prot_name(p):
    names = []
    if p & PAGE_EXECUTE_WRITECOPY: names.append('X-COW')
    elif p & PAGE_EXECUTE_READWRITE: names.append('XRW')
    elif p & PAGE_EXECUTE_READ: names.append('XR')
    elif p & PAGE_EXECUTE: names.append('X')
    if p & 0x200: names.append('NC')
    if p & PAGE_GUARD: names.append('GUARD')
    return '|'.join(names) if names else f'0x{p:X}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--min-size', type=lambda x: int(x, 0), default=0x2000)
    ap.add_argument('--dump', action='store_true',
                    help='Write each candidate region to ~/Desktop/execprivate_<pid>/')
    args = ap.parse_args()

    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                             False, args.pid)
    if not h:
        print(f'[-] OpenProcess failed: err={ctypes.get_last_error()}')
        return 1

    out_dir = os.path.join(os.path.expanduser('~'), 'Desktop',
                           f'execprivate_{args.pid}')
    if args.dump:
        os.makedirs(out_dir, exist_ok=True)

    addr = 0
    hits = []
    print(f'{"BASE":<18} {"SIZE":>12} {"PROT":<8}  first bytes             entropy')
    print('-' * 90)

    while addr < 0x7FFF_FFFFFFFF:
        mbi = MEMORY_BASIC_INFORMATION()
        if kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                   ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        region_base = mbi.BaseAddress or 0
        region_size = mbi.RegionSize or 0
        next_addr = region_base + region_size
        if next_addr <= addr:
            next_addr = addr + 0x1000
        addr = next_addr

        if mbi.State != MEM_COMMIT:                continue
        if mbi.Type != MEM_PRIVATE:                continue
        if region_size < args.min_size:            continue
        if not (mbi.Protect & EXEC_MASK):          continue
        if mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS): continue

        sample = read_mem(h, region_base, min(0x100, region_size))
        if not sample:
            continue
        ent = entropy(read_mem(h, region_base, min(0x4000, region_size)) or b'')

        # First 16 bytes as hex
        hexbytes = ' '.join(f'{b:02X}' for b in sample[:16])
        print(f'{region_base:016X}  0x{region_size:10X}  {prot_name(mbi.Protect):<7}  {hexbytes}  {ent:.2f}')

        hits.append((region_base, region_size, mbi.Protect))

        if args.dump:
            full = read_mem(h, region_base, region_size)
            if full:
                fname = f'execpriv_{region_base:016X}_0x{region_size:X}.bin'
                fpath = os.path.join(out_dir, fname)
                with open(fpath, 'wb') as f:
                    f.write(full)

    print('-' * 90)
    print(f'[=] Found {len(hits)} executable private regions')
    if args.dump and hits:
        print(f'[+] Dumped to {out_dir}')
    kernel32.CloseHandle(h)
    return 0


if __name__ == '__main__':
    sys.exit(main())
