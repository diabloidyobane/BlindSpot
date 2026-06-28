"""
dump_contiguous_image.py — dump a contiguous VA range from a target process,
walking VirtualQueryEx and stitching mapped sub-regions with zero-fill over
unmapped/protected gaps.

Use case: rebuild an MM-mapped DLL whose .text/.rdata/.pdata live in
non-contiguous sub-allocations (the loader allocated each section
separately, leaving gaps for unallocated/RW sections).

Usage:
    python dump_contiguous_image.py --pid <PID> --base 0x<HEX> --size 0x<HEX> --out <path>
"""

import argparse
import ctypes
import os
import sys
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
MEM_COMMIT                = 0x1000
PAGE_NOACCESS             = 0x01
PAGE_GUARD                = 0x100


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid',  type=int, required=True)
    ap.add_argument('--base', type=lambda x: int(x, 0), required=True)
    ap.add_argument('--size', type=lambda x: int(x, 0), required=True)
    ap.add_argument('--out',  required=True)
    args = ap.parse_args()

    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                             False, args.pid)
    if not h:
        print(f'[-] OpenProcess failed: err={ctypes.get_last_error()}')
        return 1

    img_base = args.base
    img_end  = args.base + args.size
    out      = bytearray(args.size)   # zero-init
    cur      = img_base
    total_in = 0

    print(f'{"BASE":<18} {"SIZE":>10}  STATE PROT  result')
    print('-' * 72)
    while cur < img_end:
        mbi = MEMORY_BASIC_INFORMATION()
        r = kernel32.VirtualQueryEx(h, ctypes.c_void_p(cur),
                                    ctypes.byref(mbi),
                                    ctypes.sizeof(mbi))
        if r == 0:
            print(f'{cur:016X}  -- VirtualQueryEx failed (err={ctypes.get_last_error()})')
            break
        rb = mbi.BaseAddress or 0
        rs = mbi.RegionSize or 0
        nx = rb + rs
        if nx <= cur:
            nx = cur + 0x1000

        # Trim to image window
        eff_base = max(rb, img_base)
        eff_end  = min(nx, img_end)
        eff_size = eff_end - eff_base

        committed = (mbi.State == MEM_COMMIT)
        guarded   = bool(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        readable  = committed and not guarded and (mbi.Protect & 0xFF) != 0

        if eff_size > 0 and readable:
            buf = ctypes.create_string_buffer(eff_size)
            n = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(h, ctypes.c_void_p(eff_base), buf,
                                            eff_size, ctypes.byref(n))
            got = n.value
            if ok and got > 0:
                out[eff_base - img_base : eff_base - img_base + got] = buf.raw[:got]
                total_in += got
                print(f'{eff_base:016X}  0x{eff_size:8X}  C 0x{mbi.Protect:03X}  ok read=0x{got:X}')
            else:
                print(f'{eff_base:016X}  0x{eff_size:8X}  C 0x{mbi.Protect:03X}  RPM FAIL err={ctypes.get_last_error()}')
        else:
            print(f'{eff_base:016X}  0x{max(0,eff_size):8X}  S 0x{mbi.State:05X} P 0x{mbi.Protect:03X}  skip (uncommitted/guarded)')

        cur = nx

    print('-' * 72)
    print(f'[=] read 0x{total_in:X} of 0x{args.size:X} bytes')

    with open(args.out, 'wb') as f:
        f.write(out)
    print(f'[+] wrote {args.out} ({len(out):,} bytes)')

    kernel32.CloseHandle(h)
    return 0


if __name__ == '__main__':
    sys.exit(main())
