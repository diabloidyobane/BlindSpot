"""
dump_manualmap.py — find manual-mapped DLLs in a target process and dump them.

Sweeps every MEM_COMMIT + MEM_PRIVATE region via VirtualQueryEx, checks for
MZ+PE headers, then reads the full image via ReadProcessMemory and rebuilds
section headers so raw==virtual (the file loads 1:1 into IDA).

Usage:
    python dump_manualmap.py --pid 12345
    python dump_manualmap.py --name TheDivision2.exe
    python dump_manualmap.py --pid 12345 --out C:\\dumps --min-size 0x10000

Works against any target you can OpenProcess() on — no driver, no debugger,
no EAC bypass. For EAC-hardened processes use the IOCTL-driver-backed tool
instead.
"""

import argparse
import ctypes
from ctypes import wintypes
import os
import struct
import sys

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# --- access rights & constants ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010

MEM_COMMIT   = 0x1000
MEM_PRIVATE  = 0x20000
MEM_IMAGE    = 0x1000000
MEM_MAPPED   = 0x40000

PAGE_NOACCESS = 0x01
PAGE_GUARD    = 0x100

TH32CS_SNAPPROCESS = 0x00000002

# --- structs ---
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


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize',              wintypes.DWORD),
        ('cntUsage',            wintypes.DWORD),
        ('th32ProcessID',       wintypes.DWORD),
        ('th32DefaultHeapID',   ctypes.c_void_p),
        ('th32ModuleID',        wintypes.DWORD),
        ('cntThreads',          wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase',      wintypes.LONG),
        ('dwFlags',             wintypes.DWORD),
        ('szExeFile',           ctypes.c_char * 260),
    ]


# --- API bindings ---
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

kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

kernel32.Process32First.restype = wintypes.BOOL
kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.restype = wintypes.BOOL
kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]


# --- helpers ---
def read_memory(handle, address, size):
    """Read `size` bytes at `address` in the target. Returns bytes on success."""
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address),
                                    buf, size, ctypes.byref(read))
    if not ok:
        return None
    return bytes(buf.raw[:read.value])


def find_pid_by_name(name):
    """Case-insensitive exe-name → PID via Toolhelp snapshot."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value or not snap:
        return None
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    found = None
    try:
        if kernel32.Process32First(snap, ctypes.byref(pe)):
            while True:
                exe = pe.szExeFile.decode('ascii', errors='replace')
                if exe.lower() == name.lower():
                    found = pe.th32ProcessID
                    break
                if not kernel32.Process32Next(snap, ctypes.byref(pe)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    return found


def parse_pe_header(header_bytes):
    """Return dict with bitness, machine, nsec, oh_size, image_base, size_of_image, dd_off.
    `dd_off` is the offset of the DataDirectory array inside the buffer."""
    if len(header_bytes) < 0x40 or header_bytes[:2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', header_bytes, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 0x18 + 0x70 > len(header_bytes):
        return None
    if struct.unpack_from('<I', header_bytes, e_lfanew)[0] != 0x00004550:  # 'PE\0\0'
        return None
    machine = struct.unpack_from('<H', header_bytes, e_lfanew + 4)[0]
    nsec    = struct.unpack_from('<H', header_bytes, e_lfanew + 6)[0]
    oh_size = struct.unpack_from('<H', header_bytes, e_lfanew + 0x14)[0]
    magic   = struct.unpack_from('<H', header_bytes, e_lfanew + 0x18)[0]
    oh_off  = e_lfanew + 0x18 + 2  # immediately after Magic
    if magic == 0x20B:  # PE32+
        bitness = 64
        image_base    = struct.unpack_from('<Q', header_bytes, e_lfanew + 0x18 + 0x18)[0]
        size_of_image = struct.unpack_from('<I', header_bytes, e_lfanew + 0x18 + 0x38)[0]
        dd_off        = e_lfanew + 0x18 + 0x70
        image_base_off = e_lfanew + 0x18 + 0x18
    elif magic == 0x10B:  # PE32
        bitness = 32
        image_base    = struct.unpack_from('<I', header_bytes, e_lfanew + 0x18 + 0x1C)[0]
        size_of_image = struct.unpack_from('<I', header_bytes, e_lfanew + 0x18 + 0x38)[0]
        dd_off        = e_lfanew + 0x18 + 0x60
        image_base_off = e_lfanew + 0x18 + 0x1C
    else:
        return None
    return {
        'e_lfanew':       e_lfanew,
        'machine':        machine,
        'nsec':           nsec,
        'oh_size':        oh_size,
        'magic':          magic,
        'bitness':        bitness,
        'image_base':     image_base,
        'image_base_off': image_base_off,
        'size_of_image':  size_of_image,
        'dd_off':         dd_off,
        'first_sec_off':  e_lfanew + 4 + 0x14 + oh_size,
    }


def reconstruct(img, base, meta):
    """In-place fixups:
        1. ImageBase := runtime base (so absolute addresses match the dump).
        2. Every section: PointerToRawData := VirtualAddress,
                          SizeOfRawData    := VirtualSize
           (raw == virtual so file layout mirrors loaded image, IDA opens 1:1).
        3. IMAGE_DIRECTORY_ENTRY_BASERELOC := 0 / 0 — loader won't try to
           relocate (we just baked ImageBase to the runtime address).
    """
    # 1. ImageBase
    if meta['bitness'] == 64:
        struct.pack_into('<Q', img, meta['image_base_off'], base)
    else:
        struct.pack_into('<I', img, meta['image_base_off'], base & 0xFFFFFFFF)

    # 2. Sections
    SECTION_HEADER_SIZE = 0x28
    for i in range(meta['nsec']):
        so = meta['first_sec_off'] + i * SECTION_HEADER_SIZE
        if so + SECTION_HEADER_SIZE > len(img):
            break
        virt_addr = struct.unpack_from('<I', img, so + 0x0C)[0]
        virt_size = struct.unpack_from('<I', img, so + 0x08)[0]
        # Clamp if the image got truncated
        if virt_addr + virt_size > len(img):
            virt_size = max(0, len(img) - virt_addr)
            struct.pack_into('<I', img, so + 0x08, virt_size)
        struct.pack_into('<I', img, so + 0x10, virt_size)   # SizeOfRawData
        struct.pack_into('<I', img, so + 0x14, virt_addr)   # PointerToRawData

    # 3. Clear relocation directory (entry index 5 in DataDirectory)
    struct.pack_into('<II', img, meta['dd_off'] + 5 * 8, 0, 0)


def scan_process(pid, min_size, max_size, out_dir):
    """Walk every committed private region, dump each MZ+PE hit."""
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        err = ctypes.get_last_error()
        print(f'[-] OpenProcess({pid}) failed: err={err} ({ctypes.FormatError(err).strip()})')
        print('    If this is EAC or similar, the usermode handle was stripped.')
        print('    Use the driver-backed dumper (/dumper.exe) instead.')
        return 0

    addr = 0
    limit = 0x7FFF_FFFFFFFF
    dumped = 0
    scanned = 0

    os.makedirs(out_dir, exist_ok=True)

    while addr < limit:
        mbi = MEMORY_BASIC_INFORMATION()
        ret = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi))
        if ret == 0:
            break
        scanned += 1

        region_base = mbi.BaseAddress or 0
        region_size = mbi.RegionSize or 0
        next_addr = region_base + region_size
        # Safety net against stuck-at-zero loops
        if next_addr <= addr:
            next_addr = addr + 0x1000
        addr = next_addr

        if mbi.State != MEM_COMMIT:                     continue
        if mbi.Type  != MEM_PRIVATE:                    continue
        if region_size < min_size:                      continue
        if region_size > max_size:                      continue
        if mbi.Protect & PAGE_NOACCESS:                 continue
        if mbi.Protect & PAGE_GUARD:                    continue

        # Read enough to see the DOS + NT headers + section table (generous)
        head = read_memory(h, region_base, min(0x2000, region_size))
        if not head or head[:2] != b'MZ':               continue

        meta = parse_pe_header(head)
        if not meta:                                    continue

        soi = meta['size_of_image']
        if soi == 0 or soi > region_size + 0x100_0000:  # sanity cap ~16 MB slack
            print(f'[!] {region_base:016X} SizeOfImage=0x{soi:X} looks wrong, skip')
            continue

        print(f'[+] {region_base:016X}  {meta["bitness"]}-bit  '
              f'sections={meta["nsec"]}  SizeOfImage=0x{soi:X}  '
              f'RegionSize=0x{region_size:X}')

        # Read the full mapped image, clamped to the region bound
        read_size = min(soi, region_size)
        img_bytes = read_memory(h, region_base, read_size)
        if not img_bytes or len(img_bytes) < read_size:
            # Sometimes pages within the allocation aren't all committed; fall
            # back to reading page-by-page so we salvage what we can.
            img = bytearray(read_size)
            for off in range(0, read_size, 0x1000):
                chunk = read_memory(h, region_base + off,
                                    min(0x1000, read_size - off))
                if chunk:
                    img[off:off + len(chunk)] = chunk
        else:
            img = bytearray(img_bytes)

        # Reconstruct headers
        reconstruct(img, region_base, meta)

        # Save
        tag = 'x64' if meta['bitness'] == 64 else 'x86'
        fname = f'mm_{region_base:016X}_{tag}.bin'
        fpath = os.path.join(out_dir, fname)
        with open(fpath, 'wb') as f:
            f.write(img)
        print(f'    → {fpath}  ({len(img):,} bytes)')
        dumped += 1

    kernel32.CloseHandle(h)
    print(f'\n[=] Scanned {scanned} regions, dumped {dumped} PE images to {out_dir}')
    return dumped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pid',      type=int)
    ap.add_argument('--name',     type=str)
    ap.add_argument('--min-size', type=lambda x: int(x, 0), default=0x10000,
                    help='Minimum region size to probe (default 0x10000)')
    ap.add_argument('--max-size', type=lambda x: int(x, 0), default=0x40000000,
                    help='Maximum region size (default 0x40000000 = 1 GB)')
    ap.add_argument('--out',      type=str, default=None)
    args = ap.parse_args()

    pid = args.pid
    if not pid and args.name:
        pid = find_pid_by_name(args.name)
        if not pid:
            print(f'[-] Process "{args.name}" not running'); return 1
        print(f'[+] Resolved {args.name} → PID {pid}')
    if not pid:
        ap.print_help(); return 1

    out_dir = args.out or os.path.join(os.path.expanduser('~'), 'Desktop',
                                       f'manualmap_{pid}')
    return 0 if scan_process(pid, args.min_size, args.max_size, out_dir) >= 0 else 1


if __name__ == '__main__':
    sys.exit(main())
