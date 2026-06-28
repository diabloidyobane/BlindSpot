"""
rebuild_headerless.py — forge a minimal valid PE header in front of a
raw code blob whose DOS/PE headers were wiped post-DllMain.

For a 3 MB region like implant's, we don't know the original section
layout, so we emit a single catch-all `.text` covering the whole image
with RX attributes. IDA will analyze the entire region as code, which
lets you reverse anything without the original loader's help.

Usage:
    python rebuild_headerless.py <input.bin> <runtime_base_hex> <output.dll>
    python rebuild_headerless.py execpriv_00000199CF4A0000_0x30F000.bin 0x199CF4A0000 implant.dll
"""

import struct
import sys
import os


def build_header(image_base, size_of_image, bitness=64):
    """Produce a 0x400-byte buffer containing a valid DOS + NT + 1-section
    PE header. Callers overlay this onto the dumped region's first page."""
    assert bitness == 64, 'only x64 supported for now'

    # --- DOS header (0x40 bytes) ---
    dos = bytearray(0x40)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x80)   # e_lfanew -> NT headers start at 0x80

    # --- zero-padding to 0x80 ---
    # (already zero since bytearray)

    nt_off = 0x80

    # --- NT headers ---
    nt = bytearray()
    nt += b'PE\x00\x00'                       # Signature (4)

    # IMAGE_FILE_HEADER (20 bytes)
    nt += struct.pack('<HHIIIHH',
                      0x8664,                 # Machine = AMD64
                      1,                      # NumberOfSections (single .text)
                      0,                      # TimeDateStamp
                      0,                      # PointerToSymbolTable
                      0,                      # NumberOfSymbols
                      0xF0,                   # SizeOfOptionalHeader (PE32+)
                      0x2022)                 # Characteristics: DLL|LARGE_ADDRESS_AWARE|EXECUTABLE_IMAGE

    # IMAGE_OPTIONAL_HEADER64 (0xF0 bytes)
    oh_start = len(nt)
    nt += struct.pack('<H', 0x20B)           # Magic = PE32+
    nt += struct.pack('<B', 14)              # MajorLinkerVersion
    nt += struct.pack('<B', 0)               # MinorLinkerVersion
    nt += struct.pack('<I', size_of_image - 0x1000)  # SizeOfCode (everything after headers)
    nt += struct.pack('<I', 0)               # SizeOfInitializedData
    nt += struct.pack('<I', 0)               # SizeOfUninitializedData
    nt += struct.pack('<I', 0x1000)          # AddressOfEntryPoint (first code byte)
    nt += struct.pack('<I', 0x1000)          # BaseOfCode
    nt += struct.pack('<Q', image_base)      # ImageBase
    nt += struct.pack('<I', 0x1000)          # SectionAlignment
    nt += struct.pack('<I', 0x1000)          # FileAlignment (raw==virtual for the dump)
    nt += struct.pack('<H', 6)               # MajorOperatingSystemVersion
    nt += struct.pack('<H', 0)               # MinorOperatingSystemVersion
    nt += struct.pack('<H', 0)               # MajorImageVersion
    nt += struct.pack('<H', 0)               # MinorImageVersion
    nt += struct.pack('<H', 6)               # MajorSubsystemVersion
    nt += struct.pack('<H', 0)               # MinorSubsystemVersion
    nt += struct.pack('<I', 0)               # Win32VersionValue
    nt += struct.pack('<I', size_of_image)   # SizeOfImage
    nt += struct.pack('<I', 0x400)           # SizeOfHeaders
    nt += struct.pack('<I', 0)               # CheckSum
    nt += struct.pack('<H', 2)               # Subsystem = Windows GUI
    nt += struct.pack('<H', 0x160)           # DllCharacteristics (NX_COMPAT|NO_SEH|TERMINAL_SERVER_AWARE)
    nt += struct.pack('<Q', 0x100000)        # SizeOfStackReserve
    nt += struct.pack('<Q', 0x1000)          # SizeOfStackCommit
    nt += struct.pack('<Q', 0x100000)        # SizeOfHeapReserve
    nt += struct.pack('<Q', 0x1000)          # SizeOfHeapCommit
    nt += struct.pack('<I', 0)               # LoaderFlags
    nt += struct.pack('<I', 16)              # NumberOfRvaAndSizes
    # 16 DataDirectory entries (each 8 bytes), all zero
    nt += b'\x00' * (16 * 8)

    # IMAGE_SECTION_HEADER for .text (0x28 bytes)
    sec = bytearray(0x28)
    sec[0:8]  = b'.text\x00\x00\x00'
    struct.pack_into('<I', sec, 0x08, size_of_image - 0x1000)  # VirtualSize
    struct.pack_into('<I', sec, 0x0C, 0x1000)                   # VirtualAddress
    struct.pack_into('<I', sec, 0x10, size_of_image - 0x1000)  # SizeOfRawData
    struct.pack_into('<I', sec, 0x14, 0x1000)                   # PointerToRawData
    struct.pack_into('<I', sec, 0x24, 0x60000020)               # Characteristics: CODE|EXECUTE|READ

    # Assemble full header page
    out = bytearray(0x1000)
    out[:0x40] = dos
    out[nt_off:nt_off + len(nt)] = nt
    sec_off = nt_off + len(nt)
    out[sec_off:sec_off + len(sec)] = sec

    return bytes(out)


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 1
    in_path, base_str, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

    image_base = int(base_str, 0)
    with open(in_path, 'rb') as f:
        raw = bytearray(f.read())

    size_of_image = len(raw)
    if size_of_image & 0xFFF:
        print(f'[!] Input size 0x{size_of_image:X} not page-aligned; padding up')
        pad = 0x1000 - (size_of_image & 0xFFF)
        raw += b'\x00' * pad
        size_of_image = len(raw)

    header = build_header(image_base, size_of_image)
    # Only overwrite the zero-prologue (first 0x1000) — code from 0x1000 onward is untouched
    raw[0:0x1000] = header

    with open(out_path, 'wb') as f:
        f.write(raw)

    print(f'[+] Wrote {out_path}  ({len(raw):,} bytes)')
    print(f'    ImageBase  = 0x{image_base:X}')
    print(f'    SizeOfImage = 0x{size_of_image:X}')
    print(f'    Single .text section covers 0x1000..0x{size_of_image:X} (RX)')
    print()
    print('In IDA: open as PE file. It should auto-detect as a 64-bit DLL.')
    print('All calls/jumps with absolute addresses in the 0x{0:X}-0x{1:X} range'
          .format(image_base, image_base + size_of_image))
    print('will resolve internally without you having to rebase.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
