# Walkthrough: end-to-end

Personal account of how the analysis actually went, with the rough edges left in. The [paper](implant_paper.md) is the polished version; this is the working log.

## Starting point

Bought the cheat to study it. Cheat menu draws fine in-game — implant is loaded and running. Question: where is it in memory, and what does it look like?

Plan A: dump it with `pe-sieve`. Should be a 30-second job.

## pe-sieve drew a blank

```
pe-sieve64.exe /pid 6888 /dmode 3 /imp 2
```

Output: `148 modules scanned, 21 hooks (Steam overlay), 0 implants`.

Same with the aggressive flags:

```
pe-sieve64.exe /pid 6888 /shellc 3 /data 3 /refl /jlvl 2
```

Body of *something* large got dumped to disk, but pe-sieve didn't classify it as an implant. The pe-sieve output is the entry condition for the rest of this workflow — if your scanner sees zero implants but you know one is there, the scanner has an enumeration blind spot somewhere.

## Asking Claude why

Pasted pe-sieve's `scan_report.json` and the enumeration model into Claude and asked: "why is it missing this?"

The answer:

> pe-sieve uses `EnumProcessModulesEx` to build its target list, then for each module it calls `GetMappedFileNameW` to compare in-memory headers to the on-disk file. A `MEM_PRIVATE` allocation with no `LdrLoadDll` call produces no PEB module entry, so it never reaches the per-module scan loop. The `/shellc` mode does a separate sweep but tunes its patterns for small payloads — a 2.8 MB DLL body doesn't match.

That made the next move obvious: skip enumeration, walk virtual memory directly, filter for what an implant should look like.

## VirtualQueryEx walker

Wrote `scan_exec_private.py`. The whole thing:

```python
# pseudocode
h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid)
addr = 0
while True:
    mbi = VirtualQueryEx(h, addr)
    if not mbi: break
    if mbi.State == MEM_COMMIT and (mbi.Protect & EXECUTE_FLAGS):
        path = GetMappedFileNameW(h, addr) or ""
        record(addr, mbi.RegionSize, mbi.Type, mbi.Protect, path)
    addr += mbi.RegionSize
```

275 executable regions on the TD2 process. Filter to those with no `GetMappedFileNameW` result (no file backing): 11 candidates. Sort by size descending:

```
0x1C2D2B70000   2.8 MB   <-- ding
0x?????????00   64 KB
0x?????????00   48 KB
... 8 more under 32 KB
```

The 45:1 size ratio between the top candidate and the runner-up is the tell. Legitimate JIT/CLR allocations don't get that big and stay contiguous.

## Dumping the bytes

```
python dump_manualmap.py 6888 0x1C2D2B70000 0x2B9000
```

Wrote `execpriv_000001C2D2B70000_0x2B9000.bin`. Opened in HxD. First 0x1000 bytes were zero. At +0x1000:

```
48 89 5C 24 10  ; mov [rsp+10], rbx
48 89 7C 24 18  ; mov [rsp+18], rdi
55              ; push rbp
48 8D AC 24 ... ; lea rbp, [rsp - large]
```

x64 prologue with a `0xB1E0`-byte stack frame. That's a function reserving 45 KB of locals — way too big for a leaf, consistent with a top-level tick or main DllMain-equivalent.

Loaded it into IDA. IDA refused: no `MZ`, no PE header, no entry point, no sections. Just a raw blob with the byte pattern flagged "this looks like x64 code but I won't disassemble it as a program."

## The reconstruction problem

I needed IDA to treat this dump as a real DLL so I could navigate it, name functions, follow xrefs. The dump is just the in-memory image — code + data, no metadata. To make IDA happy I had to forge metadata that pointed at the right places.

Back to Claude: "I have a raw 2.8 MB x64 code blob that was a DLL before its headers got wiped. I need IDA to open it. Help me forge a synthetic PE32+ header that wraps the existing code as a single .text section."

The minimum viable header is:
- 64-byte DOS stub with `MZ` + `e_lfanew` pointing at the NT headers
- 24-byte file header (machine = AMD64, sections = 1, characteristics = DLL)
- 240-byte optional header (PE32+, ImageBase = some sane value, SizeOfImage = 0x2B9000, EntryPoint = 0x1000, subsystem = native)
- One 40-byte section header for `.text` covering the whole 0x2B9000 image, RWX

Total: about 400 bytes of header, then the original dump body starts at +0x1000 with the prologue lined up with the section's `VirtualAddress`.

Wrote `rebuild_headerless.py`. It takes the raw dump and writes a new file with the synthetic header prepended. Output: `implant_reconstructed.dll`.

IDA opened it on the first try. Auto-analysis ran, found 3,200 functions, marked the prologue at `0x1000` as `start`. Real DLL behavior.

## IAT recovery

Imports were still unresolved. The IDA navigation worked — I could browse functions, follow internal calls — but calls to `kernel32!CreateFileW` etc. showed up as calls to numeric addresses, no names.

The IAT was inside the dump as a flat array of resolved function pointers (the implant's loader built it at runtime). Ran HollowsHunter on the live process:

```
hollows_hunter64.exe /pname TheDivision2.exe /imp 3 /shellc 3 /threads /minidmp
```

HollowsHunter's `/imp 3` walks IAT-shaped pointer arrays (sequences of pointers into known modules, terminated by zeros) and prints each one with its DLL + export name. Output for the implant region:

```
244 imports recovered:
  kernel32.dll: 67 entries
  ntdll.dll: 43 entries
  user32.dll: 38 entries
  gdi32.dll: 21 entries
  imm32.dll: 4 entries
  shell32.dll: 14 entries
  msvcp140.dll: 19 entries
  d3dcompiler_47.dll: 28 entries
  dxgi.dll: 10 entries
```

Pasted the import list into the IDA database. Calls became readable.

The DLL list itself told a story:
- `kernel32` + `ntdll` heavy: file I/O, memory ops, thread manipulation
- `user32` + `gdi32` + `imm32`: probably the menu + input handling
- `d3dcompiler_47` + `dxgi`: D3D11/12 hook for menu rendering
- `msvcp140`: STL containers

No `wininet` / `winhttp`. No `urlmon`. Either the cheat doesn't phone home from the implant body, or it does so through hooks into the game's own networking. Worth noting.

## Cross-references into the host

Now the question that pays off: where does the implant touch `TheDivision2.exe`?

```python
# pseudocode
host_range = (host_base, host_base + host_size)
buf = open(implant_dump, 'rb').read()
hits = []
for off in range(0, len(buf) - 8, 8):
    val = struct.unpack_from('<Q', buf, off)[0]
    if host_range[0] <= val < host_range[1]:
        hits.append((off, val, val - host_base))   # offset, VA, RVA
```

37 hits. All in a contiguous 1.7 KB region inside the implant body — a hook table. No rel32 hits (separate scan for `E8/E9 ?? ?? ?? ??` pointing into the host range returned zero). That's a finding: the host base is too far from the implant for 32-bit displacement to reach it, so the implant uses absolute pointers and indirect calls.

Dumped the 37 RVAs to `implant_xrefs_abs.csv`. Loaded them as bookmarks in the IDA database of `TheDivision2.exe`.

## Finding the ammo path

Walked the 37 RVAs in IDA. Most were obvious:
- Several were vtable pointers (RTTI gave away the class names)
- Several were the D3D12 swap chain hook targets — `Present`, `ExecuteCommandLists`, `ResizeBuffers`
- Several were input handler hooks (WndProc subclassing)

Two stood out, both in the weapon-tick code path:

```
RVA 0x4F6A1C0   WeaponInstance::Tick           (top of the per-frame weapon update)
RVA 0x4F6B340   <ammo-decrement helper>        (the actual `current_ammo--` call site)
```

The cheat is hooking the **decrement helper**, not patching the ammo value directly. That's the right move — it survives any state-sync the game does, because the game thinks it fired but the counter never drops.

I confirmed this two ways. First, IDA decompilation at `0x4F6B340` shows the unhooked helper as a textbook decrement-then-clamp pattern:

```c
void WeaponInstance::ConsumeRound(WeaponInstance *this) {
    if (this->current_ammo > 0)
        this->current_ammo--;
    // ... clip refill / dry-fire flag follow
}
```

Second, I built a minimal proof-of-concept that NOP'd the `dec` instruction in my own process snapshot (NOT in the live game — just a controlled bench). The magazine indicator stayed pinned at full. Same behavior the cheat exhibits.

## What this means for detection

If you write the EAC-side or BattlEye-side detection, you don't need to find the implant body — you need to detect the *hook installation*. The 37 absolute pointer hits all target executable host code; that means the implant is calling `VirtualProtect` to flip those pages to RWX, writing a jump, flipping back. Look for unexpected `NtProtectVirtualMemory` calls against your own `.text` from any non-system thread.

Alternatively, the implant has to keep its absolute pointer table live. A periodic scan of all `MEM_PRIVATE` RWX regions for any contiguous run of 8-byte values that fall inside your image range catches this with no false positives in a normal game session (game code never holds tables of pointers into itself in private RWX memory).

## What I'd do differently

- **Should've started with `VirtualQueryEx`**. pe-sieve was an unforced 5 minutes wasted. If a scanner has an enumeration model, build against the assumption that the implant defeats it.
- **HollowsHunter earlier**. I dumped the body manually before running HollowsHunter. HollowsHunter would've given me both the dump and the import table in one pass.
- **Tag the hook table in IDA as a struct**. I spent an hour following individual RVAs before realizing they were a contiguous 1.7 KB table. Naming it as a struct array earlier would've saved time.

## Time budget

| Step | Time |
|---|---|
| pe-sieve attempts | 5 min (sunk) |
| Asking Claude, understanding the blind spot | 10 min |
| Writing `scan_exec_private.py` | 20 min |
| Walking + ranking, picking the candidate | 2 min |
| Dumping the body, inspecting bytes | 5 min |
| Synthetic PE header design + `rebuild_headerless.py` | 45 min (Claude pair-programmed) |
| IDA loading, IAT recovery via HollowsHunter | 30 min |
| Xref scan + dumping CSVs | 15 min |
| Walking RVAs in IDA, finding the ammo hooks | 90 min |
| Proof-of-concept ammo NOP | 30 min |
| **Total** | **~4 hours** |

The paper claims "90 seconds wall-clock" for the procedure on a known target. That's true *after* you've built the scripts. From a cold start with pe-sieve failing in front of you, it's an afternoon.

## What this actually took, and what Claude Code did

Claude Code paid for itself on this project. The two moments where it mattered most were the pe-sieve enumeration model breakdown (saved me reading the source) and the synthetic PE header design (saved me reading the PE spec). On both, the model gave me the right answer in two prompts. The safety filters fired zero times the entire project, including questions about ring-0 primitives, MSR layouts, and runtime memory patching. Static analysis of a loaded binary in a process you own is exactly the kind of work the filters are tuned to let through.

It would be dishonest to say "Claude did the analysis." Claude did not:

- Recognize the wiped header at offset +0x1000 as a stack-frame-allocating prologue
- Decide that the 45:1 size ratio between the top two candidates meant "stop ranking, that's the one"
- Spot that 37 absolute pointer hits in a contiguous 1.7 KB block means *hook table* and not *string table*
- Identify the ammo decrement helper as the patch site versus the ten other call sites in `WeaponInstance::Tick`
- Catch that the `ConsumeRound` decompilation was missing a clamp branch and needed a second decompiler pass

Every one of those judgments came from prior reverse-engineering work that has nothing to do with AI. The model is a fast reference and a fast typist. It does not see what you see when you look at IDA output, and it cannot tell you which 1 of 37 hooks is the interesting one.

**What you actually need before this approach pays off:**

| Skill | Why |
|---|---|
| Static RE | Recognizing prologues, IAT shapes, vtables, jump tables at a glance |
| Windows internals | VAD, PEB, mapping primitives, `LdrLoadDll` flow, why pe-sieve has its blind spot |
| C++ | Reading game-engine decompilation full of templates and polymorphism |
| IDA | Navigating 3K+ functions, naming structs, propagating types, scripting through IDAPython |
| Patience | The 4-hour wall-clock includes maybe 90 minutes of dead ends I cut from the writeup |

I built this on Claude Max ($200/mo tier). That's not unlimited API access; it's a session quota. A junior analyst burning tokens on confused prompts can hit the cap in an afternoon and learn nothing. A senior analyst gets a force multiplier on existing skill. The difference is entirely on the human side.

**If you're trying to use this writeup as a "how to RE a cheat with AI" recipe, you will fail.** Not because the steps are wrong, but because the steps are downstream of judgment calls the writeup doesn't capture. Build the judgment first, then the tools accelerate it. There is no shortcut around that.
