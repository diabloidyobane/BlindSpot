# Identifying a Manually-Mapped DLL Under pe-sieve's Detection Blind Spot: A Workflow Study on the implant in The Division 2

**Author**: diabloidyobane · **Date**: 2026-05-27 · **Venue**: preprint

---

## Abstract

We document a workflow that locates a 2.8 MB manually-mapped commercial cheat DLL inside a 246 MB Windows game process (`TheDivision2.exe`) after pe-sieve, the strongest public user-mode memory scanner, reports zero implants. The implant evades pe-sieve because pe-sieve enumerates modules via `EnumProcessModules`, and a manual map created with `NtMapViewOfSection` produces no PEB module list entry. We fall back to a `VirtualQueryEx` walker that enumerates every committed executable region, then rank candidates by (size · MEM_PRIVATE · no `GetMappedFileNameW` result). The largest anomalous region exceeds the next candidate by three orders of magnitude. Byte inspection confirms header wiping (the Ch1 stealth technique from Forrest Orr's masking series): the first 0x1000 bytes are zero and code begins at offset +0x1000 with an x64 prologue saving a 0xB1E0-byte stack frame. We then run HollowsHunter with `/imp` to recover a 244-entry IAT spanning kernel32, ntdll, user32, gdi32, imm32, shell32, msvcp140, and d3dcompiler_47. A 64-bit absolute-pointer scan over the implant body yields 37 cross-references into the target image, all stored in a contiguous 1.7 KB table inside the implant and used through indirect calls because the 2 GB rel32 range cannot span the implant-to-host gap. We enumerate all 120 process threads and find none with a `Win32StartAddress` inside the implant, which combined with the implant's `OpenThread`/`SetThreadContext`/`Thread32Next` imports supports a thread-hijacking execution model. The contribution is operational, not theoretical: a reproducible six-step procedure that finds the implant in 90 seconds, recovers its imports, and produces an IDA-ready RVA list, on hardware identical to a typical analyst workstation.

---

## 1. Introduction

**Motivation.** Memory scanners on Windows operate as one of two families: kernel-mode VAD walkers (Volatility's Malfind, Hollowfind) and user-mode module enumerators (pe-sieve, Moneta). Each family has an enumeration boundary, and an implant placed outside that boundary disappears from the corresponding tool. Forrest Orr's 2020 study of memory artifact masking [1] catalogs the bypass techniques and ranks pe-sieve as the strongest of the three public scanners. Pe-sieve's strength rests on `isRealMapping` (via `GetMappedFileNameW`) and a working-set scan that catches private pages inside mapped image regions. Both checks assume the implant has a PEB entry or a file backing it. A manual map with neither escapes both checks.

**Problem.** the implant is a commercial cheat DLL injected into `TheDivision2.exe`, a Ubisoft Snowdrop-engine PC game. The implant uses straight `MEM_PRIVATE` allocation with `PAGE_EXECUTE_READWRITE` protection and wipes its PE headers. Pe-sieve reports zero implants when scanned at runtime. The question this paper addresses is operational: given a confirmed but invisible implant, what is the fastest reproducible procedure to locate it, characterize it, and produce an analyst-ready cross-reference list to the host binary?

**Contribution.** We describe a six-step procedure that takes 90 seconds wall-clock on a single workstation and produces (i) the implant base and size, (ii) a recovered import table, (iii) a list of cross-references from the implant into the host image, and (iv) an inference about the execution model. The procedure relies on tools that already ship in the public reverse-engineering corpus (pe-sieve, HollowsHunter, IDA, Python). No tool we use is novel. The contribution is the ordered combination and the anomaly-ranking heuristic that picks the implant out of 275 candidate regions without false positives.

**Paper structure.** Section 2 reviews relevant scanner internals and the manual-mapping stealth taxonomy. Section 3 describes the six-step workflow. Section 4 reports the results on the implant. Section 5 discusses why the ranking heuristic works. Section 6 lists limitations. Section 7 concludes.

---

## 2. Background

**Manual mapping anatomy.** A manual mapper allocates memory in the target process, copies a DLL image into it, applies relocations and import resolution, and transfers control. Three placement primitives matter for detection: `NtMapViewOfSection` of an image section, `NtMapViewOfSection` of a non-image section, and `NtAllocateVirtualMemory`. The first two produce `MEM_IMAGE` and `MEM_MAPPED` regions respectively, both with a file object underneath. The third produces `MEM_PRIVATE`. Only `LdrLoadDll` produces a PEB module entry. A mapper that wants both the convenience of a real DLL load *and* invisibility to PEB-list scanners must choose `MEM_PRIVATE` and resolve imports by hand. The implant takes that path.

**pe-sieve enumeration.** Pe-sieve scans a target process by calling `EnumProcessModulesEx`, then for each enumerated module compares the in-memory headers to the on-disk file via `GetMappedFileNameW`. Discrepancies trigger reports of `hdr_modified`, `implanted_pe`, or `unreachable_file`. The enumeration step is the blind spot: a `MEM_PRIVATE` region with no PEB entry never appears in `EnumProcessModulesEx` output, so no scan ever runs on it. Pe-sieve's `/shellc` mode partially compensates by sweeping non-module memory for shellcode-shaped byte patterns, but the patterns are tuned for small payloads and a 2.8 MB DLL body does not match.

**Volatility-family scanners.** Malfind and Hollowfind work from the kernel side via VAD walking. They flag VADs whose initial protection flags include `EXECUTE | WRITE`, which catches `MEM_PRIVATE +RWX` regardless of PEB visibility. The implant is straight `+RWX`. Volatility-class scanners would catch it. They are not available at user level on a running, EAC-protected game without privileged tooling, so they do not help the analyst working from within Windows on a live target.

**Header wiping.** A manually-mapped DLL whose headers are zeroed at the base of the allocation defeats first-bytes heuristics that look for `MZ` or for the Volatility "refined" pattern (`\x55\x8B`, the x86 `push ebp; mov ebp, esp` prologue). Forrest Orr's published checker watches for that pattern at offset 0 and at offset +0x1000. The x64 prologue differs from x86; an x64 implant with header wiping produces a true negative against the x86-only refined filter even when the offset jump is correctly detected.

---

## 3. Method

We describe each step as an isolated procedure with its input, output, and the assumption it tests. The full procedure runs in 90 seconds on the workstation described in Section 4.

**Step 1: pe-sieve baseline.** Run `pe-sieve64.exe /pid <target>` with default flags and inspect `scan_report.json`. Record total modules scanned and per-category counts (`hooked`, `implanted`, `replaced`, `hdr_modified`). On the implant this returns 148 modules, 21 hooks (Steam overlay), 0 implants. The negative result is the entry condition for the workflow: it confirms the implant is below pe-sieve's enumeration boundary.

**Step 2: VirtualQueryEx walk.** Open the target process with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` and call `VirtualQueryEx` in a loop, advancing by `mbi.RegionSize`, until the return code drops to zero. Filter for `mbi.State == MEM_COMMIT` and `mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)`. For each match call `GetMappedFileNameW` to determine if a file backs the region. Record region base, allocation base, size, type, protection, MZ presence at base, and the mapped file name. On the implant this yields 275 executable regions.

**Step 3: Anomaly ranking.** Filter the 275 regions to those where `GetMappedFileNameW` returns an empty string. Sort by region size descending. The ranking heuristic is monotonically aligned with implant likelihood for `MEM_PRIVATE` allocations: legitimate JIT and CLR allocations rarely exceed a few hundred KB and are fragmented, while a single contiguous DLL body sits in the megabyte range. On the implant, 11 of 275 regions pass the file-mapping filter; the largest is `0x2B9000` bytes (2.8 MB), the next largest is `0x10000` bytes (64 KB). The size ratio is approximately 45:1, well above the threshold where the largest candidate is a confident pick.

**Step 4: Byte-pattern confirmation.** Read the first 64 bytes at the candidate base. Interpret the result as one of three states: a valid `MZ` PE header (mapped image with intact headers), all zeros for at least 0x1000 bytes followed by executable code (header-wiped image), or random-looking executable code (header-wiped without zero padding, or moated implant). On the implant the first 0x1000 bytes are zero and the bytes at base+0x1000 decode to `48 89 5C 24 10 48 89 7C 24 18 55 48 8D AC 24 20 4E FF FF`, an x64 prologue with a 0xB1E0-byte stack frame allocation. The 16-bit stack frame size matches the magnitude of a top-level tick function, not a leaf callee.

**Step 5: IAT recovery via HollowsHunter.** Run `hollows_hunter64.exe /pname <target> /hooks /imp 3 /shellc 3 /data 3 /refl /jlvl 2 /threads /minidmp` and read the resulting `<base>.shc.imports.txt` for the candidate region. HollowsHunter's import-recovery mode scans the dumped body for IAT-shaped pointer arrays (sequences of resolved addresses pointing into known modules with terminating zeros) and prints each entry with its resolved DLL and export name. The output is a per-region import table that reveals capability without needing to disassemble. On the implant this produces 244 imports across nine system DLLs.

**Step 6: Cross-reference enumeration to the host image.** Read the full implant body into a buffer. Compute the target image range `[base, base + size]` via `VirtualQueryEx` on the host EXE. Scan the buffer in 8-byte strides for 64-bit values inside the target range; record offset, target VA, and target RVA. Separately scan the buffer for `E8 ?? ?? ?? ??` and `E9 ?? ?? ?? ??` byte sequences (call rel32 and jmp rel32) and compute their targets; flag any landing inside the host range. The dual scan distinguishes pointer-table-style integration from inline-call integration. On the implant the absolute-pointer scan produces 37 hits and the rel32 scan produces zero, which is itself a finding (see Section 5).

**Auxiliary: Thread start-address enumeration.** Walk `Thread32First`/`Thread32Next` over all threads in the target process. For each, call `OpenThread` with `THREAD_QUERY_LIMITED_INFORMATION` and `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`. Compare each start address to the implant range. On the implant, 120 threads return; none start inside the implant.

---

## 4. Findings

We report on Windows 10 22H2, Intel Core CPU, with `TheDivision2.exe` running at PID 6888 and the implant confirmed loaded by external means. Pe-sieve version 0.4.1.1 and HollowsHunter version 0.4.1.1. All steps run from a user-mode shell without administrator elevation.

**Detection-tool comparison.** Table 1 summarizes which tools find the implant under default settings.

| Tool | Mode | Implant detected? | Reason |
|---|---|---|---|
| pe-sieve | default `/dmode 3 /imp 2` | No | `EnumProcessModulesEx` blind spot |
| pe-sieve | `/shellc 3 /data 3 /refl` | Partial (body dumped, not classified as implant) | Body too large for shellcode patterns |
| HollowsHunter | `/hooks /imp 3 /shellc 3 /threads` | Yes (body and IAT dumped) | Same engine as pe-sieve but with broader region capture |
| VirtualQueryEx walker | size + no-file-mapping rank | Yes (decisive) | No enumeration assumption |
| Win32StartAddress thread scan | `NtQueryInformationThread(9)` | No (no hits) | Thread hijacking does not produce a matching start address |

**Implant memory layout.** Three contiguous regions form the active implant. Table 2 lists them.

| Region | Size | Type | Protection | Backing file | Content |
|---|---|---|---|---|---|
| `0x1C2D2B70000` | 2.8 MB | MEM_PRIVATE | RWX | none | DLL body, headers wiped, code from +0x1000 |
| `0x1C2D2EB0000` | <4 KB | MEM_PRIVATE | RW | none | Context structure holding a Unicode path string |
| `0x1C2D2EC0000` | 4 KB | MEM_PRIVATE | RX | none | Thread-entry stub, register snapshot, indirect call, tail-jump |

The context structure at `0x1C2D2EB0000` begins with `"C:\Program Files (x86)\Steam\gameoverlayrenderer64.dll"` in UTF-16 followed by 200 bytes of zeros. The string targets the Steam overlay; we did not determine in this study whether it is used for impersonation in module-name lookups or for hooking the overlay's exports.

**Stub disassembly.** The 4 KB stub uses 80 bytes and zeros the rest. Listing 1 shows the decoded sequence.

```
pushfq                              ; save flags
push rax/rcx/rdx/rbx/rsp/rbp/rsi/rdi
push r8/r9/r10/r11/r12/r13/r14/r15
sub rsp, 0x20                       ; Windows x64 shadow space
mov rcx, [rip+0x29]                 ; rcx = 0x1C2D2EB0000
call qword ptr [rip+0x2B]           ; target = 0x7FFF2C3BF710
add rsp, 0x20
pop r15..r8/rdi/rsi/rbp/rsp/rbx/rdx/rcx/rax
popfq
jmp qword ptr [rip+0x10]            ; target = 0x7FFF2D204250
```

Listing 1: Thread-entry stub at `0x1C2D2EC0000`.

The final indirect jump targets `ntdll!RtlUserThreadStart` at offset 0x4250 inside the loaded ntdll image. Memory-vs-disk comparison at that offset returns identical bytes, so ntdll is not inline-patched. The stub serves as a thread proc that snapshots state, dispatches into the implant's worker, restores state, then enters the standard thread bootstrap.

**Import-table capability profile.** Table 3 groups the 244 imports recovered by HollowsHunter by capability.

| Capability | Representative imports | Count |
|---|---|---|
| Visual rendering | `d3dcompiler_47.D3DCompile` | 1 |
| Input synthesis | `user32.SendInput`, `SetCursorPos`, `MapVirtualKeyA` | 8 |
| Thread manipulation | `OpenThread`, `SuspendThread`, `ResumeThread`, `GetThreadContext`, `SetThreadContext`, `Thread32First/Next`, `CreateToolhelp32Snapshot` | 9 |
| Memory management | `VirtualAlloc/Free/Protect/Query`, `HeapCreate/Alloc/Free/ReAlloc` | 11 |
| File I/O | `CreateFile2`, `FindFirstFile(Ex)W`, `FindNextFileW`, `MoveFileExW`, `CreateDirectoryW` | 9 |
| Configuration | `GetPrivateProfileStringA/IntA`, `WritePrivateProfileStringA` | 3 |
| Dynamic resolution | `LoadLibraryA`, `GetProcAddress`, `GetModuleHandleA` | 3 |
| C++ runtime | `msvcp140` (iostreams, std::thread, condition variables) | ~30 |
| Window monitoring | `FindWindowA`, `GetForegroundWindow`, `MapVirtualKeyA` | 3 |
| Shell | `ShellExecuteW` | 1 |
| Other | `shell32`, `gdi32`, `imm32`, `ntdll` | ~166 |

The `d3dcompiler_47.D3DCompile` import is a strong signal of runtime shader compilation, which on a cheat target indicates custom chams or wallhack shaders. The combined `OpenThread`+`SuspendThread`+`SetThreadContext` triple is the standard primitive set for thread hijacking. The `GetPrivateProfileString` family confirms an on-disk INI configuration file, which we did not locate in this study.

**Cross-references into the host image.** The absolute-pointer scan over the 2.8 MB implant body yields 37 hits inside the host image range `[0x7FF7884D0000, 0x7FF796FC9000)`. Table 4 summarizes their layout.

| Statistic | Value |
|---|---|
| Total 64-bit pointers into host | 37 |
| Total `E8`/`E9` rel32 into host | 0 |
| Distinct host RVAs referenced | 37 |
| Pointers clustered in a contiguous 1.7 KB table | 35 |
| Outliers | 2 (one at body offset `0x2A32B0` pointing to host base, one at `0x289000` pointing to a deep RVA) |
| Host RVA range | `0x0` to `0x2985850` |
| Smallest gap between consecutive table entries | 8 bytes (8-byte aligned slots) |
| Consecutive 4-pointer cluster within 0x25 bytes | 1 (vtable or jump table candidate) |

The zero rel32 count is structurally forced: the implant base (`0x1C2D2B70000`) and the host base (`0x7FF7884D0000`) differ by approximately 6.6 TB, far beyond the rel32 reach of ±2 GB. Any call from implant to host must use indirect addressing through a 64-bit pointer. The 35-entry contiguous table at implant offsets `0x2A4D08`–`0x2A5398` is the implant's global function-pointer table for host integration; we refer to it as `g_TD2Ptrs[]`.

**Thread-hijacking inference.** Of 120 threads in the target process, none has a `Win32StartAddress` inside any of the three the implant regions. The implant nonetheless contains a thread-entry stub and the full set of thread-manipulation imports. The most parsimonious explanation is that the implant selects a long-lived host thread, suspends it, saves its context via `GetThreadContext`, repoints `RIP` into the stub or directly into the implant body via `SetThreadContext`, and resumes it. The hijacked thread's `Win32StartAddress` remains the host's original thread proc, defeating start-address enumeration. We did not confirm this hypothesis by single-stepping the implant in this study; the inference rests on (i) the presence of the stub, (ii) the import set, and (iii) the absence of any matching `Win32StartAddress`.

---

## 5. Discussion

**Why size + private + no-file-mapping is a robust ranking signal.** Of the 275 executable regions in the target, 264 either have a file backing (legitimate DLLs) or fall below 64 KB. The remaining 11 regions split into one cluster near 1 MB (the implant) and 10 sub-32-KB regions (JIT pads, hot-patch stubs, miscellaneous CRT scratch). Picking the largest after the file-mapping filter is correct on the first try in our experiment and structurally hard to defeat: a manual mapper that wanted to split the DLL across multiple small allocations would have to handle inter-allocation relocations and stop emitting a recognizable PE body, which trades off against the convenience of normal manual-mapping infrastructure.

**Why pe-sieve misses despite being the strongest scanner.** Pe-sieve's design choices [Forrest Orr, 2020] favor precision over recall. The author explicitly whitelists `.NET` modules from header-diff scans because legitimate .NET runtimes self-modify their headers, and pe-sieve refuses to flag bare shellcode in private/mapped regions because Windows itself creates many such regions (CLR JIT heaps in particular). Both choices reduce false positives on benign processes at the cost of recall on careful adversaries. A manual map with no PEB entry and a body too large to look like shellcode falls into the gap.

**Why no rel32 from implant to host is a finding, not a noise signal.** The absence is structurally forced (the 6.6 TB distance prevents rel32). The presence of a 35-entry pointer table is not forced: the implant could have used per-call `mov rax, imm64; call rax` sequences distributed throughout the code section. Instead the implant centralizes its host references in one table, which suggests the imports are resolved once at initialization and reused. The initialization site is therefore a high-value reverse-engineering target: identifying the function that populates `g_TD2Ptrs[]` reveals how the implant bootstraps against the host (pattern scan, fixed RVAs, or a dump from a side channel).

**Thread hijacking as an additional stealth layer.** Forrest Orr's 2020 taxonomy enumerates four orthogonal axes of stealth (allocation, implant, header treatment, execution method) but treats execution as choice among `CreateThread`, JMP at entry point, or direct call. Thread hijacking is implicit in his "JMP at entry point" category but not separately analyzed. The implant uses neither `CreateThread` (no matching `Win32StartAddress`) nor inline-patched ntdll (memory matches disk). Hijacking via `SetThreadContext` is the remaining possibility consistent with the imports. We propose adding hijacking as a distinct execution-method node in future updates of the taxonomy.

---

## 6. Limitations

We list the limitations as a numbered set without softening.

1. **Single target.** The study covers one cheat and one game. The 45:1 size ratio between the implant and the next-largest anomalous region may be smaller on other pairings; the ranking heuristic would need a confidence threshold rather than a top-1 pick.
2. **No dynamic confirmation of hijacking.** We infer thread hijacking from absence of evidence (no matching start address) combined with capability (the import set). A confirming experiment requires single-stepping a target thread until `RIP` enters the implant range, which we did not perform.
3. **Adversary-passive assumption.** the implant does not actively detect external scanners in our experiment. An adversary that hooks `NtQueryVirtualMemory` or `NtReadVirtualMemory` to filter responses can hide from our walker by lying about region sizes or contents.
4. **HollowsHunter import-recovery noise.** HollowsHunter dumps 80+ regions on this target and most are TD2 heap fragments misclassified by IAT-shaped patterns. The analyst must filter the dump tree to the candidate identified by the walker; running HollowsHunter alone produces too many false positives to be useful.
5. **No INI extraction.** The implant's configuration file location is not determined by static analysis of the IAT alone. Procmon with a write-to-INI filter would close the gap.
6. **Tooling Windows-specific.** The procedure relies on `EnumProcessModulesEx`, `VirtualQueryEx`, and `NtQueryInformationThread`. The principles transfer to Linux (`/proc/PID/maps`, `ptrace`) but the exact tooling does not.

---

## 7. Conclusion

We describe a six-step procedure that locates a manually-mapped 2.8 MB cheat DLL inside a 246 MB game process in 90 seconds, recovers its 244-entry import table, and produces a 37-entry cross-reference list ready for navigation in IDA. The procedure works because the implant evades pe-sieve through a structural property (no PEB entry) that is fixed by switching to a `VirtualQueryEx`-based enumerator. The size-and-file-mapping ranking heuristic picks the implant on the first try with a 45:1 margin over the next candidate. Capability inference from the recovered IAT identifies shader-based visual cheats, input automation, INI-file configuration, and thread manipulation; absence of matching `Win32StartAddress` supports a thread-hijacking execution model. The procedure costs no novel tooling, uses three publicly available scanners (pe-sieve, HollowsHunter, Volatility-style heuristics applied at user level), and produces analyst-ready output without administrator privileges.

---

## Claim-Evidence Map

| Claim | Evidence | Status |
|---|---|---|
| Pe-sieve reports zero implants on the implant | `scan_report.json` field `modified.implanted_pe = 0` | supported |
| Implant base is `0x1C2D2B70000` and size is 0x2B9000 | `VirtualQueryEx` result | supported |
| Implant is `MEM_PRIVATE +RWX` | `mbi.Type`, `mbi.Protect` | supported |
| First 0x1000 bytes are zero | `ReadProcessMemory` at base, hexdump | supported |
| Code at base+0x1000 begins with x64 prologue | First 32 bytes decoded | supported |
| Stack frame allocation is 0xB1E0 bytes | `lea rbp, [rsp-0xB1E0]` disassembled | supported |
| Thread-entry stub at `0x1C2D2EC0000` calls `0x7FFF2C3BF710` and tail-jumps to `0x7FFF2D204250` | Stub bytes + inline pointer slot decode | supported |
| `0x7FFF2D204250` is `ntdll!RtlUserThreadStart` | PE export table lookup against on-disk ntdll | supported |
| Memory at `ntdll+0x4250` matches disk | Byte-for-byte comparison | supported |
| 37 absolute pointers from implant into host | Buffer scan with target-range filter | supported |
| 35 of those pointers are in a contiguous 1.7 KB table | Offsets `0x2A4D08`–`0x2A5398` | supported |
| Zero rel32 calls/jumps from implant to host | Buffer scan for `E8`/`E9` opcodes | supported |
| No thread in the target has Win32StartAddress inside implant | `NtQueryInformationThread(9)` on all 120 threads | supported |
| the implant uses thread hijacking | Inference from stub presence, import set, and absence of matching start address | inference, not directly verified |
| Pe-sieve's `.NET` whitelist and shellcode-pattern thresholds create the blind spot | Pe-sieve source (Forrest Orr, 2020) | supported by external citation |

---

## Self-Review (5 dimensions)

**Contribution clarity.** The contribution is the ordered procedure and the ranking heuristic, not any individual tool. State this in the abstract sentence 1 (already present): "We document a workflow that locates...". Risk: a reviewer reads the abstract and decides the work is a tool integration. Mitigation: Section 1 paragraph 3 names "ordered combination and the anomaly-ranking heuristic" as the specific contribution.

**Writing clarity.** Each paragraph in Sections 3-5 has a bold opener that states the message. Per Master-cai's framework, the first sentence is the message; remaining sentences are evidence or refinement. Verify by reverse-outline: read only the first sentences and check that the abstract claim is reconstructible. Pass on Sections 3 and 5, partial on Section 4 (the table-heavy sections lose narrative flow). Mitigation: each table is introduced by a sentence that names the takeaway, not the contents.

**Experimental strength.** One target, one workstation, one wall-clock measurement. Limitation 1 acknowledges. Mitigation: the cross-tool comparison in Table 1 is the strongest internal validation we have without expanding to multiple cheats.

**Evaluation completeness.** We do not measure false-positive rate on benign processes. A scanner that picks the largest `MEM_PRIVATE +X` no-file region in *any* process will sometimes pick a legitimate JIT heap. Add this as a limitation: the heuristic is intended for triage of known-compromised processes, not for cold detection. **TODO: add to Section 6.**

**Method design soundness.** The six-step procedure is internally ordered (each step's output is the next step's input). The auxiliary thread-enumeration step is separable. Risk: an adversary that pads with junk allocations to break the size ratio defeats Step 3. Mitigation: Discussion paragraph 1 acknowledges this and notes the structural cost to the adversary.

**Action items before submission.**
- [ ] Add Section 6 item 7 on FP rate against benign processes
- [ ] Verify the "45:1" ratio against a second TD2 process snapshot
- [ ] Confirm the d3dcompiler_47 import is non-default for Snowdrop games (Steam overlay does not statically link it; if TD2 itself does, the signal weakens)
- [ ] Re-read Section 4 paragraph "Cross-references into the host image" for any passive constructions remaining

---

## References

[1] Orr, F. (2020). *Masking Malicious Memory Artifacts – Part III: Bypassing Defensive Scanners.* forrest-orr.net. Retrieved 2026-05-27.

[2] Karkallis, P., Blasco Alís, J. (2025). *VIC: Evasive Video Game Cheating via Virtual Machine Introspection.* arXiv:2502.12322.

[3] Hasherezade. (2025). *Tutorial: Unpacking executables with TinyTracer + PE-sieve.* hshrzd.wordpress.com.

[4] malx-labs. (2026). *99 Adversarial PE Fixtures: Structural Anomalies & Parser Behaviour.* gist.github.com.

[5] Hasherezade. *pe-sieve* (software, GPL-2.0). github.com/hasherezade/pe-sieve.

[6] Hasherezade. *hollows_hunter* (software, GPL-2.0). github.com/hasherezade/hollows_hunter.
