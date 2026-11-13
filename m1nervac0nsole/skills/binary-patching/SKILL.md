---
name: binary-patching
description: "Invoke this skill when a task needs to change a compiled artifact's behaviour by editing bytes — neutering an anti-analysis check, bypassing a licence or feature gate to reach the vulnerable code path, or turning a crash into a controlled one for analysis. Covers site selection by unique byte needle, offset derivation, and the byte-for-byte acceptance test."
---

# Binary Patching

Under an **authorized** engagement only. This skill exists for analysis, not piracy: it is how you reach the code behind an anti-debug check, neutralise a licence gate so a fuzzer can exercise the real logic, or make a crash deterministic. Editing bytes to defeat a vendor's licensing for use is out of scope and is not what this skill is for.

## The one rule that prevents every silent failure

**A disassembler gives you virtual addresses. The file on disk stores file offsets. They are not related by one constant.** Each ELF/PE section carries its own paddr/vaddr relationship and sections are laid out non-contiguously, so `file_offset = vaddr - K` is wrong the moment the target is not in the first section. A patch built on that arithmetic lands in an adjacent, unrelated instruction and corrupts the artifact in a way that looks like success.

Pin the site by its **bytes**, in a window wide enough to be unique.

## Procedure

1. **Get a reliable disassembly** (`radare2`, `ghidra` headless, `objdump -d`). Identify the specific gate: the branch that selects the path you want. Read *both* the fall-through and the jump target so you know which side is the interesting one — deciding direction from intuition is how a bypass becomes a permanent error path.
2. **Extract the needle verbatim from the disassembly**: the target instruction plus one or two before and after, as raw opcodes. That 14–20 byte window is the needle. A bare `74 xx` or `0f84...` appears everywhere and is not a needle.
3. **Prove uniqueness before writing.**
   ```python
   data = open(path, 'rb').read()
   off = data.find(needle)
   assert off != -1, "needle not found — the disassembly and the file disagree"
   assert data.find(needle, off + 1) == -1, "needle not unique — widen it"
   ```
   A second match means you are about to patch the wrong copy. Widen with more surrounding instructions until unique.
4. **Patch a copy**, never the original. `<name>_patched`, then verify, then swap if the operator wants it in place.
5. **Preserve byte width.** To NOP a branch, replace N bytes with N × `\x90`. Changing an instruction's length shifts everything after it and invalidates every relative jump displacement — recompute them all or don't do it.
6. **Accept only on a byte-for-byte diff.**
   ```python
   assert patched == data[:off] + new_bytes + data[off + len(new_bytes):]
   ```
   And compare hashes: one changed, one unchanged. "It looks right" is not an acceptance criterion.
7. **Run the patched artifact** and show the behaviour changed in the way you intended. A patch that verifies byte-wise but does not change behaviour means you patched a copy that is never executed — check for duplicate code paths, inlined clones, and architecture-specific variants.

## Direction, concretely

If `JZ → error path` and the fall-through is the good path, NOP the branch. If you want the *other* branch, swap `JZ`↔`JNZ` (`\x74`↔`\x75` for short form, `\x0f\x84`↔`\x0f\x85` for near form) — and only after reading both paths.

## Report the evidence

State the virtual address, the resolved file offset, the bytes before and after, the uniqueness proof (how many matches), both file hashes, and the observed behaviour. A future session must be able to reproduce the patch from these facts alone.

## Pitfalls

- **Offset arithmetic instead of byte search** — the single most common cause of a corrupted artifact.
- **A non-unique needle** — silently patches the first copy, which is often a stub.
- **Changing instruction width** — shifts the tail, breaks relative jumps.
- **Patching the original first** — destroys the operator's artifact on a failed attempt.
- **Trusting a byte-identical diff without running it** — proves the write, not the effect.

## Related skills

`patch-diff` reads a vendor patch to find the bug; this skill edits bytes to reach code. `exploit-dev` consumes a deterministic crash this skill may have made reachable. `codeaudit` finds the logic when source is available and patching is unnecessary.
