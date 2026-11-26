# Godot 4.5.1 Windows x64 SSE2

This workflow builds official Godot 4.5.1-stable source for an **x86-64-v1 (SSE2) required baseline**.

- Compiler target: -march=x86-64 -mtune=generic.
- BMI1, BMI2, LZCNT and POPCNT are explicitly disabled.
- SSE2 is the highest required SIMD ISA.
- The build does not require SSE3, SSSE3, SSE4.x, AVX or BMI extensions.
- The Windows ShimMainCRTStartup SSE4.2 gate is omitted.
- Zstd's optional BMI1/BMI2 dispatch and x86 assembly paths are disabled; its generic path remains available.
- Mbed TLS AES-NI/PCLMUL routines remain available in a separate object, but callers check CPUID before using them.
- HarfBuzz's one TZCNT disassembly mnemonic is accepted only in hb-ot-layout.o after verifying hb_ctz checks for zero before calling __builtin_ctz. With BMI1 disabled, GCC uses the F3 0F BC encoding as a BSF-compatible alias; no BMI1-only flags or semantics are permitted.
- Vulkan and OpenGL 3 are enabled; D3D12 is disabled.
- Build uses MinGW-w64, static C++ runtime and no LTO.

## Validation

Before the expensive engine build, CI runs Python unit tests for the auditor and checks the cross-compiler's target feature switches.

The CI disassembles every SCons object file and the final PE executable. PEXTRW is accepted because it is SSE2; PEXT, PEXTRB, PEXTRD and PEXTRQ remain rejected. AES-NI/PCLMUL are allowed only in the CPUID-guarded Mbed TLS object. The HarfBuzz TZCNT/BSF alias is allowed only in the verified HarfBuzz object. Other post-x86-64-v1 instructions fail the audit.

A candidate executable and diagnostics are uploaded even if the audit fails, but the Windows smoke test and final release artifact are gated on a passing audit. The workflow uses ccache to avoid recompiling unchanged translation units on later attempts.

The Windows smoke test checks the version, command-line support and a minimal headless project before publishing the final artifact.

Candidate artifact: Godot-4.5.1-Windows-x64-SSE2-CANDIDATE.

Final artifact after all gates pass: Godot-4.5.1-Windows-x64-SSE2.

Expected runtime filename: Godot_v4.5.1-stable_windows_x86_64_SSE2.exe.

This is a custom compatibility build, not the official prebuilt win64 binary.
