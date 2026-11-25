# Godot 4.5.1 Windows x64 SSE2

This workflow builds the official Godot 4.5.1-stable source for the x86-64-v1 baseline.

- Compiler target: `-march=x86-64 -mtune=generic`.
- SSE2 is the highest required SIMD ISA.
- SSE3, SSSE3, SSE4.x, POPCNT and AVX are not required.
- The Windows `ShimMainCRTStartup` SSE4.2 gate is omitted.
- Zstd optional BMI1/BMI2/LZCNT target code generation is disabled; its generic fallback remains available.
- Vulkan and OpenGL 3 are enabled; D3D12 is disabled.
- Build uses MinGW-w64, static C++ runtime and no LTO.
- CI audits the final PE executable and runs a Windows smoke test.
- The ISA audit explicitly permits `PEXTRW`, which is an SSE2 instruction, and rejects `TZCNT`/other post-v1 instructions.

Artifact: `Godot-4.5.1-Windows-x64-SSE2`.

Expected runtime filename: `Godot_v4.5.1-stable_windows_x86_64_SSE2.exe`.

This is a custom compatibility build, not the official prebuilt win64 binary.
