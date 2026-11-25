# Godot 4.5.1 Windows x64 SSE2

This workflow builds the official Godot 4.5.1-stable source for an **x86-64-v1 (SSE2) required baseline**.

- Compiler target: -march=x86-64 -mtune=generic.
- SSE2 is the highest required SIMD ISA.
- The build does not require SSE3, SSSE3, SSE4.x, POPCNT, AVX, BMI1 or BMI2.
- The Windows ShimMainCRTStartup SSE4.2 gate is omitted.
- Zstd's optional BMI1/BMI2 dispatch and x86 assembly paths are disabled; its generic path remains available.
- Mbed TLS AES-NI/PCLMUL routines remain available in a separate object, but the callers check CPUID before using them. A Pentium E5700 without those features uses the generic software implementation.
- Vulkan and OpenGL 3 are enabled; D3D12 is disabled.
- Build uses MinGW-w64, static C++ runtime and no LTO.

## What the audit verifies

The CI checks the source guards, disassembles every SCons object file, and audits the final PE executable.

The only permitted later-ISA instructions are AES-NI/PCLMUL instructions emitted by thirdparty/mbedtls/library/aesni.c. The audit verifies the Mbed TLS CPUID checks and confirms those instructions do not appear in other object files. Any other post-x86-64-v1 instruction, including TZCNT, fails the audit.

PEXTRW is permitted because it is an SSE2 instruction, not SSE4.1.

The workflow also checks the PE architecture, confirms the SSE4.2 startup message is absent, and runs a Windows headless smoke test before publishing the final artifact.

Artifact: Godot-4.5.1-Windows-x64-SSE2.

Expected runtime filename: Godot_v4.5.1-stable_windows_x86_64_SSE2.exe.

This is a custom compatibility build, not the official prebuilt win64 binary.
