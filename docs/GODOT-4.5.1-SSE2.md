# Godot 4.5.1 Windows x64 SSE2 / Pentium E5700

This workflow builds official Godot 4.5.1-stable for a required x86-64-v1 (SSE2) baseline, with only narrowly source-verified optional paths.

## Target CPU

Intel Pentium E5700 (Wolfdale): SSE2, SSE3, SSSE3, CX16 and LAHF/SAHF are available. SSE4.1, SSE4.2, AVX, BMI1, BMI2, POPCNT, RDRAND and RDSEED are not available.

The compiler target remains generic x86-64-v1. Optional instructions are permitted only when the relevant source code proves a CPUID/OSXSAVE dispatch guard.

## Verified optional paths

- HarfBuzz: GCC may encode a generic trailing-zero builtin as the F3 0F BC form that objdump labels TZCNT. HarfBuzz checks for zero before calling the builtin, so this is a BSF-compatible alias on CPUs without BMI1. It is accepted in HarfBuzz objects only.
- meshoptimizer: its SSSE3 vertex decoder is compiled with a function-level target("ssse3") attribute and selected only after CPUID.1:ECX.SSSE3 (bit 9); otherwise the scalar decoder is selected.
- Mbed TLS AES-NI/PCLMUL: retained only in aesni.c and called after CPUID checks.
- Embree, libwebp, SharpYUV and PCRE2: XGETBV is called only after OSXSAVE checks. The E5700 does not advertise OSXSAVE, so these paths remain inactive.
- GCC 13.2 libstdc++ random_device: RDRAND and RDSEED functions are selected only after their corresponding CPUID feature bits are checked. The E5700 does not advertise either feature.
- LAHF/SAHF and CMPXCHG16B are supported by the E5700 profile and are not treated as failures.

Other SSE3, SSSE3, SSE4.x, AVX, BMI, POPCNT and post-baseline instructions remain forbidden unless explicitly listed above with a verified dispatch path.

## Build and validation workflow

1. Unit tests and source-guard preflight run before the full build.
2. The build workflow is manual only. Editing the auditor or workflow will not launch another 40–60 minute compile.
3. MinGW compiler caching uses SCons' native c_compiler_launcher=ccache and cpp_compiler_launcher=ccache; the workflow checks that cache hits occur in a small probe before the engine build.
4. The object-file auditor checks instruction categories and restricts each exception to the relevant source object.
5. The final PE is audited against the counts in those verified objects.
6. The Windows smoke test checks the runtime version, command-line support and a minimal headless project.

The build uses MinGW-w64, a static C++ runtime, no LTO, Vulkan and OpenGL 3. D3D12 is disabled.

Expected runtime filename: Godot_v4.5.1-stable_windows_x86_64_SSE2.exe.

This is a custom compatibility build, not the official prebuilt win64 binary.
