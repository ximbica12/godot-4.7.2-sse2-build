#!/usr/bin/env python3
"""Patch the official Godot 4.5.1 source for a strict x86-64-v1 (SSE2) build."""

from pathlib import Path
import sys


def read(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"Missing source file: {path}")
    return path.read_text(encoding="utf-8")


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


if len(sys.argv) != 3:
    raise SystemExit(
        "Usage: patch_sse2_451.py GODOT/SConstruct GODOT/platform/windows/SCsub"
    )

sconstruct = Path(sys.argv[1])
scsub = Path(sys.argv[2])

# Godot 4.5.1 enables SSE4.2 + POPCNT for x86_64 by default.
source = read(sconstruct)
marker = "# Set x86 CPU instruction sets to use by the compiler's autovectorization."
marker_pos = source.find(marker)
if marker_pos < 0:
    raise SystemExit("SConstruct: x86 instruction-set section not found.")

start = source.find('if env["arch"] == "x86_64":', marker_pos)
end = source.find('elif env["arch"] == "x86_32":', start)
if start < 0 or end < 0 or end <= start:
    raise SystemExit("SConstruct: could not isolate the x86_64 compiler flags.")

old_block = source[start:end]
if "-msse4.2" not in old_block or "-mpopcnt" not in old_block:
    raise SystemExit(
        "SConstruct no longer has the expected 4.5.1 SSE4.2/POPCNT flags; "
        "refusing to patch an unknown source revision."
    )

new_block = '''if env["arch"] == "x86_64":
    # Strict x86-64-v1 baseline: SSE2 is the highest required SIMD ISA.
    # Do not enable SSE3, SSSE3, SSE4.x, POPCNT, BMI, AES, or AVX.
    if env.msvc and not methods.using_clang(env):
        # MSVC x64 defaults to SSE2; do not enable a higher ISA.
        pass
    else:
        env.Append(CCFLAGS=["-march=x86-64", "-mtune=generic"])
'''
write(sconstruct, source[:start] + new_block + source[end:])

# 4.5.1's Windows SCsub installs a CRT entry shim that refuses CPUs without SSE4.2.
source = read(scsub)
anchor = "env_wrap = env.Clone()"
anchor_pos = source.find(anchor)
if anchor_pos < 0:
    raise SystemExit("Windows SCsub: env_wrap anchor not found.")

start = source.find('if env["arch"] == "x86_64":', anchor_pos)
def_pos = source.find("def arrange_program_clean(prog):", start)
if start < 0 or def_pos < 0 or def_pos <= start:
    raise SystemExit("Windows SCsub: could not isolate the SSE4.2 startup shim.")

line_start = source.rfind("\n", 0, def_pos) + 1
old_block = source[start:line_start]
if "cpu_feature_validation.c" not in old_block or "ShimMainCRTStartup" not in old_block:
    raise SystemExit(
        "Windows SCsub no longer has the expected SSE4.2 startup shim; "
        "refusing to patch an unknown source revision."
    )

new_block = (
    "# SSE2 build: use the normal Windows CRT startup path.\n"
    "# The compiler target remains the x86-64-v1 baseline.\n\n"
)
write(scsub, source[:start] + new_block + source[line_start:])

# Post-patch assertions.
patched_sconstruct = read(sconstruct)
patched_scsub = read(scsub)
arch_start = patched_sconstruct.find('if env["arch"] == "x86_64":', patched_sconstruct.find(marker))
arch_end = patched_sconstruct.find('elif env["arch"] == "x86_32":', arch_start)
arch_block = patched_sconstruct[arch_start:arch_end]
if any(flag in arch_block for flag in ("-msse4.2", "-mpopcnt", "/d2archSSE42")):
    raise SystemExit("Post-patch check failed: a post-SSE2 compiler flag remains.")
if "cpu_feature_validation.c" in patched_scsub or "ShimMainCRTStartup" in patched_scsub:
    raise SystemExit("Post-patch check failed: SSE4.2 startup shim remains.")

print("Godot 4.5.1 patched successfully.")
print("CPU baseline: x86-64-v1 (SSE2).")
print("Windows SSE4.2 startup gate: removed.")
