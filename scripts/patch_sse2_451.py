#!/usr/bin/env python3
"""Patch Godot 4.5.1 for x86-64-v1, including its Zstd optional ISA path."""

from pathlib import Path
import sys


def read(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"Missing source file: {path}")
    return path.read_text(encoding="utf-8")


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


if len(sys.argv) != 4:
    raise SystemExit(
        "Usage: patch_sse2_451.py GODOT/SConstruct GODOT/platform/windows/SCsub "
        "GODOT/thirdparty/zstd/common/compiler.h"
    )

sconstruct = Path(sys.argv[1])
scsub = Path(sys.argv[2])
zstd_compiler = Path(sys.argv[3])

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

# Zstandard has an optional runtime-dispatched BMI1/BMI2/LZCNT fast path.
# Its CPUID dispatch is correct, but this compatibility build deliberately
# compiles that optional path with the generic x86-64-v1 baseline as well.
# This prevents TZCNT/LZCNT/BMI instructions from appearing in the PE binary.
zstd_source = read(zstd_compiler)
old_attribute = '#define BMI2_TARGET_ATTRIBUTE TARGET_ATTRIBUTE("lzcnt,bmi,bmi2")'
new_attribute = '#define BMI2_TARGET_ATTRIBUTE /* x86-64-v1 build: no BMI1/BMI2/LZCNT codegen. */'
if zstd_source.count(old_attribute) != 1:
    raise SystemExit(
        "Zstd compiler.h no longer has the expected BMI2 target attribute; "
        "refusing to patch an unknown Zstd version."
    )
write(zstd_compiler, zstd_source.replace(old_attribute, new_attribute, 1))

# Post-patch assertions.
patched_sconstruct = read(sconstruct)
patched_scsub = read(scsub)
patched_zstd = read(zstd_compiler)
arch_start = patched_sconstruct.find('if env["arch"] == "x86_64":', patched_sconstruct.find(marker))
arch_end = patched_sconstruct.find('elif env["arch"] == "x86_32":', arch_start)
arch_block = patched_sconstruct[arch_start:arch_end]
if any(flag in arch_block for flag in ("-msse4.2", "-mpopcnt", "/d2archSSE42")):
    raise SystemExit("Post-patch check failed: a post-SSE2 compiler flag remains.")
if "cpu_feature_validation.c" in patched_scsub or "ShimMainCRTStartup" in patched_scsub:
    raise SystemExit("Post-patch check failed: SSE4.2 startup shim remains.")
if old_attribute in patched_zstd or new_attribute not in patched_zstd:
    raise SystemExit("Post-patch check failed: Zstd BMI1/BMI2/LZCNT target attribute remains.")

print("Godot 4.5.1 patched successfully.")
print("CPU baseline: x86-64-v1 (SSE2).")
print("Windows SSE4.2 startup gate: removed.")
print("Zstd optional BMI1/BMI2/LZCNT code generation: disabled.")
