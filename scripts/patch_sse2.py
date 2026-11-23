#!/usr/bin/env python3
"""Patch Godot 4.7.2 to build a Windows x64 executable with an SSE2-only CPU baseline."""

from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str) -> None:
    source = path.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one occurrence of patch anchor, found {count}.")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


if len(sys.argv) != 3:
    raise SystemExit(
        "Usage: patch_sse2.py PATH/TO/GODOT/SConstruct PATH/TO/GODOT/platform/windows/SCsub"
    )

sconstruct = Path(sys.argv[1])
scsub = Path(sys.argv[2])

source = sconstruct.read_text(encoding="utf-8")
marker = "# Set x86 CPU instruction sets to use by the compiler's autovectorization."
marker_pos = source.find(marker)
if marker_pos < 0:
    raise SystemExit("Could not find the x86 instruction-set section in SConstruct.")

start = source.find('if env["arch"] == "x86_64":', marker_pos)
end = source.find('elif env["arch"] == "x86_32":', start)
if start < 0 or end < 0 or end <= start:
    raise SystemExit("Could not locate the x86_64 architecture block in SConstruct.")

old_block = source[start:end]
if "-msse4.2" not in old_block or "-mpopcnt" not in old_block:
    raise SystemExit("Unexpected upstream x86_64 flags. Refusing to patch an unknown SConstruct version.")

new_block = '''if env["arch"] == "x86_64":
    # x86-64-v1 baseline: SSE2 only. Do not enable SSE4.2 or POPCNT.
    if env.msvc and not methods.using_clang(env):
        # MSVC x64 uses SSE2 by default; deliberately omit /d2archSSE42.
        pass
    else:
        # GCC/Clang: x86-64-v1 includes SSE2 and excludes later ISA extensions.
        env.Append(CCFLAGS=["-march=x86-64", "-mtune=generic"])
'''
sconstruct.write_text(source[:start] + new_block + source[end:], encoding="utf-8")

# Godot's Windows x64 executable has a separate startup shim that checks SSE4.2
# before the engine's normal entry point. Skip that shim for this SSE2 build.
replace_once(
    scsub,
    'if env["arch"] == "x86_64" and env["library_type"] == "executable":',
    'if False:  # SSE2 build: omit the SSE4.2-only Windows startup validation shim.',
)

print("Patched SConstruct to x86-64-v1 (SSE2) and removed the Windows SSE4.2 startup gate.")
