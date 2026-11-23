#!/usr/bin/env python3
"""Patch Godot 4.7.2's x86-64 compiler target to the SSE2-only x86-64-v1 baseline."""

from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: patch_sse2.py PATH/TO/GODOT/SConstruct")

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")

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
    raise SystemExit(
        "Unexpected upstream x86_64 flags. Refusing to patch an unknown SConstruct version."
    )

new_block = '''if env["arch"] == "x86_64":
    # x86-64-v1 baseline: SSE2 only. Do not enable SSE4.2 or POPCNT.
    if env.msvc and not methods.using_clang(env):
        # MSVC x64 uses SSE2 by default; deliberately omit /d2archSSE42.
        pass
    else:
        # GCC/Clang: x86-64-v1 includes SSE2 and excludes later ISA extensions.
        env.Append(CCFLAGS=["-march=x86-64", "-mtune=generic"])
'''

patched = source[:start] + new_block + source[end:]
if patched == source:
    raise SystemExit("Patch made no changes.")

path.write_text(patched, encoding="utf-8")
print("Patched x86_64 compiler target to x86-64-v1 (SSE2 baseline).")
