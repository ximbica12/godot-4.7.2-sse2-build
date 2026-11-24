#!/usr/bin/env python3
"""Patch godot-angle-static to use the x86-64-v1 / SSE2 baseline."""

from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: patch_angle_sse2.py PATH/TO/ANGLE/SConstruct")

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
old = 'env.Append(CCFLAGS=["-msse4.2"])'
new = 'env.Append(CCFLAGS=["-march=x86-64", "-mtune=generic"])'

count = source.count(old)
if count != 1:
    raise SystemExit(
        f"Expected exactly one upstream ANGLE SSE4.2 flag, found {count}. "
        "Refusing to patch an unexpected source revision."
    )

path.write_text(source.replace(old, new, 1), encoding="utf-8")
print("Patched ANGLE SConstruct: replaced -msse4.2 with x86-64-v1 (SSE2).")
