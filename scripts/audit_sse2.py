#!/usr/bin/env python3
"""Reject x86 instructions newer than SSE2 in the built PE executable."""

from pathlib import Path
import re
import shutil
import subprocess
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: audit_sse2.py PATH/TO/EXECUTABLE.exe")

binary = Path(sys.argv[1])
if not binary.is_file():
    raise SystemExit(f"Executable not found: {binary}")

objdump = shutil.which("x86_64-w64-mingw32-objdump") or shutil.which("objdump")
if not objdump:
    raise SystemExit("Could not find objdump.")

result = subprocess.run(
    [objdump, "-d", "--no-show-raw-insn", str(binary)],
    check=True,
    capture_output=True,
    text=True,
    errors="replace",
)

instruction_line = re.compile(r"^\s*[0-9a-fA-F]+:\s+([a-zA-Z][a-zA-Z0-9.]*)\b")
forbidden_prefixes = (
    "addsub", "hadd", "hsub", "lddqu", "movddup", "movshdup", "movsldup",
    "pabs", "palignr", "phadd", "phsub", "pmaddubsw", "pmulhrsw", "pshufb", "psign",
    "blend", "dpp", "extractps", "insertps", "movntdqa", "mpsadbw", "packusdw",
    "pblend", "pcmpeqq", "phminposuw", "pmuldq", "pmulld", "ptest", "round",
    "pmovsx", "pmovzx", "crc32", "pcmpestr", "pcmpistr",
)
forbidden_exact = {
    "popcnt", "fisttp", "monitor", "mwait", "pcmpgtq",
    "pextrb", "pextrd", "pextrq", "pinsrb", "pinsrd", "pinsrq",
    "pmaxsb", "pmaxsd", "pmaxud", "pmaxuw",
    "pminsb", "pminsd", "pminud", "pminuw",
}

violations = []
for line in result.stdout.splitlines():
    match = instruction_line.match(line)
    if not match:
        continue
    mnemonic = match.group(1).lower()
    is_avx = mnemonic.startswith("v") and mnemonic not in {"verr", "verw"}
    if mnemonic in forbidden_exact or is_avx or mnemonic.startswith(forbidden_prefixes):
        violations.append((mnemonic, line.strip()))

if violations:
    print("Found instructions newer than SSE2:")
    for mnemonic, line in violations[:100]:
        print(f"  {line}")
    raise SystemExit(1)

print(f"ISA audit passed: no instructions newer than SSE2 found in {binary}.")
