#!/usr/bin/env python3
"""Audit a Windows x64 executable or static archive for instructions newer than SSE2."""

from pathlib import Path
import re
import shutil
import subprocess
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: audit_sse2.py PATH/TO/EXECUTABLE.exe|LIBRARY.a")

binary = Path(sys.argv[1])
if not binary.is_file():
    raise SystemExit(f"File not found: {binary}")

is_executable = binary.suffix.lower() == ".exe"
if is_executable:
    raw = binary.read_bytes()
    startup_gate = b"A CPU with SSE4.2 instruction set support is required."
    if startup_gate in raw:
        raise SystemExit("The SSE4.2 startup dialog is still embedded in the executable.")

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

print(f"ISA audit passed: no known post-SSE2 instructions found in {binary}.")
if is_executable:
    print("SSE4.2 Windows startup gate is absent.")
