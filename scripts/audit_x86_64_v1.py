#!/usr/bin/env python3
"""Audit a Windows x64 executable/archive for instructions newer than x86-64-v1."""

from pathlib import Path
import re
import shutil
import subprocess
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: audit_x86_64_v1.py FILE.exe|FILE.a")

binary = Path(sys.argv[1])
if not binary.is_file():
    raise SystemExit(f"File not found: {binary}")

is_executable = binary.suffix.lower() == ".exe"
if is_executable:
    raw = binary.read_bytes()
    startup_gate = b"A CPU with SSE4.2 instruction set support is required."
    if startup_gate in raw:
        raise SystemExit("SSE4.2 startup gate is still embedded in the executable.")

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
    # SSE3
    "addsub", "hadd", "hsub", "lddqu", "movddup", "movshdup", "movsldup",
    # SSSE3
    "pabs", "palignr", "phadd", "phsub", "pmaddubsw", "pmulhrsw", "pshufb", "psign",
    # SSE4.1
    "blend", "dpp", "extractps", "insertps", "movntdqa", "mpsadbw",
    "packusdw", "pblend", "pcmpeqq", "phminposuw", "pmuldq", "pmulld",
    "pmovsx", "pmovzx", "ptest", "round",
    # AES / PCLMUL / GFNI
    "aes", "pclmul", "gf2p8",
    # BMI / BMI2 / ADX
    "bextr", "blsi", "blsmsk", "blsr", "bzhi", "mulx", "pdep", "pext",
    "rorx", "sarx", "shlx", "shrx", "adcx", "adox",
    # AVX, AVX2, AVX-512, FMA, F16C, VAES and VPCLMUL
    "v",
    # Newer miscellaneous ISA extensions
    "tile", "enqcmd", "movdir", "wrfsbase", "rdfsbase", "wrgsbase", "rdgsbase",
)

forbidden_exact = {
    "fisttp", "monitor", "mwait", "crc32", "pcmpestri", "pcmpestrm",
    "pcmpistri", "pcmpistrm", "pcmpgtq", "popcnt", "cmpxchg16b", "lahf", "sahf",
    "pextrb", "pextrd", "pextrq", "pinsrb", "pinsrd", "pinsrq",
    "pmaxsb", "pmaxsd", "pmaxud", "pmaxuw",
    "pminsb", "pminsd", "pminud", "pminuw",
    "lzcnt", "movbe", "rdrand", "rdseed", "tzcnt", "andn",
    "clflushopt", "clwb", "cldemote", "prefetchwt1",
    "xsaveopt", "xsavec", "xsaves", "xrstors", "rdpid",
    "serialize", "umonitor", "umwait", "tpause", "pconfig",
    "clzero", "rdpru", "wbnoinvd", "wrmsrns",
}

violations = []
for line in result.stdout.splitlines():
    match = instruction_line.match(line)
    if not match:
        continue
    mnemonic = match.group(1).lower()
    if mnemonic in {"verr", "verw"}:
        continue
    # PEXTRW is part of SSE2 (not SSE4.1); keep it legal in x86-64-v1.
    if mnemonic == "pextrw":
        continue
    if mnemonic in forbidden_exact or mnemonic.startswith(forbidden_prefixes):
        violations.append((mnemonic, line.strip()))

if violations:
    print("Post-x86-64-v1 instructions detected:")
    for mnemonic, line in violations[:200]:
        print(f"  {line}")
    raise SystemExit(1)

print(f"PASS: no known post-x86-64-v1 instructions found in {binary}.")
if is_executable:
    print("PASS: SSE4.2 startup gate is absent.")
