#!/usr/bin/env python3
"""Audit a Windows x64 PE against x86-64-v1, allowing only CPUID-guarded Mbed TLS AES-NI."""

from collections import Counter
from pathlib import Path
import argparse
import re
import shutil
import subprocess
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit the x86-64-v1 baseline and known runtime-dispatched crypto code."
    )
    parser.add_argument("binary", help="Windows x64 executable to audit")
    parser.add_argument("--source", required=True, help="Patched Godot source directory")
    parser.add_argument("--objects", required=True, help="SCons object directory")
    return parser.parse_args()


INSTRUCTION_LINE = re.compile(
    r"^\s*[0-9a-fA-F]+:\s+([a-zA-Z][a-zA-Z0-9.]*)\b"
)

# Instructions that are not part of the x86-64-v1 baseline.
# PEXTRW is deliberately absent: it is a valid SSE2 instruction.
FORBIDDEN_PREFIXES = (
    # SSE3
    "addsub", "hadd", "hsub", "lddqu", "movddup", "movshdup", "movsldup",
    # SSSE3
    "pabs", "palignr", "phadd", "phsub", "pmaddubsw", "pmulhrsw", "pshufb", "psign",
    # SSE4.1
    "blend", "dpp", "extractps", "insertps", "movntdqa", "mpsadbw",
    "packusdw", "pblend", "pcmpeqq", "phminposuw", "pmuldq", "pmulld",
    "pmovsx", "pmovzx", "ptest", "round",
    # BMI / BMI2 / ADX
    "bextr", "blsi", "blsmsk", "blsr", "bzhi", "mulx", "pdep", "pext",
    "rorx", "sarx", "shlx", "shrx", "adcx", "adox",
    # AVX, AVX2, AVX-512, FMA, F16C, VAES and VPCLMUL
    "v",
    # Other later ISA extensions
    "gf2p8", "tile", "enqcmd", "movdir", "wrfsbase", "rdfsbase",
    "wrgsbase", "rdgsbase",
)

FORBIDDEN_EXACT = {
    "fisttp", "monitor", "mwait", "crc32", "pcmpestri", "pcmpestrm",
    "pcmpistri", "pcmpistrm", "pcmpgtq", "popcnt", "cmpxchg16b", "lahf", "sahf",
    "pextrb", "pextrd", "pextrq", "pinsrb", "pinsrd", "pinsrq",
    "pmaxsb", "pmaxsd", "pmaxud", "pmaxuw",
    "pminsb", "pminsd", "pminud", "pminuw",
    "lzcnt", "tzcnt", "andn", "movbe", "rdrand", "rdseed",
    "clflushopt", "clwb", "cldemote", "prefetchwt1",
    "xsaveopt", "xsavec", "xsaves", "xrstors", "rdpid",
    "serialize", "umonitor", "umwait", "tpause", "pconfig",
    "clzero", "rdpru", "wbnoinvd", "wrmsrns",
}


def classify(mnemonic):
    mnemonic = mnemonic.lower()
    if mnemonic in {"verr", "verw"}:
        return None
    # These are permitted only in Mbed TLS's separately compiled AES-NI file.
    if mnemonic.startswith(("aes", "pclmul")):
        return "mbedtls-aesni"
    if mnemonic in FORBIDDEN_EXACT or mnemonic.startswith(FORBIDDEN_PREFIXES):
        return "forbidden"
    return None


def instructions(disassembly):
    for line in disassembly.splitlines():
        match = INSTRUCTION_LINE.match(line)
        if match:
            yield match.group(1).lower(), line.strip()


def run_objdump(objdump, path):
    result = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(path)],
        check=False,
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"objdump failed for {path}:\n{detail}")
    return result.stdout


def require_source_guards(source_root):
    checks = {
        "thirdparty/mbedtls/include/mbedtls/mbedtls_config.h": (
            "#define MBEDTLS_AESNI_C",
        ),
        "thirdparty/mbedtls/library/aesni.c": (
            '#pragma GCC target ("pclmul,sse2,aes")',
            "int mbedtls_aesni_has_support(unsigned int what)",
            "__cpuid",
            "return (c & what) != 0;",
        ),
        "thirdparty/mbedtls/library/aes.c": (
            "mbedtls_aesni_has_support(MBEDTLS_AESNI_AES)",
            "mbedtls_aesni_setkey_enc",
            "mbedtls_aesni_crypt_ecb",
        ),
        "thirdparty/mbedtls/library/gcm.c": (
            "mbedtls_aesni_has_support(MBEDTLS_AESNI_CLMUL)",
            "MBEDTLS_GCM_ACC_AESNI",
            "mbedtls_aesni_gcm_mult",
        ),
        "thirdparty/zstd/common/portability_macros.h": (
            "#undef DYNAMIC_BMI2",
            "#define DYNAMIC_BMI2 0",
            "#undef ZSTD_DISABLE_ASM",
            "#define ZSTD_DISABLE_ASM 1",
        ),
    }

    loaded = {}
    for relative, required in checks.items():
        path = source_root / relative
        if not path.is_file():
            raise SystemExit(f"Source guard check cannot find {path}")
        content = path.read_text(encoding="utf-8")
        loaded[relative] = content
        missing = [token for token in required if token not in content]
        if missing:
            raise SystemExit(
                f"Source guard check failed for {relative}; missing: {', '.join(missing)}"
            )

    aes_source = loaded["thirdparty/mbedtls/library/aes.c"]
    if aes_source.count("mbedtls_aesni_has_support(MBEDTLS_AESNI_AES)") < 3:
        raise SystemExit("Mbed TLS AES-NI CPUID checks are fewer than expected.")

    gcm_source = loaded["thirdparty/mbedtls/library/gcm.c"]
    if gcm_source.count("mbedtls_aesni_has_support(MBEDTLS_AESNI_CLMUL)") < 1:
        raise SystemExit("Mbed TLS PCLMUL CPUID check is missing.")

    print("PASS: Mbed TLS AES-NI and PCLMUL paths are guarded by CPUID checks.")
    print("PASS: Zstd BMI1/BMI2 dispatch and x86 assembly are disabled for this build.")


def is_mbedtls_aesni_object(path):
    normalized = path.as_posix().replace("\\", "/").lower()
    return "/thirdparty/mbedtls/library/aesni." in normalized or normalized.endswith(
        "/thirdparty/mbedtls/library/aesni.o"
    )


def scan_objects(objdump, objects_root):
    object_files = sorted(objects_root.rglob("*.o"))
    if not object_files:
        raise SystemExit(f"No object files found under {objects_root}")

    aesni_object_count = 0
    aesni_object_instructions = Counter()
    failures = []

    for obj in object_files:
        is_aesni_object_file = is_mbedtls_aesni_object(obj)
        if is_aesni_object_file:
            aesni_object_count += 1

        disassembly = run_objdump(objdump, obj)
        for mnemonic, line in instructions(disassembly):
            category = classify(mnemonic)
            if category == "forbidden":
                failures.append(f"{obj}: {line}")
            elif category == "mbedtls-aesni":
                if is_aesni_object_file:
                    aesni_object_instructions[mnemonic] += 1
                else:
                    failures.append(
                        f"{obj}: accelerated crypto instruction outside Mbed TLS aesni.c: {line}"
                    )

    if aesni_object_count != 1:
        failures.append(
            f"Expected exactly one Mbed TLS aesni.c object, found {aesni_object_count}."
        )

    if failures:
        print("Unsupported or unverified instructions found in object files:")
        for failure in failures[:100]:
            print(f"  {failure}")
        if len(failures) > 100:
            print(f"  ... and {len(failures) - 100} more.")
        raise SystemExit(1)

    print(f"PASS: scanned {len(object_files)} object files.")
    if aesni_object_instructions:
        summary = ", ".join(
            f"{mnemonic}={count}"
            for mnemonic, count in sorted(aesni_object_instructions.items())
        )
        print(f"Allowed runtime-dispatched Mbed TLS instructions: {summary}")
    else:
        print("No AES-NI/PCLMUL instructions were emitted by the Mbed TLS object.")
    return aesni_object_instructions


def scan_final_binary(objdump, binary, allowed_object_instructions):
    disassembly = run_objdump(objdump, binary)
    accelerated_counts = Counter()
    failures = []

    for mnemonic, line in instructions(disassembly):
        category = classify(mnemonic)
        if category == "forbidden":
            failures.append(line)
        elif category == "mbedtls-aesni":
            accelerated_counts[mnemonic] += 1

    for mnemonic, count in accelerated_counts.items():
        allowed = allowed_object_instructions.get(mnemonic, 0)
        if count > allowed:
            failures.append(
                f"PE contains {count} {mnemonic} instructions, but the guarded Mbed TLS "
                f"object contains only {allowed}."
            )

    if failures:
        print("Post-x86-64-v1 instructions detected outside the verified exception:")
        for failure in failures[:100]:
            print(f"  {failure}")
        if len(failures) > 100:
            print(f"  ... and {len(failures) - 100} more.")
        raise SystemExit(1)

    if accelerated_counts:
        summary = ", ".join(
            f"{mnemonic}={count}"
            for mnemonic, count in sorted(accelerated_counts.items())
        )
        print(f"Verified Mbed TLS runtime-dispatch instructions in PE: {summary}")

    print(f"PASS: {binary} respects the x86-64-v1 baseline.")
    print("PASS: the only permitted later-ISA instructions are CPUID-guarded Mbed TLS AES-NI/PCLMUL.")


def main():
    args = parse_args()
    binary = Path(args.binary)
    source_root = Path(args.source)
    objects_root = Path(args.objects)

    if not binary.is_file():
        raise SystemExit(f"File not found: {binary}")
    if not source_root.is_dir():
        raise SystemExit(f"Godot source directory not found: {source_root}")
    if not objects_root.is_dir():
        raise SystemExit(f"Object directory not found: {objects_root}")

    is_executable = binary.suffix.lower() == ".exe"
    if is_executable:
        startup_gate = b"A CPU with SSE4.2 instruction set support is required."
        if startup_gate in binary.read_bytes():
            raise SystemExit("SSE4.2 startup gate is still embedded in the executable.")

    objdump = shutil.which("x86_64-w64-mingw32-objdump") or shutil.which("objdump")
    if not objdump:
        raise SystemExit("Could not find objdump.")

    require_source_guards(source_root)
    allowed_object_instructions = scan_objects(objdump, objects_root)
    scan_final_binary(objdump, binary, allowed_object_instructions)


if __name__ == "__main__":
    main()
