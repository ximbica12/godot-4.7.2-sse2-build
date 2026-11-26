#!/usr/bin/env python3
"""Audit a Windows x64 PE against x86-64-v1 (SSE2)."""

from collections import Counter, defaultdict
from pathlib import Path
import argparse
import re
import shutil
import subprocess


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit x86-64-v1 and narrowly verified runtime-dispatched exceptions."
    )
    parser.add_argument("binary", help="Windows x64 executable to audit")
    parser.add_argument("--source", required=True, help="Patched Godot source directory")
    parser.add_argument("--objects", required=True, help="SCons object directory")
    return parser.parse_args()


INSTRUCTION_LINE = re.compile(
    r"^\s*[0-9a-fA-F]+:\s+([a-zA-Z][a-zA-Z0-9.]*)\b"
)

# Instructions newer than the x86-64-v1 baseline. PEXTRW is intentionally
# not listed: it is an SSE2 instruction and is valid on the target baseline.
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
    "bextr", "blsi", "blsmsk", "blsr", "bzhi", "mulx", "pdep",
    "rorx", "sarx", "shlx", "shrx", "adcx", "adox",
    # AVX, AVX2, AVX-512, FMA, F16C, VAES and VPCLMUL
    "v",
    # Other later ISA extensions
    "gf2p8", "tile", "enqcmd", "movdir", "wrfsbase", "rdfsbase",
    "wrgsbase", "rdgsbase", "bnd",
)

FORBIDDEN_EXACT = {
    "fisttp", "monitor", "mwait", "monitorx", "mwaitx",
    "crc32", "pcmpestri", "pcmpestrm", "pcmpistri", "pcmpistrm",
    "pcmpgtq", "popcnt", "cmpxchg16b", "lahf", "sahf",
    "pextrb", "pextrd", "pextrq", "pinsrb", "pinsrd", "pinsrq",
    "pmaxsb", "pmaxsd", "pmaxud", "pmaxuw",
    "pminsb", "pminsd", "pminud", "pminuw",
    "pext", "lzcnt", "andn", "movbe", "rdrand", "rdseed",
    "clflushopt", "clwb", "cldemote", "prefetchwt1", "prefetchw",
    "xsave", "xrstor", "xsaveopt", "xsavec", "xsaves", "xrstors",
    "xgetbv", "xsetbv", "rdtscp", "rdpid", "rdpkru", "wrpkru",
    "clac", "stac", "serialize", "umonitor", "umwait", "tpause",
    "pconfig", "clzero", "rdpru", "wbnoinvd", "wrmsrns",
    "sha1msg1", "sha1msg2", "sha1nexte", "sha1rnds4",
    "sha256msg1", "sha256msg2", "sha256rnds2",
}


def classify(mnemonic):
    mnemonic = mnemonic.lower()

    # Legacy instructions whose names begin with V are not AVX.
    if mnemonic in {"verr", "verw"}:
        return None

    # GCC may emit the F3 0F BC encoding for a generic x86-64 BSF operation.
    # On CPUs without BMI1 this encoding executes as BSF. The one occurrence
    # in this build is restricted to HarfBuzz's zero-guarded hb_ctz helper.
    if mnemonic == "tzcnt":
        return "bsf-compatible-alias"

    # Mbed TLS keeps these in aesni.c and dispatches only after CPUID checks.
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


def is_mbedtls_aesni_object(path):
    normalized = path.as_posix().replace("\\", "/").lower()
    return "/thirdparty/mbedtls/library/aesni." in normalized


def is_harfbuzz_ctz_object(path):
    normalized = path.as_posix().replace("\\", "/").lower()
    return "/thirdparty/harfbuzz/src/hb-ot-layout." in normalized


def has_harfbuzz_ctz_zero_guard(content):
    start = content.find("hb_ctz (T v)")
    if start < 0:
        return False

    end = content.find("\n}", start)
    if end < 0:
        return False

    body = content[start:end]
    guard = "if (unlikely (!v)) return 8 * sizeof (T);"
    guard_pos = body.find(guard)
    if guard_pos < 0:
        return False

    builtin_calls = (
        "__builtin_ctz (v)",
        "__builtin_ctzl (v)",
        "__builtin_ctzll (v)",
    )
    found = False
    for token in builtin_calls:
        pos = body.find(token)
        if pos >= 0:
            found = True
            if pos < guard_pos:
                return False
    return found


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

    sconstruct_path = source_root / "SConstruct"
    sconstruct = sconstruct_path.read_text(encoding="utf-8")
    required_baseline_flags = (
        "-march=x86-64",
        "-mtune=generic",
        "-mno-bmi",
        "-mno-bmi2",
        "-mno-lzcnt",
        "-mno-popcnt",
    )
    missing_flags = [flag for flag in required_baseline_flags if flag not in sconstruct]
    if missing_flags:
        raise SystemExit(
            "SConstruct is missing required x86-64-v1 compiler flags: "
            + ", ".join(missing_flags)
        )

    positive_feature_flag = re.compile(
        r"(?<![A-Za-z0-9_-])-m(?:bmi2?|lzcnt|popcnt|sse3|ssse3|sse4(?:\.1|\.2)?|avx2?|fma|f16c)(?![A-Za-z0-9_.-])"
    )
    if positive_feature_flag.search(sconstruct):
        raise SystemExit("SConstruct contains a compiler flag that raises the x86-64-v1 baseline.")

    harfbuzz_path = source_root / "thirdparty/harfbuzz/src/hb-algs.hh"
    if not harfbuzz_path.is_file():
        raise SystemExit(f"Source guard check cannot find {harfbuzz_path}")
    harfbuzz = harfbuzz_path.read_text(encoding="utf-8")
    if not has_harfbuzz_ctz_zero_guard(harfbuzz):
        raise SystemExit(
            "HarfBuzz hb_ctz no longer guards zero before calling __builtin_ctz; "
            "TZCNT/BSF alias cannot be approved."
        )

    print("PASS: x86-64-v1 compiler target and explicit BMI/POPCNT disables verified.")
    print("PASS: Mbed TLS AES-NI/PCLMUL paths are CPUID-guarded.")
    print("PASS: Zstd BMI1/BMI2 dispatch and x86 assembly are disabled.")
    print("PASS: HarfBuzz zero-guards its generic trailing-zero builtin.")


def record_failure(counts, examples, category, detail):
    counts[category] += 1
    if len(examples[category]) < 5:
        examples[category].append(detail)


def print_failure_report(title, counts, examples):
    total = sum(counts.values())
    print(f"{title}: {total} occurrence(s) across {len(counts)} instruction category/categories.")
    for category, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        print(f"  {category}: {count}")
        for example in examples[category]:
            print(f"    {example}")


def scan_objects(objdump, objects_root):
    object_files = sorted(objects_root.rglob("*.o"))
    if not object_files:
        raise SystemExit(f"No object files found under {objects_root}")

    aesni_object_count = 0
    aesni_instructions = Counter()
    bsf_alias_instructions = Counter()
    failure_counts = Counter()
    failure_examples = defaultdict(list)

    for obj in object_files:
        aesni_object = is_mbedtls_aesni_object(obj)
        harfbuzz_ctz_object = is_harfbuzz_ctz_object(obj)

        if aesni_object:
            aesni_object_count += 1

        disassembly = run_objdump(objdump, obj)
        for mnemonic, line in instructions(disassembly):
            category = classify(mnemonic)

            if category == "forbidden":
                record_failure(
                    failure_counts, failure_examples, mnemonic, f"{obj}: {line}"
                )
            elif category == "mbedtls-aesni":
                if aesni_object:
                    aesni_instructions[mnemonic] += 1
                else:
                    record_failure(
                        failure_counts,
                        failure_examples,
                        f"{mnemonic} outside Mbed TLS aesni.c",
                        f"{obj}: {line}",
                    )
            elif category == "bsf-compatible-alias":
                if harfbuzz_ctz_object:
                    bsf_alias_instructions[mnemonic] += 1
                else:
                    record_failure(
                        failure_counts,
                        failure_examples,
                        "tzcnt outside verified HarfBuzz hb_ctz object",
                        f"{obj}: {line}",
                    )

    if aesni_object_count != 1:
        record_failure(
            failure_counts,
            failure_examples,
            "Mbed TLS aesni.c object count",
            f"Expected exactly one object, found {aesni_object_count}.",
        )

    if failure_counts:
        print_failure_report("Unsupported or unverified object-file instructions", failure_counts, failure_examples)
        raise SystemExit(1)

    print(f"PASS: scanned {len(object_files)} object files.")
    if aesni_instructions:
        summary = ", ".join(
            f"{mnemonic}={count}"
            for mnemonic, count in sorted(aesni_instructions.items())
        )
        print(f"Verified CPUID-dispatched Mbed TLS instructions: {summary}")
    if bsf_alias_instructions:
        summary = ", ".join(
            f"{mnemonic}={count}"
            for mnemonic, count in sorted(bsf_alias_instructions.items())
        )
        print(f"Verified generic HarfBuzz TZCNT/BSF alias: {summary}")
    return aesni_instructions, bsf_alias_instructions


def scan_final_binary(objdump, binary, allowed_aesni, allowed_bsf_alias):
    disassembly = run_objdump(objdump, binary)
    aesni_counts = Counter()
    bsf_alias_counts = Counter()
    failure_counts = Counter()
    failure_examples = defaultdict(list)

    for mnemonic, line in instructions(disassembly):
        category = classify(mnemonic)
        if category == "forbidden":
            record_failure(failure_counts, failure_examples, mnemonic, line)
        elif category == "mbedtls-aesni":
            aesni_counts[mnemonic] += 1
        elif category == "bsf-compatible-alias":
            bsf_alias_counts[mnemonic] += 1

    for mnemonic, count in aesni_counts.items():
        allowed = allowed_aesni.get(mnemonic, 0)
        if count > allowed:
            record_failure(
                failure_counts,
                failure_examples,
                f"{mnemonic} count exceeds guarded object",
                f"PE contains {count}; guarded Mbed TLS object contains {allowed}.",
            )

    for mnemonic, count in bsf_alias_counts.items():
        allowed = allowed_bsf_alias.get(mnemonic, 0)
        if count > allowed:
            record_failure(
                failure_counts,
                failure_examples,
                "tzcnt count exceeds verified HarfBuzz object",
                f"PE contains {count}; verified HarfBuzz object contains {allowed}.",
            )

    if failure_counts:
        print_failure_report("Post-x86-64-v1 instructions outside verified exceptions", failure_counts, failure_examples)
        raise SystemExit(1)

    print(f"PASS: {binary} respects the x86-64-v1 baseline.")
    print("PASS: only CPUID-guarded Mbed TLS AES-NI/PCLMUL and the verified HarfBuzz BSF alias remain.")


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
        raise SystemExit(f"SCons object directory not found: {objects_root}")

    if binary.suffix.lower() == ".exe":
        startup_gate = b"A CPU with SSE4.2 instruction set support is required."
        if startup_gate in binary.read_bytes():
            raise SystemExit("SSE4.2 startup gate is still embedded in the executable.")

    objdump = shutil.which("x86_64-w64-mingw32-objdump") or shutil.which("objdump")
    if not objdump:
        raise SystemExit("Could not find objdump.")

    require_source_guards(source_root)
    allowed_aesni, allowed_bsf_alias = scan_objects(objdump, objects_root)
    scan_final_binary(objdump, binary, allowed_aesni, allowed_bsf_alias)


if __name__ == "__main__":
    main()
