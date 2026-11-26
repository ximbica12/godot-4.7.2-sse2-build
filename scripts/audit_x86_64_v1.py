#!/usr/bin/env python3
"""Audit a Windows x64 PE for the Pentium E5700 compatibility profile.

Required compiler baseline: x86-64-v1 (SSE2).
Verified optional paths: SSSE3 meshoptimizer dispatch, HarfBuzz BSF/TZCNT
encoding alias, CPUID-gated AES-NI/PCLMUL, OSXSAVE-gated XGETBV, and
GCC 13.2 libstdc++ RDRAND/RDSEED dispatch.
"""

from collections import Counter, defaultdict
from pathlib import Path
import argparse
import re
import shutil
import subprocess


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit x86-64-v1 plus source-verified Pentium E5700 runtime-dispatch exceptions."
    )
    parser.add_argument("binary", nargs="?", help="Windows x64 executable to audit")
    parser.add_argument("--source", required=True, help="Patched Godot source directory")
    parser.add_argument("--objects", help="SCons object directory")
    parser.add_argument("--gcc-random-source", required=True, help="GCC 13.2.0 libstdc++ random.cc")
    parser.add_argument("--source-only", action="store_true",
                        help="Run source-guard checks without scanning a binary or object files.")
    return parser.parse_args()


INSTRUCTION_LINE = re.compile(r"^\s*[0-9a-fA-F]+:\s+([a-zA-Z][a-zA-Z0-9.]*)\b")

FORBIDDEN_PREFIXES = (
    "addsub", "hadd", "hsub", "lddqu", "movddup", "movshdup", "movsldup",
    "pabs", "palignr", "phadd", "phsub", "pmaddubsw", "pmulhrsw", "psign",
    "blend", "dpp", "extractps", "insertps", "movntdqa", "mpsadbw",
    "packusdw", "pblend", "pcmpeqq", "phminposuw", "pmuldq", "pmulld",
    "pmovsx", "pmovzx", "ptest", "round",
    "bextr", "blsi", "blsmsk", "blsr", "bzhi", "mulx", "pdep",
    "rorx", "sarx", "shlx", "shrx", "adcx", "adox",
    "v",
    "gf2p8", "tile", "enqcmd", "movdir", "wrfsbase", "rdfsbase",
    "wrgsbase", "rdgsbase", "bnd",
)

FORBIDDEN_EXACT = {
    "fisttp", "monitor", "mwait", "monitorx", "mwaitx",
    "crc32", "pcmpestri", "pcmpestrm", "pcmpistri", "pcmpistrm",
    "pcmpgtq", "popcnt",
    "pextrb", "pextrd", "pextrq", "pinsrb", "pinsrd", "pinsrq",
    "pmaxsb", "pmaxsd", "pmaxud", "pmaxuw",
    "pminsb", "pminsd", "pminud", "pminuw",
    "pext", "lzcnt", "andn", "movbe",
    "clflushopt", "clwb", "cldemote", "prefetchwt1", "prefetchw",
    "xsave", "xrstor", "xsaveopt", "xsavec", "xsaves", "xrstors",
    "xsetbv", "rdtscp", "rdpid", "rdpkru", "wrpkru",
    "clac", "stac", "serialize", "umonitor", "umwait", "tpause",
    "pconfig", "clzero", "rdpru", "wbnoinvd", "wrmsrns",
    "sha1msg1", "sha1msg2", "sha1nexte", "sha1rnds4",
    "sha256msg1", "sha256msg2", "sha256rnds2",
}


def classify(mnemonic):
    mnemonic = mnemonic.lower()
    if mnemonic in {"verr", "verw"}:
        return None
    if mnemonic == "tzcnt":
        return "harfbuzz-bsf-alias"
    if mnemonic == "pshufb":
        return "meshoptimizer-ssse3"
    if mnemonic == "xgetbv":
        return "osxsave-xgetbv"
    if mnemonic in {"rdrand", "rdseed"}:
        return "libstdcxx-cpuid-rng"
    if mnemonic in {"lahf", "sahf", "cmpxchg16b"}:
        return "pentium-e5700-supported"
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
        check=False, capture_output=True, text=True, errors="replace",
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"objdump failed for {path}:\n{detail}")
    return result.stdout


def normalized_path(path):
    return path.as_posix().replace("\\", "/").lower()


def is_mbedtls_aesni_object(path):
    return "/thirdparty/mbedtls/library/aesni." in normalized_path(path)


def is_harfbuzz_ctz_object(path):
    return "/thirdparty/harfbuzz/src/" in normalized_path(path)


def is_meshoptimizer_vertexcodec_object(path):
    return "/thirdparty/meshoptimizer/vertexcodec." in normalized_path(path)


def is_guarded_xgetbv_object(path):
    p = normalized_path(path)
    return (
        "/thirdparty/embree/common/sys/sysinfo." in p
        or "/thirdparty/libwebp/src/dsp/cpu." in p
        or "/thirdparty/libwebp/sharpyuv/sharpyuv_cpu." in p
        or "/thirdparty/pcre2/src/pcre2_jit_compile_" in p
    )


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
    found = False
    for token in ("__builtin_ctz (v)", "__builtin_ctzl (v)", "__builtin_ctzll (v)"):
        pos = body.find(token)
        if pos >= 0:
            found = True
            if pos < guard_pos:
                return False
    return found


def has_meshoptimizer_ssse3_cpuid_dispatch(content):
    required = (
        "#define SIMD_FALLBACK",
        '#define SIMD_TARGET __attribute__((target("ssse3")))',
        "#include <tmmintrin.h>",
        "static unsigned int getCpuFeatures()",
        "__cpuid(1, cpuinfo[0], cpuinfo[1], cpuinfo[2], cpuinfo[3]);",
        "decode = (cpuid & (1 << 9)) ? decodeVertexBlockSimd : decodeVertexBlock;",
    )
    return all(token in content for token in required)


def has_embree_osxsave_guard(content):
    return all(token in content for token in (
        "CPU_FEATURE_BIT_OXSAVE = 1 << 27",
        "if (cpuid_leaf_1[ECX] & CPU_FEATURE_BIT_OXSAVE)",
        "int64_t xcr0 = get_xcr0();",
    ))


def has_webp_osxsave_guard(content):
    return all(token in content for token in (
        "if ((cpu_info[2] & 0x18000000) == 0x18000000)",
        "return (xgetbv() & 0x6) == 0x6;",
    ))


def has_pcre2_osxsave_guard(content):
    return all(token in content for token in (
        "#define CPU_FEATURE_OSXSAVE",
        "if ((feature_list & CPU_FEATURE_OSXSAVE) && (execute_get_xcr0_low() & 0x4) == 0)",
    ))


def has_gcc_random_device_cpuid_guards(content):
    rdseed_start = content.find("if (which & rdseed)")
    rdrand_start = content.find("if (which & rdrand)")
    if rdseed_start < 0 or rdrand_start < 0:
        return False
    rdseed_end = content.find("#endif // USE_RDSEED", rdseed_start)
    rdrand_end = content.find("#endif // USE_RDRAND", rdrand_start)
    if rdseed_end < 0 or rdrand_end < 0:
        return False
    rdseed_block = content[rdseed_start:rdseed_end]
    rdrand_block = content[rdrand_start:rdrand_end]
    return (
        '__attribute__ ((target("rdrnd")))' in content
        and '__attribute__ ((target("rdseed")))' in content
        and "__cpuid_count(7, 0, eax, ebx, ecx, edx);" in rdseed_block
        and "if (ebx & bit_RDSEED)" in rdseed_block
        and "_M_func = &__x86_rdseed;" in rdseed_block
        and "__cpuid(1, eax, ebx, ecx, edx);" in rdrand_block
        and "if (ecx & bit_RDRND)" in rdrand_block
        and "_M_func = &__x86_rdrand;" in rdrand_block
    )


def require_source_guards(source_root, gcc_random_source):
    checks = {
        "thirdparty/mbedtls/include/mbedtls/mbedtls_config.h": ("#define MBEDTLS_AESNI_C",),
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

    sconstruct = (source_root / "SConstruct").read_text(encoding="utf-8")
    required_flags = (
        "-march=x86-64", "-mtune=generic", "-mno-bmi", "-mno-bmi2",
        "-mno-lzcnt", "-mno-popcnt",
    )
    missing_flags = [flag for flag in required_flags if flag not in sconstruct]
    if missing_flags:
        raise SystemExit("SConstruct is missing required x86-64-v1 flags: " + ", ".join(missing_flags))
    positive_flag = re.compile(
        r"(?<![A-Za-z0-9_-])-m(?:bmi2?|lzcnt|popcnt|sse3|ssse3|sse4(?:\.1|\.2)?|avx2?|fma|f16c)(?![A-Za-z0-9_.-])"
    )
    if positive_flag.search(sconstruct):
        raise SystemExit("SConstruct contains a compiler flag that raises the x86-64-v1 baseline.")

    harfbuzz = (source_root / "thirdparty/harfbuzz/src/hb-algs.hh").read_text(encoding="utf-8")
    if not has_harfbuzz_ctz_zero_guard(harfbuzz):
        raise SystemExit("HarfBuzz hb_ctz no longer guards zero before __builtin_ctz.")

    meshoptimizer = (source_root / "thirdparty/meshoptimizer/vertexcodec.cpp").read_text(encoding="utf-8")
    if not has_meshoptimizer_ssse3_cpuid_dispatch(meshoptimizer):
        raise SystemExit("meshoptimizer SSSE3 target/CPUID/scalar fallback guard changed.")

    embree = (source_root / "thirdparty/embree/common/sys/sysinfo.cpp").read_text(encoding="utf-8")
    if not has_embree_osxsave_guard(embree):
        raise SystemExit("Embree XGETBV is no longer guarded by CPUID.OSXSAVE.")

    webp = (source_root / "thirdparty/libwebp/src/dsp/cpu.c").read_text(encoding="utf-8")
    if not has_webp_osxsave_guard(webp):
        raise SystemExit("libwebp XGETBV is no longer guarded by CPUID.OSXSAVE and AVX.")

    sharpyuv = (source_root / "thirdparty/libwebp/sharpyuv/sharpyuv_cpu.c").read_text(encoding="utf-8")
    if '#include "src/dsp/cpu.c"' not in sharpyuv:
        raise SystemExit("SharpYUV no longer reuses the guarded libwebp CPU detector.")

    pcre2 = (source_root / "thirdparty/pcre2/deps/sljit/sljit_src/sljitNativeX86_common.c").read_text(encoding="utf-8")
    if not has_pcre2_osxsave_guard(pcre2):
        raise SystemExit("PCRE2/SLJIT XGETBV is no longer guarded by CPUID.OSXSAVE.")

    if not gcc_random_source.is_file():
        raise SystemExit(f"GCC libstdc++ random.cc source not found: {gcc_random_source}")
    gcc_random = gcc_random_source.read_text(encoding="utf-8")
    if not has_gcc_random_device_cpuid_guards(gcc_random):
        raise SystemExit("GCC libstdc++ RDRAND/RDSEED paths are not CPUID-guarded.")

    print("PASS: x86-64-v1 compiler target and explicit BMI/POPCNT disables verified.")
    print("PASS: Mbed TLS AES-NI/PCLMUL paths are CPUID-guarded.")
    print("PASS: Zstd BMI1/BMI2 dispatch and x86 assembly are disabled.")
    print("PASS: HarfBuzz zero-guards the generic TZCNT/BSF alias.")
    print("PASS: meshoptimizer SSSE3 is target-scoped and CPUID-dispatched to scalar fallback.")
    print("PASS: Embree, libwebp, SharpYUV and PCRE2 guard XGETBV with OSXSAVE.")
    print("PASS: GCC 13.2 libstdc++ guards RDRAND/RDSEED with CPUID.")


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
    meshoptimizer_instructions = Counter()
    xgetbv_instructions = Counter()
    supported_profile_instructions = Counter()
    failure_counts = Counter()
    failure_examples = defaultdict(list)

    for obj in object_files:
        aesni_object = is_mbedtls_aesni_object(obj)
        harfbuzz_object = is_harfbuzz_ctz_object(obj)
        meshoptimizer_object = is_meshoptimizer_vertexcodec_object(obj)
        xgetbv_object = is_guarded_xgetbv_object(obj)
        if aesni_object:
            aesni_object_count += 1

        for mnemonic, line in instructions(run_objdump(objdump, obj)):
            category = classify(mnemonic)
            if category == "forbidden":
                record_failure(failure_counts, failure_examples, mnemonic, f"{obj}: {line}")
            elif category == "mbedtls-aesni":
                if aesni_object:
                    aesni_instructions[mnemonic] += 1
                else:
                    record_failure(failure_counts, failure_examples, f"{mnemonic} outside Mbed TLS aesni.c", f"{obj}: {line}")
            elif category == "harfbuzz-bsf-alias":
                if harfbuzz_object:
                    bsf_alias_instructions[mnemonic] += 1
                else:
                    record_failure(failure_counts, failure_examples, "tzcnt outside HarfBuzz source objects", f"{obj}: {line}")
            elif category == "meshoptimizer-ssse3":
                if meshoptimizer_object:
                    meshoptimizer_instructions[mnemonic] += 1
                else:
                    record_failure(failure_counts, failure_examples, "pshufb outside meshoptimizer vertexcodec", f"{obj}: {line}")
            elif category == "osxsave-xgetbv":
                if xgetbv_object:
                    xgetbv_instructions[mnemonic] += 1
                else:
                    record_failure(failure_counts, failure_examples, "xgetbv outside source-verified OSXSAVE detector", f"{obj}: {line}")
            elif category == "libstdcxx-cpuid-rng":
                record_failure(failure_counts, failure_examples, f"{mnemonic} inside a Godot SCons object (expected only in GCC libstdc++)", f"{obj}: {line}")
            elif category == "pentium-e5700-supported":
                supported_profile_instructions[mnemonic] += 1

    if aesni_object_count != 1:
        record_failure(failure_counts, failure_examples, "Mbed TLS aesni.c object count", f"Expected exactly one object, found {aesni_object_count}.")

    if failure_counts:
        print_failure_report("Unsupported or unverified object-file instructions", failure_counts, failure_examples)
        raise SystemExit(1)

    print(f"PASS: scanned {len(object_files)} object files.")
    for label, counts in (
        ("CPUID-dispatched Mbed TLS AES-NI/PCLMUL", aesni_instructions),
        ("HarfBuzz zero-guarded TZCNT/BSF aliases", bsf_alias_instructions),
        ("meshoptimizer CPUID-dispatched SSSE3", meshoptimizer_instructions),
        ("OSXSAVE-guarded XGETBV", xgetbv_instructions),
        ("Pentium E5700-supported LAHF/SAHF/CMPXCHG16B", supported_profile_instructions),
    ):
        if counts:
            summary = ", ".join(f"{m}={n}" for m, n in sorted(counts.items()))
            print(f"Verified {label}: {summary}")

    return aesni_instructions, bsf_alias_instructions, meshoptimizer_instructions, xgetbv_instructions


def scan_final_binary(objdump, binary, allowed_aesni, allowed_bsf_alias, allowed_meshoptimizer, allowed_xgetbv):
    aesni_counts = Counter()
    bsf_alias_counts = Counter()
    meshoptimizer_counts = Counter()
    xgetbv_counts = Counter()
    gcc_rng_counts = Counter()
    supported_profile_counts = Counter()
    failure_counts = Counter()
    failure_examples = defaultdict(list)

    for mnemonic, line in instructions(run_objdump(objdump, binary)):
        category = classify(mnemonic)
        if category == "forbidden":
            record_failure(failure_counts, failure_examples, mnemonic, line)
        elif category == "mbedtls-aesni":
            aesni_counts[mnemonic] += 1
        elif category == "harfbuzz-bsf-alias":
            bsf_alias_counts[mnemonic] += 1
        elif category == "meshoptimizer-ssse3":
            meshoptimizer_counts[mnemonic] += 1
        elif category == "osxsave-xgetbv":
            xgetbv_counts[mnemonic] += 1
        elif category == "libstdcxx-cpuid-rng":
            gcc_rng_counts[mnemonic] += 1
        elif category == "pentium-e5700-supported":
            supported_profile_counts[mnemonic] += 1

    comparisons = (
        ("AES-NI/PCLMUL", aesni_counts, allowed_aesni),
        ("HarfBuzz TZCNT/BSF alias", bsf_alias_counts, allowed_bsf_alias),
        ("meshoptimizer SSSE3", meshoptimizer_counts, allowed_meshoptimizer),
        ("OSXSAVE-guarded XGETBV", xgetbv_counts, allowed_xgetbv),
    )
    for label, found, allowed_counts in comparisons:
        for mnemonic, count in found.items():
            allowed = allowed_counts.get(mnemonic, 0)
            if count > allowed:
                record_failure(
                    failure_counts, failure_examples,
                    f"{label} count exceeds verified object files",
                    f"PE contains {count} {mnemonic}; source-verified objects contain {allowed}.",
                )

    if failure_counts:
        print_failure_report("Post-x86-64-v1 instructions outside verified Pentium E5700 exceptions", failure_counts, failure_examples)
        raise SystemExit(1)

    print(f"PASS: {binary} respects the x86-64-v1 required compiler baseline.")
    print("PASS: all optional ISA paths in the PE match source-verified runtime dispatch.")
    if gcc_rng_counts:
        print("Verified GCC libstdc++ hardware RNG dispatch in final PE: " +
              ", ".join(f"{k}={v}" for k, v in sorted(gcc_rng_counts.items())))
    if supported_profile_counts:
        print("Pentium E5700-supported instructions in final PE: " +
              ", ".join(f"{k}={v}" for k, v in sorted(supported_profile_counts.items())))


def main():
    args = parse_args()
    source_root = Path(args.source)
    gcc_random_source = Path(args.gcc_random_source)
    if not source_root.is_dir():
        raise SystemExit(f"Godot source directory not found: {source_root}")

    require_source_guards(source_root, gcc_random_source)
    if args.source_only:
        print("PASS: source-only preflight complete; no full engine build was required.")
        return

    if not args.binary:
        raise SystemExit("A binary path is required unless --source-only is used.")
    if not args.objects:
        raise SystemExit("--objects is required for a full ISA audit.")

    binary = Path(args.binary)
    objects_root = Path(args.objects)
    if not binary.is_file():
        raise SystemExit(f"File not found: {binary}")
    if not objects_root.is_dir():
        raise SystemExit(f"SCons object directory not found: {objects_root}")

    if binary.suffix.lower() == ".exe":
        startup_gate = b"A CPU with SSE4.2 instruction set support is required."
        if startup_gate in binary.read_bytes():
            raise SystemExit("SSE4.2 startup gate is still embedded in the executable.")

    objdump = shutil.which("x86_64-w64-mingw32-objdump") or shutil.which("objdump")
    if not objdump:
        raise SystemExit("Could not find objdump.")

    allowed = scan_objects(objdump, objects_root)
    scan_final_binary(objdump, binary, *allowed)


if __name__ == "__main__":
    main()
