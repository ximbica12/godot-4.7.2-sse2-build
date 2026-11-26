#!/usr/bin/env python3
"""Fast regression tests for the Pentium E5700 ISA auditor."""

import unittest
from pathlib import Path

from audit_x86_64_v1 import (
    classify,
    has_embree_osxsave_guard,
    has_gcc_random_device_cpuid_guards,
    has_harfbuzz_ctz_zero_guard,
    has_meshoptimizer_ssse3_cpuid_dispatch,
    has_pcre2_osxsave_guard,
    has_webp_osxsave_guard,
    instructions,
    is_guarded_xgetbv_object,
    is_harfbuzz_ctz_object,
    is_mbedtls_aesni_object,
    is_meshoptimizer_vertexcodec_object,
)


class InstructionClassificationTests(unittest.TestCase):
    def test_pextrw_is_valid_sse2(self):
        self.assertIsNone(classify("pextrw"))

    def test_pextrb_d_q_are_not_baseline(self):
        for mnemonic in ("pextrb", "pextrd", "pextrq"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(classify(mnemonic), "forbidden")

    def test_pext_bmi2_is_not_confused_with_pextrw(self):
        self.assertEqual(classify("pext"), "forbidden")
        self.assertIsNone(classify("pextrw"))

    def test_tzcnt_is_a_contextual_harfbuzz_bsf_alias(self):
        self.assertEqual(classify("tzcnt"), "harfbuzz-bsf-alias")

    def test_pshufb_is_a_contextual_meshoptimizer_ssse3_path(self):
        self.assertEqual(classify("pshufb"), "meshoptimizer-ssse3")

    def test_xgetbv_is_a_contextual_osxsave_path(self):
        self.assertEqual(classify("xgetbv"), "osxsave-xgetbv")

    def test_rdrand_and_rdseed_are_contextual_libstdcxx_paths(self):
        self.assertEqual(classify("rdrand"), "libstdcxx-cpuid-rng")
        self.assertEqual(classify("rdseed"), "libstdcxx-cpuid-rng")

    def test_e5700_supported_instructions_are_not_rejected(self):
        for mnemonic in ("lahf", "sahf", "cmpxchg16b"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(classify(mnemonic), "pentium-e5700-supported")

    def test_lzcnt_remains_forbidden(self):
        self.assertEqual(classify("lzcnt"), "forbidden")

    def test_bmi_and_adx_are_forbidden(self):
        for mnemonic in ("bextr", "blsi", "bzhi", "pdep", "mulx", "adcx", "adox"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(classify(mnemonic), "forbidden")

    def test_sse3_ssse3_and_sse41_are_forbidden_except_dispatch_path(self):
        for mnemonic in ("haddps", "phaddd", "pmulld", "ptest", "roundps"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(classify(mnemonic), "forbidden")
        self.assertEqual(classify("pshufb"), "meshoptimizer-ssse3")

    def test_avx_family_is_forbidden(self):
        for mnemonic in ("vzeroupper", "vaddps", "vaesenc", "vpclmulqdq"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(classify(mnemonic), "forbidden")

    def test_aesni_and_pclmul_are_narrow_exceptions(self):
        self.assertEqual(classify("aesenc"), "mbedtls-aesni")
        self.assertEqual(classify("pclmulqdq"), "mbedtls-aesni")

    def test_sse2_instructions_remain_allowed(self):
        for mnemonic in ("movdqa", "pshufd", "pextrw", "pmuludq", "lfence"):
            with self.subTest(mnemonic=mnemonic):
                self.assertIsNone(classify(mnemonic))

    def test_legacy_verr_verw_are_not_misclassified_as_avx(self):
        self.assertIsNone(classify("verr"))
        self.assertIsNone(classify("verw"))

    def test_harfbuzz_tzcnt_exception_covers_all_harfbuzz_objects(self):
        self.assertTrue(is_harfbuzz_ctz_object(Path("godot/bin/obj/thirdparty/harfbuzz/src/hb-ot-shaper-arabic.windows.template_release.x86_64.o")))
        self.assertTrue(is_harfbuzz_ctz_object(Path("godot/bin/obj/thirdparty/harfbuzz/src/hb-set.windows.template_release.x86_64.o")))
        self.assertFalse(is_harfbuzz_ctz_object(Path("godot/bin/obj/core/os/os.windows.template_release.x86_64.o")))

    def test_meshoptimizer_exception_is_path_limited(self):
        self.assertTrue(is_meshoptimizer_vertexcodec_object(Path("godot/bin/obj/thirdparty/meshoptimizer/vertexcodec.windows.template_release.x86_64.o")))
        self.assertFalse(is_meshoptimizer_vertexcodec_object(Path("godot/bin/obj/thirdparty/meshoptimizer/allocator.windows.template_release.x86_64.o")))

    def test_xgetbv_exception_is_limited_to_verified_detectors(self):
        for path in (
            "godot/bin/obj/thirdparty/embree/common/sys/sysinfo.windows.template_release.x86_64.o",
            "godot/bin/obj/thirdparty/libwebp/src/dsp/cpu.windows.template_release.x86_64.o",
            "godot/bin/obj/thirdparty/libwebp/sharpyuv/sharpyuv_cpu.windows.template_release.x86_64.o",
            "godot/bin/obj/thirdparty/pcre2/src/pcre2_jit_compile_16.windows.template_release.x86_64.o",
        ):
            with self.subTest(path=path):
                self.assertTrue(is_guarded_xgetbv_object(Path(path)))
        self.assertFalse(is_guarded_xgetbv_object(Path("godot/bin/obj/core/os/os.windows.template_release.x86_64.o")))

    def test_mbedtls_aesni_exception_is_path_limited(self):
        self.assertTrue(is_mbedtls_aesni_object(Path("godot/bin/obj/thirdparty/mbedtls/library/aesni.windows.template_release.x86_64.o")))
        self.assertFalse(is_mbedtls_aesni_object(Path("godot/bin/obj/core/os/os.windows.template_release.x86_64.o")))

    def test_harfbuzz_zero_guard_is_required_before_builtin(self):
        source = """
static inline unsigned int
hb_ctz (T v)
{
  if (unlikely (!v)) return 8 * sizeof (T);
  return __builtin_ctzll (v);
}
"""
        self.assertTrue(has_harfbuzz_ctz_zero_guard(source))

    def test_harfbuzz_guard_missing_is_rejected(self):
        source = """
static inline unsigned int
hb_ctz (T v)
{
  return __builtin_ctzll (v);
}
"""
        self.assertFalse(has_harfbuzz_ctz_zero_guard(source))

    def test_meshoptimizer_dispatch_requires_target_attribute_and_cpuid(self):
        source = """
#define SIMD_FALLBACK
#define SIMD_TARGET __attribute__((target("ssse3")))
#include <tmmintrin.h>
static unsigned int getCpuFeatures()
{
  __cpuid(1, cpuinfo[0], cpuinfo[1], cpuinfo[2], cpuinfo[3]);
}
decode = (cpuid & (1 << 9)) ? decodeVertexBlockSimd : decodeVertexBlock;
"""
        self.assertTrue(has_meshoptimizer_ssse3_cpuid_dispatch(source))

    def test_meshoptimizer_dispatch_missing_cpuid_fallback_is_rejected(self):
        source = """
#define SIMD_TARGET __attribute__((target("ssse3")))
#include <tmmintrin.h>
decode = decodeVertexBlockSimd;
"""
        self.assertFalse(has_meshoptimizer_ssse3_cpuid_dispatch(source))

    def test_embree_xgetbv_requires_osxsave(self):
        source = """
static const int CPU_FEATURE_BIT_OXSAVE = 1 << 27;
if (cpuid_leaf_1[ECX] & CPU_FEATURE_BIT_OXSAVE) {
  int64_t xcr0 = get_xcr0();
}
"""
        self.assertTrue(has_embree_osxsave_guard(source))
        self.assertFalse(has_embree_osxsave_guard("int64_t xcr0 = get_xcr0();"))

    def test_webp_xgetbv_requires_osxsave_and_avx(self):
        source = """
if ((cpu_info[2] & 0x18000000) == 0x18000000) {
  return (xgetbv() & 0x6) == 0x6;
}
"""
        self.assertTrue(has_webp_osxsave_guard(source))
        self.assertFalse(has_webp_osxsave_guard("return (xgetbv() & 0x6) == 0x6;"))

    def test_pcre2_xgetbv_requires_osxsave(self):
        source = """
#define CPU_FEATURE_OSXSAVE 0x100
if ((feature_list & CPU_FEATURE_OSXSAVE) && (execute_get_xcr0_low() & 0x4) == 0)
"""
        self.assertTrue(has_pcre2_osxsave_guard(source))
        self.assertFalse(has_pcre2_osxsave_guard("execute_get_xcr0_low();"))

    def test_gcc_random_device_checks_rdrand_and_rdseed_cpuid(self):
        source = """
__attribute__ ((target("rdrnd")))
__attribute__ ((target("rdseed")))
if (which & rdseed) {
  __cpuid_count(7, 0, eax, ebx, ecx, edx);
  if (ebx & bit_RDSEED) _M_func = &__x86_rdseed;
}
if (which & rdrand) {
  __cpuid(1, eax, ebx, ecx, edx);
  if (ecx & bit_RDRND) _M_func = &__x86_rdrand;
}
#endif // USE_RDSEED
#endif // USE_RDRAND
"""
        self.assertTrue(has_gcc_random_device_cpuid_guards(source))
        self.assertFalse(has_gcc_random_device_cpuid_guards("return __x86_rdrand();"))

    def test_instruction_parser_extracts_mnemonics(self):
        disassembly = """
 e99:    pextrw $0x1,%xmm1,%eax
 ea5:    tzcnt %rax,%rax
 eb0:    movdqa %xmm0,%xmm1
"""
        parsed = list(instructions(disassembly))
        self.assertEqual([item[0] for item in parsed], ["pextrw", "tzcnt", "movdqa"])


if __name__ == "__main__":
    unittest.main()
