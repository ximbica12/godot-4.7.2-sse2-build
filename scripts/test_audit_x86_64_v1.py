#!/usr/bin/env python3
"""Fast regression tests for the x86-64-v1 instruction auditor."""

import unittest
from pathlib import Path

from audit_x86_64_v1 import (
    classify,
    has_harfbuzz_ctz_zero_guard,
    instructions,
    is_harfbuzz_ctz_object,
    is_mbedtls_aesni_object,
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

    def test_tzcnt_is_marked_as_a_contextual_bsf_alias(self):
        self.assertEqual(classify("tzcnt"), "bsf-compatible-alias")

    def test_lzcnt_remains_forbidden(self):
        self.assertEqual(classify("lzcnt"), "forbidden")

    def test_bmi_and_adx_are_forbidden(self):
        for mnemonic in ("bextr", "blsi", "bzhi", "pdep", "mulx", "adcx", "adox"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(classify(mnemonic), "forbidden")

    def test_sse3_ssse3_and_sse41_are_forbidden(self):
        for mnemonic in ("haddps", "pshufb", "pmulld", "ptest", "roundps"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(classify(mnemonic), "forbidden")

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

    def test_harfbuzz_tzcnt_exception_is_path_limited(self):
        self.assertTrue(
            is_harfbuzz_ctz_object(
                Path("godot/bin/obj/thirdparty/harfbuzz/src/hb-ot-layout.windows.template_release.x86_64.o")
            )
        )
        self.assertFalse(
            is_harfbuzz_ctz_object(
                Path("godot/bin/obj/core/os/os.windows.template_release.x86_64.o")
            )
        )

    def test_mbedtls_aesni_exception_is_path_limited(self):
        self.assertTrue(
            is_mbedtls_aesni_object(
                Path("godot/bin/obj/thirdparty/mbedtls/library/aesni.windows.template_release.x86_64.o")
            )
        )
        self.assertFalse(
            is_mbedtls_aesni_object(
                Path("godot/bin/obj/core/os/os.windows.template_release.x86_64.o")
            )
        )

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
