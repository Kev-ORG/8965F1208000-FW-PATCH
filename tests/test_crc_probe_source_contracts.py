import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "payload" / "build"


def _crc_sources() -> tuple[str, str, str]:
  return tuple(
    (ROOT / "payload" / name).read_text()
    for name in ("crc_runtime.h", "crc_probe.c", "crc_verify.c")
  )


def test_crc_probe_uses_exact_dcra_contract_and_has_no_flash_write_path():
  probe = (ROOT / "payload" / "crc_probe.c").read_text()
  dcra = (ROOT / "payload" / "crc_runtime.h").read_text()
  common = (ROOT / "payload" / "patch_common.h").read_text()
  combined = probe + dcra + common

  for value in (
    "0xFFD51000u", "0xFFD51004u", "0xFFD51020u",
    "0x00018000u", "0x000FFDF0u", "0x000FFDECu",
  ):
    assert value in combined
  for forbidden in (
    "0xFFA20000", "FACI_CMD8", "0xE8u", "0xD0u", "FLWE_REG", "FLWL_REG",
  ):
    assert forbidden not in combined
  assert "crc32_update" in dcra
  assert "prefix_crc ^ 0xFFFFFFFFu" in dcra


def test_dcra_runs_boot_equivalent_words_and_restores_entry_registers():
  dcra = (ROOT / "payload" / "crc_runtime.h").read_text()

  assert "entry_ctl = DCRA_CTL" in dcra
  assert "entry_cout = DCRA_COUT" in dcra
  assert "DCRA_CTL = 0u" in dcra
  assert "DCRA_COUT = 0xFFFFFFFFu" in dcra
  assert "address += 4u" in dcra
  assert "DCRA_IN = word" in dcra
  assert "DCRA_CTL = entry_ctl" in dcra
  assert "(entry_ctl & 3u) != 0u" in dcra
  assert "DCRA_COUT = entry_cout ^ 0xFFFFFFFFu" in dcra


def test_probe_and_verify_bind_the_fixed_crc_record_meanings():
  dcra, probe, verify = _crc_sources()

  assert "ORIGINAL_INSTRUCTION_WORD" in probe
  assert "CRC_PATCH_VALUE" in dcra
  assert "crc_prefix_sw(1u" in probe
  assert "crc_full_sw(0u" in probe
  assert "crc_full_sw(1u" in probe
  assert "dcra_full_raw(0u" in probe
  assert "dcra_full_raw(1u" in probe
  assert "SRAM_BUFFER" in probe

  assert "PATCHED_INSTRUCTION_WORD" in verify
  assert "crc_prefix_sw(0u" in verify
  assert "live_adjust == new_adjust" in verify
  assert "live_sw == 0xFFFFFFFFu" in verify
  assert "live_dcra == 0xFFFFFFFFu" in verify
  assert "values[PROTO_CRC_ORIGINAL_SW_FULL] = live_sw" in verify
  assert "values[PROTO_CRC_PATCHED_SW_FULL] = live_sw" in verify
  assert "values[PROTO_CRC_ORIGINAL_DCRA_RAW] = live_dcra" in verify
  assert "values[PROTO_CRC_PATCHED_DCRA_RAW] = live_dcra" in verify

  assert "send_crc_stream" in dcra
  assert "PROTO_REGION_BEGIN" in dcra
  assert "PROTO_REGION_LENGTH" in dcra
  assert "PROTO_REGION_END" in dcra
  assert "PROTO_CRC_RECORD_COUNT" in dcra


def test_crc_payload_sources_are_read_only_and_have_no_steering_can_path():
  common = (ROOT / "payload" / "patch_common.h").read_text()
  dcra = (ROOT / "payload" / "crc_runtime.h").read_text()
  translation_units = tuple(
    (ROOT / "payload" / f"{name}.c").read_text() + common + dcra
    for name in ("crc_probe", "crc_verify")
  )

  for source in translation_units:
    assert "static int can_send" in source
    assert "static uint32_t dcra_full_raw" in source
    assert "0x7A9u" in source
    for forbidden in (
      "0xFFA20000", "0xFFA10030", "0xFFA10034", "0xFFA100E0",
      "0xFFF82410", "0xFFF8A430", "0x7A1u", "FACI_", "FLWE", "FLWL",
      "erase_target", "program_page",
    ):
      assert forbidden not in source


def test_sram_echo_crc_helper_is_compiled_only_for_staged_crc_prechecks():
  dcra, probe, verify = _crc_sources()

  assert "#define CRC_PROBE_PAYLOAD 1" in probe
  assert "CRC_PROBE_PAYLOAD" not in verify
  assert (
    "#if defined(CRC_PROBE_PAYLOAD) || defined(CRC_INTERMEDIATE_PAYLOAD)\n"
    "static uint32_t crc_region" in dcra
  )


def test_dcra_restore_order_and_reporting_paths_are_fail_closed():
  dcra, probe, verify = _crc_sources()
  restore_start = dcra.index("static uint32_t restore_dcra")
  restore_end = dcra.index("\n}\n", restore_start)
  restore = dcra[restore_start:restore_end]

  assert re.search(
    r"if\s*\(\(entry_ctl\s*&\s*3u\)\s*!=\s*0u\)\s*return\s+1u;\s*"
    r"DCRA_CTL\s*=\s*entry_ctl;\s*syncp\(\);\s*"
    r"DCRA_COUT\s*=\s*entry_cout\s*\^\s*0xFFFFFFFFu;\s*syncp\(\);\s*"
    r"return\s+0u;",
    restore,
  )

  for source in (probe, verify):
    capture = source.index("capture_dcra")
    tail = source[capture:]
    assert "if ((entry_ctl & 3u) != 0u)" in tail
    restore_call = tail.index("if (restore_dcra(entry_ctl, entry_cout) != 0u)")
    exit_ctl = tail.index("values[PROTO_CRC_EXIT_CTL] = DCRA_CTL")
    exit_cout = tail.index("values[PROTO_CRC_EXIT_COUT] = DCRA_COUT")
    assert restore_call < exit_ctl < exit_cout
    assert exit_cout < tail.index("(void)send_crc_stream")
    assert "can_send(" not in source
