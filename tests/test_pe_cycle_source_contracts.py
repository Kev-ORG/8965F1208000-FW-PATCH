import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "payload" / "probe_pe_cycle.c"
DCRA_PATH = ROOT / "payload" / "dcra.h"


def source_text() -> str:
  return SOURCE_PATH.read_text(encoding="utf-8")


def test_comprehensive_probe_has_only_reviewed_faci_register_stores():
  source = source_text()
  stores = re.findall(
    r"\b(FACI_FPCKAR|FACI_FENTRYR|FACI_FREQR|FLWL_REG|FLWE_REG)\s*=\s*"
    r"(0x[0-9A-Fa-f]+u|[01]u)",
    source,
  )
  assert stores == [
    ("FACI_FPCKAR", "0xAA01u"),
    ("FLWL_REG", "1u"),
    ("FLWE_REG", "1u"),
    ("FACI_FREQR", "0x3B00u"),
    ("FACI_FENTRYR", "0x5501u"),
    ("FLWL_REG", "0u"),
    ("FLWE_REG", "0u"),
    ("FACI_FENTRYR", "0x5500u"),
    ("FACI_FPCKAR", "0xAA00u"),
  ]
  for forbidden in (
    "0xFFA20000", "0xFFA10030", "0xFFA10034", "0xFFA100E0",
    "FACI_CMD", "FSADDR", "FEADDR", "erase", "program_page",
    "clear_status", "forced_stop", "retry",
  ):
    assert forbidden not in source


def test_comprehensive_probe_checks_context_and_idle_before_any_faci_store():
  source = source_text()
  assert "original_instruction[4] = {0x20, 0xE6, 0x31, 0x00}" in source
  assert "if (primary_code == 0u && !equal_bytes(" in source
  assert "snapshot_is_idle(&snapshots[0])" in source
  first_store = source.index("FACI_FPCKAR = 0xAA01u")
  assert source.index("original_instruction") < first_store
  assert source.index("snapshot_is_idle(&snapshots[0])") < first_store


def test_comprehensive_probe_keeps_magic_and_instruction_pre_gates_before_faci_activity():
  source = source_text()
  assert "magic0 != MAGIC_WORD || magic1 != MAGIC_WORD" in source
  instruction_gate = source.index("!equal_bytes(")
  assert "(volatile uint8_t *)(PATCH_ADDRESS - 2u), original_instruction, 4u" in re.sub(
    r"\s+", " ", source,
  )
  first_store = source.index("FACI_FPCKAR = 0xAA01u")
  assert source.index("magic0 != MAGIC_WORD || magic1 != MAGIC_WORD") < first_store
  assert instruction_gate < first_store


def test_comprehensive_probe_moves_semantic_hash_and_software_crc_to_host():
  source = source_text()
  dcra = DCRA_PATH.read_text(encoding="utf-8")
  for moved in (
    "original_sha256", "sha256_k", "sha256_compress", "sha256_sector",
    "crc_full_observation", "crc_region", "SRAM_ECHO", "PATCHED_PREFIX_SW",
    "ORIGINAL_SW_FULL", "PATCHED_SW_FULL",
  ):
    assert moved not in source
    assert moved not in dcra
  assert "crc32_update" not in dcra
  assert "crc32_update" not in source


def test_comprehensive_probe_streams_two_full_regions_crc_dcra_magic_and_40_diagnostics():
  source = source_text()
  assert "uint32_t values[PROTO_DCRA_RECORD_COUNT];" in source
  assert "uint32_t values[PROTO_DCRA_RECORD_COUNT] =" not in source
  assert "PROTO_OP_FACI_PE_CYCLE" in source
  assert "stream_probe_region(PROTO_OP_FACI_PE_CYCLE, 0u, TARGET_BASE" in source
  assert "stream_probe_region(PROTO_OP_FACI_PE_CYCLE, 1u, CRC_SECTOR_BASE" in source
  assert "PROTO_DCRA_RECORD_COUNT" in source
  assert "capture_dcra" in source and "restore_dcra" in source
  assert "dcra_full_raw(0u, &guard)" in source
  assert "dcra_full_raw(1u, &guard)" in source
  dcra = DCRA_PATH.read_text(encoding="utf-8")
  assert "CRC_PATCHED_ADJUST_WORD 0x414F47CCu" in dcra
  restore = dcra[dcra.index("static uint32_t restore_dcra"):]
  assert "(ctl & 3u) != 0u" in restore
  assert "DCRA_COUT = cout ^ 0xFFFFFFFFu" in restore
  assert "return 1u;" in restore and "return 0u;" in restore
  assert "if (restore_dcra(values[PROTO_DCRA_ENTRY_CTL], values[PROTO_DCRA_ENTRY_COUT]) != 0u)" in source
  assert "values[PROTO_DCRA_ORIGINAL_RAW] = 0u;" in source
  assert "values[PROTO_DCRA_PATCHED_RAW] = 0u;" in source
  assert "slot < 40u" in source
  assert "send_diagnostic(slot, widths[slot & 7u], snapshots[slot]" in source
  assert source.count("send_status_code(1u, outcome") == 1
  assert "((uint32_t)cleanup_code << 16) | primary_code" in source


def test_comprehensive_probe_uses_bounded_polls_and_stage_aware_exact_cleanup():
  source = source_text()
  for offset in (0, 8, 16, 24, 32):
    assert f"capture_snapshot(&snapshots[{offset}])" in source
  assert "#define FACI_PE_POLL_LIMIT 100000u" in source
  assert "wait_register_masked" in source
  assert source.count("uint32_t spins = FACI_PE_POLL_LIMIT") == 1
  assert source.count("while (spins != 0u)") == 1
  assert not re.search(r"while\s*\([^)]*spins--", source)
  for call in (
    "wait_register_masked(0xFFA10084u, 2u, 0xFFFFu, 0x0001u",
    "wait_register_masked(0xFFF8A430u, 4u, 0xFFFFFFFFu, 1u",
    "wait_register_masked(0xFFF82410u, 4u, 0xFFFFFFFFu, 1u",
    "wait_register_masked(0xFFA10088u, 2u, 1u, 1u",
    "wait_register_masked(0xFFF8A430u, 4u, 0xFFFFFFFFu, 0u",
    "wait_register_masked(0xFFF82410u, 4u, 0xFFFFFFFFu, 0u",
    "wait_register_masked(0xFFA10088u, 2u, 1u, 0u",
    "wait_register_masked(0xFFA10084u, 2u, 0x0081u, 0u",
  ):
    assert call in source
  for flag in ("unlock_attempted", "flwl_attempted", "flwe_attempted", "fentry_attempted"):
    assert flag in source
  cleanup_stores = [
    source.rindex("FLWL_REG = 0u"),
    source.rindex("FLWE_REG = 0u"),
    source.rindex("FACI_FENTRYR = 0x5500u"),
    source.rindex("FACI_FPCKAR = 0xAA00u"),
  ]
  assert cleanup_stores == sorted(cleanup_stores)
  for bit in ("0x0001u", "0x0002u", "0x0004u", "0x0008u", "0x0010u"):
    assert f"cleanup_code |= {bit}" in source


def test_build_exposes_no_separate_normal_or_unlock_probe_payload():
  payload = ROOT / "payload"
  assert not (payload / "probe.c").exists()
  assert not (payload / "probe_unlock.c").exists()
  build_script = (payload / "build.sh").read_text(encoding="utf-8")
  assert "for name in probe_pe_cycle" in build_script
  assert "probe_unlock" not in build_script
