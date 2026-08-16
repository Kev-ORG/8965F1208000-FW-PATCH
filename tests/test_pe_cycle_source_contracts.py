import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "payload" / "probe_pe_cycle.c"


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


def test_comprehensive_probe_streams_two_full_regions_crc_dcra_magic_and_40_diagnostics():
  source = source_text()
  assert "PROTO_OP_FACI_PE_CYCLE" in source
  assert "stream_probe_region(PROTO_OP_FACI_PE_CYCLE, 0u, TARGET_BASE" in source
  assert "stream_probe_region(PROTO_OP_FACI_PE_CYCLE, 1u, CRC_SECTOR_BASE" in source
  assert "PROTO_CRC_RECORD_COUNT" in source
  assert "capture_dcra" in source and "restore_dcra" in source
  assert "slot < 40u" in source
  assert "send_diagnostic(slot, widths[slot & 7u], snapshots[slot]" in source
  assert source.count("send_status_code(1u, outcome") == 1
  assert "((uint32_t)cleanup_code << 16) | primary_code" in source


def test_comprehensive_probe_uses_bounded_polls_and_stage_aware_exact_cleanup():
  source = source_text()
  for offset in (0, 8, 16, 24, 32):
    assert f"capture_snapshot(&snapshots[{offset}])" in source
  assert "#define FACI_PE_POLL_LIMIT 100000u" in source
  assert source.count("uint32_t spins = FACI_PE_POLL_LIMIT") >= 5
  assert source.count("while (spins != 0u)") >= 5
  assert not re.search(r"while\s*\([^)]*spins--", source)
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
