import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "payload" / "build"


def test_restore_sector_source_has_one_selected_fsaddr_and_no_feaddr():
  source = (ROOT / "payload" / "restore_sector.c").read_text()
  header = (ROOT / "payload" / "faci_dual.h").read_text()
  combined = source + header
  assert "intent_word(8u)" in source
  assert "0xFFA10034" not in combined
  assert "FEADDR" not in combined
  assert source.count("erase_sector(") == 1
  assert source.count("program_sector(") == 1
  assert "FACI_FSADDR = sector_base" in header
  assert "FACI_FSADDR = address" in header


def test_restore_source_derives_local_candidate_and_checks_idle_before_pe_entry():
  source = (ROOT / "payload" / "restore_sector.c").read_text()
  assert source.index("validate_restore_intent") < source.index("enter_pe(")
  assert source.index("copy_sector_to_sram(base,guard)") < source.index("enter_pe(")
  assert source.index("restore_crc32(SRAM_BUFFER,guard)") < source.index("enter_pe(")
  assert source.index("exact_idle") < source.index("enter_pe(")
  assert "TARGET_SECTOR_BASE" in source and "CRC_SECTOR_BASE" in source
  assert "SOURCE_ADJUST_OFFSET" in source and "CRC_MAGIC_OFFSET" in source
  assert "send_restore_result" in source and "stream_sector" in source
  assert "sha_sector" not in source


def test_c_and_host_restore_intent_layout_is_exactly_128_bytes():
  import struct

  source = (ROOT / "payload" / "restore_sector.c").read_text()
  assert struct.calcsize("<IHHIII4s4sII88sI") == 128
  assert "sizeof(struct restore_intent)==INTENT_LENGTH" in source
  assert "uint32_t source_crc32;" in source
  assert "uint32_t candidate_crc32;" in source
  assert "uint8_t reserved[88];" in source


def test_restore_uses_retained_patch_runtime_and_bounded_nonretrying_faci_sequence():
  source = (ROOT / "payload" / "restore_sector.c").read_text()
  common = (ROOT / "payload" / "patch_common.h").read_text()
  header = (ROOT / "payload" / "faci_dual.h").read_text()
  assert '#include "patch_common.h"' in source
  for token in (
    "FACI_FENTRYR = 0xAA01u", "FHVE15 = 1u", "FHVE3 = 1u",
    "FACI_FAREASELC = 0x3B00u", "FACI_FPROTR = 0x5501u", "FACI_FPSADDR = 1u",
    "FACI_CMD8 = 0x20u", "FACI_CMD8 = 0xD0u", "FACI_CMD8 = 0xE8u",
    "FACI_CMD8 = 0x80u", "FHVE15 = 0u", "FHVE3 = 0u",
    "FACI_FPROTR = 0x5500u", "FACI_FENTRYR = 0xAA00u",
    "FRDY_LIMIT", "DBFULL_LIMIT", "feed_watchdog",
  ):
    assert token in header
  assert "PAGE_COUNT 128u" in header
  assert "PAGE_HALFWORDS 128u" in header
  assert not re.search(r"while\s*\([^)]*--", header)
  assert "retry" not in (source + common + header).lower()


def test_restore_template_remains_within_fixed_intent_envelope_boundary():
  binary = (BUILD / "restore_sector.bin").read_bytes()
  assert 0 < len(binary) <= 0xFD0
  assert len(binary) >= 0x680
