import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ROOT / "payload"


def test_live_read_streams_only_the_two_fixed_complete_flash_regions():
  source = (PAYLOAD / "live_read.c").read_text(encoding="utf-8")

  assert '#include "patch_common.h"' in source
  assert "PROTO_OP_LIVE_READ" in source
  target_call = "stream_live_region(0u, TARGET_BASE"
  crc_call = "stream_live_region(1u, CRC_SECTOR_BASE"
  assert source.count(target_call) == 1
  assert source.count(crc_call) == 1
  assert source.index(target_call) < source.index(crc_call)
  assert "TARGET_LENGTH" in source
  assert "PROTO_REGION_BEGIN" in source
  assert "PROTO_REGION_LENGTH" in source
  assert "PROTO_REGION_END" in source
  assert "send_magic(0u, MMIO32(MAGIC0_ADDRESS)" in source
  assert "send_magic(1u, MMIO32(MAGIC1_ADDRESS)" in source
  assert "send_status(1u, guard)" in source
  assert "PROTO_END" in source


def test_live_read_has_no_flash_write_faci_or_dcra_capability():
  source = (PAYLOAD / "live_read.c").read_text(encoding="utf-8")

  for forbidden in (
    "faci_dual.h", "dcra.h", "crc_runtime.h", "FACI_", "DCRA_", "FHVE3",
    "FHVE15", "erase", "program", "enter_pe", "failure_cleanup", "retry",
  ):
    assert forbidden not in source
  assert re.search(r"MMIO(?:8|16|32)\([^)]*\)\s*=", source) is None
  assert "MMIO32(base + offset)" in source
  assert "MMIO32(MAGIC0_ADDRESS)" in source
  assert "MMIO32(MAGIC1_ADDRESS)" in source


def test_live_read_declares_no_intent_or_staged_ram_dependency():
  source = (PAYLOAD / "live_read.c").read_text(encoding="utf-8")

  for forbidden in (
    "SRAM_BUFFER", "INTENT", "intent", "RESTORE_SECTOR_PAYLOAD",
    "CANDIDATE_WRITER_PAYLOAD",
  ):
    assert forbidden not in source


def test_live_read_translation_unit_is_warning_clean_before_cross_build():
  result = subprocess.run(
    (
      "cc", "-D__attribute__(x)=", "-std=c11", "-ffreestanding", "-Wall",
      "-Wextra", "-Werror", "-Wno-int-to-pointer-cast", "-fsyntax-only",
      str(PAYLOAD / "live_read.c"),
    ),
    check=False,
    capture_output=True,
    text=True,
  )

  assert result.returncode == 0, result.stderr
