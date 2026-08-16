from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "payload" / "build"


def test_ram_echo_reads_only_the_exact_reviewed_sram_sector():
  source = (ROOT / "payload" / "ram_echo.c").read_text()

  assert '#include "patch_common.h"' in source
  assert "SRAM_BUFFER" in source
  assert "TARGET_LENGTH" in source
  assert "PROTO_OP_RAM_ECHO" in source
  assert "stream_sector(SRAM_BUFFER" in source
  assert "MMIO8(" not in source
  assert "MMIO16(" not in source
  assert "MMIO32(" not in source


def test_ram_echo_source_has_no_flash_or_dcra_capability():
  source = (ROOT / "payload" / "ram_echo.c").read_text()
  for forbidden in (
    "FACI_", "FLWE", "FLWL", "DCRA_", "erase_sector",
    "program_sector", "restore", "retry",
  ):
    assert forbidden not in source


def test_ram_echo_binary_remains_inside_the_bootloader_shellcode_boundary():
  binary = (BUILD / "ram_echo.bin").read_bytes()
  assert 0 < len(binary) <= 0xFD0
