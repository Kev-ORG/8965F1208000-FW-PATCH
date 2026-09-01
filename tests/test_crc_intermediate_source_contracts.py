from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "payload" / "build"


def test_intermediate_is_read_only_and_requires_exact_intermediate_context():
  source = (ROOT / "payload" / "crc_intermediate.c").read_text()
  combined = source + (ROOT / "payload" / "crc_runtime.h").read_text()
  assert "PATCHED_INSTRUCTION_WORD" in source
  assert "ORIGINAL_ADJUST" in source
  assert "MAGIC_WORD" in source
  assert "PROTO_OP_CRC_INTERMEDIATE" in source
  for forbidden in (
    "0xFFA20000", "0xFFA10030", "0xFFA10034", "FSADDR", "FEADDR",
    "FHVE3", "FHVE15", "erase_sector", "program_sector", "0x191", "STEERING_LTA",
  ):
    assert forbidden not in combined


def test_intermediate_computes_live_and_hypothetical_dcra_and_restores_entry_state():
  source = (ROOT / "payload" / "crc_intermediate.c").read_text()
  assert source.index("capture_dcra") < source.index("dcra_full_raw")
  assert source.count("dcra_full_raw") == 2
  assert source.index("restore_dcra") < source.index("send_crc_stream")
  assert "crc_prefix_sw(0u" in source
  assert "crc_full_sw(0u" in source
  assert "crc_full_sw(1u" in source
  assert "SRAM_BUFFER" not in source
  assert "if ((entry_ctl & 3u) != 0u)" in source
  assert "if (restore_dcra(entry_ctl, entry_cout) != 0u)" in source
  assert "CRC_CANDIDATE_ADJUST 0xDD5F1477u" in source


def test_intermediate_requires_current_software_hardware_agreement_and_nonpass_state():
  source = (ROOT / "payload" / "crc_intermediate.c").read_text()
  gate = source[source.index("if (new_adjust") : source.index("values[PROTO_CRC_ENTRY_CTL]")]
  assert "live_sw != live_dcra" in gate
  assert "live_sw == 0xFFFFFFFFu" in gate
  assert "final_sw != 0xFFFFFFFFu" in gate
  assert "final_dcra != 0xFFFFFFFFu" in gate


def test_intermediate_runtime_binary_fits_the_reviewed_envelope():
  binary = (BUILD / "crc_intermediate.bin").read_bytes()
  assert 0 < len(binary) <= 0xFD0
