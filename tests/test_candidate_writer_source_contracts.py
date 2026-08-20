import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "payload" / "build"


def _sources():
  return {
    name: (ROOT / "payload" / f"write_{name}_candidate.c").read_text()
    for name in ("target", "crc")
  }


def test_each_writer_binds_one_literal_base_and_operation_without_runtime_selector():
  sources = _sources()
  assert "#define WRITER_SECTOR_BASE 0x00088000u" in sources["target"]
  assert "#define WRITER_OPERATION PROTO_OP_WRITE_TARGET_CANDIDATE" in sources["target"]
  assert "#define WRITER_SECTOR_BASE 0x000F8000u" in sources["crc"]
  assert "#define WRITER_OPERATION PROTO_OP_WRITE_CRC_CANDIDATE" in sources["crc"]
  for source in sources.values():
    assert "intent->sector_base" not in source
    assert "WRITER_SECTOR_BASE" in source
    assert source.count("write_candidate_exploit();") == 1


def test_writer_intent_is_exact_128_bytes_with_crc_and_zero_reserved_contract():
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  assert "CANDIDATE_INTENT_LENGTH 0x80u" in header
  assert "CANDIDATE_INTENT_CRC_OFFSET 124u" in header
  assert "uint8_t reserved[60];" in header
  assert "sizeof(struct candidate_writer_intent)==CANDIDATE_INTENT_LENGTH" in header
  assert "validate_candidate_intent" in header
  assert "candidate_intent_word(64u+index*4u)!=0u" in header


def test_writer_prechecks_dominate_first_faci_control_write_and_cover_both_live_sectors():
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  exploit = header[header.index("static void write_candidate_exploit") :]
  assert exploit.index("validate_candidate_intent") < exploit.index("candidate_exact_idle_snapshot")
  assert exploit.index("candidate_exact_idle_snapshot") < exploit.index("enter_pe")
  validation = header[header.index("static int validate_candidate_intent") : header.index("static void send_candidate_result")]
  for token in (
    "crc_region32((const volatile uint8_t *)TARGET_BASE",
    "crc_region32((const volatile uint8_t *)CRC_SECTOR_BASE",
    "copy_sector_to_sram(WRITER_SECTOR_BASE",
    "ORIGINAL_INSTRUCTION_WORD", "PATCHED_INSTRUCTION_WORD",
    "CRC_ADJUST", "MAGIC0_ADDRESS", "MAGIC1_ADDRESS",
  ):
    assert token in validation
  assert validation.index("copy_sector_to_sram(WRITER_SECTOR_BASE") < validation.index(
    "crc_region32(SRAM_BUFFER"
  )
  assert "exact_idle" in exploit


def test_writer_has_one_erase_one_program_no_retry_no_feaddr_and_complete_readback():
  combined = "\n".join(_sources().values())
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  faci = (ROOT / "payload" / "faci_dual.h").read_text()
  for source in _sources().values():
    assert source.count("#include \"candidate_writer.h\"") == 1
  assert header.count("erase_sector(WRITER_SECTOR_BASE") == 1
  assert header.count("program_sector(WRITER_SECTOR_BASE") == 1
  assert "stream_candidate_sector" in header
  assert "for(stage=0u;stage<CANDIDATE_STAGE_COUNT;++stage)" in header
  assert "retry" not in (combined + header).lower()
  assert "0xFFA10034" not in (combined + header + faci)
  assert "FEADDR" not in (combined + header + faci)


def test_writer_sources_have_no_other_sector_or_steering_capability():
  for name, source in _sources().items():
    other = "0x000F8000u" if name == "target" else "0x00088000u"
    # Other-sector reads are centralized in the shared gate; the template TU
    # itself exposes only its compile-time write destination.
    assert other not in source
    assert not re.search(r"steer|0x191|isotp", source, re.I)


def test_crc_and_writer_context_constants_have_one_shared_reviewed_definition():
  common = (ROOT / "payload" / "patch_common.h").read_text()
  dcra = (ROOT / "payload" / "crc_runtime.h").read_text()
  writer = (ROOT / "payload" / "candidate_writer.h").read_text()
  for name in (
    "CRC_SECTOR_BASE", "CRC_ADJUST", "ORIGINAL_INSTRUCTION_WORD",
    "PATCHED_INSTRUCTION_WORD",
  ):
    assert f"#define {name}" in common
    assert f"#define {name}" not in dcra
    assert f"#define {name}" not in writer


def test_candidate_writer_role_excludes_only_unrelated_common_status_helper():
  common = (ROOT / "payload" / "patch_common.h").read_text()
  helper = common.index("static int send_status(")
  guard = common[common.rfind("#elif", 0, helper):helper]
  assert "!defined(CANDIDATE_WRITER_PAYLOAD)" in guard
  assert "static int send_error(" in common
  assert "static int send_magic(" in common
  assert "static int stream_sector(" in common


def test_direction_specific_context_checks_are_compile_time_guarded():
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  branch = header.index("#if WRITER_OPERATION == PROTO_OP_WRITE_TARGET_CANDIDATE")
  alternate = header.index("#else", branch)
  end = header.index("#endif", alternate)
  assert "ORIGINAL_INSTRUCTION_WORD" in header[branch:alternate]
  assert "CANDIDATE_ADJUST_WORD" in header[alternate:end]


def test_compact_writer_reuses_crc_kernel_and_aligned_literal_context_words():
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  assert "static int equal4(" not in header
  assert "static const uint8_t original_instruction" not in header
  assert "static const uint8_t patched_instruction" not in header
  assert "static const uint8_t original_adjust" not in header
  assert "static const uint8_t candidate_adjust" not in header
  intent_crc = header[header.index("static uint32_t candidate_intent_crc") : header.index("static int validate_candidate_intent")]
  assert "crc_region32(data,CANDIDATE_INTENT_CRC_OFFSET,guard)" in intent_crc
  assert "crc32_update(crc,0u)" in intent_crc
  for offset in ("36u", "40u", "44u", "56u"):
    assert f"candidate_intent_word({offset})" in header


def test_compact_writer_takes_complete_idle_snapshot_without_stack_copy_helpers():
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  exploit = header[header.index("static void write_candidate_exploit") :]
  assert "candidate_exact_idle_snapshot()" in exploit
  assert "take_faci_snapshot" not in exploit
  assert "exact_idle(" not in exploit
  idle = header[header.index("static int candidate_exact_idle_snapshot") : header.index("static void write_candidate_exploit")]
  for register in (
    "FACI_FPMON", "FACI_FSTATR", "FACI_FASTAT", "FACI_FENTRYR",
    "FACI_FPROTR", "FACI_FAREASELC", "FHVE15", "FHVE3",
  ):
    assert register in idle
  assert "mismatch |=" in idle


def test_every_exit_path_records_complete_idle_evidence_without_short_circuit():
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  exploit = header[header.index("static void write_candidate_exploit") :]
  assert "error=exit_pe(&guard);exit_idle=candidate_exact_idle_snapshot();" in exploit
  assert "error!=0||!exit_idle" in exploit
  assert "candidate_failure_cleanup(&guard)" in exploit
  cleanup = header[header.index("static uint32_t candidate_failure_cleanup") : header.index("static void write_candidate_exploit")]
  assert "failure_cleanup(guard)" in cleanup
  assert "candidate_exact_idle_snapshot()" in cleanup
  assert cleanup.index("failure_cleanup(guard)") < cleanup.index("candidate_exact_idle_snapshot()")
  assert "&&" not in cleanup and "||" not in cleanup
  assert "cleanup_code" in cleanup and "idle_ok" in cleanup


def test_compact_writer_validates_aligned_intent_header_as_exact_words():
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  validation = header[header.index("static int validate_candidate_intent") : header.index("static int stream_candidate_sector")]
  for offset in ("0u", "4u", "8u", "12u", "16u", "20u", "24u", "28u", "32u", "48u", "52u", "60u", "124u"):
    assert f"candidate_intent_word({offset})" in validation
  for member in (
    "intent->magic", "intent->schema", "intent->length", "intent->operation",
    "intent->direction", "intent->reserved0", "intent->sector_base",
    "intent->sram_address", "intent->sram_length", "intent->context_tag",
    "intent->boot_magic0", "intent->boot_magic1",
  ):
    assert member not in validation


def test_compact_writer_preserves_two_failure_codes_without_six_word_status_array():
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  exploit = header[header.index("static void write_candidate_exploit") :]
  report = header[header.index("static void send_candidate_result") : header.index("static int candidate_exact_idle_snapshot")]
  assert "uint32_t codes[CANDIDATE_STAGE_COUNT]" not in header
  assert "primary_stage" in exploit and "primary_code" in exploit and "exit_code" in exploit
  assert "primary_stage" in report and "primary_code" in report and "exit_code" in report
  assert "stage==primary_stage" in report
  assert "stage==4u" in report
  assert "stage<CANDIDATE_STAGE_COUNT" in report


def test_zero_reserved_intent_gate_checks_all_fifteen_aligned_words():
  header = (ROOT / "payload" / "candidate_writer.h").read_text()
  validation = header[header.index("static int validate_candidate_intent") : header.index("static int stream_candidate_sector")]
  assert "index<15u" in validation
  assert "candidate_intent_word(64u+index*4u)!=0u" in validation
  assert "reserved[index]" not in validation


def test_retained_writer_binaries_fit_the_reviewed_envelope():
  for name in ("write_target_candidate", "write_crc_candidate"):
    binary = (BUILD / f"{name}.bin").read_bytes()
    assert 0 < len(binary) <= 0xFD0
