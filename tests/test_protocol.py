import binascii
import hashlib
import struct

import pytest


FACI_VALUES = (
  0x80, 0x00008000, 0x00, 0x0000, 0x0000, 0x3B00, 0x00000000, 0x00000000,
)
PE_PRE = (0x80, 0x00008000, 0x00, 0x0000, 0x0000, 0x0000, 0x00000000, 0x00000000)
PE_UNLOCKED = PE_PRE[:3] + (0x0001,) + PE_PRE[4:]
PE_WINDOWS = PE_UNLOCKED[:6] + (0x00000001, 0x00000001)
PE_CONFIGURED = PE_WINDOWS[:4] + (0x0001, 0x3B00) + PE_WINDOWS[6:]
PE_VALUES = PE_PRE + PE_UNLOCKED + PE_WINDOWS + PE_CONFIGURED + PE_PRE
PATCH_V2_VALUES = PE_PRE + PE_CONFIGURED + PE_CONFIGURED + PE_CONFIGURED + PE_PRE


def diagnostic_frames(values=FACI_VALUES, *, layout=None):
  from eps_patch.protocol import FACI_DIAGNOSTICS, FrameType

  if layout is None:
    layout = FACI_DIAGNOSTICS

  return [
    bytes([FrameType.DIAGNOSTIC, slot, width, 0]) + struct.pack("<I", value)
    for slot, ((_, _, width), value) in enumerate(zip(layout, values))
  ]


def complete_frames(sector: bytes, *, operation=1, result=0, status_code=0):
  from eps_patch.protocol import (
    FACI_PE_CYCLE_DIAGNOSTICS, FACI_UNLOCK_DIAGNOSTICS, FrameType, PROTOCOL_VERSION,
  )

  frames = [
    bytes([FrameType.BEGIN0, PROTOCOL_VERSION, operation, 0]) + struct.pack("<I", 0x60000),
    bytes([FrameType.BEGIN1, PROTOCOL_VERSION, operation, 1]) + struct.pack("<I", len(sector)),
  ]
  for index in range(0, len(sector), 4):
    frames.append(bytes([FrameType.DATA]) + struct.pack("<H", index // 4) + b"\x00" + sector[index:index + 4])
  frames.extend([
    bytes([FrameType.MAGIC, 0, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.MAGIC, 1, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
  ])
  if operation == 1:
    frames.extend(diagnostic_frames())
  elif operation == 3:
    frames.extend(diagnostic_frames(FACI_VALUES * 3, layout=FACI_UNLOCK_DIAGNOSTICS))
  elif operation == 4:
    frames.extend(diagnostic_frames(PE_VALUES, layout=FACI_PE_CYCLE_DIAGNOSTICS))
  frames.extend([
    bytes([FrameType.STATUS, 1, 0, 0]) + struct.pack("<I", status_code),
    bytes([FrameType.END, result, 0, 0]) + struct.pack("<I", binascii.crc32(sector)),
  ])
  return frames


def collect(frames, *, operation=1):
  from eps_patch.protocol import StreamCollector

  collector = StreamCollector(expected_operation=operation)
  for frame in frames:
    collector.consume(0x7A9, 0, frame)
  return collector.finish()


def patch_v2_frames(sector: bytes | None, status_codes=(0, 0, 0, 0, 0, 0)):
  from eps_patch.protocol import (
    FrameType, OP_PATCH_V2, PATCH_V2_DIAGNOSTICS, PROTOCOL_VERSION,
  )

  payload = b"" if sector is None else sector
  frames = [
    bytes([FrameType.BEGIN0, PROTOCOL_VERSION, OP_PATCH_V2, 0])
    + struct.pack("<I", 0x60000),
    bytes([FrameType.BEGIN1, PROTOCOL_VERSION, OP_PATCH_V2, 1])
    + struct.pack("<I", len(payload)),
  ]
  for index in range(0, len(payload), 4):
    frames.append(
      bytes([FrameType.DATA]) + struct.pack("<H", index // 4) + b"\x00"
      + payload[index:index + 4]
    )
  frames.extend([
    bytes([FrameType.MAGIC, 0, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.MAGIC, 1, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    *diagnostic_frames(PATCH_V2_VALUES, layout=PATCH_V2_DIAGNOSTICS),
  ])
  frames.extend(
    bytes([FrameType.STATUS, stage, 0, 0]) + struct.pack("<I", code)
    for stage, code in enumerate(status_codes, start=1)
  )
  frames.append(
    bytes([FrameType.END, 0, 0, 0]) + struct.pack("<I", binascii.crc32(payload))
  )
  return frames


def restore_frames(sector: bytes | None, status_codes=(0, 0, 0, 0, 0, 0)):
  from eps_patch.protocol import OP_PATCH_V2, OP_RESTORE

  frames = patch_v2_frames(sector, status_codes=status_codes)
  return [
    bytes([frame[0], frame[1], OP_RESTORE, frame[3]]) + frame[4:]
    if frame[0] in (0xB0, 0xB1) and frame[2] == OP_PATCH_V2 else frame
    for frame in frames
  ]


def restore_sector_frames(base: int, sector: bytes, status_codes=(0, 0, 0, 0, 0, 0)):
  from eps_patch.protocol import FrameType, OP_RESTORE_SECTOR, PROTOCOL_VERSION

  assert len(sector) == 0x8000
  frames = [
    bytes([FrameType.BEGIN0, PROTOCOL_VERSION, OP_RESTORE_SECTOR, 0]) + struct.pack("<I", base),
    bytes([FrameType.BEGIN1, PROTOCOL_VERSION, OP_RESTORE_SECTOR, 1]) + struct.pack("<I", 0x8000),
  ]
  frames.extend(
    bytes([FrameType.DATA]) + struct.pack("<H", index) + b"\x00"
    + sector[index * 4:index * 4 + 4]
    for index in range(len(sector) // 4)
  )
  frames.extend([
    bytes([FrameType.MAGIC, 0, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.MAGIC, 1, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
  ])
  frames.extend(
    bytes([FrameType.STATUS, stage, 0, 0]) + struct.pack("<I", code)
    for stage, code in enumerate(status_codes, start=1)
  )
  frames.append(bytes([FrameType.END, 0, 0, 0]) + struct.pack("<I", binascii.crc32(sector)))
  return frames


def candidate_writer_frames(operation: int, sector: bytes, status_codes=(0, 0, 0, 0, 0, 0)):
  from eps_patch.protocol import FrameType, PROTOCOL_VERSION

  base = {13: 0x60000, 14: 0xF8000}[operation]
  frames = [
    bytes([FrameType.BEGIN0, PROTOCOL_VERSION, operation, 0]) + struct.pack("<I", base),
    bytes([FrameType.BEGIN1, PROTOCOL_VERSION, operation, 1]) + struct.pack("<I", 0x8000),
  ]
  frames.extend(
    bytes([FrameType.DATA]) + struct.pack("<H", index) + b"\x00"
    + sector[index * 4:index * 4 + 4]
    for index in range(0x8000 // 4)
  )
  frames.extend([
    bytes([FrameType.MAGIC, 0, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.MAGIC, 1, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
  ])
  frames.extend(
    bytes([FrameType.STATUS, stage, 0, 0]) + struct.pack("<I", code)
    for stage, code in enumerate(status_codes, start=1)
  )
  frames.append(bytes([FrameType.END, 0, 0, 0]) + struct.pack("<I", binascii.crc32(sector)))
  return frames


@pytest.mark.parametrize(
  ("operation", "base"),
  ((13, 0x60000), (14, 0xF8000)),
)
def test_candidate_writer_stream_is_fixed_base_complete_and_zero_status(operation, base):
  from eps_patch.protocol import RegionResult, decode_candidate_writer_statuses

  sector = bytes((index * 7) & 0xFF for index in range(0x8000))
  result = collect(candidate_writer_frames(operation, sector), operation=operation)
  assert result.operation == operation
  assert result.regions == (RegionResult(base, sector),)
  assert result.sector == sector
  assert result.magic_words == (0x5AA5A55A, 0x5AA5A55A)
  assert tuple(decode_candidate_writer_statuses(operation, result.statuses)) == (
    "PRECHECK", "ENTER", "ERASE", "PROGRAM", "EXIT", "READBACK",
  )
  assert result.faci_values == () and result.crc_values == () and result.crc is None


@pytest.mark.parametrize("operation", (13, 14))
@pytest.mark.parametrize("mutation", ("truncate", "duplicate", "reorder", "wrong-base", "wrong-magic"))
def test_candidate_writer_stream_rejects_ambiguous_result(operation, mutation):
  from eps_patch.protocol import FrameType, ProtocolError

  frames = candidate_writer_frames(operation, bytes(0x8000))
  if mutation == "truncate": del frames[5]
  elif mutation == "duplicate": frames.insert(5, frames[4])
  elif mutation == "reorder": frames[-3], frames[-4] = frames[-4], frames[-3]
  elif mutation == "wrong-base": frames[0] = frames[0][:4] + struct.pack("<I", 0xF8000 if operation == 13 else 0x60000)
  elif mutation == "wrong-magic":
    magic = next(i for i, frame in enumerate(frames) if frame[0] == FrameType.MAGIC)
    frames[magic] = frames[magic][:4] + struct.pack("<I", 0)
  with pytest.raises(ProtocolError):
    collect(frames, operation=operation)


@pytest.mark.parametrize("operation", (13, 14))
def test_candidate_writer_collects_complete_structured_failure_before_pass_gate(operation):
  from eps_patch.protocol import CandidateWriterFailure, require_candidate_writer_pass

  sector = bytes((index * 11) & 0xFF for index in range(0x8000))
  codes = (0, 0x101, 0, 0xDEAD0004, 0xCAFE0005, 0)
  result = collect(
    candidate_writer_frames(operation, sector, status_codes=codes),
    operation=operation,
  )

  assert result.statuses == tuple(enumerate(codes, start=1))
  assert len(result.regions) == 1 and result.regions[0].data == sector
  with pytest.raises(CandidateWriterFailure) as failure:
    require_candidate_writer_pass(result)
  assert failure.value.result is result
  assert failure.value.codes == {
    "PRECHECK": 0, "ENTER": 0x101, "ERASE": 0,
    "PROGRAM": 0xDEAD0004, "EXIT": 0xCAFE0005, "READBACK": 0,
  }
  assert failure.value.result.regions[0].data == sector


def test_candidate_writer_pass_gate_is_separate_and_requires_all_zero_codes():
  from eps_patch.protocol import require_candidate_writer_pass

  result = collect(candidate_writer_frames(13, bytes(0x8000)), operation=13)
  assert require_candidate_writer_pass(result) is result


@pytest.mark.parametrize(
  "statuses",
  (
    ((True, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0)),
    ((1, False), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0)),
    ((1.0, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0)),
    ((1, 0.0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0)),
  ),
)
def test_candidate_writer_status_decoder_rejects_bool_and_float_coercion(statuses):
  from eps_patch.protocol import ProtocolError, decode_candidate_writer_statuses

  with pytest.raises(ProtocolError):
    decode_candidate_writer_statuses(13, statuses)


@pytest.mark.parametrize("base", (0x60000, 0xF8000))
def test_restore_sector_stream_binds_one_allowlisted_region(base):
  from eps_patch.protocol import OP_RESTORE_SECTOR, RegionResult

  sector = bytes((index * 13) & 0xFF for index in range(0x8000))
  result = collect(restore_sector_frames(base, sector), operation=OP_RESTORE_SECTOR)
  assert result.regions == (RegionResult(base, sector),)
  assert result.sector == sector
  assert result.statuses == tuple((stage, 0) for stage in range(1, 7))


def test_restore_sector_stream_rejects_unreviewed_base_and_false_success():
  from eps_patch.protocol import OP_RESTORE_SECTOR, ProtocolError

  with pytest.raises(ProtocolError, match="base"):
    collect(restore_sector_frames(0x70000, bytes(0x8000)), operation=OP_RESTORE_SECTOR)
  frames = restore_sector_frames(0x60000, bytes(0x8000))
  del frames[4]
  with pytest.raises(ProtocolError, match="DATA index"):
    collect(frames, operation=OP_RESTORE_SECTOR)


CRC_VALUES = (
  0, 0xFFFFFFFF, 0x18000, 0xFFDF0, 0xFFDEC,
  0x0962887F, 0x2E0B31DB, 0xD1F4CE24,
  0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
  0, 0xFFFFFFFF, 0x8000, 0x88341866,
)


@pytest.mark.parametrize("bad", (True, False, 1.0, 12.0, 13.0, 14.0))
def test_stream_collector_requires_exact_integer_expected_operation(bad):
  from eps_patch.protocol import ProtocolError, StreamCollector

  with pytest.raises(ProtocolError):
    StreamCollector(expected_operation=bad)


def crc_probe_frames(
  target_sector: bytes,
  crc_sector: bytes,
  crc_values=CRC_VALUES,
  *,
  operation=7,
):
  from eps_patch.protocol import FrameType, PROTOCOL_VERSION

  frames = [
    bytes([FrameType.BEGIN0, PROTOCOL_VERSION, operation, 0]) + struct.pack("<I", 0x18000),
    bytes([FrameType.BEGIN1, PROTOCOL_VERSION, operation, 1]) + struct.pack("<I", 2),
  ]
  for slot, (base, region) in enumerate(((0x60000, target_sector), (0xF8000, crc_sector))):
    frames.extend([
      bytes([FrameType.REGION_BEGIN, PROTOCOL_VERSION, operation, slot]) + struct.pack("<I", base),
      bytes([FrameType.REGION_LENGTH, PROTOCOL_VERSION, operation, slot]) + struct.pack("<I", len(region)),
    ])
    frames.extend(
      bytes([FrameType.DATA]) + struct.pack("<H", index) + b"\x00" + region[index * 4:index * 4 + 4]
      for index in range(len(region) // 4)
    )
    frames.append(
      bytes([FrameType.REGION_END, PROTOCOL_VERSION, operation, slot])
      + struct.pack("<I", binascii.crc32(region))
    )
  frames.extend(
    bytes([FrameType.CRC_RECORD, slot, 4, 0]) + struct.pack("<I", value)
    for slot, value in enumerate(crc_values)
  )
  frames.extend([
    bytes([FrameType.MAGIC, 0, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.MAGIC, 1, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.STATUS, 1, 0, 0]) + bytes(4),
    bytes([FrameType.END, 0, 0, 0]) + struct.pack("<I", binascii.crc32(target_sector + crc_sector)),
  ])
  return frames


def collect_crc_probe_frames(target_sector: bytes, crc_sector: bytes, crc_values=CRC_VALUES, *, operation=7):
  return collect(crc_probe_frames(target_sector, crc_sector, crc_values, operation=operation), operation=operation)


def test_crc_probe_collects_two_exact_regions_and_crc_observations():
  from eps_patch.protocol import CrcObservation, OP_CRC_PROBE, RegionResult

  result = collect_crc_probe_frames(
    bytes([0x31]) * 0x8000,
    bytes([0xA5]) * 0x8000,
    operation=OP_CRC_PROBE,
  )

  assert result.regions == (
    RegionResult(0x60000, bytes([0x31]) * 0x8000),
    RegionResult(0xF8000, bytes([0xA5]) * 0x8000),
  )
  assert result.crc_values == CRC_VALUES
  assert result.crc == CrcObservation.from_values(result.crc_values)


@pytest.mark.parametrize(
  "mutation",
  (
    lambda frames: frames[:0x2005] + frames[2:0x2005] + frames[0x2005:],
    lambda frames: [
      frame[:4] + struct.pack("<I", 0x60000) if frame[0] == 0xB2 and frame[3] == 1 else frame
      for frame in frames
    ],
    lambda frames: [
      frame for frame in frames if not (frame[0] == 0xD0 and frame[1:3] == struct.pack("<H", 7))
    ],
    lambda frames: [
      bytes([frame[0], 7, frame[2], frame[3]]) + frame[4:] if frame[0] == 0xA2 and frame[1] == 8 else frame
      for frame in frames
    ],
  ),
  ids=("duplicate-region", "wrong-base", "skip-word", "crc-slot"),
)
def test_crc_stream_rejects_ambiguous_or_incomplete_records(mutation):
  from eps_patch.protocol import OP_CRC_PROBE, ProtocolError

  with pytest.raises(ProtocolError):
    collect(mutation(crc_probe_frames(bytes(0x8000), bytes(0x8000))), operation=OP_CRC_PROBE)


def test_verify_crc_uses_the_same_exact_two_region_grammar():
  from eps_patch.protocol import OP_VERIFY_CRC

  result = collect_crc_probe_frames(bytes(0x8000), bytes([0xFF]) * 0x8000, operation=OP_VERIFY_CRC)

  assert result.operation == OP_VERIFY_CRC
  assert tuple(region.base for region in result.regions) == (0x60000, 0xF8000)


def test_crc_intermediate_uses_exact_two_region_sixteen_record_grammar():
  from eps_patch.protocol import OP_CRC_INTERMEDIATE

  values = list(CRC_VALUES)
  values[14] = 0x8000
  values[15] = 0x12345678
  result = collect_crc_probe_frames(
    bytes([0x10]) * 0x8000,
    bytes([0xA5]) * 0x8000,
    crc_values=tuple(values),
    operation=OP_CRC_INTERMEDIATE,
  )
  assert result.operation == OP_CRC_INTERMEDIATE
  assert tuple(region.base for region in result.regions) == (0x60000, 0xF8000)
  assert result.crc.sram_echo_length == 0x8000
  assert result.crc.sram_echo_crc32 == 0x12345678


def _valid_intermediate_fixture():
  from eps_patch.manifest import TARGET

  target = bytearray(TARGET.sector_length)
  target[TARGET.instruction_offset:TARGET.instruction_offset + 4] = TARGET.patched_instruction
  crc_source = bytearray(TARGET.sector_length)
  crc_source[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = bytes.fromhex("7f886209")
  crc_source[0x7E00:0x7E04] = TARGET.magic_word.to_bytes(4, "little")
  staged = bytearray(crc_source)
  staged[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = bytes.fromhex("24cef4d1")
  values = (
    0x10203040, 0x50607080, TARGET.crc_range_start, TARGET.crc_range_end,
    TARGET.crc_adjust_address, 0x0962887F, 0x2E0B31DB, 0xD1F4CE24,
    0x12345678, 0xFFFFFFFF, 0x12345678, 0xFFFFFFFF,
    0x10203040, 0x50607080, TARGET.sector_length, binascii.crc32(staged),
  )
  return bytes(target), bytes(crc_source), bytes(staged), values


def test_crc_intermediate_requires_exact_ordered_target_magic_words():
  from eps_patch.protocol import FrameType, OP_CRC_INTERMEDIATE, ProtocolError

  target, crc_source, _staged, values = _valid_intermediate_fixture()
  frames = crc_probe_frames(target, crc_source, crc_values=values, operation=OP_CRC_INTERMEDIATE)
  magic = next(index for index, frame in enumerate(frames) if frame[0] == FrameType.MAGIC)
  frames[magic] = frames[magic][:4] + struct.pack("<I", 0)
  with pytest.raises(ProtocolError, match="MAGIC"):
    collect(frames, operation=OP_CRC_INTERMEDIATE)


def test_crc_intermediate_semantic_validator_requires_all_exact_evidence():
  from eps_patch.protocol import OP_CRC_INTERMEDIATE, validate_crc_intermediate

  target, crc_source, staged, values = _valid_intermediate_fixture()
  result = collect(
    crc_probe_frames(target, crc_source, crc_values=values, operation=OP_CRC_INTERMEDIATE),
    operation=OP_CRC_INTERMEDIATE,
  )
  assert validate_crc_intermediate(result, staged_candidate=staged) is result.crc


@pytest.mark.parametrize("slot", range(16))
def test_crc_intermediate_semantic_validator_rejects_each_inconsistent_slot(slot):
  from eps_patch.protocol import OP_CRC_INTERMEDIATE, ProtocolError, validate_crc_intermediate

  target, crc_source, staged, values = _valid_intermediate_fixture()
  changed = list(values)
  changed[slot] ^= 1
  result = collect(
    crc_probe_frames(target, crc_source, crc_values=tuple(changed), operation=OP_CRC_INTERMEDIATE),
    operation=OP_CRC_INTERMEDIATE,
  )
  with pytest.raises(ProtocolError, match="intermediate"):
    validate_crc_intermediate(result, staged_candidate=staged)


@pytest.mark.parametrize(
  "mutation", ("crc-values", "result-subclass", "region-subclass", "crc-subclass"),
)
def test_crc_intermediate_semantic_validator_requires_exact_result_component_types(mutation):
  from dataclasses import replace
  from eps_patch.protocol import (
    CrcObservation, OP_CRC_INTERMEDIATE, ProtocolError, RegionResult, StreamResult,
    validate_crc_intermediate,
  )

  target, crc_source, staged, values = _valid_intermediate_fixture()
  result = collect(
    crc_probe_frames(target, crc_source, crc_values=values, operation=OP_CRC_INTERMEDIATE),
    operation=OP_CRC_INTERMEDIATE,
  )
  if mutation == "crc-values":
    changed = replace(result, crc_values=result.crc_values[:-1] + (0,))
  elif mutation == "result-subclass":
    class ResultSubclass(StreamResult):
      pass
    changed = ResultSubclass(**{
      field: getattr(result, field)
      for field in result.__dataclass_fields__
    })
  elif mutation == "region-subclass":
    class RegionSubclass(RegionResult):
      pass
    changed = replace(
      result,
      regions=(RegionSubclass(result.regions[0].base, result.regions[0].data), result.regions[1]),
    )
  else:
    class CrcSubclass(CrcObservation):
      pass
    changed = replace(result, crc=CrcSubclass(*result.crc_values))
  with pytest.raises(ProtocolError, match="intermediate"):
    validate_crc_intermediate(changed, staged_candidate=staged)


@pytest.mark.parametrize("mutation", ("float", "bool"))
def test_crc_intermediate_rejects_equal_by_coercion_crc_value_elements(mutation):
  from dataclasses import replace
  from eps_patch.protocol import OP_CRC_INTERMEDIATE, ProtocolError, validate_crc_intermediate

  target, crc_source, staged, values = _valid_intermediate_fixture()
  if mutation == "bool":
    values = (0,) + values[1:12] + (0,) + values[13:]
  result = collect(
    crc_probe_frames(target, crc_source, crc_values=values, operation=OP_CRC_INTERMEDIATE),
    operation=OP_CRC_INTERMEDIATE,
  )
  coerced = list(result.crc_values)
  coerced[0] = float(coerced[0]) if mutation == "float" else False
  changed = replace(result, crc_values=tuple(coerced))
  with pytest.raises(ProtocolError, match="exact uint32"):
    validate_crc_intermediate(changed, staged_candidate=staged)


@pytest.mark.parametrize("mutation", ("drop-crc", "duplicate-crc", "wrong-status", "legacy-diagnostic"))
def test_crc_intermediate_rejects_incomplete_or_legacy_fields(mutation):
  from eps_patch.protocol import FrameType, OP_CRC_INTERMEDIATE, ProtocolError

  frames = crc_probe_frames(bytes(0x8000), bytes(0x8000), operation=OP_CRC_INTERMEDIATE)
  crc = [i for i, frame in enumerate(frames) if frame[0] == FrameType.CRC_RECORD]
  if mutation == "drop-crc": del frames[crc[-1]]
  elif mutation == "duplicate-crc": frames.insert(crc[1], frames[crc[0]])
  elif mutation == "wrong-status":
    status = next(i for i, frame in enumerate(frames) if frame[0] == FrameType.STATUS)
    frames[status] = frames[status][:4] + struct.pack("<I", 1)
  else:
    status = next(i for i, frame in enumerate(frames) if frame[0] == FrameType.STATUS)
    frames.insert(status, bytes([FrameType.DIAGNOSTIC, 0, 1, 0]) + bytes(4))
  with pytest.raises(ProtocolError):
    collect(frames, operation=OP_CRC_INTERMEDIATE)


def test_patch_crc_uses_two_regions_sixteen_crc_records_and_twelve_statuses():
  from eps_patch.protocol import OP_PATCH_CRC, FrameType, decode_patch_crc_statuses

  frames = crc_probe_frames(bytes(0x8000), bytes([0xFF]) * 0x8000, operation=OP_PATCH_CRC)
  status = next(i for i, frame in enumerate(frames) if frame[0] == FrameType.STATUS)
  frames[status:status + 1] = [
    bytes([FrameType.STATUS, stage, 0, 0]) + struct.pack("<I", 0)
    for stage in range(1, 13)
  ]
  result = collect(frames, operation=OP_PATCH_CRC)
  assert tuple(region.base for region in result.regions) == (0x60000, 0xF8000)
  assert len(result.crc_values) == 16
  assert tuple(decode_patch_crc_statuses(result.statuses)) == (
    "PRECHECK", "TARGET_ENTER", "TARGET_ERASE", "TARGET_PROGRAM",
    "TARGET_EXIT_READBACK", "CRC_ENTER", "CRC_ERASE", "CRC_PROGRAM",
    "CRC_EXIT_READBACK", "FINAL_DCRA", "ROLLBACK_CRC", "ROLLBACK_TARGET",
  )


def test_crc_observation_requires_all_fixed_slots():
  from eps_patch.protocol import CrcObservation, ProtocolError

  assert CrcObservation.from_values(CRC_VALUES).sram_echo_crc32 == 0x88341866
  with pytest.raises(ProtocolError, match="exactly 16"):
    CrcObservation.from_values(CRC_VALUES[:-1])


def test_stream_collector_reconstructs_exact_sector_and_magic_words():
  sector = bytes((index * 17) & 0xFF for index in range(0x8000))
  result = collect(complete_frames(sector))

  assert result.sector == sector
  assert result.magic_words == (0x5AA5A55A, 0x5AA5A55A)
  assert result.operation == 1
  assert result.faci_values == FACI_VALUES


@pytest.mark.parametrize(
  ("mutation", "message"),
  [
    (lambda fs: fs[:1] + fs[2:], "BEGIN1"),
    (lambda fs: fs[:2] + [fs[2], fs[2]] + fs[3:], "index"),
    (lambda fs: fs[:-1] + [fs[-1][:-1]], "8 bytes"),
    (lambda fs: fs[:-1] + [fs[-1][:4] + b"\x00\x00\x00\x00"], "CRC"),
    (lambda fs: fs[:-1] + [bytes([fs[-1][0], 1, 0, 0]) + fs[-1][4:]], "result"),
  ],
)
def test_stream_collector_fails_closed_on_malformed_stream(mutation, message):
  from eps_patch.protocol import ProtocolError

  sector = bytes(0x8000)
  with pytest.raises(ProtocolError, match=message):
    collect(mutation(complete_frames(sector)))


def test_stream_collector_rejects_wrong_can_route():
  from eps_patch.protocol import ProtocolError, StreamCollector

  collector = StreamCollector(expected_operation=1)
  first = complete_frames(bytes(0x8000))[0]
  with pytest.raises(ProtocolError, match="CAN route"):
    collector.consume(0x7A1, 0, first)
  with pytest.raises(ProtocolError, match="CAN route"):
    collector.consume(0x7A9, 1, first)


def test_stream_collector_rejects_payload_error_status():
  from eps_patch.protocol import FrameType, ProtocolError, StreamCollector

  collector = StreamCollector(expected_operation=1)
  frames = complete_frames(bytes(0x8000))
  collector.consume(0x7A9, 0, frames[0])
  collector.consume(0x7A9, 0, frames[1])
  error = bytes([FrameType.ERROR, 3, 0, 0]) + struct.pack("<I", 0xDEAD)
  with pytest.raises(ProtocolError, match="stage 3.*0x0000dead"):
    collector.consume(0x7A9, 0, error)


@pytest.mark.parametrize(
  ("mutation", "message"),
  [
    (lambda ds: ds[1:], "slot"),
    (lambda ds: [ds[0], ds[0], *ds[2:]], "slot"),
    (lambda ds: [ds[1], ds[0], *ds[2:]], "slot"),
    (lambda ds: [bytes([ds[0][0], 0, 2, 0]) + ds[0][4:], *ds[1:]], "width"),
    (lambda ds: [bytes([ds[0][0], 0, 1, 1]) + ds[0][4:], *ds[1:]], "padding"),
    (lambda ds: [ds[0][:4] + b"\x80\x01\x00\x00", *ds[1:]], "zero-extended"),
  ],
)
def test_stream_collector_rejects_malformed_faci_diagnostics(mutation, message):
  from eps_patch.protocol import ProtocolError

  frames = complete_frames(bytes(0x8000))
  diagnostic_start = 2 + (0x8000 // 4) + 2
  mutated = frames[:diagnostic_start] + mutation(frames[diagnostic_start:diagnostic_start + 8]) + frames[diagnostic_start + 8:]
  with pytest.raises(ProtocolError, match=message):
    collect(mutated)


def test_stream_collector_forbids_faci_diagnostics_for_patch_operation():
  from eps_patch.protocol import ProtocolError

  frames = complete_frames(bytes(0x8000), operation=2)
  frames.insert(-2, diagnostic_frames()[0])
  with pytest.raises(ProtocolError, match="forbidden"):
    collect(frames, operation=2)


def test_unlock_stream_collects_exact_three_checkpoint_layout_and_nonzero_outcome():
  from eps_patch.protocol import FACI_DIAGNOSTICS, FACI_UNLOCK_DIAGNOSTICS, OP_FACI_UNLOCK

  sector = bytes((index * 29) & 0xFF for index in range(0x8000))
  status_code = (1 << 16) | 5
  result = collect(
    complete_frames(sector, operation=OP_FACI_UNLOCK, status_code=status_code),
    operation=OP_FACI_UNLOCK,
  )

  assert len(FACI_UNLOCK_DIAGNOSTICS) == 24
  assert tuple(name for name, _, _ in FACI_UNLOCK_DIAGNOSTICS[:8]) == tuple(
    f"PRE.{name}" for name, _, _ in FACI_DIAGNOSTICS
  )
  assert result.operation == OP_FACI_UNLOCK
  assert result.sector == sector
  assert result.faci_values == FACI_VALUES * 3
  assert result.statuses == ((1, status_code),)


@pytest.mark.parametrize(
  ("mutation", "message"),
  [
    (lambda fs: fs[:-2] + fs[-1:], "STATUS"),
    (lambda fs: fs[:-1] + [fs[-2], fs[-1]], "STATUS"),
    (
      lambda fs: fs[:-(24 + 2)] + fs[-(24 + 2) + 1:],
      "DIAGNOSTIC slot",
    ),
    (
      lambda fs: fs[:-2] + [bytes([fs[-2][0], 2, 0, 0]) + fs[-2][4:], fs[-1]],
      "stage 1",
    ),
  ],
)
def test_unlock_stream_requires_exact_diagnostics_and_one_stage1_status(mutation, message):
  from eps_patch.protocol import OP_FACI_UNLOCK, ProtocolError

  frames = complete_frames(bytes(0x8000), operation=OP_FACI_UNLOCK)
  with pytest.raises(ProtocolError, match=message):
    collect(mutation(frames), operation=OP_FACI_UNLOCK)


def test_nonzero_status_remains_forbidden_for_normal_probe():
  from eps_patch.protocol import ProtocolError

  with pytest.raises(ProtocolError, match="nonzero STATUS"):
    collect(complete_frames(bytes(0x8000), operation=1, status_code=5))


def test_patch_v2_failure_stream_preserves_diagnostics_without_claiming_readback():
  from eps_patch.protocol import OP_PATCH_V2, PATCH_V2_DIAGNOSTICS

  result = collect(
    patch_v2_frames(None, status_codes=(0, 0, 0x4012, 0, 0, 0)),
    operation=OP_PATCH_V2,
  )

  assert len(PATCH_V2_DIAGNOSTICS) == 40
  assert result.sector is None
  assert result.statuses == (
    (1, 0), (2, 0), (3, 0x4012), (4, 0), (5, 0), (6, 0),
  )
  assert result.faci_values == PATCH_V2_VALUES


def test_patch_v2_success_requires_full_target_sector():
  from eps_patch.protocol import OP_PATCH_V2, ProtocolError

  with pytest.raises(ProtocolError, match="successful patch-v2.*sector"):
    collect(patch_v2_frames(None), operation=OP_PATCH_V2)


def test_restore_stream_collects_full_original_sector_and_exact_contract():
  from eps_patch.protocol import OP_RESTORE, PATCH_V2_DIAGNOSTICS

  sector = bytes((index * 31) & 0xFF for index in range(0x8000))
  result = collect(restore_frames(sector), operation=OP_RESTORE)

  assert result.operation == OP_RESTORE
  assert result.sector == sector
  assert result.magic_words == (0x5AA5A55A, 0x5AA5A55A)
  assert result.faci_values == PATCH_V2_VALUES
  assert len(PATCH_V2_DIAGNOSTICS) == 40
  assert result.statuses == tuple((stage, 0) for stage in range(1, 7))


@pytest.mark.parametrize(
  ("mutation", "message"),
  [
    (lambda fs: fs[:-2] + [fs[-2], fs[-2], fs[-1]], "stage"),
    (lambda fs: fs[:-2] + fs[-1:], "six ordered"),
    (lambda fs: fs[:-42] + fs[-41:], "DIAGNOSTIC slot"),
    (
      lambda fs: fs[:-7]
      + [bytes([fs[-7][0], 2, 0, 0]) + fs[-7][4:]]
      + fs[-6:],
      "stage",
    ),
  ],
)
def test_restore_stream_rejects_incomplete_or_reordered_contract(mutation, message):
  from eps_patch.protocol import OP_RESTORE, ProtocolError

  with pytest.raises(ProtocolError, match=message):
    collect(mutation(restore_frames(None, status_codes=(1, 0, 0, 0, 0, 0))), operation=OP_RESTORE)


def test_restore_stream_rejects_wrong_operation_and_crc():
  from eps_patch.protocol import OP_RESTORE, ProtocolError

  sector = bytes(0x8000)
  with pytest.raises(ProtocolError, match="operation"):
    collect(patch_v2_frames(sector), operation=OP_RESTORE)

  frames = restore_frames(sector)
  frames[-1] = frames[-1][:4] + bytes(4)
  with pytest.raises(ProtocolError, match="CRC"):
    collect(frames, operation=OP_RESTORE)


@pytest.mark.parametrize(
  ("mutation", "message"),
  [
    (lambda fs: fs[:-2] + [fs[-2], fs[-2], fs[-1]], "stage"),
    (
      lambda fs: fs[:-7]
      + [bytes([fs[-7][0], 2, 0, 0]) + fs[-7][4:]]
      + fs[-6:],
      "stage",
    ),
  ],
)
def test_patch_v2_requires_exactly_six_ordered_statuses(mutation, message):
  from eps_patch.protocol import OP_PATCH_V2, ProtocolError

  frames = patch_v2_frames(None, status_codes=(1, 0, 0, 0, 0, 0))
  with pytest.raises(ProtocolError, match=message):
    collect(mutation(frames), operation=OP_PATCH_V2)


def test_zero_length_sector_remains_forbidden_for_probe_and_legacy_patch():
  from eps_patch.protocol import OP_PATCH, OP_PROBE, ProtocolError

  for operation in (OP_PROBE, OP_PATCH):
    frames = complete_frames(b"", operation=operation)
    with pytest.raises(ProtocolError, match="sector length"):
      collect(frames, operation=operation)
