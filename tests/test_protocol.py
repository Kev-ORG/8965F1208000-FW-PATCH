import binascii
import hashlib
import struct

import pytest


def collect(frames, *, operation=1):
  from eps_patch.protocol import StreamCollector

  collector = StreamCollector(expected_operation=operation)
  for frame in frames:
    collector.consume(0x7A9, 0, frame)
  return collector.finish()


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

  base = {13: 0x88000, 14: 0xF8000}[operation]
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
  ((13, 0x88000), (14, 0xF8000)),
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
  elif mutation == "wrong-base": frames[0] = frames[0][:4] + struct.pack("<I", 0xF8000 if operation == 13 else 0x88000)
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


@pytest.mark.parametrize("base", (0x88000, 0xF8000))
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
  frames = restore_sector_frames(0x88000, bytes(0x8000))
  del frames[4]
  with pytest.raises(ProtocolError, match="DATA index"):
    collect(frames, operation=OP_RESTORE_SECTOR)


CRC_VALUES = (
  0, 0xFFFFFFFF, 0x18000, 0xFFDF0, 0xFFDEC,
  0x0962887F, 0xBE36F00D, 0x41C90FF2,
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
  for slot, (base, region) in enumerate(((0x88000, target_sector), (0xF8000, crc_sector))):
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


def live_read_frames(target_sector: bytes, crc_sector: bytes):
  from eps_patch.protocol import FrameType, OP_LIVE_READ, PROTOCOL_VERSION

  frames = [
    bytes([FrameType.BEGIN0, PROTOCOL_VERSION, OP_LIVE_READ, 0])
    + struct.pack("<I", 0x88000),
    bytes([FrameType.BEGIN1, PROTOCOL_VERSION, OP_LIVE_READ, 1])
    + struct.pack("<I", 2),
  ]
  for slot, (base, region) in enumerate(
    ((0x88000, target_sector), (0xF8000, crc_sector)),
  ):
    frames.extend([
      bytes([FrameType.REGION_BEGIN, PROTOCOL_VERSION, OP_LIVE_READ, slot])
      + struct.pack("<I", base),
      bytes([FrameType.REGION_LENGTH, PROTOCOL_VERSION, OP_LIVE_READ, slot])
      + struct.pack("<I", len(region)),
    ])
    frames.extend(
      bytes([FrameType.DATA]) + struct.pack("<H", index) + b"\x00"
      + region[index * 4:index * 4 + 4]
      for index in range(len(region) // 4)
    )
    frames.append(
      bytes([FrameType.REGION_END, PROTOCOL_VERSION, OP_LIVE_READ, slot])
      + struct.pack("<I", binascii.crc32(region))
    )
  frames.extend([
    bytes([FrameType.MAGIC, 0, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.MAGIC, 1, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.STATUS, 1, 0, 0]) + bytes(4),
    bytes([FrameType.END, 0, 0, 0])
    + struct.pack("<I", binascii.crc32(target_sector + crc_sector)),
  ])
  return frames


def test_live_read_collects_only_two_complete_fixed_regions():
  from eps_patch.protocol import OP_LIVE_READ, RegionResult

  target = bytes([0x31]) * 0x8000
  crc = bytes([0xA5]) * 0x8000

  result = collect(live_read_frames(target, crc), operation=OP_LIVE_READ)

  assert result.operation == OP_LIVE_READ
  assert result.sector is None
  assert result.regions == (
    RegionResult(0x88000, target),
    RegionResult(0xF8000, crc),
  )
  assert result.magic_words == (0x5AA5A55A, 0x5AA5A55A)
  assert result.statuses == ((1, 0),)
  assert result.faci_values == ()
  assert result.crc_values == () and result.crc is None
  assert result.dcra_values == () and result.dcra is None


@pytest.mark.parametrize(
  "mutation",
  (
    "wrong-begin-base", "wrong-region-base", "missing-region", "truncated-data",
    "extra-region", "nonzero-status", "bad-combined-crc",
  ),
)
def test_live_read_rejects_ambiguous_or_non_read_only_result(mutation):
  from eps_patch.protocol import FrameType, OP_LIVE_READ, ProtocolError, PROTOCOL_VERSION

  frames = live_read_frames(bytes(0x8000), bytes([0xFF]) * 0x8000)
  if mutation == "wrong-begin-base":
    frames[0] = frames[0][:4] + struct.pack("<I", 0x18000)
  elif mutation == "wrong-region-base":
    second = next(
      index for index, frame in enumerate(frames)
      if frame[0] == FrameType.REGION_BEGIN and frame[3] == 1
    )
    frames[second] = frames[second][:4] + struct.pack("<I", 0x88000)
  elif mutation == "missing-region":
    second = next(
      index for index, frame in enumerate(frames)
      if frame[0] == FrameType.REGION_BEGIN and frame[3] == 1
    )
    magic = next(
      index for index, frame in enumerate(frames)
      if frame[0] == FrameType.MAGIC
    )
    del frames[second:magic]
  elif mutation == "truncated-data":
    del frames[5]
  elif mutation == "extra-region":
    magic = next(
      index for index, frame in enumerate(frames)
      if frame[0] == FrameType.MAGIC
    )
    frames.insert(
      magic,
      bytes([FrameType.REGION_BEGIN, PROTOCOL_VERSION, OP_LIVE_READ, 2])
      + struct.pack("<I", 0x88000),
    )
  elif mutation == "nonzero-status":
    status = next(
      index for index, frame in enumerate(frames)
      if frame[0] == FrameType.STATUS
    )
    frames[status] = frames[status][:4] + struct.pack("<I", 1)
  else:
    frames[-1] = frames[-1][:4] + struct.pack("<I", 0)

  with pytest.raises(ProtocolError):
    collect(frames, operation=OP_LIVE_READ)


def test_crc_probe_collects_two_exact_regions_and_crc_observations():
  from eps_patch.protocol import CrcObservation, OP_CRC_PROBE, RegionResult

  result = collect_crc_probe_frames(
    bytes([0x31]) * 0x8000,
    bytes([0xA5]) * 0x8000,
    operation=OP_CRC_PROBE,
  )

  assert result.regions == (
    RegionResult(0x88000, bytes([0x31]) * 0x8000),
    RegionResult(0xF8000, bytes([0xA5]) * 0x8000),
  )
  assert result.crc_values == CRC_VALUES
  assert result.crc == CrcObservation.from_values(result.crc_values)


@pytest.mark.parametrize(
  "mutation",
  (
    lambda frames: frames[:0x2005] + frames[2:0x2005] + frames[0x2005:],
    lambda frames: [
      frame[:4] + struct.pack("<I", 0x88000) if frame[0] == 0xB2 and frame[3] == 1 else frame
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
  assert tuple(region.base for region in result.regions) == (0x88000, 0xF8000)


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
  assert tuple(region.base for region in result.regions) == (0x88000, 0xF8000)
  assert result.crc.sram_echo_length == 0x8000
  assert result.crc.sram_echo_crc32 == 0x12345678


def _valid_intermediate_fixture():
  from eps_patch.manifest import TARGET

  target = bytearray(TARGET.sector_length)
  target[TARGET.instruction_offset:TARGET.instruction_offset + 4] = TARGET.patched_instruction
  crc_source = bytearray(TARGET.sector_length)
  crc_source[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = bytes.fromhex("7f886209")
  crc_source[0x7E00:0x7E04] = TARGET.magic_word.to_bytes(4, "little")
  values = (
    0x10203040, 0x50607080, TARGET.crc_range_start, TARGET.crc_range_end,
    TARGET.crc_adjust_address, 0x0962887F, 0xBE36F00D, 0x41C90FF2,
    0x12345678, 0xFFFFFFFF, 0x12345678, 0xFFFFFFFF,
    0x10203040, 0x50607080, 0, 0,
  )
  return bytes(target), bytes(crc_source), values


def test_crc_intermediate_requires_exact_ordered_target_magic_words():
  from eps_patch.protocol import FrameType, OP_CRC_INTERMEDIATE, ProtocolError

  target, crc_source, values = _valid_intermediate_fixture()
  frames = crc_probe_frames(target, crc_source, crc_values=values, operation=OP_CRC_INTERMEDIATE)
  magic = next(index for index, frame in enumerate(frames) if frame[0] == FrameType.MAGIC)
  frames[magic] = frames[magic][:4] + struct.pack("<I", 0)
  with pytest.raises(ProtocolError, match="MAGIC"):
    collect(frames, operation=OP_CRC_INTERMEDIATE)


def test_crc_intermediate_semantic_validator_requires_all_exact_evidence():
  from eps_patch.protocol import OP_CRC_INTERMEDIATE, validate_crc_intermediate

  target, crc_source, values = _valid_intermediate_fixture()
  result = collect(
    crc_probe_frames(target, crc_source, crc_values=values, operation=OP_CRC_INTERMEDIATE),
    operation=OP_CRC_INTERMEDIATE,
  )
  assert validate_crc_intermediate(result) is result.crc


@pytest.mark.parametrize("slot", range(16))
def test_crc_intermediate_semantic_validator_rejects_each_inconsistent_slot(slot):
  from eps_patch.protocol import OP_CRC_INTERMEDIATE, ProtocolError, validate_crc_intermediate

  target, crc_source, values = _valid_intermediate_fixture()
  changed = list(values)
  changed[slot] ^= 1
  result = collect(
    crc_probe_frames(target, crc_source, crc_values=tuple(changed), operation=OP_CRC_INTERMEDIATE),
    operation=OP_CRC_INTERMEDIATE,
  )
  with pytest.raises(ProtocolError, match="intermediate"):
    validate_crc_intermediate(result)


@pytest.mark.parametrize(
  "mutation", ("crc-values", "result-subclass", "region-subclass", "crc-subclass"),
)
def test_crc_intermediate_semantic_validator_requires_exact_result_component_types(mutation):
  from dataclasses import replace
  from eps_patch.protocol import (
    CrcObservation, OP_CRC_INTERMEDIATE, ProtocolError, RegionResult, StreamResult,
    validate_crc_intermediate,
  )

  target, crc_source, values = _valid_intermediate_fixture()
  result = collect(
    crc_probe_frames(target, crc_source, crc_values=values, operation=OP_CRC_INTERMEDIATE),
    operation=OP_CRC_INTERMEDIATE,
  )
  if mutation == "crc-values":
    changed = replace(result, crc_values=result.crc_values[:-1] + (1,))
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
    validate_crc_intermediate(changed)


@pytest.mark.parametrize("mutation", ("float", "bool"))
def test_crc_intermediate_rejects_equal_by_coercion_crc_value_elements(mutation):
  from dataclasses import replace
  from eps_patch.protocol import OP_CRC_INTERMEDIATE, ProtocolError, validate_crc_intermediate

  target, crc_source, values = _valid_intermediate_fixture()
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
    validate_crc_intermediate(changed)


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
