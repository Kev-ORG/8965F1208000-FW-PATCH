"""Strict framed CAN stream produced by the V850 RAM payloads."""

from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass
from enum import IntEnum

from .manifest import TARGET


PROTOCOL_VERSION = 1
OP_PROBE = 1
OP_PATCH = 2
OP_FACI_UNLOCK = 3
OP_FACI_PE_CYCLE = 4
OP_PATCH_V2 = 5
OP_RESTORE = 6
OP_CRC_PROBE = 7
OP_PATCH_CRC = 8
OP_RAM_ECHO = 9
OP_RESTORE_SECTOR = 10
OP_VERIFY_CRC = 11
OP_CRC_INTERMEDIATE = 12
OP_WRITE_TARGET_CANDIDATE = 13
OP_WRITE_CRC_CANDIDATE = 14
WORD_SIZE = 4
WORD_COUNT = 0x8000 // WORD_SIZE
CRC_RECORDS = (
  "ENTRY_CTL", "ENTRY_COUT", "RANGE_START", "RANGE_END", "ADJUST_ADDRESS",
  "OLD_ADJUST_WORD", "PATCHED_PREFIX_SW", "NEW_ADJUST_WORD",
  "ORIGINAL_SW_FULL", "PATCHED_SW_FULL", "ORIGINAL_DCRA_RAW", "PATCHED_DCRA_RAW",
  "EXIT_CTL", "EXIT_COUT", "SRAM_ECHO_LENGTH", "SRAM_ECHO_CRC32",
)
PATCH_CRC_STAGES = (
  "PRECHECK", "TARGET_ENTER", "TARGET_ERASE", "TARGET_PROGRAM",
  "TARGET_EXIT_READBACK", "CRC_ENTER", "CRC_ERASE", "CRC_PROGRAM",
  "CRC_EXIT_READBACK", "FINAL_DCRA", "ROLLBACK_CRC", "ROLLBACK_TARGET",
)
CANDIDATE_WRITER_STAGES = (
  "PRECHECK", "ENTER", "ERASE", "PROGRAM", "EXIT", "READBACK",
)
FACI_DIAGNOSTICS = (
  ("FPMON", 0xFFA10000, 1),
  ("FASTAT", 0xFFA10080, 4),
  ("FAESTAT", 0xFFA10010, 1),
  ("REG84", 0xFFA10084, 2),
  ("REG88", 0xFFA10088, 2),
  ("REG20", 0xFFA10020, 2),
  ("FLWL", 0xFFF8A430, 4),
  ("FLWE", 0xFFF82410, 4),
)
FACI_UNLOCK_DIAGNOSTICS = tuple(
  (f"{checkpoint}.{name}", address, width)
  for checkpoint in ("PRE", "UNLOCKED", "RESTORED")
  for name, address, width in FACI_DIAGNOSTICS
)
FACI_PE_CYCLE_DIAGNOSTICS = tuple(
  (f"{checkpoint}.{name}", address, width)
  for checkpoint in ("PRE", "UNLOCKED", "WINDOWS", "CONFIGURED", "RESTORED")
  for name, address, width in FACI_DIAGNOSTICS
)
PATCH_V2_DIAGNOSTICS = tuple(
  (f"{checkpoint}.{name}", address, width)
  for checkpoint in ("PRE", "ENTERED", "POST_ERASE", "POST_PROGRAM", "RESTORED")
  for name, address, width in FACI_DIAGNOSTICS
)


class FrameType(IntEnum):
  MAGIC = 0xA0
  DIAGNOSTIC = 0xA1
  CRC_RECORD = 0xA2
  BEGIN0 = 0xB0
  BEGIN1 = 0xB1
  REGION_BEGIN = 0xB2
  REGION_LENGTH = 0xB3
  REGION_END = 0xB4
  STATUS = 0xC0
  DATA = 0xD0
  END = 0xE0
  ERROR = 0xEE


class ProtocolError(RuntimeError):
  pass


@dataclass(frozen=True, slots=True)
class RegionResult:
  base: int
  data: bytes


@dataclass(frozen=True, slots=True)
class CrcObservation:
  entry_ctl: int
  entry_cout: int
  range_start: int
  range_end: int
  adjust_address: int
  old_adjust_word: int
  patched_prefix_sw: int
  new_adjust_word: int
  original_sw_full: int
  patched_sw_full: int
  original_dcra_raw: int
  patched_dcra_raw: int
  exit_ctl: int
  exit_cout: int
  sram_echo_length: int
  sram_echo_crc32: int

  @classmethod
  def from_values(cls, values: tuple[int, ...]) -> "CrcObservation":
    if len(values) != len(CRC_RECORDS):
      raise ProtocolError("CRC observation must contain exactly 16 records")
    return cls(*values)


@dataclass(frozen=True, slots=True)
class StreamResult:
  operation: int
  sector: bytes | None
  magic_words: tuple[int, int]
  statuses: tuple[tuple[int, int], ...]
  faci_values: tuple[int, ...] = ()
  regions: tuple[RegionResult, ...] = ()
  crc_values: tuple[int, ...] = ()
  crc: CrcObservation | None = None


class CandidateWriterFailure(ProtocolError):
  """A complete, CRC-valid writer result whose six-stage outcome is not PASS."""

  def __init__(self, result: StreamResult, codes: dict[str, int]):
    self.result = result
    self.codes = codes
    nonzero = ", ".join(f"{name}=0x{code:08x}" for name, code in codes.items() if code)
    super().__init__(f"candidate-writer completed with nonzero status: {nonzero}")


class StreamCollector:
  def __new__(cls, *, expected_operation: int):
    if type(expected_operation) is not int:
      raise ProtocolError("expected operation must be an exact integer")
    if cls is StreamCollector and expected_operation in (
      OP_FACI_PE_CYCLE, OP_CRC_PROBE, OP_VERIFY_CRC, OP_PATCH_CRC,
      OP_CRC_INTERMEDIATE,
    ):
      return CrcStreamCollector(expected_operation=expected_operation)
    if cls is StreamCollector and expected_operation == OP_RESTORE_SECTOR:
      return RestoreSectorStreamCollector(expected_operation=expected_operation)
    if cls is StreamCollector and expected_operation in (
      OP_WRITE_TARGET_CANDIDATE, OP_WRITE_CRC_CANDIDATE,
    ):
      return CandidateWriterStreamCollector(expected_operation=expected_operation)
    return super().__new__(cls)

  def __init__(self, *, expected_operation: int):
    if type(expected_operation) is not int or expected_operation not in (
      OP_PROBE, OP_PATCH, OP_FACI_UNLOCK, OP_FACI_PE_CYCLE, OP_PATCH_V2,
      OP_RESTORE, OP_RAM_ECHO, OP_RESTORE_SECTOR,
    ):
      raise ProtocolError("unknown expected operation")
    self._expected_operation = expected_operation
    self._state = "BEGIN0"
    self._sector = bytearray()
    self._next_index = 0
    self._expected_word_count = WORD_COUNT
    self._advertised_length = TARGET.sector_length
    self._magic: dict[int, int] = {}
    self._statuses: list[tuple[int, int]] = []
    self._faci_values: list[int] = []
    self._finished = False
    self._stream_base: int | None = None

  @property
  def _diagnostic_layout(self) -> tuple[tuple[str, int, int], ...]:
    if self._expected_operation == OP_PROBE:
      return FACI_DIAGNOSTICS
    if self._expected_operation == OP_FACI_UNLOCK:
      return FACI_UNLOCK_DIAGNOSTICS
    if self._expected_operation == OP_FACI_PE_CYCLE:
      return FACI_PE_CYCLE_DIAGNOSTICS
    if self._expected_operation in (OP_PATCH_V2, OP_RESTORE):
      return PATCH_V2_DIAGNOSTICS
    return ()

  @property
  def _has_diagnostic_outcome(self) -> bool:
    return self._expected_operation in (OP_FACI_UNLOCK, OP_FACI_PE_CYCLE)

  @property
  def _has_patch_v2_outcome(self) -> bool:
    return self._expected_operation in (OP_PATCH_V2, OP_RESTORE, OP_RESTORE_SECTOR)

  @property
  def _destructive_operation_name(self) -> str:
    if self._expected_operation == OP_RESTORE_SECTOR:
      return "restore-sector"
    return "restore" if self._expected_operation == OP_RESTORE else "patch-v2"

  def consume(self, can_id: int, bus: int, data: bytes) -> None:
    if can_id != TARGET.uds_response_id or bus != TARGET.bus:
      raise ProtocolError("unexpected CAN route")
    if len(data) != 8:
      raise ProtocolError("payload frame must be exactly 8 bytes")
    if self._finished:
      raise ProtocolError("trailing frame after END")

    try:
      frame_type = FrameType(data[0])
    except ValueError as exc:
      raise ProtocolError(f"unknown frame type 0x{data[0]:02x}") from exc

    if frame_type is FrameType.ERROR:
      stage = data[1]
      code = struct.unpack_from("<I", data, 4)[0]
      raise ProtocolError(f"payload error at stage {stage}: 0x{code:08x}")

    if self._state == "BEGIN0":
      if frame_type is not FrameType.BEGIN0:
        raise ProtocolError("expected BEGIN0")
      self._validate_begin(data, sequence=0)
      base = struct.unpack_from("<I", data, 4)[0]
      permitted_bases = (
        (TARGET.sram_buffer,) if self._expected_operation == OP_RAM_ECHO
        else (TARGET.sector_base, TARGET.crc_sector_base)
        if self._expected_operation == OP_RESTORE_SECTOR
        else (TARGET.sector_base,)
      )
      if base not in permitted_bases:
        raise ProtocolError("BEGIN0 sector base does not match target")
      self._stream_base = base
      self._state = "BEGIN1"
      return

    if self._state == "BEGIN1":
      if frame_type is not FrameType.BEGIN1:
        raise ProtocolError("expected BEGIN1")
      self._validate_begin(data, sequence=1)
      length = struct.unpack_from("<I", data, 4)[0]
      permitted_lengths = (
        (0, TARGET.sector_length)
        if self._has_patch_v2_outcome else (TARGET.sector_length,)
      )
      if length not in permitted_lengths:
        raise ProtocolError("BEGIN1 sector length does not match target")
      self._advertised_length = length
      self._expected_word_count = length // WORD_SIZE
      self._state = "DATA"
      return

    if frame_type is FrameType.DATA:
      if self._state != "DATA":
        raise ProtocolError("DATA frame is out of sequence")
      index = struct.unpack_from("<H", data, 1)[0]
      if (
        data[3] != 0
        or index != self._next_index
        or index >= self._expected_word_count
      ):
        raise ProtocolError(f"unexpected DATA index {index}, expected {self._next_index}")
      self._sector.extend(data[4:8])
      self._next_index += 1
      return

    if self._next_index != self._expected_word_count:
      raise ProtocolError(f"stream ended before DATA index {self._expected_word_count}")
    self._state = "TRAILER"

    if frame_type is FrameType.MAGIC:
      slot = data[1]
      if (
        data[2:4] != b"\x00\x00"
        or slot not in (0, 1)
        or slot in self._magic
        or self._faci_values
        or self._statuses
      ):
        raise ProtocolError("invalid or duplicate MAGIC record")
      self._magic[slot] = struct.unpack_from("<I", data, 4)[0]
      return

    if frame_type is FrameType.DIAGNOSTIC:
      layout = self._diagnostic_layout
      if not layout:
        raise ProtocolError("DIAGNOSTIC record is forbidden for this operation")
      if set(self._magic) != {0, 1} or self._statuses:
        raise ProtocolError("FACI diagnostic is out of sequence")
      slot = data[1]
      if slot != len(self._faci_values) or slot >= len(layout):
        raise ProtocolError("unexpected DIAGNOSTIC slot")
      expected_width = layout[slot][2]
      if data[2] != expected_width:
        raise ProtocolError("DIAGNOSTIC width does not match the register contract")
      if data[3] != 0:
        raise ProtocolError("DIAGNOSTIC padding is nonzero")
      value = struct.unpack_from("<I", data, 4)[0]
      if value >= (1 << (expected_width * 8)):
        raise ProtocolError("DIAGNOSTIC value is not zero-extended")
      self._faci_values.append(value)
      return

    if frame_type is FrameType.STATUS:
      stage = data[1]
      code = struct.unpack_from("<I", data, 4)[0]
      if data[2:4] != b"\x00\x00":
        raise ProtocolError("STATUS padding is nonzero")
      if not (self._has_diagnostic_outcome or self._has_patch_v2_outcome) and code != 0:
        raise ProtocolError(f"nonzero STATUS at stage {stage}: 0x{code:08x}")
      if self._expected_operation == OP_RAM_ECHO:
        if stage != 1 or self._statuses:
          raise ProtocolError("RAM echo stream requires one stage-1 STATUS")
      if self._has_diagnostic_outcome:
        if stage != 1:
          raise ProtocolError("FACI diagnostic STATUS must use stage 1")
        if self._statuses:
          raise ProtocolError("FACI diagnostic stream has duplicate STATUS")
      if self._has_patch_v2_outcome:
        expected_stage = len(self._statuses) + 1
        if stage != expected_stage or stage > 6:
          raise ProtocolError(
            f"{self._destructive_operation_name} STATUS stage {stage} is out of sequence; "
            f"expected stage {expected_stage}"
          )
      if self._diagnostic_layout and len(self._faci_values) != len(self._diagnostic_layout):
        raise ProtocolError("FACI diagnostic snapshot is incomplete")
      self._statuses.append((stage, code))
      return

    if frame_type is FrameType.END:
      result = data[1]
      if data[2:4] != b"\x00\x00" or result != 0:
        raise ProtocolError(f"payload END result is nonzero: {result}")
      if self._has_diagnostic_outcome:
        if len(self._statuses) != 1 or self._statuses[0][0] != 1:
          raise ProtocolError("FACI diagnostic stream requires exactly one stage-1 STATUS")
      if self._has_patch_v2_outcome:
        if tuple(stage for stage, _code in self._statuses) != (1, 2, 3, 4, 5, 6):
          raise ProtocolError(
            f"{self._destructive_operation_name} stream requires exactly six ordered STATUS stages"
          )
        if self._advertised_length == 0 and all(code == 0 for _stage, code in self._statuses):
          raise ProtocolError(
            f"successful {self._destructive_operation_name} stream requires a full target sector"
          )
      supplied_crc = struct.unpack_from("<I", data, 4)[0]
      actual_crc = binascii.crc32(self._sector)
      if supplied_crc != actual_crc:
        raise ProtocolError(
          f"sector CRC mismatch: supplied 0x{supplied_crc:08x}, actual 0x{actual_crc:08x}"
        )
      self._finished = True
      return
    raise ProtocolError(f"unexpected {frame_type.name} record in trailer")

  def _validate_begin(self, data: bytes, *, sequence: int) -> None:
    if data[1] != PROTOCOL_VERSION:
      raise ProtocolError("unsupported protocol version")
    if data[2] != self._expected_operation:
      raise ProtocolError("payload operation does not match request")
    if data[3] != sequence:
      raise ProtocolError("invalid BEGIN sequence")

  def finish(self) -> StreamResult:
    if not self._finished:
      raise ProtocolError("stream has no valid END record")
    if set(self._magic) != {0, 1}:
      raise ProtocolError("stream is missing one or both MAGIC records")
    if self._diagnostic_layout and len(self._faci_values) != len(self._diagnostic_layout):
      raise ProtocolError("FACI diagnostic snapshot is incomplete")
    if self._expected_operation == OP_PATCH and self._faci_values:
      raise ProtocolError("DIAGNOSTIC record is forbidden for patch operation")
    if self._has_diagnostic_outcome:
      if len(self._statuses) != 1 or self._statuses[0][0] != 1:
        raise ProtocolError("FACI diagnostic stream requires exactly one stage-1 STATUS")
    if self._has_patch_v2_outcome:
      if tuple(stage for stage, _code in self._statuses) != (1, 2, 3, 4, 5, 6):
        raise ProtocolError(
          f"{self._destructive_operation_name} stream requires exactly six ordered STATUS stages"
        )
    if self._expected_operation == OP_RAM_ECHO and self._statuses != [(1, 0)]:
      raise ProtocolError("RAM echo stream requires exactly one stage-1 STATUS")
    return StreamResult(
      operation=self._expected_operation,
      sector=None if self._advertised_length == 0 else bytes(self._sector),
      magic_words=(self._magic[0], self._magic[1]),
      statuses=tuple(self._statuses),
      faci_values=tuple(self._faci_values),
      regions=(
        (RegionResult(self._stream_base, bytes(self._sector)),)
        if self._expected_operation == OP_RESTORE_SECTOR
        and self._advertised_length != 0 and self._stream_base is not None
        else ()
      ),
    )


class CrcStreamCollector:
  """Fail-closed collector for the operation-specific two-region CRC stream."""

  _region_bases = (TARGET.sector_base, TARGET.crc_sector_base)

  def __init__(self, *, expected_operation: int):
    if type(expected_operation) is not int or expected_operation not in (
      OP_FACI_PE_CYCLE, OP_CRC_PROBE, OP_VERIFY_CRC, OP_PATCH_CRC,
      OP_CRC_INTERMEDIATE,
    ):
      raise ProtocolError("unknown CRC stream operation")
    self._expected_operation = expected_operation
    self._state = "BEGIN0"
    self._region_slot = 0
    self._region = bytearray()
    self._next_index = 0
    self._regions: list[RegionResult] = []
    self._crc_values: list[int] = []
    self._magic: list[int] = []
    self._faci_values: list[int] = []
    self._statuses: list[tuple[int, int]] = []
    self._finished = False

  def consume(self, can_id: int, bus: int, data: bytes) -> None:
    if can_id != TARGET.uds_response_id or bus != TARGET.bus:
      raise ProtocolError("unexpected CAN route")
    if len(data) != 8:
      raise ProtocolError("payload frame must be exactly 8 bytes")
    if self._finished:
      raise ProtocolError("trailing frame after END")
    try:
      frame_type = FrameType(data[0])
    except ValueError as exc:
      raise ProtocolError(f"unknown frame type 0x{data[0]:02x}") from exc
    if frame_type is FrameType.ERROR:
      stage = data[1]
      code = struct.unpack_from("<I", data, 4)[0]
      raise ProtocolError(f"payload error at stage {stage}: 0x{code:08x}")

    if self._state == "BEGIN0":
      if frame_type is not FrameType.BEGIN0:
        raise ProtocolError("expected BEGIN0")
      self._validate_header(data, sequence=0)
      if struct.unpack_from("<I", data, 4)[0] != TARGET.crc_range_start:
        raise ProtocolError("BEGIN0 CRC range start does not match target")
      self._state = "BEGIN1"
      return
    if self._state == "BEGIN1":
      if frame_type is not FrameType.BEGIN1:
        raise ProtocolError("expected BEGIN1")
      self._validate_header(data, sequence=1)
      if struct.unpack_from("<I", data, 4)[0] != 2:
        raise ProtocolError("BEGIN1 CRC region count must be exactly two")
      self._state = "REGION_BEGIN"
      return
    if self._state == "REGION_BEGIN":
      if frame_type is not FrameType.REGION_BEGIN:
        raise ProtocolError("expected REGION_BEGIN")
      self._validate_region_header(data)
      if struct.unpack_from("<I", data, 4)[0] != self._region_bases[self._region_slot]:
        raise ProtocolError("REGION_BEGIN base does not match target")
      self._state = "REGION_LENGTH"
      return
    if self._state == "REGION_LENGTH":
      if frame_type is not FrameType.REGION_LENGTH:
        raise ProtocolError("expected REGION_LENGTH")
      self._validate_region_header(data)
      if struct.unpack_from("<I", data, 4)[0] != TARGET.sector_length:
        raise ProtocolError("REGION_LENGTH does not match target sector")
      self._region.clear()
      self._next_index = 0
      self._state = "DATA"
      return
    if self._state == "DATA":
      if frame_type is not FrameType.DATA:
        raise ProtocolError("stream ended before complete region DATA")
      index = struct.unpack_from("<H", data, 1)[0]
      if data[3] != 0 or index != self._next_index or index >= WORD_COUNT:
        raise ProtocolError(f"unexpected DATA index {index}, expected {self._next_index}")
      self._region.extend(data[4:8])
      self._next_index += 1
      if self._next_index == WORD_COUNT:
        self._state = "REGION_END"
      return
    if self._state == "REGION_END":
      if frame_type is not FrameType.REGION_END:
        raise ProtocolError("expected REGION_END")
      self._validate_region_header(data)
      supplied_crc = struct.unpack_from("<I", data, 4)[0]
      actual_crc = binascii.crc32(self._region)
      if supplied_crc != actual_crc:
        raise ProtocolError(
          f"region CRC mismatch: supplied 0x{supplied_crc:08x}, actual 0x{actual_crc:08x}"
        )
      self._regions.append(RegionResult(self._region_bases[self._region_slot], bytes(self._region)))
      self._region_slot += 1
      self._state = "REGION_BEGIN" if self._region_slot < 2 else "CRC_RECORD"
      return
    if self._state == "CRC_RECORD":
      if frame_type is not FrameType.CRC_RECORD:
        raise ProtocolError("expected CRC_RECORD")
      slot = data[1]
      if data[2:4] != b"\x04\x00" or slot != len(self._crc_values) or slot >= len(CRC_RECORDS):
        raise ProtocolError("invalid, duplicate, or out-of-sequence CRC record")
      self._crc_values.append(struct.unpack_from("<I", data, 4)[0])
      if len(self._crc_values) == len(CRC_RECORDS):
        self._state = "MAGIC"
      return
    if self._state == "MAGIC":
      if frame_type is not FrameType.MAGIC:
        raise ProtocolError("expected MAGIC")
      slot = data[1]
      if data[2:4] != b"\x00\x00" or slot != len(self._magic) or slot > 1:
        raise ProtocolError("invalid or out-of-sequence MAGIC record")
      value = struct.unpack_from("<I", data, 4)[0]
      if self._expected_operation == OP_CRC_INTERMEDIATE and value != TARGET.magic_word:
        raise ProtocolError("CRC intermediate MAGIC value does not match target")
      self._magic.append(value)
      if len(self._magic) == 2:
        self._state = (
          "DIAGNOSTIC" if self._expected_operation == OP_FACI_PE_CYCLE else "STATUS"
        )
      return
    if self._state == "DIAGNOSTIC":
      if frame_type is not FrameType.DIAGNOSTIC:
        raise ProtocolError("expected DIAGNOSTIC")
      slot = data[1]
      if slot != len(self._faci_values) or slot >= len(FACI_PE_CYCLE_DIAGNOSTICS):
        raise ProtocolError("invalid or out-of-sequence FACI DIAGNOSTIC slot")
      width = FACI_PE_CYCLE_DIAGNOSTICS[slot][2]
      value = struct.unpack_from("<I", data, 4)[0]
      if data[2] != width or data[3] != 0 or value >= (1 << (width * 8)):
        raise ProtocolError("FACI DIAGNOSTIC width, padding, or value is invalid")
      self._faci_values.append(value)
      if len(self._faci_values) == len(FACI_PE_CYCLE_DIAGNOSTICS):
        self._state = "STATUS"
      return
    if self._state == "STATUS":
      if frame_type is not FrameType.STATUS:
        raise ProtocolError("expected STATUS")
      stage = data[1]
      code = struct.unpack_from("<I", data, 4)[0]
      expected_stage = len(self._statuses) + 1
      status_count = len(PATCH_CRC_STAGES) if self._expected_operation == OP_PATCH_CRC else 1
      if data[2:4] != b"\x00\x00" or stage != expected_stage or stage > status_count:
        raise ProtocolError("CRC stream STATUS is out of sequence")
      if self._expected_operation not in (OP_PATCH_CRC, OP_FACI_PE_CYCLE) and code != 0:
        raise ProtocolError("CRC stream requires zero STATUS at stage 1")
      self._statuses.append((stage, code))
      if len(self._statuses) == status_count:
        self._state = "END"
      return
    if self._state == "END":
      if frame_type is not FrameType.END:
        raise ProtocolError("expected END")
      if data[1:4] != b"\x00\x00\x00":
        raise ProtocolError("payload END result is nonzero")
      supplied_crc = struct.unpack_from("<I", data, 4)[0]
      actual_crc = binascii.crc32(b"".join(region.data for region in self._regions))
      if supplied_crc != actual_crc:
        raise ProtocolError(
          f"combined region CRC mismatch: supplied 0x{supplied_crc:08x}, actual 0x{actual_crc:08x}"
        )
      self._finished = True
      return
    raise ProtocolError("invalid CRC stream state")

  def _validate_header(self, data: bytes, *, sequence: int) -> None:
    if data[1] != PROTOCOL_VERSION:
      raise ProtocolError("unsupported protocol version")
    if data[2] != self._expected_operation:
      raise ProtocolError("payload operation does not match request")
    if data[3] != sequence:
      raise ProtocolError("invalid BEGIN sequence")

  def _validate_region_header(self, data: bytes) -> None:
    if data[1] != PROTOCOL_VERSION:
      raise ProtocolError("unsupported protocol version")
    if data[2] != self._expected_operation:
      raise ProtocolError("payload operation does not match request")
    if data[3] != self._region_slot:
      raise ProtocolError("region slot is out of sequence")

  def finish(self) -> StreamResult:
    if not self._finished:
      raise ProtocolError("stream has no valid END record")
    values = tuple(self._crc_values)
    return StreamResult(
      operation=self._expected_operation,
      sector=None,
      magic_words=(self._magic[0], self._magic[1]),
      statuses=tuple(self._statuses),
      faci_values=tuple(self._faci_values),
      regions=tuple(self._regions),
      crc_values=values,
      crc=CrcObservation.from_values(values),
    )


def validate_crc_intermediate(
  result: StreamResult, *, staged_candidate: bytes,
) -> CrcObservation:
  """Validate every semantic claim in one complete intermediate-state result."""
  if (
    type(result) is not StreamResult or type(result.operation) is not int
    or result.operation != OP_CRC_INTERMEDIATE
  ):
    raise ProtocolError("intermediate result has the wrong operation")
  if type(staged_candidate) is not bytes or len(staged_candidate) != TARGET.sector_length:
    raise ProtocolError("intermediate staged candidate must be one immutable sector")
  if (
    result.magic_words != (TARGET.magic_word, TARGET.magic_word)
    or result.statuses != ((1, 0),)
    or type(result.regions) is not tuple or len(result.regions) != 2
    or any(type(region) is not RegionResult for region in result.regions)
    or tuple(region.base for region in result.regions)
      != (TARGET.sector_base, TARGET.crc_sector_base)
    or any(type(region.data) is not bytes or len(region.data) != TARGET.sector_length
           for region in result.regions)
    or type(result.crc) is not CrcObservation
  ):
    raise ProtocolError("intermediate stream structure or target magic is invalid")

  target_sector, crc_sector = (region.data for region in result.regions)
  if (
    target_sector[TARGET.instruction_offset:TARGET.instruction_offset + 4]
      != TARGET.patched_instruction
    or crc_sector[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4]
      != bytes.fromhex("7f886209")
    or crc_sector[0x7E00:0x7E04] != TARGET.magic_word.to_bytes(4, "little")
    or staged_candidate[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4]
      != bytes.fromhex("24cef4d1")
    or staged_candidate[0x7E00:0x7E04] != TARGET.magic_word.to_bytes(4, "little")
  ):
    raise ProtocolError("intermediate live or staged sector context is invalid")

  crc = result.crc
  values = tuple(getattr(crc, name.lower()) for name in CRC_RECORDS)
  if (
    type(result.crc_values) is not tuple or len(result.crc_values) != len(CRC_RECORDS)
    or any(
      type(value) is not int or not 0 <= value <= 0xFFFFFFFF
      for value in result.crc_values
    )
  ):
    raise ProtocolError("intermediate CRC record tuple elements must be exact uint32 values")
  if result.crc_values != values:
    raise ProtocolError("intermediate CRC record tuple does not match its observation")
  if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in values):
    raise ProtocolError("intermediate CRC evidence fields must be exact uint32 values")
  if (
    crc.range_start != TARGET.crc_range_start
    or crc.range_end != TARGET.crc_range_end
    or crc.adjust_address != TARGET.crc_adjust_address
    or crc.old_adjust_word != 0x0962887F
    or crc.new_adjust_word != 0xD1F4CE24
    or crc.patched_prefix_sw != (crc.new_adjust_word ^ 0xFFFFFFFF)
    or crc.original_sw_full != crc.original_dcra_raw
    or crc.original_sw_full == 0xFFFFFFFF
    or crc.patched_sw_full != 0xFFFFFFFF
    or crc.patched_dcra_raw != 0xFFFFFFFF
    or crc.exit_ctl != crc.entry_ctl
    or crc.exit_cout != crc.entry_cout
    or crc.sram_echo_length != TARGET.sector_length
    or crc.sram_echo_crc32 != binascii.crc32(staged_candidate)
  ):
    raise ProtocolError("intermediate CRC/DCRA/SRAM evidence is inconsistent")
  return crc


def decode_patch_crc_statuses(statuses: tuple[tuple[int, int], ...]) -> dict[str, int]:
  if type(statuses) is not tuple or len(statuses) != len(PATCH_CRC_STAGES):
    raise ProtocolError("patch-crc requires exactly twelve STATUS records")
  decoded: dict[str, int] = {}
  for expected, (record, name) in enumerate(zip(statuses, PATCH_CRC_STAGES), start=1):
    if type(record) is not tuple or len(record) != 2:
      raise ProtocolError("patch-crc STATUS record is malformed")
    stage, code = record
    if type(stage) is not int or stage != expected or type(code) is not int or not 0 <= code <= 0xFFFFFFFF:
      raise ProtocolError("patch-crc STATUS record is invalid or out of sequence")
    decoded[name] = code
  return decoded


def decode_candidate_writer_statuses(
  operation: int, statuses: tuple[tuple[int, int], ...],
) -> dict[str, int]:
  if type(operation) is not int or operation not in (
    OP_WRITE_TARGET_CANDIDATE, OP_WRITE_CRC_CANDIDATE,
  ):
    raise ProtocolError("candidate-writer operation is not exact")
  if type(statuses) is not tuple or len(statuses) != len(CANDIDATE_WRITER_STAGES):
    raise ProtocolError("candidate-writer requires exactly six STATUS records")
  decoded: dict[str, int] = {}
  for expected, (record, name) in enumerate(
    zip(statuses, CANDIDATE_WRITER_STAGES), start=1,
  ):
    if type(record) is not tuple or len(record) != 2:
      raise ProtocolError("candidate-writer STATUS record is malformed")
    stage, code = record
    if (
      type(stage) is not int or stage != expected
      or type(code) is not int or not 0 <= code <= 0xFFFFFFFF
    ):
      raise ProtocolError("candidate-writer STATUS record is invalid")
    decoded[name] = code
  return decoded


def require_candidate_writer_pass(result: StreamResult) -> StreamResult:
  """Apply the all-zero PASS policy only after a complete writer result exists."""
  if type(result) is not StreamResult:
    raise ProtocolError("candidate-writer PASS gate requires one exact StreamResult")
  codes = decode_candidate_writer_statuses(result.operation, result.statuses)
  expected_base = {
    OP_WRITE_TARGET_CANDIDATE: TARGET.sector_base,
    OP_WRITE_CRC_CANDIDATE: TARGET.crc_sector_base,
  }[result.operation]
  if (
    len(result.regions) != 1 or result.sector is None
    or result.regions[0].data != result.sector
    or result.regions[0].base != expected_base
    or len(result.sector) != TARGET.sector_length
    or result.magic_words != (TARGET.magic_word, TARGET.magic_word)
  ):
    raise ProtocolError("candidate-writer PASS gate requires one complete readback region")
  if any(codes.values()):
    raise CandidateWriterFailure(result, codes)
  return result


class CandidateWriterStreamCollector:
  """Strict complete readback for one compile-time fixed candidate writer."""

  _fixed_bases = {
    OP_WRITE_TARGET_CANDIDATE: TARGET.sector_base,
    OP_WRITE_CRC_CANDIDATE: TARGET.crc_sector_base,
  }

  def __init__(self, *, expected_operation: int):
    if type(expected_operation) is not int or expected_operation not in self._fixed_bases:
      raise ProtocolError("unknown candidate-writer stream operation")
    self._operation = expected_operation
    self._base = self._fixed_bases[expected_operation]
    self._state = "BEGIN0"
    self._sector = bytearray()
    self._next_index = 0
    self._magic: list[int] = []
    self._statuses: list[tuple[int, int]] = []
    self._finished = False

  def consume(self, can_id: int, bus: int, data: bytes) -> None:
    if can_id != TARGET.uds_response_id or bus != TARGET.bus:
      raise ProtocolError("unexpected CAN route")
    if type(data) is not bytes or len(data) != 8:
      raise ProtocolError("payload frame must be exactly 8 bytes")
    if self._finished:
      raise ProtocolError("trailing frame after END")
    try:
      frame_type = FrameType(data[0])
    except ValueError as exc:
      raise ProtocolError(f"unknown frame type 0x{data[0]:02x}") from exc
    if frame_type is FrameType.ERROR:
      raise ProtocolError(
        f"payload error at stage {data[1]}: 0x{struct.unpack_from('<I', data, 4)[0]:08x}"
      )
    if self._state == "BEGIN0":
      if frame_type is not FrameType.BEGIN0:
        raise ProtocolError("expected BEGIN0")
      self._header(data, 0)
      if struct.unpack_from("<I", data, 4)[0] != self._base:
        raise ProtocolError("candidate-writer base does not match its fixed template")
      self._state = "BEGIN1"
      return
    if self._state == "BEGIN1":
      if frame_type is not FrameType.BEGIN1:
        raise ProtocolError("expected BEGIN1")
      self._header(data, 1)
      if struct.unpack_from("<I", data, 4)[0] != TARGET.sector_length:
        raise ProtocolError("candidate-writer length does not match one sector")
      self._state = "DATA"
      return
    if self._state == "DATA":
      if frame_type is not FrameType.DATA:
        raise ProtocolError("candidate-writer stream ended before complete DATA")
      index = struct.unpack_from("<H", data, 1)[0]
      if data[3] != 0 or index != self._next_index or index >= WORD_COUNT:
        raise ProtocolError(
          f"unexpected candidate-writer DATA index {index}, expected {self._next_index}"
        )
      self._sector.extend(data[4:8])
      self._next_index += 1
      if self._next_index == WORD_COUNT:
        self._state = "MAGIC"
      return
    if self._state == "MAGIC":
      if frame_type is not FrameType.MAGIC:
        raise ProtocolError("expected MAGIC")
      slot = data[1]
      if data[2:4] != b"\x00\x00" or slot != len(self._magic) or slot > 1:
        raise ProtocolError("invalid candidate-writer MAGIC record")
      value = struct.unpack_from("<I", data, 4)[0]
      if value != TARGET.magic_word:
        raise ProtocolError("candidate-writer MAGIC value does not match target")
      self._magic.append(value)
      if len(self._magic) == 2:
        self._state = "STATUS"
      return
    if self._state == "STATUS":
      if frame_type is not FrameType.STATUS:
        raise ProtocolError("expected STATUS")
      stage = data[1]
      code = struct.unpack_from("<I", data, 4)[0]
      if (
        data[2:4] != b"\x00\x00" or stage != len(self._statuses) + 1
        or stage > len(CANDIDATE_WRITER_STAGES)
      ):
        raise ProtocolError("candidate-writer STATUS is out of sequence")
      self._statuses.append((stage, code))
      if len(self._statuses) == len(CANDIDATE_WRITER_STAGES):
        self._state = "END"
      return
    if self._state == "END":
      if frame_type is not FrameType.END:
        raise ProtocolError("expected END")
      if data[1:4] != b"\x00\x00\x00":
        raise ProtocolError("candidate-writer END result is nonzero")
      supplied = struct.unpack_from("<I", data, 4)[0]
      if supplied != binascii.crc32(self._sector):
        raise ProtocolError("candidate-writer readback CRC does not match")
      self._finished = True
      return
    raise ProtocolError("invalid candidate-writer stream state")

  def _header(self, data: bytes, sequence: int) -> None:
    if (
      data[1] != PROTOCOL_VERSION or data[2] != self._operation
      or data[3] != sequence
    ):
      raise ProtocolError("candidate-writer header does not match request")

  def finish(self) -> StreamResult:
    if not self._finished or len(self._sector) != TARGET.sector_length:
      raise ProtocolError("candidate-writer stream has no valid END record")
    statuses = tuple(self._statuses)
    decode_candidate_writer_statuses(self._operation, statuses)
    sector = bytes(self._sector)
    return StreamResult(
      operation=self._operation,
      sector=sector,
      magic_words=(self._magic[0], self._magic[1]),
      statuses=statuses,
      regions=(RegionResult(self._base, sector),),
    )


class RestoreSectorStreamCollector:
  """Strict complete one-region readback for the bounded recovery payload."""

  def __init__(self, *, expected_operation: int):
    if type(expected_operation) is not int or expected_operation != OP_RESTORE_SECTOR:
      raise ProtocolError("unknown restore-sector stream operation")
    self._state = "BEGIN0"
    self._base: int | None = None
    self._sector = bytearray()
    self._next_index = 0
    self._magic: list[int] = []
    self._statuses: list[tuple[int, int]] = []
    self._finished = False

  def consume(self, can_id: int, bus: int, data: bytes) -> None:
    if can_id != TARGET.uds_response_id or bus != TARGET.bus:
      raise ProtocolError("unexpected CAN route")
    if len(data) != 8:
      raise ProtocolError("payload frame must be exactly 8 bytes")
    if self._finished:
      raise ProtocolError("trailing frame after END")
    try:
      frame_type = FrameType(data[0])
    except ValueError as exc:
      raise ProtocolError(f"unknown frame type 0x{data[0]:02x}") from exc
    if frame_type is FrameType.ERROR:
      stage = data[1]
      code = struct.unpack_from("<I", data, 4)[0]
      raise ProtocolError(f"payload error at stage {stage}: 0x{code:08x}")
    if self._state == "BEGIN0":
      if frame_type is not FrameType.BEGIN0:
        raise ProtocolError("expected BEGIN0")
      self._header(data, sequence=0)
      base = struct.unpack_from("<I", data, 4)[0]
      if base not in (TARGET.sector_base, TARGET.crc_sector_base):
        raise ProtocolError("restore-sector base is not allowlisted")
      self._base = base
      self._state = "BEGIN1"
      return
    if self._state == "BEGIN1":
      if frame_type is not FrameType.BEGIN1:
        raise ProtocolError("expected BEGIN1")
      self._header(data, sequence=1)
      if struct.unpack_from("<I", data, 4)[0] != TARGET.sector_length:
        raise ProtocolError("restore-sector region length does not match one sector")
      self._state = "DATA"
      return
    if self._state == "DATA":
      if frame_type is not FrameType.DATA:
        raise ProtocolError("restore-sector stream ended before complete DATA")
      index = struct.unpack_from("<H", data, 1)[0]
      if data[3] != 0 or index != self._next_index or index >= WORD_COUNT:
        raise ProtocolError(
          f"unexpected restore-sector DATA index {index}, expected {self._next_index}"
        )
      self._sector.extend(data[4:8])
      self._next_index += 1
      if self._next_index == WORD_COUNT:
        self._state = "MAGIC"
      return
    if self._state == "MAGIC":
      if frame_type is not FrameType.MAGIC:
        raise ProtocolError("expected MAGIC")
      slot = data[1]
      if data[2:4] != b"\x00\x00" or slot != len(self._magic) or slot > 1:
        raise ProtocolError("invalid restore-sector MAGIC record")
      self._magic.append(struct.unpack_from("<I", data, 4)[0])
      if len(self._magic) == 2:
        self._state = "STATUS"
      return
    if self._state == "STATUS":
      if frame_type is not FrameType.STATUS:
        raise ProtocolError("expected STATUS")
      stage = data[1]
      code = struct.unpack_from("<I", data, 4)[0]
      if data[2:4] != b"\x00\x00" or stage != len(self._statuses) + 1 or stage > 6:
        raise ProtocolError("restore-sector STATUS stage is out of sequence")
      self._statuses.append((stage, code))
      if len(self._statuses) == 6:
        self._state = "END"
      return
    if self._state == "END":
      if frame_type is not FrameType.END:
        raise ProtocolError("expected END")
      if data[1:4] != b"\x00\x00\x00":
        raise ProtocolError("restore-sector END result is nonzero")
      supplied = struct.unpack_from("<I", data, 4)[0]
      actual = binascii.crc32(self._sector)
      if supplied != actual:
        raise ProtocolError("restore-sector readback CRC does not match")
      self._finished = True
      return
    raise ProtocolError("invalid restore-sector stream state")

  @staticmethod
  def _header(data: bytes, *, sequence: int) -> None:
    if data[1] != PROTOCOL_VERSION or data[2] != OP_RESTORE_SECTOR or data[3] != sequence:
      raise ProtocolError("restore-sector header does not match request")

  def finish(self) -> StreamResult:
    if not self._finished or self._base is None or len(self._sector) != TARGET.sector_length:
      raise ProtocolError("restore-sector stream has no valid END record")
    sector = bytes(self._sector)
    return StreamResult(
      operation=OP_RESTORE_SECTOR,
      sector=sector,
      magic_words=(self._magic[0], self._magic[1]),
      statuses=tuple(self._statuses),
      regions=(RegionResult(self._base, sector),),
    )
