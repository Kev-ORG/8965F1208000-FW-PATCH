"""Typed fixed-direction candidate-writer intent and offline fault model."""

from __future__ import annotations

import binascii
import hashlib
import struct
from dataclasses import dataclass

from .manifest import TARGET
from .protocol import OP_WRITE_CRC_CANDIDATE, OP_WRITE_TARGET_CANDIDATE


CANDIDATE_INTENT_MAGIC = 0x57524954
CANDIDATE_INTENT_SCHEMA = 1
CANDIDATE_INTENT_LENGTH = 0x80
CANDIDATE_INTENT_CRC_OFFSET = 124
_TARGET_CONTEXT_TAG = 0x54524754
_CRC_CONTEXT_TAG = 0x43524353
ORIGINAL_ADJUSTMENT = bytes.fromhex("7f886209")
CANDIDATE_ADJUSTMENT = bytes.fromhex("cc474f41")


class CandidateWriterError(RuntimeError):
  pass


@dataclass(frozen=True, slots=True)
class CandidateWriterIntent:
  operation: int
  sector_base: int
  live_target_crc32: int
  live_crc_crc32: int
  staged_candidate_crc32: int
  live_target_instruction: bytes
  live_adjustment: bytes
  staged_context: bytes
  candidate_adjustment: bytes

  @classmethod
  def for_target(cls, **values) -> "CandidateWriterIntent":
    return cls(
      operation=OP_WRITE_TARGET_CANDIDATE,
      sector_base=TARGET.sector_base,
      **values,
    )

  @classmethod
  def for_crc(cls, **values) -> "CandidateWriterIntent":
    return cls(
      operation=OP_WRITE_CRC_CANDIDATE,
      sector_base=TARGET.crc_sector_base,
      **values,
    )

  def to_bytes(self) -> bytes:
    expected = {
      OP_WRITE_TARGET_CANDIDATE: (TARGET.sector_base, 1, _TARGET_CONTEXT_TAG),
      OP_WRITE_CRC_CANDIDATE: (TARGET.crc_sector_base, 2, _CRC_CONTEXT_TAG),
    }
    if type(self.operation) is not int or self.operation not in expected:
      raise CandidateWriterError("candidate writer operation is not exact")
    expected_base, direction, context_tag = expected[self.operation]
    if type(self.sector_base) is not int or self.sector_base != expected_base:
      raise CandidateWriterError("candidate writer base does not match its fixed template")
    numbers = (
      self.live_target_crc32,
      self.live_crc_crc32,
      self.staged_candidate_crc32,
    )
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in numbers):
      raise CandidateWriterError("candidate writer CRC32 fields must be exact uint32 values")
    contexts = (
      self.live_target_instruction,
      self.live_adjustment,
      self.staged_context,
      self.candidate_adjustment,
    )
    if any(type(value) is not bytes or len(value) != 4 for value in contexts):
      raise CandidateWriterError("candidate writer contexts must be immutable four-byte values")
    expected_contexts = (
      (TARGET.original_instruction, TARGET.patched_instruction)
      if self.operation == OP_WRITE_TARGET_CANDIDATE
      else (TARGET.patched_instruction, CANDIDATE_ADJUSTMENT)
    )
    if (
      self.live_target_instruction != expected_contexts[0]
      or self.staged_context != expected_contexts[1]
      or self.live_adjustment != ORIGINAL_ADJUSTMENT
      or self.candidate_adjustment != CANDIDATE_ADJUSTMENT
    ):
      raise CandidateWriterError("candidate writer context does not match its fixed transaction")
    block = bytearray(CANDIDATE_INTENT_LENGTH)
    struct.pack_into(
      "<IHHBBHIIIIII", block, 0,
      CANDIDATE_INTENT_MAGIC, CANDIDATE_INTENT_SCHEMA,
      CANDIDATE_INTENT_LENGTH, self.operation, direction, 0,
      self.sector_base, TARGET.sram_buffer, TARGET.sector_length,
      *numbers,
    )
    block[36:40] = self.live_target_instruction
    block[40:44] = self.live_adjustment
    block[44:48] = self.staged_context
    struct.pack_into("<II", block, 48, TARGET.magic_word, TARGET.magic_word)
    block[56:60] = self.candidate_adjustment
    struct.pack_into("<I", block, 60, context_tag)
    crc_input = bytearray(block)
    crc_input[CANDIDATE_INTENT_CRC_OFFSET:] = bytes(4)
    struct.pack_into(
      "<I", block, CANDIDATE_INTENT_CRC_OFFSET, binascii.crc32(crc_input),
    )
    return bytes(block)


@dataclass(frozen=True, slots=True)
class CandidateWriterPayloadImage:
  """One typed writer image bound to its fixed direction and staged sector."""

  operation: int
  sector_base: int
  staged_candidate: bytes
  staged_candidate_sha256: str
  intent: CandidateWriterIntent
  payload: object

  def validate(self):
    from .payload import REVIEWED_TEMPLATE_MANIFESTS, SpecializedPayloadImage

    expected = {
      OP_WRITE_TARGET_CANDIDATE: (TARGET.sector_base, "write_target_candidate"),
      OP_WRITE_CRC_CANDIDATE: (TARGET.crc_sector_base, "write_crc_candidate"),
    }
    if type(self.operation) is not int or self.operation not in expected:
      raise CandidateWriterError("candidate payload operation is not exact")
    expected_base, expected_name = expected[self.operation]
    if type(self.sector_base) is not int or self.sector_base != expected_base:
      raise CandidateWriterError("candidate payload metadata base is mislabeled")
    if type(self.intent) is not CandidateWriterIntent:
      raise CandidateWriterError("candidate payload intent has the wrong concrete type")
    if self.intent.operation != self.operation or self.intent.sector_base != expected_base:
      raise CandidateWriterError("candidate payload intent direction does not match metadata")
    if type(self.staged_candidate) is not bytes or len(self.staged_candidate) != TARGET.sector_length:
      raise CandidateWriterError("candidate payload staged sector is not exact")
    actual_sha = hashlib.sha256(self.staged_candidate).hexdigest()
    if (
      type(self.staged_candidate_sha256) is not str
      or self.staged_candidate_sha256 != actual_sha
      or binascii.crc32(self.staged_candidate) != self.intent.staged_candidate_crc32
    ):
      raise CandidateWriterError("candidate payload staged CRC/SHA metadata is inconsistent")
    if self.operation == OP_WRITE_TARGET_CANDIDATE:
      staged_context = self.staged_candidate[
        TARGET.instruction_offset:TARGET.instruction_offset + 4
      ]
      expected_context = TARGET.patched_instruction
    else:
      staged_context = self.staged_candidate[
        TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4
      ]
      expected_context = CANDIDATE_ADJUSTMENT
      if self.staged_candidate[0x7E00:0x7E04] != TARGET.magic_word.to_bytes(4, "little"):
        raise CandidateWriterError("CRC candidate staged boot magic is invalid")
    if staged_context != expected_context:
      raise CandidateWriterError("candidate payload staged direction context is invalid")
    if type(self.payload) is not SpecializedPayloadImage:
      raise CandidateWriterError("candidate payload image has the wrong concrete type")
    if (
      self.payload.name != expected_name
      or self.payload.manifest is not REVIEWED_TEMPLATE_MANIFESTS[expected_name]
      or self.payload.sector_base != expected_base
      or self.payload.backup_sha256 != actual_sha
      or self.payload.intent != self.intent.to_bytes()
    ):
      raise CandidateWriterError("candidate payload template/name/base/intent binding is invalid")
    self.payload.validate()
    return self.payload


def _build_candidate_payload_image(
  *, expected_operation: int, expected_name: str, template: bytes,
  manifest, intent: CandidateWriterIntent, staged_candidate: bytes,
) -> CandidateWriterPayloadImage:
  from .payload import REVIEWED_TEMPLATE_MANIFESTS, build_specialized_payload_image

  if type(intent) is not CandidateWriterIntent or intent.operation != expected_operation:
    raise CandidateWriterError("candidate payload intent is for the wrong direction")
  if manifest is not REVIEWED_TEMPLATE_MANIFESTS.get(expected_name):
    raise CandidateWriterError("candidate payload manifest is for the wrong direction")
  if type(staged_candidate) is not bytes or len(staged_candidate) != TARGET.sector_length:
    raise CandidateWriterError("candidate payload staged sector is not exact")
  expected_base = (
    TARGET.sector_base
    if expected_operation == OP_WRITE_TARGET_CANDIDATE else TARGET.crc_sector_base
  )
  staged_sha = hashlib.sha256(staged_candidate).hexdigest()
  payload = build_specialized_payload_image(
    template=template, manifest=manifest, intent=intent.to_bytes(),
    sector_base=expected_base, backup_sha256=staged_sha,
  )
  image = CandidateWriterPayloadImage(
    operation=expected_operation, sector_base=expected_base,
    staged_candidate=staged_candidate, staged_candidate_sha256=staged_sha,
    intent=intent, payload=payload,
  )
  image.validate()
  return image


def build_target_candidate_payload_image(
  *, template: bytes, manifest, intent: CandidateWriterIntent,
  staged_candidate: bytes,
) -> CandidateWriterPayloadImage:
  return _build_candidate_payload_image(
    expected_operation=OP_WRITE_TARGET_CANDIDATE,
    expected_name="write_target_candidate", template=template,
    manifest=manifest, intent=intent, staged_candidate=staged_candidate,
  )


def build_crc_candidate_payload_image(
  *, template: bytes, manifest, intent: CandidateWriterIntent,
  staged_candidate: bytes,
) -> CandidateWriterPayloadImage:
  return _build_candidate_payload_image(
    expected_operation=OP_WRITE_CRC_CANDIDATE,
    expected_name="write_crc_candidate", template=template,
    manifest=manifest, intent=intent, staged_candidate=staged_candidate,
  )


@dataclass(frozen=True, slots=True)
class CandidateWriterModelResult:
  final_result: str
  erase_counts: dict[int, int]
  programmed_bases: frozenset[int]
  attempts: int
  retries: int


def all_candidate_writer_fault_boundaries() -> tuple[str, ...]:
  return (
    "intent", "reserved", "fixed-base", "sram", "staged-crc",
    "live-target-crc", "live-crc-sector-crc", "source-context",
    "candidate-context", "idle-entry", "entry", "erase",
    *(f"program:{page}" for page in range(128)),
    "exit", "readback", "reporting", "lost-response", "malformed-result",
  )


def run_candidate_writer_fault_model(
  *, operation: int, failure: str,
) -> CandidateWriterModelResult:
  if type(operation) is not int or operation not in (
    OP_WRITE_TARGET_CANDIDATE, OP_WRITE_CRC_CANDIDATE,
  ):
    raise ValueError("unknown candidate-writer operation")
  if type(failure) is not str or failure not in all_candidate_writer_fault_boundaries():
    raise ValueError("unknown candidate-writer fault boundary")
  base = TARGET.sector_base if operation == OP_WRITE_TARGET_CANDIDATE else TARGET.crc_sector_base
  erase_counts = {TARGET.sector_base: 0, TARGET.crc_sector_base: 0}
  programmed: set[int] = set()
  prechecks = all_candidate_writer_fault_boundaries()[:10]
  if failure not in (*prechecks, "entry"):
    erase_counts[base] = 1
  if failure.startswith("program:") or failure in (
    "exit", "readback", "reporting", "lost-response", "malformed-result",
  ):
    programmed.add(base)
  result = "INDETERMINATE" if failure in (
    "erase", "exit", "readback", "reporting", "lost-response", "malformed-result",
  ) or failure.startswith("program:") else "FAIL"
  return CandidateWriterModelResult(
    final_result=result,
    erase_counts=erase_counts,
    programmed_bases=frozenset(programmed),
    attempts=1,
    retries=0,
  )


def recovery_actions_for_states(
  *, target_state: str, crc_state: str,
) -> tuple[str, ...]:
  known = {"source", "candidate", "other"}
  if type(target_state) is not str or type(crc_state) is not str:
    raise TypeError("recovery sector states must be strings")
  if target_state not in known or crc_state not in known:
    raise ValueError("recovery actions require exact known sector states")
  actions: list[str] = []
  if crc_state != "source":
    actions.append("restore-crc-source")
  if target_state != "source":
    actions.append("restore-target-source")
  return tuple(actions)


def classify_interruption(
  *, stage: str, target_state: str, crc_state: str,
) -> tuple[str, tuple[str, ...]]:
  if any(type(value) is not str for value in (stage, target_state, crc_state)):
    raise TypeError("interruption classification values must be strings")
  if stage not in ("target", "crc-ambiguous"):
    return "INDETERMINATE", ("classify-read-only",)
  if "unknown" in (target_state, crc_state):
    return "INDETERMINATE", ("classify-read-only",)
  known = {"source", "candidate", "other"}
  if target_state not in known or crc_state not in known:
    return "INDETERMINATE", ("classify-read-only",)
  if target_state == "candidate" and crc_state == "candidate":
    return "VERIFY_PENDING", ("final-read-only-verify",)
  actions = recovery_actions_for_states(
    target_state=target_state, crc_state=crc_state,
  )
  return ("RECOVERY_REQUIRED", actions) if actions else ("RECOVERY_COMPLETE", ())
