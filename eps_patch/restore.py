"""Automatic, fail-closed recovery from persisted patch incident state."""

from __future__ import annotations

import binascii
import hashlib
import json
import os
import re
import struct
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path

from .artifacts import _atomic_create, sha256_bytes
from .crc import build_crc_candidate
from .evidence import EvidenceError, TrustedProbeEvidence, load_probe_pass
from .manifest import TARGET, TargetManifest
from .operation_lock import exclusive_operation
from .paths import ArtifactLayout
from .payload import (
  REVIEWED_TEMPLATE_MANIFESTS,
  SpecializedPayloadImage,
  build_specialized_payload_image,
)
from .power import PowerCycleCheckpoint, request_power_cycle
from .protocol import OP_LIVE_READ, OP_RESTORE_SECTOR, RegionResult, StreamResult
from .transport import BootloaderIdentity, EcuIdentity


LIVE_READ_ENVELOPE_SHA256: str | None = (
  "4efdeeca07e98b3ae9f1df68b49521f9931b0938204d33ca543f6b78ccae4dd0"
)
RESTORE_INTENT_MAGIC = 0x52535452
RESTORE_INTENT_SCHEMA = 2
RESTORE_INTENT_LENGTH = 0x80
RESTORE_INTENT_CRC_OFFSET = 124
_ATTEMPT_TIMESTAMP = re.compile(r"\A\d{8}T\d{6}Z\Z")
_PATCH_STATE_KEYS_V1 = {
  "schema",
  "workflow",
  "attempt",
  "sequence",
  "result",
  "restore_order",
  "created_at",
  "updated_at",
  "probe_report_sha256",
  "automatic_forward_resume",
  "automatic_retry",
  "transitions",
  "validation_errors",
}
_PATCH_STATE_KEYS_V2 = _PATCH_STATE_KEYS_V1 | {"power_cycle"}
_RESTORE_STATE_KEYS_V1 = {
  "schema",
  "workflow",
  "attempt",
  "sequence",
  "result",
  "restore_order",
  "sector_bases",
  "completed_sector_bases",
  "created_at",
  "updated_at",
  "incident_timestamp",
  "incident_result",
  "incident_state_sha256",
  "probe_report_sha256",
  "automatic_retry",
  "external_recovery_required",
  "transitions",
  "validation_errors",
}
_RESTORE_STATE_KEYS_V2 = _RESTORE_STATE_KEYS_V1 | {"power_cycle"}
_PATCH_ORDERS: dict[str, tuple[tuple[str, ...], ...]] = {
  "STARTED": ((),),
  "PROBED": ((),),
  "TARGET_PRECHECKED": ((),),
  "TARGET_ARMED": (("target",),),
  "TARGET_INDETERMINATE": (("target",),),
  "TARGET_COMMITTED": (("target",),),
  "CRC_PRECHECKED": (("target",),),
  "CRC_ARMED": (("crc", "target"),),
  "CRC_INDETERMINATE": (("crc", "target"),),
  "CRC_COMMITTED": (("crc", "target"),),
  "VERIFY_PENDING": (("crc", "target"),),
  "RECOVERY_REQUIRED": (("target",), ("crc", "target")),
  "FAILED": ((),),
  "PASS": ((),),
}
_PATCH_NEXT = {
  "STARTED": {"PROBED", "FAILED"},
  "PROBED": {"TARGET_PRECHECKED", "FAILED"},
  "TARGET_PRECHECKED": {"TARGET_ARMED", "FAILED"},
  "TARGET_ARMED": {
    "TARGET_COMMITTED", "TARGET_INDETERMINATE", "RECOVERY_REQUIRED",
  },
  "TARGET_COMMITTED": {"CRC_PRECHECKED", "RECOVERY_REQUIRED"},
  "CRC_PRECHECKED": {"CRC_ARMED", "RECOVERY_REQUIRED"},
  "CRC_ARMED": {"CRC_COMMITTED", "CRC_INDETERMINATE", "RECOVERY_REQUIRED"},
  "CRC_INDETERMINATE": {"CRC_PRECHECKED", "CRC_COMMITTED"},
  "CRC_COMMITTED": {"VERIFY_PENDING", "RECOVERY_REQUIRED"},
  "VERIFY_PENDING": {"PASS", "RECOVERY_REQUIRED"},
  "PASS": {"RECOVERY_REQUIRED"},
}
_PATCH_FAILURE_STATES = {
  "FAILED", "TARGET_INDETERMINATE", "CRC_INDETERMINATE", "RECOVERY_REQUIRED",
}
_PATCH_RESUME_NEXT = {
  "PROBED": "TARGET_PRECHECKED",
  "TARGET_PRECHECKED": "TARGET_ARMED",
  "TARGET_COMMITTED": "CRC_PRECHECKED",
  "CRC_PRECHECKED": "CRC_ARMED",
  "CRC_COMMITTED": "VERIFY_PENDING",
}
_LEGACY_UNKNOWN_FRAME_ERROR = (
  "PostTriggerTransportError: post-trigger destructive outcome is indeterminate: "
  "invalid payload stream: unknown frame type 0x03"
)
_LEGACY_NRC31_ERROR = (
  "PostTriggerTransportError: post-trigger destructive outcome is indeterminate: "
  "RoutineControl negative response NRC 0x31; raw=037f313100000000"
)
_LEGACY_LIVE_READ_ENVELOPE_SHA256 = (
  "4efdeeca07e98b3ae9f1df68b49521f9931b0938204d33ca543f6b78ccae4dd0"
)


def _legacy_crc_trigger_recovery_status(
  transitions: list[dict[str, object]],
) -> str | None:
  """Recognize only the audited rejected-route CRC incident and its successor."""
  if type(transitions) is not list:
    return None
  incidents = [
    index for index, transition in enumerate(transitions)
    if type(transition) is dict and transition.get("result") == "CRC_INDETERMINATE"
  ]
  if len(incidents) == 3:
    _first_index, second_index, third_index = incidents
    if (
      third_index != len(transitions) - 1
      or third_index != second_index + 3
      or [
        transition.get("result") if type(transition) is dict else None
        for transition in transitions[second_index + 1:third_index]
      ] != ["CRC_PRECHECKED", "CRC_ARMED"]
      or _legacy_crc_trigger_recovery_status(transitions[:third_index])
        != "consumed"
    ):
      return None
    probed = next(
      (
        transition for transition in transitions[:incidents[0]]
        if type(transition) is dict and transition.get("result") == "PROBED"
      ),
      None,
    )
    probed_evidence = probed.get("evidence") if type(probed) is dict else None
    identity = (
      probed_evidence.get("identity")
      if type(probed_evidence) is dict else None
    )
    expected_boot_identity = (
      {
        "boot_software_id": identity.get("boot_software_id"),
        "panda_serial": identity.get("panda_serial"),
      }
      if type(identity) is dict else None
    )
    previous_arm_evidence = transitions[second_index - 1].get("evidence")
    final_arm_evidence = transitions[third_index - 1].get("evidence")
    writer_fields = (
      "operation", "sector_base", "source_sha256", "candidate_sha256",
      "candidate_crc32", "payload",
    )
    if (
      type(previous_arm_evidence) is not dict
      or type(final_arm_evidence) is not dict
      or expected_boot_identity is None
      or final_arm_evidence.get("identity") != expected_boot_identity
      or any(
        final_arm_evidence.get(name) != previous_arm_evidence.get(name)
        for name in writer_fields
      )
    ):
      return None
    return "restore-only"
  if len(incidents) != 2:
    return None
  first_index, second_index = incidents
  if (
    second_index != first_index + 3
    or [
      transition.get("result") if type(transition) is dict else None
      for transition in transitions[first_index + 1:second_index]
    ] != ["CRC_PRECHECKED", "CRC_ARMED"]
    or first_index < 1
  ):
    return None
  first = transitions[first_index]
  first_arm = transitions[first_index - 1]
  reconciliation = transitions[first_index + 1]
  second_arm = transitions[first_index + 2]
  second = transitions[second_index]
  probed = next(
    (
      transition for transition in transitions[:first_index]
      if type(transition) is dict and transition.get("result") == "PROBED"
    ),
    None,
  )
  if probed is None:
    return None
  probed_evidence = probed.get("evidence")
  reconciliation_evidence = reconciliation.get("evidence")
  arm_evidence = second_arm.get("evidence")
  first_arm_evidence = first_arm.get("evidence")
  if not all(
    type(evidence) is dict
    for evidence in (
      probed_evidence, first_arm_evidence, reconciliation_evidence, arm_evidence,
    )
  ):
    return None
  probed_identity = probed_evidence.get("identity")
  if (
    type(probed_identity) is not dict
    or set(probed_identity) != {
      "part_number", "application_software_id", "boot_software_id",
      "panda_serial",
    }
    or any(type(value) is not str or not value for value in probed_identity.values())
    or any(
      not _is_sha256(probed_evidence.get(name))
      for name in (
        "target_source_sha256", "crc_source_sha256",
        "target_candidate_sha256", "crc_candidate_sha256",
      )
    )
  ):
    return None
  expected_boot_identity = {
    "boot_software_id": probed_identity["boot_software_id"],
    "panda_serial": probed_identity["panda_serial"],
  }
  expected_live_read = {
    "name": "live_read", "sha256": _LEGACY_LIVE_READ_ENVELOPE_SHA256,
  }
  if (
    first.get("error") != _LEGACY_UNKNOWN_FRAME_ERROR
    or second.get("error") != _LEGACY_NRC31_ERROR
    or reconciliation_evidence.get("classification") != "source"
    or reconciliation_evidence.get("reconciled_from") != "CRC_INDETERMINATE"
    or reconciliation_evidence.get("reconciled_sequence") != first.get("sequence")
    or reconciliation_evidence.get("target_readback_sha256")
      != probed_evidence.get("target_candidate_sha256")
    or reconciliation_evidence.get("crc_readback_sha256")
      != probed_evidence.get("crc_source_sha256")
    or reconciliation_evidence.get("identity") != expected_boot_identity
    or reconciliation_evidence.get("payload") != expected_live_read
    or arm_evidence.get("operation") != 14
    or arm_evidence.get("sector_base") != "0xf8000"
    or arm_evidence.get("source_sha256") != probed_evidence.get("crc_source_sha256")
    or arm_evidence.get("candidate_sha256")
      != probed_evidence.get("crc_candidate_sha256")
    or arm_evidence.get("candidate_crc32")
      != first_arm_evidence.get("candidate_crc32")
    or arm_evidence.get("payload") != first_arm_evidence.get("payload")
    or arm_evidence.get("identity") != expected_boot_identity
  ):
    return None
  if second_index == len(transitions) - 1:
    return "pending"
  successor_index = second_index + 1
  if successor_index >= len(transitions):
    return None
  successor = transitions[successor_index]
  if type(successor) is not dict:
    return None
  evidence = successor.get("evidence")
  result = successor.get("result")
  expected_classification = {
    "CRC_PRECHECKED": "source",
    "CRC_COMMITTED": "candidate",
  }.get(result)
  if (
    type(evidence) is not dict
    or expected_classification is None
    or evidence.get("legacy_trigger_recovery") != "nrc31-route-v1"
    or evidence.get("legacy_trigger_rejection_sequence") != second.get("sequence")
    or evidence.get("reconciled_from") != "CRC_INDETERMINATE"
    or evidence.get("reconciled_sequence") != second.get("sequence")
    or evidence.get("classification") != expected_classification
    or evidence.get("target_readback_sha256")
      != probed_evidence.get("target_candidate_sha256")
    or evidence.get("crc_readback_sha256") != probed_evidence.get(
      "crc_source_sha256" if expected_classification == "source"
      else "crc_candidate_sha256"
    )
    or evidence.get("identity") != expected_boot_identity
    or evidence.get("payload") != expected_live_read
  ):
    return None
  return "consumed"


class RestoreError(RuntimeError):
  """Restore evidence, planning, identity, or one-shot execution was unsafe."""


class RestoreState(str, Enum):
  STARTED = "STARTED"
  CRC_LIVE_PRECHECKED = "CRC_LIVE_PRECHECKED"
  CRC_ARMED = "CRC_ARMED"
  CRC_COMMITTED = "CRC_COMMITTED"
  TARGET_LIVE_PRECHECKED = "TARGET_LIVE_PRECHECKED"
  TARGET_ARMED = "TARGET_ARMED"
  TARGET_COMMITTED = "TARGET_COMMITTED"
  FAILED = "FAILED"
  INDETERMINATE = "INDETERMINATE"
  PASS = "PASS"


class _PlannedPowerCycle(Exception):
  def __init__(self, path: Path, checkpoint: PowerCycleCheckpoint) -> None:
    super().__init__(checkpoint.completed_state)
    self.path = path
    self.checkpoint = checkpoint


@dataclass(frozen=True, slots=True)
class RestorePlan:
  incident_directory: Path
  incident_state_path: Path
  incident_timestamp: str
  incident_result: str
  restore_order: tuple[str, ...]
  sector_bases: tuple[int, ...]
  incident_state_sha256: str
  probe_report_sha256: str


@dataclass(frozen=True, slots=True)
class RestoreBackup:
  base: int
  label: str
  data: bytes
  sha256: str
  source_adjustment: bytes


@dataclass(frozen=True, slots=True)
class LiveReadClassification:
  target_state: str
  crc_state: str
  target_sha256: str
  crc_sha256: str

  def as_evidence(self) -> dict[str, dict[str, str]]:
    return {
      "target": {"state": self.target_state, "sha256": self.target_sha256},
      "crc": {"state": self.crc_state, "sha256": self.crc_sha256},
    }


class _StateRecorder:
  def __init__(
    self,
    directory: Path,
    *,
    timestamp: str,
    plan: RestorePlan,
    transitions: list[dict[str, object]] | None = None,
    completed: list[int] | None = None,
  ) -> None:
    self.path = directory / "state.json"
    self.timestamp = timestamp
    self.plan = plan
    self.transitions = list(transitions or [])
    self.completed = list(completed or [])

  def record(
    self,
    state: RestoreState,
    *,
    evidence: dict[str, object] | None = None,
    error: str | None = None,
    power_cycle: PowerCycleCheckpoint | None = None,
  ) -> Path:
    transition: dict[str, object] = {
      "sequence": len(self.transitions),
      "result": state.value,
      "recorded_at": _now(),
      "evidence": evidence or {},
    }
    if error is not None:
      transition["error"] = error
    self.transitions.append(transition)
    try:
      report: dict[str, object] = {
        "schema": 2,
        "workflow": "restore",
        "attempt": self.timestamp,
        "sequence": transition["sequence"],
        "result": state.value,
        "restore_order": list(self.plan.restore_order),
        "sector_bases": [f"0x{base:x}" for base in self.plan.sector_bases],
        "completed_sector_bases": [f"0x{base:x}" for base in self.completed],
        "created_at": self.transitions[0]["recorded_at"],
        "updated_at": transition["recorded_at"],
        "incident_timestamp": self.plan.incident_timestamp,
        "incident_result": self.plan.incident_result,
        "incident_state_sha256": self.plan.incident_state_sha256,
        "probe_report_sha256": self.plan.probe_report_sha256,
        "automatic_retry": False,
        "external_recovery_required": state is RestoreState.INDETERMINATE,
        "power_cycle": None if power_cycle is None else power_cycle.as_dict(),
        "transitions": self.transitions,
        "validation_errors": [] if error is None else [error],
      }
      _atomic_replace_json(self.path, report)
    except BaseException:
      self.transitions.pop()
      raise
    return self.path


def select_restore_plan(layout: ArtifactLayout) -> RestorePlan:
  """Select the newest persisted patch incident that canonically needs restore."""
  plans = _recoverable_restore_plans(layout)
  if plans:
    return plans[0]
  raise RestoreError("no recoverable persisted patch incident exists")


def _recoverable_restore_plans(layout: ArtifactLayout) -> tuple[RestorePlan, ...]:
  """Return every recoverable persisted patch incident, newest first."""
  if not isinstance(layout, ArtifactLayout):
    raise TypeError("layout must be an ArtifactLayout")
  try:
    entries = list(layout.patch_root.iterdir())
  except FileNotFoundError:
    entries = []
  except OSError as exc:
    raise RestoreError("cannot inspect persisted patch attempts") from exc
  plans = []
  for directory in sorted(entries, key=lambda path: path.name, reverse=True):
    if (
      _ATTEMPT_TIMESTAMP.fullmatch(directory.name) is None
      or not directory.is_dir()
      or directory.is_symlink()
    ):
      raise RestoreError("patch state layout contains an invalid attempt entry")
    state_path = directory / "state.json"
    state, raw = _load_patch_state(state_path, directory.name)
    order = tuple(state["restore_order"])
    if not order:
      continue
    bases = tuple(
      TARGET.crc_sector_base if name == "crc" else TARGET.sector_base
      for name in order
    )
    plans.append(
      RestorePlan(
        incident_directory=directory,
        incident_state_path=state_path,
        incident_timestamp=directory.name,
        incident_result=state["result"],
        restore_order=order,
        sector_bases=bases,
        incident_state_sha256=sha256_bytes(raw),
        probe_report_sha256=state["probe_report_sha256"],
      )
    )
  return tuple(plans)


def build_restore_intent(
  backup: RestoreBackup,
  *,
  target: TargetManifest = TARGET,
) -> bytes:
  """Bind one fixed reverse derivation to the reviewed restore template."""
  if type(backup) is not RestoreBackup:
    raise RestoreError("restore intent requires an exact RestoreBackup")
  if backup.base not in (target.sector_base, target.crc_sector_base):
    raise RestoreError("restore intent sector base is not allowlisted")
  if (
    type(backup.data) is not bytes
    or len(backup.data) != target.sector_length
    or sha256_bytes(backup.data) != backup.sha256
  ):
    raise RestoreError("restore intent backup hash or length changed")
  source = bytearray(backup.data)
  if backup.base == target.sector_base:
    source_context = target.patched_instruction
    candidate_context = target.original_instruction
    source[
      target.instruction_offset:target.instruction_offset + 4
    ] = source_context
  else:
    source_context = target.crc_patched_adjust_word.to_bytes(4, "little")
    candidate_context = target.crc_original_adjust_word.to_bytes(4, "little")
    source[
      target.crc_adjust_offset:target.crc_adjust_offset + 4
    ] = source_context
    if source[0x7E00:0x7E04] != target.magic_word.to_bytes(4, "little"):
      raise RestoreError("CRC restore source does not contain the fixed boot magic")
  block = bytearray(RESTORE_INTENT_LENGTH)
  struct.pack_into(
    "<IHHIII4s4sII",
    block,
    0,
    RESTORE_INTENT_MAGIC,
    RESTORE_INTENT_SCHEMA,
    RESTORE_INTENT_LENGTH,
    backup.base,
    binascii.crc32(source),
    binascii.crc32(backup.data),
    source_context,
    candidate_context,
    target.magic_word,
    target.magic_word,
  )
  crc_input = bytearray(block)
  crc_input[RESTORE_INTENT_CRC_OFFSET:] = bytes(4)
  struct.pack_into(
    "<I", block, RESTORE_INTENT_CRC_OFFSET, binascii.crc32(crc_input),
  )
  return bytes(block)


def run_restore(
  *,
  layout: ArtifactLayout,
  payloads,
  templates,
  preflight: Callable[[], object],
  transport_factory: Callable[[], object],
  confirmation: Callable[[str], object],
  power_cycle_checkpoint: Callable[[str], object],
  target: TargetManifest = TARGET,
  new_uds: bool,
) -> Path:
  """Run one restore while excluding every concurrent patch/restore process."""
  with exclusive_operation(layout, "restore"):
    return _run_restore_locked(
      layout=layout,
      payloads=payloads,
      templates=templates,
      preflight=preflight,
      transport_factory=transport_factory,
      confirmation=confirmation,
      power_cycle_checkpoint=power_cycle_checkpoint,
      target=target,
      new_uds=new_uds,
    )


def _run_restore_locked(
  *,
  layout: ArtifactLayout,
  payloads,
  templates,
  preflight: Callable[[], object],
  transport_factory: Callable[[], object],
  confirmation: Callable[[str], object],
  power_cycle_checkpoint: Callable[[str], object],
  target: TargetManifest = TARGET,
  new_uds: bool,
) -> Path:
  """Run one safe restore stage or persist one planned restart boundary."""
  _validate_inputs(
    layout=layout,
    preflight=preflight,
    transport_factory=transport_factory,
    confirmation=confirmation,
    power_cycle_checkpoint=power_cycle_checkpoint,
    target=target,
    new_uds=new_uds,
  )
  plan = select_restore_plan(layout)
  resume = _select_restore_resume(layout, plan)
  try:
    trusted = load_probe_pass(layout, target)
  except EvidenceError as exc:
    raise RestoreError(f"fixed probe evidence is not a semantic PASS: {exc}") from exc
  semantic_probe_digest = sha256_bytes(json.dumps(
    trusted.report,
    sort_keys=True,
    separators=(",", ":"),
  ).encode("utf-8"))
  if semantic_probe_digest != plan.probe_report_sha256:
    raise RestoreError("patch incident is not bound to the fixed probe evidence")
  live_read = _validate_live_read_payload(payloads, target)
  restore_template = _validate_restore_template(templates)
  backups = tuple(_backup_for_base(trusted, base, target) for base in plan.sector_bases)
  restore_images = tuple(
    _build_restore_payload(restore_template, backup, target)
    for backup in backups
  )
  backup_by_label = {backup.label: backup for backup in backups}
  image_by_label = {
    backup.label: image
    for backup, image in zip(backups, restore_images, strict=True)
  }
  if resume is None:
    preflight()
    timestamp, directory = _create_attempt(layout)
    recorder = _StateRecorder(directory, timestamp=timestamp, plan=plan)
    recorder.record(
      RestoreState.STARTED,
      evidence={
        "incident_state": str(plan.incident_state_path),
        "incident_state_sha256": plan.incident_state_sha256,
        "restore_order": list(plan.restore_order),
      },
    )
    entry = RestoreState.STARTED
  else:
    state, directory = resume
    timestamp = directory.name
    completed = [int(value, 16) for value in state["completed_sector_bases"]]
    recorder = _StateRecorder(
      directory,
      timestamp=timestamp,
      plan=plan,
      transitions=state["transitions"],
      completed=completed,
    )
    entry = RestoreState(state["result"])
  armed = any(
    transition["result"].endswith("_ARMED")
    for transition in recorder.transitions
  )
  planned: _PlannedPowerCycle | None = None
  try:
    if resume is not None:
      preflight()
    if entry is RestoreState.STARTED or entry is RestoreState.CRC_COMMITTED:
      label_name = plan.restore_order[0] if entry is RestoreState.STARTED else "target"
      backup = backup_by_label[label_name]
      live_precheck_state = (
        RestoreState.CRC_LIVE_PRECHECKED
        if backup.label == "crc" else RestoreState.TARGET_LIVE_PRECHECKED
      )
      with transport_factory() as transport:
        live_identity = transport.read_bootloader_identity()
        _require_boot_identity(live_identity, trusted.identity)
        live_result = transport.run_payload(
          live_read,
          operation=OP_LIVE_READ,
          new_uds=new_uds,
        )
      live_classification = _validate_live_precheck(
        live_result,
        plan=plan,
        trusted=trusted,
        completed=tuple(recorder.completed),
        target=target,
      )
      arm_state = (
        RestoreState.CRC_ARMED
        if backup.label == "crc" else RestoreState.TARGET_ARMED
      )
      checkpoint = PowerCycleCheckpoint(live_precheck_state.value, arm_state.value)
      path = recorder.record(
        live_precheck_state,
        evidence={
          "identity": _boot_identity_record(live_identity),
          "payload": _payload_record(live_read),
          "live_sectors": live_classification.as_evidence(),
        },
        power_cycle=checkpoint,
      )
      raise _PlannedPowerCycle(path, checkpoint)

    if entry not in (RestoreState.CRC_LIVE_PRECHECKED, RestoreState.TARGET_LIVE_PRECHECKED):
      raise RestoreError("restore state is not restart-resumable")
    label_name = "crc" if entry is RestoreState.CRC_LIVE_PRECHECKED else "target"
    backup = backup_by_label[label_name]
    image = image_by_label[label_name]
    arm_state = (
      RestoreState.CRC_ARMED
      if backup.label == "crc" else RestoreState.TARGET_ARMED
    )
    with transport_factory() as transport:
      writer_identity = transport.read_bootloader_identity()
      _require_boot_identity(writer_identity, trusted.identity)
      prompt = _restore_prompt(
        backup=backup,
        incident_sha256=plan.incident_state_sha256,
        envelope_sha256=image.sha256,
        target=target,
      )
      exact_confirmation = _require_exact_confirmation(confirmation, prompt)
      recorder.record(
        arm_state,
        evidence={
          "identity": _boot_identity_record(writer_identity),
          "confirmation": exact_confirmation,
          "operation": OP_RESTORE_SECTOR,
          "sector_base": f"0x{backup.base:x}",
          "backup_sha256": backup.sha256,
          "payload": _restore_payload_record(image),
        },
      )
      armed = True
      restore_result = transport.run_payload(
        image,
        operation=OP_RESTORE_SECTOR,
        new_uds=new_uds,
      )
    _validate_restore_result(restore_result, backup, target)
    returned_path = directory / f"returned-sector-0x{backup.base:x}.bin"
    _persist_sector(returned_path, restore_result.sector, target)
    recorder.completed.append(backup.base)
    committed_state = (
      RestoreState.CRC_COMMITTED
      if backup.label == "crc" else RestoreState.TARGET_COMMITTED
    )
    more_sectors = len(recorder.completed) < len(backups)
    checkpoint = (
      PowerCycleCheckpoint(
        committed_state.value, RestoreState.TARGET_LIVE_PRECHECKED.value,
      )
      if more_sectors else None
    )
    try:
      state_path = recorder.record(
        committed_state,
        evidence={
          "returned_file": returned_path.name,
          "returned_sha256": sha256_bytes(restore_result.sector),
          "statuses": _status_records(restore_result),
        },
        power_cycle=checkpoint,
      )
    except BaseException:
      recorder.completed.pop()
      raise
    if checkpoint is not None:
      raise _PlannedPowerCycle(state_path, checkpoint)

    report = {
      "schema": 1,
      "workflow": "restore",
      "result": "PASS",
      "created_at": _now(),
      "attempt": timestamp,
      "incident_timestamp": plan.incident_timestamp,
      "incident_state_sha256": plan.incident_state_sha256,
      "probe_report_sha256": plan.probe_report_sha256,
      "restore_order": list(plan.restore_order),
      "sectors": [
        {
          "base": f"0x{item.base:x}",
          "length": len(item.data),
          "sha256": item.sha256,
          "returned_file": f"returned-sector-0x{item.base:x}.bin",
        }
        for item in backups
      ],
      "automatic_retry": False,
      "validation_errors": [],
    }
    report_path = directory / "restore-report.json"
    _atomic_create(report_path, _json_bytes(report))
    recorder.record(
      RestoreState.PASS,
      evidence={"restore_report_sha256": sha256_bytes(report_path.read_bytes())},
    )
    return report_path
  except _PlannedPowerCycle as exc:
    planned = exc
  except BaseException as exc:
    failure_state = RestoreState.INDETERMINATE if armed else RestoreState.FAILED
    detail = f"{type(exc).__name__}: {exc}"
    try:
      recorder.record(failure_state, error=detail)
    except BaseException as state_exc:
      raise RestoreError(
        f"restore failed and canonical state could not be persisted: {state_exc}"
      ) from exc
    if failure_state is RestoreState.INDETERMINATE:
      raise RestoreError(
        "restore outcome is INDETERMINATE; do not retry; external programming "
        f"or professional recovery is required: {exc}"
      ) from exc
    raise RestoreError(f"restore stopped before any writer was armed: {exc}") from exc
  if planned is None:
    raise RestoreError("restore did not produce a report or planned checkpoint")
  request_power_cycle(
    planned.checkpoint.completed_state,
    planned.checkpoint.next_state,
    power_cycle_checkpoint,
  )
  return planned.path


def _load_patch_state(path: Path, timestamp: str) -> tuple[dict[str, object], bytes]:
  if path.is_symlink() or not path.is_file():
    raise RestoreError("patch state is missing or not a regular file")
  try:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
  except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise RestoreError("patch state is not readable UTF-8 JSON") from exc
  if (
    type(value) is not dict
    or set(value) not in (_PATCH_STATE_KEYS_V1, _PATCH_STATE_KEYS_V2)
  ):
    raise RestoreError("patch state does not have the exact canonical schema")
  schema = value["schema"]
  power_cycle = value.get("power_cycle")
  if (
    type(schema) is not int
    or schema not in (1, 2)
    or (schema == 1 and set(value) != _PATCH_STATE_KEYS_V1)
    or (schema == 2 and set(value) != _PATCH_STATE_KEYS_V2)
    or value["workflow"] != "patch"
    or value["attempt"] != timestamp
    or type(value["sequence"]) is not int
    or value["sequence"] < 0
    or type(value["result"]) is not str
    or value["result"] not in _PATCH_ORDERS
    or type(value["restore_order"]) is not list
    or tuple(value["restore_order"]) not in _PATCH_ORDERS[value["result"]]
    or not _is_utc_timestamp(value["created_at"])
    or not _is_utc_timestamp(value["updated_at"])
    or not _is_sha256(value["probe_report_sha256"])
    or value["automatic_forward_resume"] is not False
    or value["automatic_retry"] is not False
    or type(value["validation_errors"]) is not list
    or value["validation_errors"]
  ):
    raise RestoreError("patch state fields are malformed or contradictory")
  expected_resume = _PATCH_RESUME_NEXT.get(value["result"])
  if schema == 2 and (power_cycle is None) != (expected_resume is None):
    raise RestoreError("patch power-cycle checkpoint is missing or unexpected")
  if power_cycle is not None:
    try:
      checkpoint = PowerCycleCheckpoint.from_dict(power_cycle)
    except ValueError as exc:
      raise RestoreError("patch power-cycle checkpoint is malformed or unsafe") from exc
    if (
      schema != 2
      or checkpoint.completed_state != value["result"]
      or expected_resume != checkpoint.next_state
    ):
      raise RestoreError("patch power-cycle checkpoint is malformed or unsafe")
  transitions = value["transitions"]
  if type(transitions) is not list or len(transitions) != value["sequence"] + 1:
    raise RestoreError("patch state transition history is incomplete")
  for index, transition in enumerate(transitions):
    if type(transition) is not dict or set(transition) not in (
      {"sequence", "result", "recorded_at", "evidence"},
      {"sequence", "result", "recorded_at", "evidence", "error"},
    ):
      raise RestoreError("patch state transition schema is malformed")
    if (
      type(transition["sequence"]) is not int
      or transition["sequence"] != index
      or type(transition["result"]) is not str
      or transition["result"] not in _PATCH_ORDERS
      or not _is_utc_timestamp(transition["recorded_at"])
      or type(transition["evidence"]) is not dict
      or (
        "error" in transition
        and (type(transition["error"]) is not str or not transition["error"])
      )
    ):
      raise RestoreError("patch state transition fields are malformed")
    if transition["result"] in _PATCH_FAILURE_STATES:
      if "error" not in transition:
        raise RestoreError("patch state failure transition has no error evidence")
    elif not transition["evidence"] or "error" in transition:
      raise RestoreError("patch state normal transition evidence is incomplete")
  if transitions[0]["result"] != "STARTED" or any(
    current["result"] not in _PATCH_NEXT.get(previous["result"], set())
    for previous, current in zip(transitions, transitions[1:])
  ):
    raise RestoreError("patch state transition history is not reachable")
  legacy_recovery = _legacy_crc_trigger_recovery_status(transitions)
  crc_indeterminate_total = sum(
    transition["result"] == "CRC_INDETERMINATE" for transition in transitions
  )
  incident_errors = {
    transition.get("error")
    for transition in transitions
    if transition["result"] == "CRC_INDETERMINATE"
  }
  if (
    crc_indeterminate_total == 2
    and legacy_recovery is None
    and incident_errors & {_LEGACY_UNKNOWN_FRAME_ERROR, _LEGACY_NRC31_ERROR}
  ):
    raise RestoreError("patch state exceeds the one-time CRC retry limit")
  indeterminate_count = 0
  for previous, current in zip(transitions, transitions[1:]):
    if previous["result"] == "CRC_INDETERMINATE":
      indeterminate_count += 1
      if (
        indeterminate_count != 1
        and legacy_recovery not in {"consumed", "restore-only"}
        and current["result"] in {"CRC_PRECHECKED", "CRC_COMMITTED"}
      ):
        raise RestoreError("patch state exceeds the one-time CRC retry limit")
  if (
    transitions[-1]["result"] != value["result"]
    or transitions[0]["recorded_at"] != value["created_at"]
    or transitions[-1]["recorded_at"] != value["updated_at"]
  ):
    raise RestoreError("patch state transition history contradicts its summary")
  return value, raw


def _reject_prior_restore(
  layout: ArtifactLayout,
  plan: RestorePlan,
  *,
  allow_selected_pass: bool = False,
) -> bool | None:
  selected_pass = False
  try:
    entries = list(layout.restore_root.iterdir())
  except FileNotFoundError:
    return
  except OSError as exc:
    raise RestoreError("cannot inspect prior restore attempts") from exc
  for directory in sorted(entries, key=lambda path: path.name, reverse=True):
    if (
      _ATTEMPT_TIMESTAMP.fullmatch(directory.name) is None
      or not directory.is_dir()
      or directory.is_symlink()
    ):
      raise RestoreError("prior restore layout contains an invalid attempt entry")
    state_path = directory / "state.json"
    if state_path.is_symlink() or not state_path.is_file():
      raise RestoreError("an already-running restore attempt has no terminal state")
    try:
      state = _load_restore_state(state_path, directory.name)
    except RestoreError as exc:
      raise RestoreError("an already-running restore attempt has malformed state") from exc
    if state["result"] == RestoreState.INDETERMINATE.value:
      raise RestoreError(
        "a prior restore is INDETERMINATE; external programming or professional "
        "recovery is required"
      )
    if state["result"] == RestoreState.FAILED.value:
      continue
    if state["incident_timestamp"] == plan.incident_timestamp:
      if state["result"] == RestoreState.PASS.value:
        if allow_selected_pass:
          selected_pass = True
          continue
        raise RestoreError("the selected patch incident already has a PASS restore")
      if state["incident_state_sha256"] != plan.incident_state_sha256:
        raise RestoreError("selected patch incident changed after restore started")
      raise RestoreError("an already-running restore exists for the selected incident")
    if state["result"] != RestoreState.PASS.value:
      raise RestoreError("an already-running restore exists for a different incident")
  return selected_pass if allow_selected_pass else None


def _select_restore_resume(
  layout: ArtifactLayout,
  plan: RestorePlan,
) -> tuple[dict[str, object], Path] | None:
  """Select one exact planned restore checkpoint without relaxing one-shot guards."""
  try:
    entries = list(layout.restore_root.iterdir())
  except FileNotFoundError:
    return None
  except OSError as exc:
    raise RestoreError("cannot inspect prior restore attempts") from exc
  resumable: list[tuple[dict[str, object], Path]] = []
  for directory in sorted(entries, key=lambda path: path.name, reverse=True):
    if (
      _ATTEMPT_TIMESTAMP.fullmatch(directory.name) is None
      or not directory.is_dir()
      or directory.is_symlink()
    ):
      raise RestoreError("prior restore layout contains an invalid attempt entry")
    state_path = directory / "state.json"
    if state_path.is_symlink() or not state_path.is_file():
      raise RestoreError("an already-running restore attempt has no terminal state")
    try:
      state = _load_restore_state(state_path, directory.name)
    except RestoreError as exc:
      raise RestoreError("an already-running restore attempt has malformed state") from exc
    if state["result"] == RestoreState.INDETERMINATE.value:
      raise RestoreError(
        "a prior restore is INDETERMINATE; external programming or professional "
        "recovery is required"
      )
    if state["result"] == RestoreState.FAILED.value:
      continue
    if state["incident_timestamp"] == plan.incident_timestamp:
      if state["result"] == RestoreState.PASS.value:
        raise RestoreError("the selected patch incident already has a PASS restore")
      if state["incident_state_sha256"] != plan.incident_state_sha256:
        raise RestoreError("selected patch incident changed after restore started")
      if state["schema"] == 2 and state["power_cycle"] is not None:
        resumable.append((state, directory))
        continue
      raise RestoreError("an already-running restore exists for the selected incident")
    if state["result"] != RestoreState.PASS.value:
      raise RestoreError("an already-running restore exists for a different incident")
  if len(resumable) > 1:
    raise RestoreError("multiple resumable restore attempts exist")
  return resumable[0] if resumable else None


def _load_restore_state(path: Path, timestamp: str) -> dict[str, object]:
  try:
    state = json.loads(path.read_text(encoding="utf-8"))
  except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise RestoreError("restore state is not readable UTF-8 JSON") from exc
  if (
    type(state) is not dict
    or set(state) not in (_RESTORE_STATE_KEYS_V1, _RESTORE_STATE_KEYS_V2)
  ):
    raise RestoreError("restore state does not have the exact canonical schema")
  schema = state["schema"]
  power_cycle = state.get("power_cycle")
  order = state["restore_order"]
  if type(order) is not list or tuple(order) not in (
    ("target",), ("crc", "target"),
  ):
    raise RestoreError("restore state order is not canonical")
  bases = tuple(
    TARGET.crc_sector_base if label == "crc" else TARGET.sector_base
    for label in order
  )
  base_records = [f"0x{base:x}" for base in bases]
  result = state["result"]
  known_results = {item.value for item in RestoreState}
  if (
    type(schema) is not int
    or schema not in (1, 2)
    or (schema == 1 and set(state) != _RESTORE_STATE_KEYS_V1)
    or (schema == 2 and set(state) != _RESTORE_STATE_KEYS_V2)
    or state["workflow"] != "restore"
    or state["attempt"] != timestamp
    or type(state["sequence"]) is not int
    or state["sequence"] < 0
    or type(result) is not str
    or result not in known_results
    or state["sector_bases"] != base_records
    or type(state["completed_sector_bases"]) is not list
    or not _is_utc_timestamp(state["created_at"])
    or not _is_utc_timestamp(state["updated_at"])
    or type(state["incident_timestamp"]) is not str
    or _ATTEMPT_TIMESTAMP.fullmatch(state["incident_timestamp"]) is None
    or type(state["incident_result"]) is not str
    or state["incident_result"] not in _PATCH_ORDERS
    or tuple(order) not in _PATCH_ORDERS[state["incident_result"]]
    or not _is_sha256(state["incident_state_sha256"])
    or not _is_sha256(state["probe_report_sha256"])
    or state["automatic_retry"] is not False
    or type(state["external_recovery_required"]) is not bool
    or type(state["validation_errors"]) is not list
  ):
    raise RestoreError("restore state fields are malformed or contradictory")
  expected_next: str | None = None
  if result.endswith("_LIVE_PRECHECKED"):
    expected_next = result.removesuffix("_LIVE_PRECHECKED") + "_ARMED"
  elif result == RestoreState.CRC_COMMITTED.value and tuple(order) == ("crc", "target"):
    expected_next = RestoreState.TARGET_LIVE_PRECHECKED.value
  if schema == 2 and (power_cycle is None) != (expected_next is None):
    raise RestoreError("restore power-cycle checkpoint is missing or unexpected")
  if power_cycle is not None:
    try:
      checkpoint = PowerCycleCheckpoint.from_dict(power_cycle)
    except ValueError as exc:
      raise RestoreError("restore power-cycle checkpoint is malformed or unsafe") from exc
    if (
      schema != 2
      or expected_next is None
      or checkpoint.completed_state != result
      or checkpoint.next_state != expected_next
    ):
      raise RestoreError("restore power-cycle checkpoint is malformed or unsafe")
  transitions = state["transitions"]
  if type(transitions) is not list or len(transitions) != state["sequence"] + 1:
    raise RestoreError("restore state transition history is incomplete")
  happy_path = ["STARTED"]
  for label in order:
    upper = label.upper()
    happy_path.extend((
      f"{upper}_LIVE_PRECHECKED",
      f"{upper}_ARMED", f"{upper}_COMMITTED",
    ))
  happy_path.append("PASS")
  happy_index = 0
  armed_seen = False
  committed: list[str] = []
  for index, transition in enumerate(transitions):
    if type(transition) is not dict or set(transition) not in (
      {"sequence", "result", "recorded_at", "evidence"},
      {"sequence", "result", "recorded_at", "evidence", "error"},
    ):
      raise RestoreError("restore state transition schema is malformed")
    transition_result = transition["result"]
    if (
      type(transition["sequence"]) is not int
      or transition["sequence"] != index
      or type(transition_result) is not str
      or transition_result not in known_results
      or not _is_utc_timestamp(transition["recorded_at"])
      or type(transition["evidence"]) is not dict
      or (
        "error" in transition
        and (type(transition["error"]) is not str or not transition["error"])
      )
    ):
      raise RestoreError("restore state transition fields are malformed")
    if index == 0:
      if transition_result != "STARTED":
        raise RestoreError("restore state does not start at STARTED")
    elif transition_result == "FAILED":
      if armed_seen or index != len(transitions) - 1:
        raise RestoreError("restore FAILED state did not terminate before arm")
    elif transition_result == "INDETERMINATE":
      if not armed_seen or index != len(transitions) - 1:
        raise RestoreError("restore INDETERMINATE state has no prior arm")
    else:
      happy_index += 1
      if happy_index >= len(happy_path) or transition_result != happy_path[happy_index]:
        raise RestoreError("restore state transition history is not reachable")
    if transition_result.endswith("_ARMED"):
      armed_seen = True
    if transition_result.endswith("_COMMITTED"):
      label = transition_result.removesuffix("_COMMITTED").lower()
      committed.append(
        f"0x{TARGET.crc_sector_base:x}"
        if label == "crc" else f"0x{TARGET.sector_base:x}"
      )
    if transition_result in {"FAILED", "INDETERMINATE"}:
      if "error" not in transition:
        raise RestoreError("restore failure transition has no error evidence")
    elif not transition["evidence"] or "error" in transition:
      raise RestoreError("restore normal transition evidence is incomplete")
  if (
    transitions[-1]["result"] != result
    or transitions[0]["recorded_at"] != state["created_at"]
    or transitions[-1]["recorded_at"] != state["updated_at"]
    or state["completed_sector_bases"] != committed
    or state["external_recovery_required"] != (result == "INDETERMINATE")
    or (
      result in {"FAILED", "INDETERMINATE"}
      and state["validation_errors"] != [transitions[-1]["error"]]
    )
    or (
      result not in {"FAILED", "INDETERMINATE"}
      and state["validation_errors"] != []
    )
  ):
    raise RestoreError("restore state transition history contradicts its summary")
  return state


def _validate_inputs(
  *,
  layout,
  preflight,
  transport_factory,
  confirmation,
  power_cycle_checkpoint,
  target,
  new_uds,
) -> None:
  if not isinstance(layout, ArtifactLayout):
    raise TypeError("layout must be an ArtifactLayout")
  if not isinstance(target, TargetManifest):
    raise TypeError("target must be a TargetManifest")
  try:
    target.validate()
  except ValueError as exc:
    raise RestoreError(f"target manifest is invalid: {exc}") from exc
  if type(new_uds) is not bool or new_uds is not target.new_uds:
    raise RestoreError("restore UDS variant does not match the target")
  for callback, label in (
    (preflight, "preflight"),
    (transport_factory, "transport factory"),
    (confirmation, "restore confirmation"),
    (power_cycle_checkpoint, "power-cycle checkpoint"),
  ):
    if not callable(callback):
      raise TypeError(f"{label} must be callable")


def _container_value(container, name: str, *, label: str):
  if isinstance(container, Mapping):
    try:
      return container[name]
    except KeyError as exc:
      raise RestoreError(f"{label} is missing {name}") from exc
  try:
    return getattr(container, name)
  except AttributeError as exc:
    raise RestoreError(f"{label} is missing {name}") from exc


def _validate_live_read_payload(payloads, target: TargetManifest):
  if LIVE_READ_ENVELOPE_SHA256 is None:
    raise RestoreError("reviewed live_read payload is not built and pinned")
  payload = _container_value(payloads, "live_read", label="restore payload set")
  try:
    name = payload.name
    envelope = payload.envelope
    digest = payload.sha256
  except AttributeError as exc:
    raise RestoreError("live_read payload image is malformed") from exc
  if name != "live_read":
    raise RestoreError("live_read payload image has the wrong name")
  if type(envelope) is not bytes or len(envelope) != target.envelope_length:
    raise RestoreError("live_read payload envelope is not exact")
  if (
    type(digest) is not str
    or hashlib.sha256(envelope).hexdigest() != digest
    or digest != LIVE_READ_ENVELOPE_SHA256
  ):
    raise RestoreError("live_read payload is not the exact reviewed envelope")
  return payload


def _validate_restore_template(templates) -> bytes:
  template = _container_value(
    templates, "restore_sector", label="restore template set",
  )
  manifest = REVIEWED_TEMPLATE_MANIFESTS["restore_sector"]
  if (
    type(template) is not bytes
    or len(template) != manifest.size
    or sha256_bytes(template) != manifest.sha256
  ):
    raise RestoreError("restore_sector is not the exact reviewed writer template")
  return template


def _backup_for_base(
  trusted: TrustedProbeEvidence,
  base: int,
  target: TargetManifest,
) -> RestoreBackup:
  if type(trusted) is not TrustedProbeEvidence:
    raise RestoreError("restore backup requires exact trusted probe evidence")
  if base == target.sector_base:
    data = trusted.target_sector
    label = "target"
    context = data[
      target.instruction_offset:target.instruction_offset + len(target.original_instruction)
    ]
    if context != target.original_instruction or sha256_bytes(data) != target.original_sha256:
      raise RestoreError("target original backup structure is invalid")
    source_adjustment = bytes(4)
  elif base == target.crc_sector_base:
    data = trusted.crc_sector
    label = "crc"
    source_adjustment = data[
      target.crc_adjust_offset:target.crc_adjust_offset + 4
    ]
    magic_offset = target.magic_addresses[1] - target.crc_sector_base
    if (
      source_adjustment
        != target.crc_original_adjust_word.to_bytes(4, "little")
      or data[magic_offset:magic_offset + 4]
        != target.magic_word.to_bytes(4, "little")
    ):
      raise RestoreError("CRC original backup structure is invalid")
  else:
    raise RestoreError("restore backup base is not allowlisted")
  if type(data) is not bytes or len(data) != target.sector_length:
    raise RestoreError("restore backup is not one exact immutable sector")
  return RestoreBackup(
    base=base,
    label=label,
    data=data,
    sha256=sha256_bytes(data),
    source_adjustment=source_adjustment,
  )


def _build_restore_payload(
  template: bytes,
  backup: RestoreBackup,
  target: TargetManifest,
) -> SpecializedPayloadImage:
  try:
    image = build_specialized_payload_image(
      template=template,
      manifest=REVIEWED_TEMPLATE_MANIFESTS["restore_sector"],
      intent=build_restore_intent(backup, target=target),
      sector_base=backup.base,
    )
    image.validate()
  except Exception as exc:
    raise RestoreError(f"restore payload specialization failed: {exc}") from exc
  return image


def _require_boot_identity(current: object, expected: EcuIdentity) -> None:
  if (
    type(current) is not BootloaderIdentity
    or current.software_id != expected.boot_software_id
    or current.panda_serial != expected.panda_serial
    or not current.panda_serial
  ):
    raise RestoreError("fresh bootloader identity does not match fixed probe evidence")


def _validate_live_precheck(
  result: object,
  *,
  plan: RestorePlan,
  trusted: TrustedProbeEvidence,
  completed: tuple[int, ...],
  target: TargetManifest,
) -> LiveReadClassification:
  if type(plan) is not RestorePlan or type(trusted) is not TrustedProbeEvidence:
    raise RestoreError("live-read precheck inputs are not exact trusted records")
  if type(completed) is not tuple or any(type(base) is not int for base in completed):
    raise RestoreError("live-read completed-sector progress is malformed")
  if (
    type(result) is not StreamResult
    or result.operation != OP_LIVE_READ
    or result.sector is not None
    or result.magic_words != (target.magic_word, target.magic_word)
    or result.statuses != ((1, 0),)
    or result.faci_values
    or type(result.regions) is not tuple
    or len(result.regions) != 2
    or any(type(region) is not RegionResult for region in result.regions)
    or tuple(region.base for region in result.regions)
      != (target.sector_base, target.crc_sector_base)
    or any(
      type(region.data) is not bytes or len(region.data) != target.sector_length
      for region in result.regions
    )
    or result.crc_values
    or result.crc is not None
    or result.dcra_values
    or result.dcra is not None
  ):
    raise RestoreError("live-read result is malformed or ambiguous")

  try:
    candidate = build_crc_candidate(
      trusted.target_sector,
      trusted.crc_sector,
      target.crc_patched_adjust_word.to_bytes(4, "little"),
      target=target,
    )
  except (TypeError, ValueError) as exc:
    raise RestoreError("live-read candidates cannot be derived from probe backups") from exc
  if (
    sha256_bytes(candidate.target_source) != target.original_sha256
    or sha256_bytes(candidate.target_final) != target.patched_sha256
    or candidate.old_adjustment
      != target.crc_original_adjust_word.to_bytes(4, "little")
    or candidate.new_adjustment
      != target.crc_patched_adjust_word.to_bytes(4, "little")
  ):
    raise RestoreError("live-read candidates contradict the fixed target manifest")

  target_live, crc_live = (region.data for region in result.regions)

  def classify(live: bytes, source: bytes, patched: bytes) -> str:
    if live == source:
      return "source"
    if live == patched:
      return "candidate"
    return "other"

  target_state = classify(
    target_live, candidate.target_source, candidate.target_final,
  )
  crc_state = classify(crc_live, candidate.crc_source, candidate.crc_final)

  if completed == (target.crc_sector_base,):
    if plan.restore_order != ("crc", "target"):
      raise RestoreError("live-read progress contradicts the persisted incident scope")
    allowed = ({"candidate"}, {"source"})
  elif completed:
    raise RestoreError("live-read progress contradicts the persisted incident scope")
  elif (
    plan.incident_result == "TARGET_INDETERMINATE"
    and plan.restore_order == ("target",)
  ):
    allowed = ({"source", "candidate", "other"}, {"source"})
  elif (
    plan.incident_result in {"TARGET_COMMITTED", "RECOVERY_REQUIRED"}
    and plan.restore_order == ("target",)
  ):
    allowed = ({"candidate"}, {"source"})
  elif (
    plan.incident_result == "CRC_INDETERMINATE"
    and plan.restore_order == ("crc", "target")
  ):
    allowed = ({"candidate"}, {"source", "candidate", "other"})
  elif (
    plan.incident_result in {"CRC_COMMITTED", "RECOVERY_REQUIRED"}
    and plan.restore_order == ("crc", "target")
  ):
    allowed = ({"candidate"}, {"candidate"})
  else:
    raise RestoreError("live-read plan has no canonical persisted incident policy")
  if target_state not in allowed[0] or crc_state not in allowed[1]:
    raise RestoreError("live flash state contradicts the persisted incident scope")

  return LiveReadClassification(
    target_state=target_state,
    crc_state=crc_state,
    target_sha256=sha256_bytes(target_live),
    crc_sha256=sha256_bytes(crc_live),
  )


def _validate_restore_result(
  result: object,
  backup: RestoreBackup,
  target: TargetManifest,
) -> None:
  if (
    type(result) is not StreamResult
    or result.operation != OP_RESTORE_SECTOR
    or result.sector != backup.data
    or sha256_bytes(result.sector) != backup.sha256
    or result.regions != (RegionResult(backup.base, backup.data),)
    or result.magic_words != (target.magic_word, target.magic_word)
    or result.statuses != tuple((stage, 0) for stage in range(1, 7))
    or result.faci_values
    or result.crc_values
    or result.crc is not None
    or result.dcra_values
    or result.dcra is not None
  ):
    raise RestoreError("restore writer returned malformed or uncertain readback evidence")


def _restore_prompt(
  *,
  backup: RestoreBackup,
  incident_sha256: str,
  envelope_sha256: str,
  target: TargetManifest,
) -> str:
  return (
    f"RESTORE-SECTOR {target.part_number.decode('ascii')} 0x{backup.base:x} "
    f"SHA256={backup.sha256} INCIDENT={incident_sha256} "
    f"PAYLOAD={envelope_sha256}"
  )


def _require_exact_confirmation(
  callback: Callable[[str], object], prompt: str,
) -> str:
  response = callback(prompt)
  if type(response) is not str or response != prompt:
    raise RestoreError("destructive restore confirmation text does not match exactly")
  return response


def _create_attempt(layout: ArtifactLayout) -> tuple[str, Path]:
  instant = datetime.now(timezone.utc).replace(microsecond=0)
  restore_root_existed = layout.restore_root.exists()
  layout.restore_root.mkdir(parents=True, exist_ok=True)
  if not restore_root_existed:
    _fsync_directory(layout.root)
  for offset in range(86_400):
    timestamp = (instant + timedelta(seconds=offset)).strftime("%Y%m%dT%H%M%SZ")
    directory = layout.restore_attempt(timestamp)
    try:
      directory.mkdir(parents=False, exist_ok=False)
    except FileExistsError:
      continue
    _fsync_directory(layout.restore_root)
    return timestamp, directory
  raise RestoreError("cannot allocate a unique UTC restore attempt directory")


def _persist_sector(path: Path, sector: bytes, target: TargetManifest) -> None:
  if type(sector) is not bytes or len(sector) != target.sector_length:
    raise RestoreError(f"{path.name} is not one exact sector")
  _atomic_create(path, sector)


def _status_records(result: StreamResult) -> list[dict[str, int]]:
  return [{"stage": stage, "code": code} for stage, code in result.statuses]


def _boot_identity_record(identity: BootloaderIdentity) -> dict[str, str]:
  return {
    "boot_software_id": identity.software_id.hex(),
    "panda_serial": identity.panda_serial,
  }


def _payload_record(payload) -> dict[str, str]:
  return {"name": payload.name, "sha256": payload.sha256}


def _restore_payload_record(image: SpecializedPayloadImage) -> dict[str, str]:
  return {
    "name": image.name,
    "template_sha256": image.manifest.sha256,
    "review_sha256": image.manifest.review_sha256,
    "intent_sha256": sha256_bytes(image.intent),
    "envelope_sha256": image.sha256,
  }


def _is_sha256(value: object) -> bool:
  return (
    type(value) is str
    and len(value) == 64
    and all(character in "0123456789abcdef" for character in value)
  )


def _is_utc_timestamp(value: object) -> bool:
  if type(value) is not str:
    return False
  try:
    parsed = datetime.fromisoformat(value)
  except ValueError:
    return False
  return parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)


def _now() -> str:
  return datetime.now(timezone.utc).isoformat()


def _json_bytes(report: dict[str, object]) -> bytes:
  return (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _atomic_replace_json(path: Path, report: dict[str, object]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  descriptor, temporary = tempfile.mkstemp(
    prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
  )
  try:
    with os.fdopen(descriptor, "wb") as stream:
      stream.write(_json_bytes(report))
      stream.flush()
      os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_descriptor = os.open(path.parent, os.O_RDONLY)
    try:
      os.fsync(directory_descriptor)
    finally:
      os.close(directory_descriptor)
  finally:
    try:
      os.unlink(temporary)
    except FileNotFoundError:
      pass


def _fsync_directory(path: Path) -> None:
  descriptor = os.open(path, os.O_RDONLY)
  try:
    os.fsync(descriptor)
  finally:
    os.close(descriptor)


__all__ = [
  "LIVE_READ_ENVELOPE_SHA256",
  "LiveReadClassification",
  "RestoreError",
  "RestorePlan",
  "RestoreState",
  "build_restore_intent",
  "run_restore",
  "select_restore_plan",
]
