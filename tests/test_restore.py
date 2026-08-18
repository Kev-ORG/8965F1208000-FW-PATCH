import binascii
import hashlib
import inspect
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from eps_patch.artifacts import sha256_bytes
from eps_patch.paths import ArtifactLayout
from eps_patch.protocol import (
  OP_LIVE_READ, OP_RAM_ECHO, OP_RESTORE_SECTOR, RegionResult, StreamResult,
)
from eps_patch.transport import BootloaderIdentity

import test_patch as patch_fx


TEST_LIVE_READ_ENVELOPE = bytes(0x1000)
TEST_LIVE_READ_ENVELOPE_SHA256 = hashlib.sha256(TEST_LIVE_READ_ENVELOPE).hexdigest()


@pytest.fixture(autouse=True)
def pin_test_live_read_envelope(monkeypatch):
  import eps_patch.restore as restore_module

  monkeypatch.setattr(
    restore_module,
    "LIVE_READ_ENVELOPE_SHA256",
    TEST_LIVE_READ_ENVELOPE_SHA256,
    raising=False,
  )


def _patch_state(
  layout: ArtifactLayout,
  *,
  result: str,
  restore_order: list[str],
  timestamp: str = "20260817T010203Z",
  power_cycle: dict[str, str] | None = None,
) -> Path:
  directory = layout.patch_attempt(timestamp)
  directory.mkdir(parents=True, exist_ok=False)
  recorded_at = "2026-08-17T01:02:03+00:00"
  if result == "TARGET_INDETERMINATE":
    states = (
      "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
      "TARGET_INDETERMINATE",
    )
  elif result == "RECOVERY_REQUIRED" and restore_order == ["target"]:
    states = (
      "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
      "TARGET_COMMITTED", "RECOVERY_REQUIRED",
    )
  elif result == "RECOVERY_REQUIRED":
    states = (
      "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
      "TARGET_COMMITTED", "CRC_PRECHECKED", "CRC_ARMED", "CRC_COMMITTED",
      "VERIFY_PENDING", "RECOVERY_REQUIRED",
    )
  elif result == "CRC_INDETERMINATE":
    states = (
      "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
      "TARGET_COMMITTED", "CRC_PRECHECKED", "CRC_ARMED", "CRC_INDETERMINATE",
    )
  elif result == "TARGET_COMMITTED":
    states = (
      "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
      "TARGET_COMMITTED",
    )
  elif result == "TARGET_PRECHECKED":
    states = ("STARTED", "PROBED", "TARGET_PRECHECKED")
  elif result == "CRC_PRECHECKED":
    states = (
      "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
      "TARGET_COMMITTED", "CRC_PRECHECKED",
    )
  elif result == "CRC_COMMITTED":
    states = (
      "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
      "TARGET_COMMITTED", "CRC_PRECHECKED", "CRC_ARMED", "CRC_COMMITTED",
    )
  elif result == "PASS":
    states = (
      "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
      "TARGET_COMMITTED", "CRC_PRECHECKED", "CRC_ARMED", "CRC_COMMITTED",
      "VERIFY_PENDING", "PASS",
    )
  elif result == "FAILED":
    states = ("STARTED", "FAILED")
  else:
    states = (result,)
  transitions = []
  for sequence, state_name in enumerate(states):
    transition = {
      "sequence": sequence,
      "result": state_name,
      "recorded_at": recorded_at,
      "evidence": {} if state_name in {
        "FAILED", "TARGET_INDETERMINATE", "CRC_INDETERMINATE",
        "RECOVERY_REQUIRED",
      } else {"state": state_name},
    }
    if state_name in {
      "FAILED", "TARGET_INDETERMINATE", "CRC_INDETERMINATE",
      "RECOVERY_REQUIRED",
    }:
      transition["error"] = "test incident"
    transitions.append(transition)
  state = {
    "schema": 2 if power_cycle is not None else 1,
    "workflow": "patch",
    "attempt": timestamp,
    "sequence": len(transitions) - 1,
    "result": result,
    "restore_order": restore_order,
    "created_at": recorded_at,
    "updated_at": recorded_at,
    "probe_report_sha256": sha256_bytes(json.dumps(
      json.loads(layout.probe_report.read_text(encoding="utf-8")),
      sort_keys=True,
      separators=(",", ":"),
    ).encode("utf-8")),
    "automatic_forward_resume": False,
    "automatic_retry": False,
    "transitions": transitions,
    "validation_errors": [],
  }
  if power_cycle is not None:
    state["power_cycle"] = power_cycle
  path = directory / "state.json"
  path.write_text(json.dumps(state), encoding="utf-8")
  return path


def _probe_case(tmp_path: Path):
  layout = ArtifactLayout(tmp_path / "artifacts")
  target, identity, target_source, crc_source, target_candidate, crc_candidate = (
    patch_fx._case(layout)
  )
  return (
    layout,
    target,
    identity,
    target_source,
    crc_source,
    target_candidate,
    crc_candidate,
  )


@pytest.mark.parametrize("classification", ("source", "candidate"))
def test_patch_state_audit_accepts_exact_pending_and_consumed_legacy_history(
  tmp_path, classification,
):
  from eps_patch.restore import (
    _legacy_crc_trigger_recovery_status, _load_patch_state,
  )

  (
    layout, state_path, target, identity, _target_source, crc_source,
    target_candidate, crc_candidate,
  ) = patch_fx._legacy_crc_trigger_case(tmp_path)
  pending, pending_raw = _load_patch_state(state_path, state_path.parent.name)
  assert pending_raw == state_path.read_bytes()
  assert _legacy_crc_trigger_recovery_status(pending["transitions"]) == "pending"
  crc_live = {"source": crc_source, "candidate": crc_candidate}[classification]
  patch_fx._invoke_patch_resume(
    layout=layout,
    target=target,
    transport=patch_fx.FakeTransport(
      "legacy-reconcile", [], identity,
      patch_fx._live_read_result(target_candidate, crc_live), boot=True,
    ),
    events=[],
    confirmations=[],
    powers=[],
  )

  consumed, consumed_raw = _load_patch_state(state_path, state_path.parent.name)
  assert consumed_raw == state_path.read_bytes()
  assert consumed["result"] == {
    "source": "CRC_PRECHECKED", "candidate": "CRC_COMMITTED",
  }[classification]
  assert _legacy_crc_trigger_recovery_status(consumed["transitions"]) == "consumed"


@pytest.mark.parametrize("classification", ("source", "candidate"))
def test_patch_state_audit_accepts_completed_legacy_recovery_history(
  tmp_path, classification,
):
  from eps_patch.restore import (
    _legacy_crc_trigger_recovery_status, _load_patch_state,
  )

  _layout, state_path, report_path, _events, _confirmations = (
    patch_fx._complete_legacy_crc_recovery(tmp_path, classification)
  )

  completed, raw = _load_patch_state(state_path, state_path.parent.name)
  assert report_path.name == "patch-report.json"
  assert raw == state_path.read_bytes()
  assert completed["result"] == "PASS"
  assert _legacy_crc_trigger_recovery_status(completed["transitions"]) == "consumed"


def test_patch_state_audit_accepts_exact_restore_only_third_indeterminate(tmp_path):
  from eps_patch.restore import (
    _legacy_crc_trigger_recovery_status, _load_patch_state,
  )

  _layout, state_path, *_case = (
    patch_fx._legacy_crc_trigger_third_indeterminate_case(tmp_path)
  )

  state, raw = _load_patch_state(state_path, state_path.parent.name)

  assert raw == state_path.read_bytes()
  assert state["result"] == "CRC_INDETERMINATE"
  assert state["restore_order"] == ["crc", "target"]
  assert _legacy_crc_trigger_recovery_status(state["transitions"]) == (
    "restore-only"
  )


def test_restore_selects_crc_before_target_for_exact_third_indeterminate(tmp_path):
  from eps_patch.restore import select_restore_plan

  layout, state_path, *_case = (
    patch_fx._legacy_crc_trigger_third_indeterminate_case(tmp_path)
  )

  plan = select_restore_plan(layout)

  assert plan.incident_state_path == state_path
  assert plan.incident_result == "CRC_INDETERMINATE"
  assert plan.restore_order == ("crc", "target")
  assert plan.sector_bases == (0xF8000, 0x88000)


@pytest.mark.parametrize("successor", ("CRC_PRECHECKED", "CRC_COMMITTED"))
def test_patch_state_audit_rejects_forward_transition_after_restore_only_suffix(
  tmp_path, successor,
):
  from eps_patch.restore import RestoreError, _load_patch_state

  _layout, state_path, *_case = (
    patch_fx._legacy_crc_trigger_third_indeterminate_case(tmp_path)
  )
  _load_patch_state(state_path, state_path.parent.name)
  state = json.loads(state_path.read_text(encoding="utf-8"))
  transition = {
    "sequence": len(state["transitions"]),
    "result": successor,
    "recorded_at": state["updated_at"],
    "evidence": {"forged": "third-indeterminate forward transition"},
  }
  state["transitions"].append(transition)
  state["sequence"] = transition["sequence"]
  state["result"] = successor
  state["restore_order"] = (
    ["target"] if successor == "CRC_PRECHECKED" else ["crc", "target"]
  )
  state["power_cycle"] = {
    "completed_state": successor,
    "next_state": "CRC_ARMED" if successor == "CRC_PRECHECKED" else "VERIFY_PENDING",
  }
  state_path.write_text(json.dumps(state), encoding="utf-8")

  with pytest.raises(RestoreError, match="one-time CRC retry limit"):
    _load_patch_state(state_path, state_path.parent.name)


@pytest.mark.parametrize(
  "mutation",
  (
    "nrc22", "wrong-raw", "first-error", "missing-classification",
    "changed-classification", "wrong-reconciled-sequence",
    "reconcile-target-hash", "reconcile-crc-hash", "arm-operation",
    "arm-base", "arm-source", "arm-candidate", "arm-crc32", "arm-payload",
    "extra-transition",
  ),
)
def test_patch_state_audit_rejects_every_legacy_history_near_miss(
  tmp_path, mutation,
):
  from eps_patch.restore import RestoreError, _load_patch_state

  _layout, state_path, *_case = patch_fx._legacy_crc_trigger_case(tmp_path)
  state = json.loads(state_path.read_text(encoding="utf-8"))
  patch_fx._mutate_legacy_state(state, mutation)
  state_path.write_text(json.dumps(state), encoding="utf-8")

  with pytest.raises(RestoreError):
    _load_patch_state(state_path, state_path.parent.name)


@pytest.mark.parametrize(
  "mutation",
  (
    "marker", "rejection-sequence", "reconciled-from", "reconciled-sequence",
    "classification", "target-hash", "crc-hash",
  ),
)
def test_patch_state_audit_rejects_mutated_consumption_marker(tmp_path, mutation):
  from eps_patch.restore import RestoreError, _load_patch_state

  (
    layout, state_path, target, identity, _target_source, crc_source,
    target_candidate, _crc_candidate,
  ) = patch_fx._legacy_crc_trigger_case(tmp_path)
  patch_fx._invoke_patch_resume(
    layout=layout,
    target=target,
    transport=patch_fx.FakeTransport(
      "legacy-reconcile", [], identity,
      patch_fx._live_read_result(target_candidate, crc_source), boot=True,
    ),
    events=[],
    confirmations=[],
    powers=[],
  )
  state = json.loads(state_path.read_text(encoding="utf-8"))
  evidence = state["transitions"][-1]["evidence"]
  if mutation == "marker":
    evidence["legacy_trigger_recovery"] = "nrc31-route-v2"
  elif mutation == "rejection-sequence":
    evidence["legacy_trigger_rejection_sequence"] = 9
  elif mutation == "reconciled-from":
    evidence["reconciled_from"] = "CRC_ARMED"
  elif mutation == "reconciled-sequence":
    evidence["reconciled_sequence"] = 9
  elif mutation == "classification":
    evidence["classification"] = "candidate"
  elif mutation == "target-hash":
    evidence["target_readback_sha256"] = "0" * 64
  else:
    evidence["crc_readback_sha256"] = "0" * 64
  state_path.write_text(json.dumps(state), encoding="utf-8")

  with pytest.raises(RestoreError, match="one-time CRC retry limit"):
    _load_patch_state(state_path, state_path.parent.name)


def test_patch_state_audit_retains_generic_second_indeterminate_retry_rejection(
  tmp_path,
):
  from eps_patch.patch import PatchError
  from eps_patch.restore import RestoreError, _load_patch_state

  (
    layout, state_path, target, identity, _target_source, crc_source,
    target_candidate, _crc_candidate,
  ) = patch_fx._crc_indeterminate_case(tmp_path)
  patch_fx._invoke_patch_resume(
    layout=layout,
    target=target,
    transport=patch_fx.FakeTransport(
      "reconcile", [], identity,
      patch_fx._live_read_result(target_candidate, crc_source), boot=True,
    ),
    events=[],
    confirmations=[],
    powers=[],
  )
  with pytest.raises(PatchError):
    patch_fx._invoke_patch_resume(
      layout=layout,
      target=target,
      transport=patch_fx.FakeTransport(
        "retry-writer", [], identity, None,
        failure=TimeoutError("second response lost"), boot=True,
      ),
      events=[],
      confirmations=[],
      powers=[],
    )
  state = json.loads(state_path.read_text(encoding="utf-8"))
  transition = {
    "sequence": 11,
    "result": "CRC_PRECHECKED",
    "recorded_at": state["updated_at"],
    "evidence": {"state": "generic second retry"},
  }
  state["transitions"].append(transition)
  state["sequence"] = 11
  state["result"] = "CRC_PRECHECKED"
  state["restore_order"] = ["target"]
  state["power_cycle"] = {
    "completed_state": "CRC_PRECHECKED", "next_state": "CRC_ARMED",
  }
  state_path.write_text(json.dumps(state), encoding="utf-8")

  with pytest.raises(RestoreError, match="one-time CRC retry limit"):
    _load_patch_state(state_path, state_path.parent.name)


@pytest.mark.parametrize(
  ("state", "expected"),
  [
    ({"result": "TARGET_INDETERMINATE", "restore_order": ["target"]}, (0x88000,)),
    (
      {"result": "RECOVERY_REQUIRED", "restore_order": ["crc", "target"]},
      (0xF8000, 0x88000),
    ),
  ],
)
def test_restore_uses_persisted_minimum_safe_order(tmp_path, state, expected):
  from eps_patch.restore import select_restore_plan

  layout, *_case = _probe_case(tmp_path)
  _patch_state(layout, **state)

  assert select_restore_plan(layout).sector_bases == expected


def test_restore_classifies_new_patch_precheck_checkpoints_by_actual_write_scope(
  tmp_path,
):
  from eps_patch.restore import RestoreError, select_restore_plan

  target_layout, *_case = _probe_case(tmp_path / "target")
  _patch_state(
    target_layout,
    result="TARGET_PRECHECKED",
    restore_order=[],
    power_cycle={
      "completed_state": "TARGET_PRECHECKED",
      "next_state": "TARGET_ARMED",
    },
  )
  with pytest.raises(RestoreError, match="no recoverable"):
    select_restore_plan(target_layout)

  crc_layout, *_case = _probe_case(tmp_path / "crc")
  _patch_state(
    crc_layout,
    result="CRC_PRECHECKED",
    restore_order=["target"],
    power_cycle={
      "completed_state": "CRC_PRECHECKED",
      "next_state": "CRC_ARMED",
    },
  )
  assert select_restore_plan(crc_layout).restore_order == ("target",)


def test_restore_selects_newest_non_pass_recoverable_incident(tmp_path):
  from eps_patch.restore import select_restore_plan

  layout, *_case = _probe_case(tmp_path)
  older = _patch_state(
    layout,
    timestamp="20260817T010203Z",
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  _patch_state(
    layout,
    timestamp="20260817T010204Z",
    result="PASS",
    restore_order=[],
  )

  plan = select_restore_plan(layout)

  assert plan.incident_state_path == older
  assert plan.incident_timestamp == "20260817T010203Z"


def test_patch_report_install_failure_remains_a_selectable_two_sector_incident(
  tmp_path,
  monkeypatch,
):
  import eps_patch.patch as patch_module
  from eps_patch.restore import select_restore_plan

  real_create = patch_module._atomic_create

  def fail_final_report(path, content):
    if path.name == "patch-report.json":
      raise OSError("final report storage unavailable")
    return real_create(path, content)

  monkeypatch.setattr(patch_module, "_atomic_create", fail_final_report)
  result, state_path, _events, _confirmations = patch_fx._run_patch(tmp_path)

  assert result is None
  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert [item["result"] for item in state["transitions"][-2:]] == [
    "PASS", "RECOVERY_REQUIRED",
  ]
  assert select_restore_plan(ArtifactLayout(tmp_path / "artifacts")).sector_bases == (
    patch_fx.TARGET.crc_sector_base,
    patch_fx.TARGET.sector_base,
  )


@pytest.mark.parametrize("module_name", ("patch", "restore"))
def test_failed_state_write_does_not_retain_an_unpersisted_prospective_transition(
  tmp_path,
  monkeypatch,
  module_name,
):
  from eps_patch.evidence import load_probe_pass
  from eps_patch.restore import RestorePlan

  layout, target, *_case = _probe_case(tmp_path)
  if module_name == "patch":
    import eps_patch.patch as module

    recorder = module._StateRecorder(
      tmp_path / "patch-recorder",
      timestamp="20260817T010203Z",
      evidence=load_probe_pass(layout, target),
    )
    first = module.PatchState.STARTED
    prospective = module.PatchState.TARGET_ARMED
  else:
    import eps_patch.restore as module

    plan = RestorePlan(
      incident_directory=layout.patch_attempt("20260817T010203Z"),
      incident_state_path=layout.patch_attempt("20260817T010203Z") / "state.json",
      incident_timestamp="20260817T010203Z",
      incident_result="TARGET_INDETERMINATE",
      restore_order=("target",),
      sector_bases=(target.sector_base,),
      incident_state_sha256="1" * 64,
      probe_report_sha256="2" * 64,
    )
    recorder = module._StateRecorder(
      tmp_path / "restore-recorder",
      timestamp="20260817T010204Z",
      plan=plan,
    )
    first = module.RestoreState.STARTED
    prospective = module.RestoreState.TARGET_ARMED
  recorder.record(first, evidence={"state": first.value})
  monkeypatch.setattr(
    module,
    "_atomic_replace_json",
    lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("state fsync failed")),
  )

  with pytest.raises(OSError, match="fsync"):
    recorder.record(prospective, evidence={"state": prospective.value})

  assert [transition["result"] for transition in recorder.transitions] == [first.value]


def test_committed_state_write_failure_keeps_indeterminate_state_canonical(
  tmp_path,
  monkeypatch,
):
  import eps_patch.restore as restore_module

  real_replace = restore_module._atomic_replace_json
  failed = False

  def fail_committed_once(path, report):
    nonlocal failed
    if report["result"] == "TARGET_COMMITTED" and not failed:
      failed = True
      raise OSError("committed state fsync failed")
    return real_replace(path, report)

  monkeypatch.setattr(restore_module, "_atomic_replace_json", fail_committed_once)

  report, state_path, _incident, _events, _confirmations, _powers = _run_restore(
    tmp_path,
    order=("target",),
  )

  assert report is None
  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert state["result"] == "INDETERMINATE"
  assert state["completed_sector_bases"] == []
  assert restore_module._load_restore_state(state_path, state_path.parent.name) == state


def _live_read_result(target_sector: bytes, crc_sector: bytes) -> StreamResult:
  from eps_patch.protocol import OP_LIVE_READ

  return StreamResult(
    operation=OP_LIVE_READ,
    sector=None,
    magic_words=(patch_fx.TARGET.magic_word, patch_fx.TARGET.magic_word),
    statuses=((1, 0),),
    regions=(
      RegionResult(patch_fx.TARGET.sector_base, target_sector),
      RegionResult(patch_fx.TARGET.crc_sector_base, crc_sector),
    ),
  )


@pytest.mark.parametrize(
  (
    "incident_result", "restore_order", "target_live", "crc_live", "completed",
    "expected_states",
  ),
  (
    ("TARGET_INDETERMINATE", ["target"], "other", "source", (), ("other", "source")),
    ("TARGET_INDETERMINATE", ["target"], "source", "source", (), ("source", "source")),
    ("TARGET_COMMITTED", ["target"], "candidate", "source", (), ("candidate", "source")),
    ("RECOVERY_REQUIRED", ["target"], "candidate", "source", (), ("candidate", "source")),
    ("CRC_INDETERMINATE", ["crc", "target"], "candidate", "other", (), ("candidate", "other")),
    ("RECOVERY_REQUIRED", ["crc", "target"], "candidate", "candidate", (), ("candidate", "candidate")),
    ("CRC_COMMITTED", ["crc", "target"], "candidate", "candidate", (), ("candidate", "candidate")),
    (
      "RECOVERY_REQUIRED", ["crc", "target"], "candidate", "source",
      (patch_fx.TARGET.crc_sector_base,), ("candidate", "source"),
    ),
  ),
)
def test_live_precheck_classifies_complete_sectors_against_incident_and_backups(
  tmp_path,
  incident_result,
  restore_order,
  target_live,
  crc_live,
  completed,
  expected_states,
):
  from eps_patch.evidence import load_probe_pass
  from eps_patch.restore import _validate_live_precheck, select_restore_plan

  (
    layout, target, _identity, target_source, crc_source,
    target_candidate, crc_candidate,
  ) = _probe_case(tmp_path)
  _patch_state(
    layout,
    result=incident_result,
    restore_order=restore_order,
  )
  choices = {
    "target": {
      "source": target_source,
      "candidate": target_candidate,
      "other": bytes([target_source[0] ^ 1]) + target_source[1:],
    },
    "crc": {
      "source": crc_source,
      "candidate": crc_candidate,
      "other": bytes([crc_source[0] ^ 1]) + crc_source[1:],
    },
  }

  classification = _validate_live_precheck(
    _live_read_result(choices["target"][target_live], choices["crc"][crc_live]),
    plan=select_restore_plan(layout),
    trusted=load_probe_pass(layout, target),
    completed=completed,
    target=target,
  )

  assert (classification.target_state, classification.crc_state) == expected_states
  assert classification.target_sha256 == sha256_bytes(choices["target"][target_live])
  assert classification.crc_sha256 == sha256_bytes(choices["crc"][crc_live])


@pytest.mark.parametrize(
  ("incident_result", "restore_order", "target_live", "crc_live", "completed"),
  (
    ("TARGET_INDETERMINATE", ["target"], "other", "candidate", ()),
    ("RECOVERY_REQUIRED", ["target"], "source", "source", ()),
    ("CRC_INDETERMINATE", ["crc", "target"], "source", "other", ()),
    ("RECOVERY_REQUIRED", ["crc", "target"], "candidate", "source", ()),
    (
      "RECOVERY_REQUIRED", ["crc", "target"], "candidate", "candidate",
      (patch_fx.TARGET.crc_sector_base,),
    ),
  ),
)
def test_live_precheck_rejects_state_that_contradicts_incident_or_restore_progress(
  tmp_path,
  incident_result,
  restore_order,
  target_live,
  crc_live,
  completed,
):
  from eps_patch.evidence import load_probe_pass
  from eps_patch.restore import RestoreError, _validate_live_precheck, select_restore_plan

  (
    layout, target, _identity, target_source, crc_source,
    target_candidate, crc_candidate,
  ) = _probe_case(tmp_path)
  _patch_state(layout, result=incident_result, restore_order=restore_order)
  choices = {
    "target": {
      "source": target_source,
      "candidate": target_candidate,
      "other": bytes([target_source[0] ^ 1]) + target_source[1:],
    },
    "crc": {
      "source": crc_source,
      "candidate": crc_candidate,
      "other": bytes([crc_source[0] ^ 1]) + crc_source[1:],
    },
  }

  with pytest.raises(RestoreError, match="live.*incident|incident.*live"):
    _validate_live_precheck(
      _live_read_result(choices["target"][target_live], choices["crc"][crc_live]),
      plan=select_restore_plan(layout),
      trusted=load_probe_pass(layout, target),
      completed=completed,
      target=target,
    )


@pytest.mark.parametrize(
  "mutation",
  (
    "wrong-operation", "scalar-sector", "wrong-order", "wrong-base", "short-data",
    "wrong-magic", "nonzero-status", "extra-faci", "extra-crc", "extra-dcra",
  ),
)
def test_live_precheck_rejects_malformed_or_ambiguous_result(tmp_path, mutation):
  from eps_patch.evidence import load_probe_pass
  from eps_patch.restore import RestoreError, _validate_live_precheck, select_restore_plan

  layout, target, _identity, target_source, crc_source, *_candidates = _probe_case(
    tmp_path,
  )
  _patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  result = _live_read_result(target_source, crc_source)
  if mutation == "wrong-operation":
    result = replace(result, operation=OP_RAM_ECHO)
  elif mutation == "scalar-sector":
    result = replace(result, sector=target_source)
  elif mutation == "wrong-order":
    result = replace(result, regions=tuple(reversed(result.regions)))
  elif mutation == "wrong-base":
    result = replace(
      result,
      regions=(RegionResult(0x70000, target_source), result.regions[1]),
    )
  elif mutation == "short-data":
    result = replace(
      result,
      regions=(RegionResult(target.sector_base, target_source[:-1]), result.regions[1]),
    )
  elif mutation == "wrong-magic":
    result = replace(result, magic_words=(0, target.magic_word))
  elif mutation == "nonzero-status":
    result = replace(result, statuses=((1, 1),))
  elif mutation == "extra-faci":
    result = replace(result, faci_values=(0,))
  elif mutation == "extra-crc":
    result = replace(result, crc_values=(0,))
  else:
    result = replace(result, dcra_values=(0,))

  with pytest.raises(RestoreError, match="live-read"):
    _validate_live_precheck(
      result,
      plan=select_restore_plan(layout),
      trusted=load_probe_pass(layout, target),
      completed=(),
      target=target,
    )


@pytest.mark.parametrize(
  "setup",
  (
    "missing-root",
    "pass-only",
    "failed-without-restore",
  ),
)
def test_restore_rejects_when_no_recoverable_incident_exists(tmp_path, setup):
  from eps_patch.restore import RestoreError, select_restore_plan

  layout, *_case = _probe_case(tmp_path)
  if setup == "pass-only":
    _patch_state(layout, result="PASS", restore_order=[])
  elif setup == "failed-without-restore":
    _patch_state(layout, result="FAILED", restore_order=[])

  with pytest.raises(RestoreError, match="recoverable"):
    select_restore_plan(layout)


@pytest.mark.parametrize(
  "mutation",
  (
    "invalid-json",
    "wrong-order",
    "contradictory-result",
    "attempt-mismatch",
    "transition-mismatch",
    "automatic-retry",
    "invalid-time",
    "impossible-history",
    "missing-transition-evidence",
    "extra-field",
  ),
)
def test_restore_rejects_malformed_or_contradictory_patch_state(tmp_path, mutation):
  from eps_patch.restore import RestoreError, select_restore_plan

  layout, *_case = _probe_case(tmp_path)
  path = _patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  if mutation == "invalid-json":
    path.write_text("{", encoding="utf-8")
  else:
    state = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "wrong-order":
      state["restore_order"] = ["target", "crc"]
    elif mutation == "contradictory-result":
      state["restore_order"] = ["crc", "target"]
    elif mutation == "attempt-mismatch":
      state["attempt"] = "20260817T010204Z"
    elif mutation == "transition-mismatch":
      state["transitions"][-1]["result"] = "PASS"
    elif mutation == "automatic-retry":
      state["automatic_retry"] = True
    elif mutation == "invalid-time":
      state["updated_at"] = "not-a-time"
      state["transitions"][-1]["recorded_at"] = "not-a-time"
    elif mutation == "impossible-history":
      del state["transitions"][2]
      for sequence, transition in enumerate(state["transitions"]):
        transition["sequence"] = sequence
      state["sequence"] -= 1
    elif mutation == "missing-transition-evidence":
      state["transitions"][1]["evidence"] = {}
    else:
      state["extra"] = 0
    path.write_text(json.dumps(state), encoding="utf-8")

  with pytest.raises(RestoreError, match="patch state"):
    select_restore_plan(layout)


def _restore_result(base: int, data: bytes) -> StreamResult:
  return StreamResult(
    operation=OP_RESTORE_SECTOR,
    sector=data,
    magic_words=(patch_fx.TARGET.magic_word, patch_fx.TARGET.magic_word),
    statuses=tuple((stage, 0) for stage in range(1, 7)),
    regions=(RegionResult(base, data),),
  )


class FakeRestoreTransport:
  def __init__(self, label, events, identity, operation, result=None, failure=None):
    self.label = label
    self.events = events
    self.identity = identity
    self.operation = operation
    self.result = result
    self.failure = failure

  def __enter__(self):
    self.events.append((self.label, "open"))
    return self

  def __exit__(self, *_args):
    self.events.append((self.label, "close"))

  def read_bootloader_identity(self):
    self.events.append((self.label, "identity"))
    return self.identity

  def run_payload(self, image, *, operation, new_uds):
    self.events.append((self.label, "payload", operation, image.name))
    assert operation == self.operation
    assert new_uds is False
    if self.failure is not None:
      raise self.failure
    return self.result


def _restore_payloads():
  return {
    "live_read": SimpleNamespace(
      name="live_read",
      envelope=TEST_LIVE_READ_ENVELOPE,
      sha256=TEST_LIVE_READ_ENVELOPE_SHA256,
    ),
  }


def _restore_templates():
  build = Path(__file__).resolve().parents[1] / "payload" / "build"
  return {"restore_sector": (build / "restore_sector.bin").read_bytes()}


def test_restore_first_invocation_for_third_indeterminate_is_live_read_only(
  tmp_path,
):
  from eps_patch.restore import run_restore

  (
    layout, _incident_path, target, identity, _target_source, crc_source,
    target_candidate, _crc_candidate,
  ) = patch_fx._legacy_crc_trigger_third_indeterminate_case(tmp_path)
  events = []
  confirmations = []
  power_prompts = []
  boot_identity = BootloaderIdentity(
    identity.boot_software_id, identity.panda_serial,
  )

  state_path = run_restore(
    layout=layout,
    payloads=_restore_payloads(),
    templates=_restore_templates(),
    preflight=lambda: events.append(("preflight",)),
    transport_factory=lambda: FakeRestoreTransport(
      "crc-live",
      events,
      boot_identity,
      OP_LIVE_READ,
      _live_read_result(target_candidate, crc_source),
    ),
    confirmation=lambda prompt: confirmations.append(prompt) or prompt,
    power_cycle_checkpoint=lambda prompt: power_prompts.append(prompt),
    target=target,
    new_uds=False,
  )

  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert state["result"] == "CRC_LIVE_PRECHECKED"
  assert state["power_cycle"] == {
    "completed_state": "CRC_LIVE_PRECHECKED",
    "next_state": "CRC_ARMED",
  }
  assert [event for event in events if event[0] == "crc-live"] == [
    ("crc-live", "open"),
    ("crc-live", "identity"),
    ("crc-live", "payload", OP_LIVE_READ, "live_read"),
    ("crc-live", "close"),
  ]
  assert confirmations == []
  assert len(power_prompts) == 1
  assert not any(
    len(event) > 2 and event[1] == "payload" and event[2] == OP_RESTORE_SECTOR
    for event in events
  )


def _run_restore(
  tmp_path,
  *,
  order=("crc", "target"),
  failure=None,
  wrong_identity=False,
  exact_confirmation=True,
  live_overrides=None,
  incident_result=None,
):
  from eps_patch.restore import RestoreError, run_restore

  (
    layout,
    target,
    identity,
    target_source,
    crc_source,
    target_candidate,
    crc_candidate,
  ) = _probe_case(tmp_path)
  result = incident_result or (
    "RECOVERY_REQUIRED" if len(order) == 2 else "TARGET_INDETERMINATE"
  )
  incident_path = _patch_state(layout, result=result, restore_order=list(order))
  boot_identity = BootloaderIdentity(identity.boot_software_id, identity.panda_serial)
  wrong = BootloaderIdentity(identity.boot_software_id, "other-panda")
  data_by_name = {"crc": crc_source, "target": target_source}
  base_by_name = {"crc": target.crc_sector_base, "target": target.sector_base}
  events = []
  transports = []
  for name in order:
    data = data_by_name[name]
    base = base_by_name[name]
    writer_result = _restore_result(base, data)
    if failure == "malformed-result" and name == order[0]:
      altered = bytes([data[0] ^ 1]) + data[1:]
      writer_result = _restore_result(base, altered)
    if len(order) == 2 and name == "crc":
      live_target, live_crc = target_candidate, crc_candidate
    elif len(order) == 2:
      live_target, live_crc = target_candidate, crc_source
    else:
      live_target, live_crc = (
        target_candidate if result == "TARGET_COMMITTED" else target_source,
        crc_source,
      )
    if live_overrides is not None and name in live_overrides:
      live_target, live_crc = live_overrides[name]
    transports.extend((
      FakeRestoreTransport(
        f"{name}-live",
        events,
        wrong if wrong_identity and not transports else boot_identity,
        OP_LIVE_READ,
        _live_read_result(live_target, live_crc),
        failure=TimeoutError("live read response lost")
        if failure == f"{name}-live" else None,
      ),
      FakeRestoreTransport(
        f"{name}-writer",
        events,
        boot_identity,
        OP_RESTORE_SECTOR,
        writer_result,
        failure=TimeoutError("writer response lost") if failure == f"{name}-writer" else None,
      ),
    ))

  def factory():
    assert transports
    return transports.pop(0)

  confirmations = []
  power_prompts = []
  report = None
  for _invocation in range(len(order) * 2):
    try:
      report = run_restore(
        layout=layout,
        payloads=_restore_payloads(),
        templates=_restore_templates(),
        preflight=lambda: events.append(("preflight",)),
        transport_factory=factory,
        confirmation=lambda prompt: confirmations.append(prompt) or (
          prompt if exact_confirmation else prompt + " "
        ),
        power_cycle_checkpoint=lambda prompt: (
          power_prompts.append(prompt), events.append(("power", prompt)), None,
        )[-1],
        target=target,
        new_uds=False,
      )
    except RestoreError:
      report = None
      break
    if report.name == "restore-report.json":
      break
  attempts = sorted(layout.restore_root.iterdir())
  assert len(attempts) == 1
  return (
    report,
    attempts[0] / "state.json",
    incident_path,
    events,
    confirmations,
    power_prompts,
  )


def test_run_restore_discovers_fixed_evidence_and_attempt_paths_from_layout_only():
  from eps_patch.restore import run_restore

  parameters = inspect.signature(run_restore).parameters
  assert "layout" in parameters
  assert not {
    "backup", "backup_path", "probe_directory", "incident_directory",
    "artifact_directory", "output",
  } & set(parameters)


def test_restore_crc_first_then_target_with_fresh_identity_and_exact_confirmation(tmp_path):
  report, state_path, incident_path, events, confirmations, power_prompts = _run_restore(
    tmp_path,
  )

  assert report == state_path.parent / "restore-report.json"
  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert state["result"] == "PASS"
  assert state["completed_sector_bases"] == ["0xf8000", "0x88000"]
  assert state["incident_state_sha256"] == sha256_bytes(incident_path.read_bytes())
  payloads = [event for event in events if len(event) > 2 and event[1] == "payload"]
  assert [event[2] for event in payloads] == [
    OP_LIVE_READ, OP_RESTORE_SECTOR, OP_LIVE_READ, OP_RESTORE_SECTOR,
  ]
  assert [event[3] for event in payloads] == [
    "live_read", "restore_sector", "live_read", "restore_sector",
  ]
  assert len(confirmations) == 2
  assert confirmations[0].startswith("RESTORE-SECTOR 8965B4512000 0xf8000 ")
  assert confirmations[1].startswith("RESTORE-SECTOR 8965B4512000 0x88000 ")
  incident_digest = sha256_bytes(incident_path.read_bytes())
  assert all(incident_digest in prompt for prompt in confirmations)
  assert any("CRC_COMMITTED -> TARGET_LIVE_PRECHECKED" in prompt for prompt in power_prompts)
  assert (state_path.parent / "returned-sector-0xf8000.bin").exists()
  assert (state_path.parent / "returned-sector-0x88000.bin").exists()


@pytest.mark.parametrize(
  ("incident_result", "order"),
  (
    ("TARGET_COMMITTED", ("target",)),
    ("CRC_COMMITTED", ("crc", "target")),
  ),
)
def test_restore_accepts_planned_committed_patch_checkpoint(
  tmp_path,
  incident_result,
  order,
):
  report, state_path, _incident, _events, _confirmations, _prompts = _run_restore(
    tmp_path,
    order=order,
    incident_result=incident_result,
  )

  assert report == state_path.parent / "restore-report.json"
  assert json.loads(state_path.read_text(encoding="utf-8"))["result"] == "PASS"


def test_restore_live_reads_both_sectors_before_each_writer_arm(tmp_path):
  report, state_path, _incident, events, _confirmations, power_prompts = _run_restore(
    tmp_path,
  )

  assert report is not None
  live_events = [
    event for event in events
    if len(event) > 2 and event[1] == "payload" and event[2] == OP_LIVE_READ
  ]
  assert [(event[0], event[2], event[3]) for event in live_events] == [
    ("crc-live", OP_LIVE_READ, "live_read"),
    ("target-live", OP_LIVE_READ, "live_read"),
  ]
  transitions = json.loads(state_path.read_text(encoding="utf-8"))["transitions"]
  names = [transition["result"] for transition in transitions]
  assert names.index("CRC_LIVE_PRECHECKED") < names.index("CRC_ARMED")
  assert names.index("TARGET_LIVE_PRECHECKED") < names.index("TARGET_ARMED")
  crc_evidence = next(
    transition["evidence"] for transition in transitions
    if transition["result"] == "CRC_LIVE_PRECHECKED"
  )
  target_evidence = next(
    transition["evidence"] for transition in transitions
    if transition["result"] == "TARGET_LIVE_PRECHECKED"
  )
  assert crc_evidence["live_sectors"]["target"]["state"] == "candidate"
  assert crc_evidence["live_sectors"]["crc"]["state"] == "candidate"
  assert target_evidence["live_sectors"]["target"]["state"] == "candidate"
  assert target_evidence["live_sectors"]["crc"]["state"] == "source"
  assert any("CRC_LIVE_PRECHECKED -> CRC_ARMED" in item for item in power_prompts)
  assert any("CRC_COMMITTED -> TARGET_LIVE_PRECHECKED" in item for item in power_prompts)
  assert any("TARGET_LIVE_PRECHECKED -> TARGET_ARMED" in item for item in power_prompts)


def test_restore_rejects_contradictory_live_state_before_confirmation_or_writer(tmp_path):
  layout, _target, _identity, _target_source, crc_source, _tc, crc_candidate = (
    _probe_case(tmp_path / "fixture")
  )
  del layout
  report, state_path, _incident, events, confirmations, _powers = _run_restore(
    tmp_path,
    order=("target",),
    live_overrides={"target": (bytes(0x8000), crc_candidate)},
  )

  assert report is None
  assert json.loads(state_path.read_text(encoding="utf-8"))["result"] == "FAILED"
  assert confirmations == []
  assert not any(
    len(event) > 2 and event[1] == "payload" and event[2] == OP_RESTORE_SECTOR
    for event in events
  )
  assert crc_source != crc_candidate


def test_live_read_failure_after_crc_commit_is_terminal_indeterminate(tmp_path):
  report, state_path, _incident, events, confirmations, _powers = _run_restore(
    tmp_path,
    failure="target-live",
  )

  assert report is None
  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert state["result"] == "INDETERMINATE"
  assert state["completed_sector_bases"] == ["0xf8000"]
  assert len(confirmations) == 1
  assert not any(
    event[0] == "target-writer" and len(event) > 1 and event[1] == "payload"
    for event in events
  )


def test_restore_fails_closed_while_reviewed_live_read_pin_is_missing(monkeypatch):
  import eps_patch.restore as restore_module

  monkeypatch.setattr(restore_module, "LIVE_READ_ENVELOPE_SHA256", None)
  with pytest.raises(restore_module.RestoreError, match="not built and pinned"):
    restore_module._validate_live_read_payload(_restore_payloads(), patch_fx.TARGET)


def test_restore_rejects_missing_original_backup_before_hardware(tmp_path):
  from eps_patch.restore import RestoreError, run_restore

  layout, target, *_case = _probe_case(tmp_path)
  _patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  layout.target_backup.unlink()
  events = []

  with pytest.raises(RestoreError, match="probe evidence"):
    run_restore(
      layout=layout,
      payloads=_restore_payloads(),
      templates=_restore_templates(),
      preflight=lambda: events.append("preflight"),
      transport_factory=lambda: events.append("transport"),
      confirmation=lambda prompt: prompt,
      power_cycle_checkpoint=lambda _prompt: "",
      target=target,
      new_uds=False,
    )

  assert events == []
  assert not layout.restore_root.exists()


def test_restore_rejects_live_identity_mismatch_without_flash_write(tmp_path):
  report, state_path, _incident, events, _confirmations, _powers = _run_restore(
    tmp_path,
    order=("target",),
    wrong_identity=True,
  )

  assert report is None
  assert json.loads(state_path.read_text(encoding="utf-8"))["result"] == "FAILED"
  assert not any(
    len(event) > 2 and event[1] == "payload" and event[2] == OP_RESTORE_SECTOR
    for event in events
  )


def test_restore_requires_incident_bound_confirmation_before_writer_arm(tmp_path):
  report, state_path, _incident, events, confirmations, _powers = _run_restore(
    tmp_path,
    order=("target",),
    exact_confirmation=False,
  )

  assert report is None
  assert len(confirmations) == 1
  assert json.loads(state_path.read_text(encoding="utf-8"))["result"] == "FAILED"
  assert not any(
    len(event) > 2 and event[1] == "payload" and event[2] == OP_RESTORE_SECTOR
    for event in events
  )


def test_restore_rejects_an_already_running_restore_attempt(tmp_path):
  from eps_patch.restore import RestoreError, run_restore

  layout, target, *_case = _probe_case(tmp_path)
  _patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  running = layout.restore_attempt("20260817T010204Z")
  running.mkdir(parents=True)
  events = []

  with pytest.raises(RestoreError, match="already-running"):
    run_restore(
      layout=layout,
      payloads=_restore_payloads(),
      templates=_restore_templates(),
      preflight=lambda: events.append("preflight"),
      transport_factory=lambda: events.append("transport"),
      confirmation=lambda prompt: prompt,
      power_cycle_checkpoint=lambda _prompt: "",
      target=target,
      new_uds=False,
    )

  assert events == []


def _write_prior_restore_state(layout, plan, *, result: str) -> Path:
  timestamp = "20260817T010204Z"
  prior = layout.restore_attempt(timestamp)
  prior.mkdir(parents=True)
  recorded_at = "2026-08-17T01:02:04+00:00"
  if result == "FAILED":
    states = ("STARTED", "FAILED")
  elif result == "INDETERMINATE":
    states = (
      "STARTED", "TARGET_LIVE_PRECHECKED",
      "TARGET_ARMED", "INDETERMINATE",
    )
  elif result == "PASS":
    states = ["STARTED"]
    for label in plan.restore_order:
      upper = label.upper()
      states.extend((
        f"{upper}_LIVE_PRECHECKED",
        f"{upper}_ARMED", f"{upper}_COMMITTED",
      ))
    states.append("PASS")
  else:
    states = ("STARTED", result)
  transitions = []
  for sequence, state_name in enumerate(states):
    transition = {
      "sequence": sequence,
      "result": state_name,
      "recorded_at": recorded_at,
      "evidence": {} if state_name in {"FAILED", "INDETERMINATE"} else {
        "state": state_name,
      },
    }
    if state_name in {"FAILED", "INDETERMINATE"}:
      transition["error"] = "test restore failure"
    transitions.append(transition)
  state = {
    "schema": 1,
    "workflow": "restore",
    "attempt": timestamp,
    "sequence": len(transitions) - 1,
    "result": result,
    "restore_order": list(plan.restore_order),
    "sector_bases": [f"0x{base:x}" for base in plan.sector_bases],
    "completed_sector_bases": [f"0x{base:x}" for base in plan.sector_bases]
    if result == "PASS" else [],
    "created_at": recorded_at,
    "updated_at": recorded_at,
    "incident_timestamp": plan.incident_timestamp,
    "incident_result": plan.incident_result,
    "incident_state_sha256": plan.incident_state_sha256,
    "probe_report_sha256": plan.probe_report_sha256,
    "automatic_retry": False,
    "external_recovery_required": result == "INDETERMINATE",
    "transitions": transitions,
    "validation_errors": [] if result == "PASS" else ["test restore failure"],
  }
  path = prior / "state.json"
  path.write_text(json.dumps(state), encoding="utf-8")
  return path


def test_restore_rejects_an_indeterminate_prior_restore_and_requires_external_recovery(tmp_path):
  from eps_patch.restore import RestoreError, run_restore, select_restore_plan

  layout, target, *_case = _probe_case(tmp_path)
  _patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  plan = select_restore_plan(layout)
  _write_prior_restore_state(layout, plan, result="INDETERMINATE")
  events = []

  with pytest.raises(RestoreError, match="external programming|professional recovery"):
    run_restore(
      layout=layout,
      payloads=_restore_payloads(),
      templates=_restore_templates(),
      preflight=lambda: events.append("preflight"),
      transport_factory=lambda: events.append("transport"),
      confirmation=lambda prompt: prompt,
      power_cycle_checkpoint=lambda _prompt: "",
      target=target,
      new_uds=False,
    )

  assert events == []


def test_terminal_pre_arm_failure_does_not_block_a_new_restore_attempt(tmp_path):
  from eps_patch.restore import _reject_prior_restore, select_restore_plan

  layout, *_case = _probe_case(tmp_path)
  _patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  plan = select_restore_plan(layout)
  _write_prior_restore_state(layout, plan, result="FAILED")

  assert _reject_prior_restore(layout, plan) is None


def test_pass_restore_supersedes_incident_by_timestamp_after_state_hash_changes(tmp_path):
  """Using the mutable state digest as incident identity can repeat a writer."""
  from eps_patch.restore import (
    RestoreError,
    _reject_prior_restore,
    run_restore,
    select_restore_plan,
  )

  layout, target, *_case = _probe_case(tmp_path)
  incident_path = _patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  original_plan = select_restore_plan(layout)
  _write_prior_restore_state(layout, original_plan, result="PASS")
  incident = json.loads(incident_path.read_text(encoding="utf-8"))
  incident["transitions"][0]["evidence"]["state"] = "same incident, new digest"
  incident_path.write_text(json.dumps(incident), encoding="utf-8")
  changed_plan = select_restore_plan(layout)

  assert changed_plan.incident_timestamp == original_plan.incident_timestamp
  assert changed_plan.incident_state_sha256 != original_plan.incident_state_sha256
  assert _reject_prior_restore(
    layout, changed_plan, allow_selected_pass=True,
  ) is True
  events = []
  with pytest.raises(RestoreError, match="already has a PASS restore"):
    run_restore(
      layout=layout,
      payloads=_restore_payloads(),
      templates=_restore_templates(),
      preflight=lambda: events.append("preflight"),
      transport_factory=lambda: events.append("transport"),
      confirmation=lambda prompt: prompt,
      power_cycle_checkpoint=lambda _prompt: None,
      target=target,
      new_uds=False,
    )
  assert events == []


def test_malformed_prior_failed_restore_does_not_bypass_one_shot_guard(tmp_path):
  from eps_patch.restore import RestoreError, _reject_prior_restore, select_restore_plan

  layout, *_case = _probe_case(tmp_path)
  _patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  plan = select_restore_plan(layout)
  prior = layout.restore_attempt("20260817T010204Z")
  prior.mkdir(parents=True)
  (prior / "state.json").write_text(json.dumps({
    "schema": 1,
    "workflow": "restore",
    "result": "FAILED",
    "incident_state_sha256": plan.incident_state_sha256,
  }), encoding="utf-8")

  with pytest.raises(RestoreError, match="malformed"):
    _reject_prior_restore(layout, plan)


def test_patch_and_restore_share_one_nonblocking_operation_lock(tmp_path):
  from eps_patch.operation_lock import OperationBusyError, exclusive_operation
  from eps_patch.patch import run_patch
  from eps_patch.restore import run_restore

  layout = ArtifactLayout(tmp_path / "artifacts")
  arguments = {
    "layout": layout,
    "payloads": {},
    "templates": {},
    "preflight": lambda: None,
    "transport_factory": lambda: None,
    "confirmation": lambda prompt: prompt,
    "power_cycle_checkpoint": lambda _prompt: "",
    "target": patch_fx.TARGET,
    "new_uds": False,
  }
  with exclusive_operation(layout, "test-holder"):
    with pytest.raises(OperationBusyError, match="already running"):
      run_patch(**arguments)
    with pytest.raises(OperationBusyError, match="already running"):
      run_restore(**arguments)


def test_restore_attempt_creation_fails_if_parent_directory_cannot_be_synced(
  tmp_path,
  monkeypatch,
):
  import eps_patch.restore as restore_module

  layout = ArtifactLayout(tmp_path / "artifacts")
  layout.root.mkdir(parents=True)
  real_sync = restore_module._fsync_directory

  def fail_restore_root(path):
    if path == layout.restore_root:
      raise OSError("directory fsync failed")
    return real_sync(path)

  monkeypatch.setattr(restore_module, "_fsync_directory", fail_restore_root)
  with pytest.raises(OSError, match="fsync"):
    restore_module._create_attempt(layout)


@pytest.mark.parametrize("fault", ("transport-loss", "malformed-result", "evidence-install"))
def test_post_arm_restore_uncertainty_is_terminal_indeterminate_without_retry(
  tmp_path,
  monkeypatch,
  fault,
):
  import eps_patch.restore as restore_module

  if fault == "transport-loss":
    failure = "crc-writer"
  elif fault == "malformed-result":
    failure = "malformed-result"
  else:
    failure = None
  if fault == "evidence-install":
    monkeypatch.setattr(
      restore_module,
      "_persist_sector",
      lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk unavailable")),
    )

  report, state_path, _incident, events, _confirmations, _powers = _run_restore(
    tmp_path,
    failure=failure,
  )

  assert report is None
  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert state["result"] == "INDETERMINATE"
  assert state["automatic_retry"] is False
  assert state["external_recovery_required"] is True
  restore_calls = [
    event for event in events
    if len(event) > 2 and event[1] == "payload" and event[2] == OP_RESTORE_SECTOR
  ]
  assert len(restore_calls) == 1


def test_restore_intent_binds_fixed_reverse_source_and_candidate_crc(tmp_path):
  from eps_patch.evidence import load_probe_pass
  from eps_patch.restore import _backup_for_base, build_restore_intent

  layout, target, *_case = _probe_case(tmp_path)
  trusted = load_probe_pass(layout, target)
  for base in (target.crc_sector_base, target.sector_base):
    backup = _backup_for_base(trusted, base, target)
    intent = build_restore_intent(backup, target=target)
    assert len(intent) == 0x80
    assert int.from_bytes(intent[16:20], "little") == binascii.crc32(backup.data)
    check = bytearray(intent)
    supplied = check[124:128]
    check[124:128] = bytes(4)
    assert supplied == binascii.crc32(check).to_bytes(4, "little")
    if base == target.crc_sector_base:
      source = bytearray(backup.data)
      source[target.crc_adjust_offset:target.crc_adjust_offset + 4] = (
        target.crc_patched_adjust_word.to_bytes(4, "little")
      )
      assert intent[20:24] == target.crc_patched_adjust_word.to_bytes(4, "little")
      assert intent[24:28] == target.crc_original_adjust_word.to_bytes(4, "little")
    else:
      source = bytearray(backup.data)
      source[target.instruction_offset:target.instruction_offset + 4] = target.patched_instruction
      assert intent[20:24] == target.patched_instruction
      assert intent[24:28] == target.original_instruction
    assert int.from_bytes(intent[12:16], "little") == binascii.crc32(source)
