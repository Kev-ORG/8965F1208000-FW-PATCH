"""Durable restart-resume behavior at planned complete power cycles."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from eps_patch.paths import ArtifactLayout
from eps_patch.protocol import (
  OP_CRC_INTERMEDIATE,
  OP_CRC_PROBE,
  OP_LIVE_READ,
  OP_RAM_ECHO,
  OP_RESTORE_SECTOR,
  OP_VERIFY_CRC,
  OP_WRITE_CRC_CANDIDATE,
  OP_WRITE_TARGET_CANDIDATE,
)
from eps_patch.transport import BootloaderIdentity

import test_patch as patch_fx
import test_restore as restore_fx


def _checkpoint(state_path):
  state = json.loads(state_path.read_text(encoding="utf-8"))
  return state, state["power_cycle"]


def _patch_results(target, target_source, crc_source, target_candidate, crc_candidate):
  target_precheck = patch_fx._crc_result(
    OP_CRC_PROBE,
    target_source,
    crc_source,
    patch_fx._observation(
      old_adjustment=patch_fx.OLD_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
    ),
  )
  intermediate_observation = replace(
    patch_fx._observation(
      old_adjustment=patch_fx.OLD_ADJUSTMENT,
      target_candidate=crc_candidate,
      crc_candidate=crc_candidate,
    ),
    original_sw_full=0x12345678,
    original_dcra_raw=0x12345678,
  )
  intermediate = patch_fx._crc_result(
    OP_CRC_INTERMEDIATE,
    target_candidate,
    crc_source,
    intermediate_observation,
  )
  final = patch_fx._crc_result(
    OP_VERIFY_CRC,
    target_candidate,
    crc_candidate,
    patch_fx._observation(
      old_adjustment=patch_fx.NEW_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
      final=True,
    ),
  )
  return (
    target_precheck,
    patch_fx._writer_result(
      OP_WRITE_TARGET_CANDIDATE, target.sector_base, target_candidate,
    ),
    intermediate,
    patch_fx._writer_result(
      OP_WRITE_CRC_CANDIDATE, target.crc_sector_base, crc_candidate,
    ),
    final,
  )


def test_patch_persists_before_emitting_the_first_restart_instruction(tmp_path):
  """Moving persistence after output could lose the only resume checkpoint."""
  from eps_patch.patch import run_patch

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, *_case = patch_fx._case(layout)

  def output_failed(_prompt):
    raise RuntimeError("stdout unavailable")

  with pytest.raises(RuntimeError, match="stdout unavailable"):
    run_patch(
      layout=layout,
      payloads=patch_fx._payloads(),
      templates=patch_fx._templates(),
      preflight=lambda: None,
      transport_factory=lambda: pytest.fail("first invocation must not connect"),
      confirmation=lambda _prompt: pytest.fail("first invocation must not confirm"),
      power_cycle_checkpoint=output_failed,
      target=target,
      new_uds=False,
    )

  attempts = tuple(layout.patch_root.iterdir())
  assert len(attempts) == 1
  state, checkpoint = _checkpoint(attempts[0] / "state.json")
  assert state["schema"] == 2
  assert state["result"] == "PROBED"
  assert checkpoint == {
    "completed_state": "PROBED",
    "next_state": "TARGET_PRECHECKED",
  }


def test_patch_resumes_one_stage_per_manual_rerun_in_the_same_attempt(tmp_path):
  """Starting over or crossing two cycle boundaries in one run is unsafe."""
  from eps_patch.patch import run_patch

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, identity, target_source, crc_source, target_candidate, crc_candidate = (
    patch_fx._case(layout)
  )
  results = list(_patch_results(
    target, target_source, crc_source, target_candidate, crc_candidate,
  ))
  transports = []
  events = []
  prompts = []

  def factory():
    events.append("transport")
    assert transports
    return transports.pop(0)

  def invoke():
    return run_patch(
      layout=layout,
      payloads=patch_fx._payloads(),
      templates=patch_fx._templates(),
      preflight=lambda: events.append("preflight"),
      transport_factory=factory,
      confirmation=lambda prompt: events.append("confirmation") or prompt,
      power_cycle_checkpoint=lambda prompt: prompts.append(prompt),
      target=target,
      new_uds=False,
    )

  state_path = invoke()
  assert state_path.name == "state.json"
  assert len(tuple(layout.patch_root.iterdir())) == 1
  assert events == ["preflight"]
  state, checkpoint = _checkpoint(state_path)
  assert state["result"] == "PROBED"
  assert checkpoint["next_state"] == "TARGET_PRECHECKED"

  transports.extend((
    patch_fx.FakeTransport("target-precheck", events, identity, results.pop(0)),
    patch_fx.FakeTransport("target-writer", events, identity, results.pop(0)),
  ))
  events.clear()
  assert invoke() == state_path
  assert [event for event in events if event == "transport"] == [
    "transport", "transport",
  ]
  state, checkpoint = _checkpoint(state_path)
  assert state["result"] == "TARGET_COMMITTED"
  assert checkpoint == {
    "completed_state": "TARGET_COMMITTED",
    "next_state": "CRC_PRECHECKED",
  }

  transports.extend((
    patch_fx.FakeTransport("crc-precheck", events, identity, results.pop(0), boot=True),
    patch_fx.FakeTransport("crc-writer", events, identity, results.pop(0), boot=True),
  ))
  events.clear()
  assert invoke() == state_path
  state, checkpoint = _checkpoint(state_path)
  assert state["result"] == "CRC_COMMITTED"
  assert checkpoint == {
    "completed_state": "CRC_COMMITTED",
    "next_state": "VERIFY_PENDING",
  }

  transports.append(
    patch_fx.FakeTransport("verify", events, identity, results.pop(0)),
  )
  events.clear()
  report_path = invoke()
  assert report_path.name == "patch-report.json"
  assert json.loads(report_path.read_text(encoding="utf-8"))["result"] == "PASS"
  assert results == []
  assert transports == []
  assert len(tuple(layout.patch_root.iterdir())) == 1


def test_patch_writer_commit_stays_resumable_when_instruction_output_fails(tmp_path):
  """Output loss after exact writer PASS must not turn into writer uncertainty."""
  from eps_patch.patch import run_patch

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, identity, target_source, crc_source, target_candidate, crc_candidate = (
    patch_fx._case(layout)
  )
  results = list(_patch_results(
    target, target_source, crc_source, target_candidate, crc_candidate,
  ))
  events = []
  transports = [
    patch_fx.FakeTransport("target-precheck", events, identity, results.pop(0)),
    patch_fx.FakeTransport("target-writer", events, identity, results.pop(0)),
  ]
  outputs = 0

  def emit(_prompt):
    nonlocal outputs
    outputs += 1
    if outputs == 2:
      raise RuntimeError("stdout unavailable after target commit")

  arguments = {
    "layout": layout,
    "payloads": patch_fx._payloads(),
    "templates": patch_fx._templates(),
    "preflight": lambda: None,
    "transport_factory": lambda: transports.pop(0),
    "confirmation": lambda prompt: prompt,
    "power_cycle_checkpoint": emit,
    "target": target,
    "new_uds": False,
  }
  state_path = run_patch(**arguments)
  with pytest.raises(RuntimeError, match="stdout unavailable after target commit"):
    run_patch(**arguments)

  state, checkpoint = _checkpoint(state_path)
  assert state["result"] == "TARGET_COMMITTED"
  assert checkpoint["next_state"] == "CRC_PRECHECKED"
  target_writes = [
    event for event in events
    if len(event) > 2 and event[1] == "staged"
      and event[2] == OP_WRITE_TARGET_CANDIDATE
  ]
  assert len(target_writes) == 1


def test_patch_rejects_a_schema_two_resume_state_without_its_checkpoint(tmp_path):
  """Treating a missing checkpoint as an abandoned pre-arm run could start over."""
  from eps_patch.patch import PatchError, run_patch

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, *_case = patch_fx._case(layout)
  arguments = {
    "layout": layout,
    "payloads": patch_fx._payloads(),
    "templates": patch_fx._templates(),
    "preflight": lambda: None,
    "transport_factory": lambda: pytest.fail("malformed state must fail before hardware"),
    "confirmation": lambda _prompt: pytest.fail("malformed state must not confirm"),
    "power_cycle_checkpoint": lambda _prompt: None,
    "target": target,
    "new_uds": False,
  }
  state_path = run_patch(**arguments)
  state = json.loads(state_path.read_text(encoding="utf-8"))
  state["power_cycle"] = None
  state_path.write_text(json.dumps(state), encoding="utf-8")

  with pytest.raises(PatchError, match="checkpoint|state"):
    run_patch(**arguments)


def test_pass_restore_supersedes_paused_patch_by_timestamp_after_hash_change(tmp_path):
  """A restored paused attempt must never resume a destructive next stage."""
  from eps_patch.patch import run_patch
  from eps_patch.restore import select_restore_plan

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, identity, target_source, crc_source, target_candidate, crc_candidate = (
    patch_fx._case(layout)
  )
  results = list(_patch_results(
    target, target_source, crc_source, target_candidate, crc_candidate,
  ))
  events = []
  transports = [
    patch_fx.FakeTransport("target-precheck", events, identity, results.pop(0)),
    patch_fx.FakeTransport("target-writer", events, identity, results.pop(0)),
  ]

  def factory():
    events.append("transport")
    return transports.pop(0)

  arguments = {
    "layout": layout,
    "payloads": patch_fx._payloads(),
    "templates": patch_fx._templates(),
    "preflight": lambda: events.append("preflight"),
    "transport_factory": factory,
    "confirmation": lambda prompt: events.append("confirmation") or prompt,
    "power_cycle_checkpoint": lambda _prompt: None,
    "target": target,
    "new_uds": False,
  }
  first_state = run_patch(**arguments)
  paused_state = run_patch(**arguments)
  assert json.loads(paused_state.read_text(encoding="utf-8"))["result"] == (
    "TARGET_COMMITTED"
  )
  plan = select_restore_plan(layout)
  restore_fx._write_prior_restore_state(layout, plan, result="PASS")
  changed = json.loads(paused_state.read_text(encoding="utf-8"))
  changed["transitions"][0]["evidence"]["probe_report"] += "#same-incident"
  paused_state.write_text(json.dumps(changed), encoding="utf-8")

  events.clear()
  new_state = run_patch(**arguments)

  assert new_state != first_state
  assert new_state.parent != paused_state.parent
  assert events == ["preflight"]
  assert transports == []
  assert json.loads(new_state.read_text(encoding="utf-8"))["result"] == "PROBED"


def test_restore_resumes_one_hardware_stage_per_manual_rerun(tmp_path, monkeypatch):
  """A restore rerun must not repeat echo/live-read or cross a planned cycle."""
  import eps_patch.restore as restore_module

  monkeypatch.setattr(
    restore_module,
    "LIVE_READ_ENVELOPE_SHA256",
    restore_fx.TEST_LIVE_READ_ENVELOPE_SHA256,
  )
  layout, target, identity, target_source, crc_source, target_candidate, _crc_candidate = (
    restore_fx._probe_case(tmp_path)
  )
  restore_fx._patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  boot_identity = BootloaderIdentity(
    identity.boot_software_id, identity.panda_serial,
  )
  events = []
  prompts = []
  transports = [
    restore_fx.FakeRestoreTransport(
      "target-echo", events, boot_identity, OP_RAM_ECHO,
      restore_fx._ram_echo_result(target_source),
    ),
    restore_fx.FakeRestoreTransport(
      "target-live", events, boot_identity, OP_LIVE_READ,
      restore_fx._live_read_result(target_candidate, crc_source),
    ),
    restore_fx.FakeRestoreTransport(
      "target-writer", events, boot_identity, OP_RESTORE_SECTOR,
      restore_fx._restore_result(target.sector_base, target_source),
    ),
  ]

  def invoke():
    return restore_module.run_restore(
      layout=layout,
      payloads=restore_fx._restore_payloads(),
      templates=restore_fx._restore_templates(),
      preflight=lambda: events.append(("preflight",)),
      transport_factory=lambda: transports.pop(0),
      confirmation=lambda prompt: events.append(("confirmation",)) or prompt,
      power_cycle_checkpoint=lambda prompt: prompts.append(prompt),
      target=target,
      new_uds=False,
    )

  state_path = invoke()
  state, checkpoint = _checkpoint(state_path)
  assert state["result"] == "TARGET_ECHO_VERIFIED"
  assert checkpoint["next_state"] == "TARGET_LIVE_PRECHECKED"
  assert len(transports) == 2

  assert invoke() == state_path
  state, checkpoint = _checkpoint(state_path)
  assert state["result"] == "TARGET_LIVE_PRECHECKED"
  assert checkpoint["next_state"] == "TARGET_ARMED"
  assert len(transports) == 1

  report_path = invoke()
  assert report_path.name == "restore-report.json"
  assert json.loads(report_path.read_text(encoding="utf-8"))["result"] == "PASS"
  assert transports == []
  assert len(tuple(layout.restore_root.iterdir())) == 1


def test_restore_persists_echo_before_instruction_output_failure(tmp_path, monkeypatch):
  """A lost prompt must leave the completed read-only stage restart-resumable."""
  import eps_patch.restore as restore_module

  monkeypatch.setattr(
    restore_module,
    "LIVE_READ_ENVELOPE_SHA256",
    restore_fx.TEST_LIVE_READ_ENVELOPE_SHA256,
  )
  layout, target, identity, target_source, *_case = restore_fx._probe_case(tmp_path)
  restore_fx._patch_state(
    layout,
    result="TARGET_INDETERMINATE",
    restore_order=["target"],
  )
  boot_identity = BootloaderIdentity(
    identity.boot_software_id, identity.panda_serial,
  )
  transport = restore_fx.FakeRestoreTransport(
    "target-echo", [], boot_identity, OP_RAM_ECHO,
    restore_fx._ram_echo_result(target_source),
  )

  with pytest.raises(RuntimeError, match="stdout unavailable"):
    restore_module.run_restore(
      layout=layout,
      payloads=restore_fx._restore_payloads(),
      templates=restore_fx._restore_templates(),
      preflight=lambda: None,
      transport_factory=lambda: transport,
      confirmation=lambda _prompt: pytest.fail("echo stage must not confirm"),
      power_cycle_checkpoint=lambda _prompt: (_ for _ in ()).throw(
        RuntimeError("stdout unavailable")
      ),
      target=target,
      new_uds=False,
    )

  attempts = tuple(layout.restore_root.iterdir())
  assert len(attempts) == 1
  state, checkpoint = _checkpoint(attempts[0] / "state.json")
  assert state["result"] == "TARGET_ECHO_VERIFIED"
  assert checkpoint["next_state"] == "TARGET_LIVE_PRECHECKED"


def test_probe_has_no_restart_resume_dependency():
  """Adding a boot-session dependency to probe would create a planned cycle."""
  import inspect

  from eps_patch.probe import run_probe

  parameters = inspect.signature(run_probe).parameters
  assert "boot_session_id" not in parameters
  assert "power_cycle_checkpoint" not in parameters
