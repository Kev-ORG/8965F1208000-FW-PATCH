import binascii
import hashlib
import inspect
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from eps_patch.evidence import install_probe_pass
from eps_patch.manifest import TARGET
from eps_patch.paths import ArtifactLayout
from eps_patch.protocol import (
  CrcObservation,
  OP_CRC_INTERMEDIATE,
  OP_CRC_PROBE,
  OP_VERIFY_CRC,
  OP_WRITE_CRC_CANDIDATE,
  OP_WRITE_TARGET_CANDIDATE,
  RegionResult,
  StreamResult,
)
from eps_patch.transport import BootloaderIdentity, EcuIdentity

import test_evidence as evidence_fx


OLD_ADJUSTMENT = TARGET.crc_original_adjust_word.to_bytes(4, "little")
NEW_ADJUSTMENT = TARGET.crc_patched_adjust_word.to_bytes(4, "little")


def _case(layout: ArtifactLayout):
  target_source = bytearray((index * 17) & 0xFF for index in range(TARGET.sector_length))
  target_source[TARGET.instruction_offset:TARGET.instruction_offset + 4] = TARGET.original_instruction
  target_source = bytes(target_source)
  target_candidate = bytearray(target_source)
  target_candidate[TARGET.patch_offset] = TARGET.patched_instruction[2]
  target_candidate = bytes(target_candidate)
  crc_source = bytearray((index * 29) & 0xFF for index in range(TARGET.sector_length))
  crc_source[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = OLD_ADJUSTMENT
  magic_offset = TARGET.magic_addresses[1] - TARGET.crc_sector_base
  crc_source[magic_offset:magic_offset + 4] = TARGET.magic_word.to_bytes(4, "little")
  crc_source = bytes(crc_source)
  crc_candidate = bytearray(crc_source)
  crc_candidate[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = NEW_ADJUSTMENT
  crc_candidate = bytes(crc_candidate)
  target = replace(
    TARGET,
    original_sha256=hashlib.sha256(target_source).hexdigest(),
    patched_sha256=hashlib.sha256(target_candidate).hexdigest(),
  )
  report = evidence_fx.make_report(target_source, crc_source)
  metadata = evidence_fx.make_metadata(target_source, crc_source)
  install_probe_pass(layout, target_source, crc_source, report, metadata)
  identity = EcuIdentity(
    part_number=target.part_number,
    application_software_id=target.application_software_id,
    boot_software_id=target.boot_software_id,
    panda_serial="test-panda",
  )
  return target, identity, target_source, crc_source, target_candidate, crc_candidate


def _observation(*, old_adjustment, target_candidate, crc_candidate, final=False):
  return CrcObservation(
    entry_ctl=0x10203040,
    entry_cout=0x50607080,
    range_start=TARGET.crc_range_start,
    range_end=TARGET.crc_range_end,
    adjust_address=TARGET.crc_adjust_address,
    old_adjust_word=int.from_bytes(old_adjustment, "little"),
    patched_prefix_sw=TARGET.crc_patched_prefix_sw,
    new_adjust_word=TARGET.crc_patched_adjust_word,
    original_sw_full=TARGET.crc_residue,
    patched_sw_full=TARGET.crc_residue,
    original_dcra_raw=TARGET.crc_residue,
    patched_dcra_raw=TARGET.crc_residue,
    exit_ctl=0x10203040,
    exit_cout=0x50607080,
    sram_echo_length=0 if final else TARGET.sector_length,
    sram_echo_crc32=0 if final else binascii.crc32(target_candidate),
  )


def _crc_result(operation, target_sector, crc_sector, observation):
  values = tuple(
    getattr(observation, name)
    for name in (
      "entry_ctl", "entry_cout", "range_start", "range_end", "adjust_address",
      "old_adjust_word", "patched_prefix_sw", "new_adjust_word",
      "original_sw_full", "patched_sw_full", "original_dcra_raw",
      "patched_dcra_raw", "exit_ctl", "exit_cout", "sram_echo_length",
      "sram_echo_crc32",
    )
  )
  return StreamResult(
    operation=operation,
    sector=None,
    magic_words=(TARGET.magic_word, TARGET.magic_word),
    statuses=((1, 0),),
    regions=(
      RegionResult(TARGET.sector_base, target_sector),
      RegionResult(TARGET.crc_sector_base, crc_sector),
    ),
    crc_values=values,
    crc=observation,
  )


def _writer_result(operation, sector_base, sector):
  return StreamResult(
    operation=operation,
    sector=sector,
    magic_words=(TARGET.magic_word, TARGET.magic_word),
    statuses=tuple((stage, 0) for stage in range(1, 7)),
    regions=(RegionResult(sector_base, sector),),
  )


class FakeTransport:
  def __init__(self, label, events, identity, result, *, failure=None, boot=False):
    self.label = label
    self.events = events
    self.identity = identity
    self.result = result
    self.failure = failure
    self.boot = boot

  def __enter__(self):
    self.events.append((self.label, "open"))
    return self

  def __exit__(self, *_args):
    self.events.append((self.label, "close"))

  def read_identity(self):
    self.events.append((self.label, "identity"))
    return self.identity

  def read_bootloader_identity(self):
    self.events.append((self.label, "boot-identity"))
    return BootloaderIdentity(self.identity.boot_software_id, self.identity.panda_serial)

  def run_staged_payload(self, _image, *, ram_blob, operation, new_uds):
    self.events.append((self.label, "staged", operation, ram_blob.data))
    if self.failure is not None:
      raise self.failure
    return self.result

  def run_payload(self, _image, *, operation, new_uds):
    self.events.append((self.label, "payload", operation))
    if self.failure is not None:
      raise self.failure
    return self.result


def _payloads():
  from eps_patch.patch import (
    CRC_INTERMEDIATE_ENVELOPE_SHA256,
    CRC_PROBE_ENVELOPE_SHA256,
    CRC_VERIFY_ENVELOPE_SHA256,
  )
  from eps_patch.payload import build_envelope, load_built_shellcode

  build = Path(__file__).resolve().parents[1] / "payload" / "build"
  digests = {
    "crc_probe": CRC_PROBE_ENVELOPE_SHA256,
    "crc_intermediate": CRC_INTERMEDIATE_ENVELOPE_SHA256,
    "crc_verify": CRC_VERIFY_ENVELOPE_SHA256,
  }
  payloads = {}
  for name, digest in digests.items():
    shellcode = load_built_shellcode(build, name)
    envelope = build_envelope(
      shellcode, did_201=bytes(16), did_202=bytes(16), iv=bytes(16),
    )
    assert hashlib.sha256(envelope).hexdigest() == digest
    payloads[name] = SimpleNamespace(name=name, envelope=envelope, sha256=digest)
  return payloads


def _templates():
  build = Path(__file__).resolve().parents[1] / "payload" / "build"
  return {
    name: (build / f"{name}.bin").read_bytes()
    for name in ("write_target_candidate", "write_crc_candidate")
  }


def _run_patch(tmp_path, *, failure_stage=None):
  from eps_patch.patch import PatchError, run_patch

  layout = ArtifactLayout(tmp_path / "artifacts")
  target, identity, target_source, crc_source, target_candidate, crc_candidate = _case(layout)
  target_precheck = _crc_result(
    OP_CRC_PROBE,
    target_source,
    crc_source,
    _observation(
      old_adjustment=OLD_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
    ),
  )
  intermediate_observation = replace(
    _observation(
      old_adjustment=OLD_ADJUSTMENT,
      target_candidate=crc_candidate,
      crc_candidate=crc_candidate,
    ),
    original_sw_full=0x12345678,
    original_dcra_raw=0x12345678,
  )
  intermediate = _crc_result(
    OP_CRC_INTERMEDIATE, target_candidate, crc_source, intermediate_observation,
  )
  final = _crc_result(
    OP_VERIFY_CRC,
    target_candidate,
    crc_candidate,
    _observation(
      old_adjustment=NEW_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
      final=True,
    ),
  )
  events = []
  transports = [
    FakeTransport("target-precheck", events, identity, target_precheck),
    FakeTransport(
      "target-writer", events, identity,
      _writer_result(OP_WRITE_TARGET_CANDIDATE, target.sector_base, target_candidate),
      failure=TimeoutError("target response lost") if failure_stage == "target-armed" else None,
    ),
    FakeTransport("crc-precheck", events, identity, intermediate, boot=True),
    FakeTransport(
      "crc-writer", events, identity,
      _writer_result(OP_WRITE_CRC_CANDIDATE, target.crc_sector_base, crc_candidate),
      failure=TimeoutError("CRC response lost") if failure_stage == "crc-armed" else None,
      boot=True,
    ),
    FakeTransport("verify", events, identity, final),
  ]

  if failure_stage == "before-target-arm":
    transports[0].failure = RuntimeError("precheck failed")

  def factory():
    assert transports
    return transports.pop(0)

  power_count = 0

  def power(prompt):
    nonlocal power_count
    power_count += 1
    events.append(("power", prompt))
    if failure_stage == "target-committed" and power_count == 2:
      raise RuntimeError("cycle failed")
    if failure_stage == "crc-committed" and power_count == 3:
      raise RuntimeError("cycle failed")
    return ""

  confirmations = []

  def confirmation(prompt):
    confirmations.append(prompt)
    return prompt

  try:
    result = run_patch(
      layout=layout,
      payloads=_payloads(),
      templates=_templates(),
      preflight=lambda: events.append(("preflight",)),
      transport_factory=factory,
      confirmation=confirmation,
      power_cycle_checkpoint=power,
      target=target,
      new_uds=False,
    )
  except PatchError:
    result = None
  attempts = sorted(layout.patch_root.iterdir())
  assert len(attempts) == 1
  return result, attempts[0] / "state.json", events, confirmations


def test_run_patch_discovers_fixed_probe_and_attempt_paths_from_layout_only():
  from eps_patch.patch import run_patch

  parameters = inspect.signature(run_patch).parameters
  assert "layout" in parameters
  assert not {"probe_directory", "probe_report", "artifact_directory", "output"} & set(parameters)


def test_patch_preserves_two_sector_order_confirmations_and_reconnects(tmp_path):
  result, state_path, events, confirmations = _run_patch(tmp_path)

  assert result == state_path.parent / "patch-report.json"
  state = json.loads(state_path.read_text())
  assert state["result"] == "PASS"
  assert state["restore_order"] == []
  power_prompts = [event[1] for event in events if event[0] == "power"]
  assert len(power_prompts) == 3
  assert "PROBED -> TARGET_PRECHECKED" in power_prompts[0]
  assert "TARGET_COMMITTED -> CRC_PRECHECKED" in power_prompts[1]
  assert "CRC_COMMITTED -> VERIFY_PENDING" in power_prompts[2]
  assert [event[0] for event in events if len(event) > 1 and event[1] in {
    "open", "identity", "boot-identity",
  }] == [
    "target-precheck", "target-precheck",
    "target-writer", "target-writer",
    "crc-precheck", "crc-precheck",
    "crc-writer", "crc-writer",
    "verify", "verify",
  ]
  assert len(confirmations) == 2
  assert confirmations[0].startswith("WRITE-TARGET 8965B4512000 0x60000 ")
  assert confirmations[1].startswith("WRITE-CRC 8965B4512000 0xf8000 ")
  assert all("->" in prompt for prompt in confirmations)


@pytest.mark.parametrize(
  ("failure_stage", "expected_result", "restore_order"),
  [
    ("before-target-arm", "FAILED", []),
    ("target-armed", "TARGET_INDETERMINATE", ["target"]),
    ("target-committed", "RECOVERY_REQUIRED", ["target"]),
    ("crc-armed", "CRC_INDETERMINATE", ["crc", "target"]),
    ("crc-committed", "RECOVERY_REQUIRED", ["crc", "target"]),
  ],
)
def test_patch_failure_persists_restore_plan(
  tmp_path, failure_stage, expected_result, restore_order,
):
  result, state_path, _events, _confirmations = _run_patch(
    tmp_path, failure_stage=failure_stage,
  )

  assert result is None
  state = json.loads(state_path.read_text())
  assert state["result"] == expected_result
  assert state["restore_order"] == restore_order
