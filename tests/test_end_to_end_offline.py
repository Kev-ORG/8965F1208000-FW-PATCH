"""Offline lifecycle coverage using deterministic transport fakes only."""

import binascii
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from eps_patch.manifest import TARGET
from eps_patch.paths import ArtifactLayout
from eps_patch.protocol import (
  CrcObservation,
  DcraObservation,
  FACI_PE_CYCLE_DIAGNOSTICS,
  OP_CRC_INTERMEDIATE,
  OP_CRC_PROBE,
  OP_FACI_PE_CYCLE,
  OP_LIVE_READ,
  OP_RESTORE_SECTOR,
  OP_VERIFY_CRC,
  OP_WRITE_CRC_CANDIDATE,
  OP_WRITE_TARGET_CANDIDATE,
  RegionResult,
  StreamResult,
)
from eps_patch.transport import BootloaderIdentity, EcuIdentity

import test_patch as patch_fx


class _PatchTransport:
  def __init__(self, identity, result):
    self.identity = identity
    self.result = result

  def __enter__(self):
    return self

  def __exit__(self, *_args):
    return None

  def read_identity(self):
    return self.identity

  def read_bootloader_identity(self):
    return BootloaderIdentity(self.identity.boot_software_id, self.identity.panda_serial)

  def run_payload(self, _image, *, operation, new_uds):
    assert operation == self.result.operation
    assert new_uds is False
    return self.result


class _RestoreTransport:
  def __init__(self, identity, result):
    self.identity = identity
    self.result = result

  def __enter__(self):
    return self

  def __exit__(self, *_args):
    return None

  def read_bootloader_identity(self):
    return self.identity

  def run_payload(self, image, *, operation, new_uds):
    assert image.name in {"live_read", "restore_sector"}
    assert operation == self.result.operation
    assert new_uds is False
    return self.result


class _TriggerPanda:
  def __init__(self, _serial=None):
    pass

  def set_safety_mode(self, _mode):
    return None

  def close(self):
    return None


class _TriggerUds:
  def __init__(self, *_args, **_kwargs):
    pass


class _RoutedTransport:
  """Return deterministic streams while exercising the real FF00 router."""

  def __init__(self, identity, result, records):
    self.identity = identity
    self.result = result
    self.records = records
    self._route_transport = None
    self._frames = []

  def __enter__(self):
    from eps_patch.transport import EcuTransport

    bindings = SimpleNamespace(
      Panda=_TriggerPanda,
      UdsClient=_TriggerUds,
      elm327=0,
      isotp_send=lambda _panda, frame, *_args, **_kwargs: self._frames.append(
        bytes(frame)
      ),
    )
    self._route_transport = EcuTransport(
      bindings=bindings, sleeper=lambda _seconds: None,
    ).__enter__()
    return self

  def __exit__(self, *_args):
    assert self._route_transport is not None
    self._route_transport.__exit__(None, None, None)
    self._route_transport = None

  def read_identity(self):
    return self.identity

  def read_bootloader_identity(self):
    return BootloaderIdentity(
      self.identity.boot_software_id, self.identity.panda_serial,
    )

  def run_payload(self, image, *, operation, new_uds):
    assert self._route_transport is not None
    assert operation == self.result.operation
    assert new_uds is False
    destructive = operation in (
      OP_RESTORE_SECTOR, OP_WRITE_CRC_CANDIDATE, OP_WRITE_TARGET_CANDIDATE,
    )
    actual_base = image.sector_base if destructive else None
    frame_count = len(self._frames)
    self._route_transport.trigger(
      operation=operation,
      new_uds=new_uds,
      sector_base=actual_base,
    )
    assert len(self._frames) == frame_count + 1
    returned_base = (
      self.result.regions[0].base if self.result.sector is not None else None
    )
    self.records.append(SimpleNamespace(
      operation=operation,
      actual_base=actual_base,
      trigger_frame=self._frames[-1],
      returned_base=returned_base,
    ))
    return self.result


class OfflineBench:
  """A deterministic, hardware-free fixture for the public workflows."""

  def __init__(self, target, identity, source_target, source_crc):
    self.target = target
    self.identity = identity
    self.source_target = source_target
    self.source_crc = source_crc
    target_candidate = bytearray(source_target)
    target_candidate[target.patch_offset] = target.patched_instruction[2]
    self.target_candidate = bytes(target_candidate)
    crc_candidate = bytearray(source_crc)
    crc_candidate[target.crc_adjust_offset:target.crc_adjust_offset + 4] = (
      target.crc_patched_adjust_word.to_bytes(4, "little")
    )
    self.crc_candidate = bytes(crc_candidate)
    self.restore_writes: list[int] = []

  @classmethod
  def original_8965b4512000(cls):
    source_target = bytearray(
      (index * 17) & 0xFF for index in range(TARGET.sector_length)
    )
    source_target[
      TARGET.instruction_offset:TARGET.instruction_offset + 4
    ] = TARGET.original_instruction
    source_crc = bytearray(
      (index * 29) & 0xFF for index in range(TARGET.sector_length)
    )
    source_crc[
      TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4
    ] = TARGET.crc_original_adjust_word.to_bytes(4, "little")
    magic_offset = TARGET.magic_addresses[1] - TARGET.crc_sector_base
    source_crc[magic_offset:magic_offset + 4] = TARGET.magic_word.to_bytes(4, "little")
    target_candidate = bytearray(source_target)
    target_candidate[TARGET.patch_offset] = TARGET.patched_instruction[2]
    target = replace(
      TARGET,
      original_sha256=hashlib.sha256(source_target).hexdigest(),
      patched_sha256=hashlib.sha256(target_candidate).hexdigest(),
    )
    identity = EcuIdentity(
      part_number=target.part_number,
      application_software_id=target.application_software_id,
      boot_software_id=target.boot_software_id,
      panda_serial="offline-panda",
    )
    return cls(target, identity, bytes(source_target), bytes(source_crc))

  def _payload(self, name):
    from eps_patch.payload import build_envelope, load_built_shellcode

    root = Path(__file__).resolve().parents[1] / "payload" / "build"
    envelope = build_envelope(
      load_built_shellcode(root, name),
      did_201=bytes(16),
      did_202=bytes(16),
      iv=bytes(16),
    )
    return SimpleNamespace(
      name=name,
      envelope=envelope,
      sha256=hashlib.sha256(envelope).hexdigest(),
    )

  def _probe_result(self):
    observation = DcraObservation(
      entry_ctl=0x10203040,
      entry_cout=0x50607080,
      range_start=self.target.crc_range_start,
      range_end=self.target.crc_range_end,
      adjust_address=self.target.crc_adjust_address,
      old_adjust_word=self.target.crc_original_adjust_word,
      new_adjust_word=self.target.crc_patched_adjust_word,
      original_dcra_raw=self.target.crc_residue,
      patched_dcra_raw=self.target.crc_residue,
      exit_ctl=0x10203040,
      exit_cout=0x50607080,
    )
    values = tuple(getattr(observation, name.lower()) for name in (
      "ENTRY_CTL", "ENTRY_COUT", "RANGE_START", "RANGE_END", "ADJUST_ADDRESS",
      "OLD_ADJUST_WORD", "NEW_ADJUST_WORD", "ORIGINAL_DCRA_RAW",
      "PATCHED_DCRA_RAW", "EXIT_CTL", "EXIT_COUT",
    ))
    idle = (0x80, 0x8000, 0, 0, 0, 0, 0, 0)
    unlocked = idle[:3] + (1,) + idle[4:]
    windows = unlocked[:6] + (1, 1)
    configured = unlocked[:4] + (1, 0, 1, 1)
    assert len(FACI_PE_CYCLE_DIAGNOSTICS) == 40
    return StreamResult(
      operation=OP_FACI_PE_CYCLE,
      sector=None,
      magic_words=(self.target.magic_word, self.target.magic_word),
      statuses=((1, 0),),
      faci_values=idle + unlocked + windows + configured + idle,
      regions=(
        RegionResult(self.target.sector_base, self.source_target),
        RegionResult(self.target.crc_sector_base, self.source_crc),
      ),
      dcra_values=values,
      dcra=observation,
    )

  def run_probe(self, *, layout):
    from eps_patch.probe import PayloadImage, run_probe

    payload = self._payload("probe_pe_cycle")
    return run_probe(
      layout=layout,
      payload=PayloadImage(**payload.__dict__),
      preflight=lambda: None,
      transport_factory=lambda: _PatchTransport(self.identity, self._probe_result()),
      target=self.target,
      new_uds=False,
    )

  def _crc_observation(self, *, adjustment, staged, final=False):
    return CrcObservation(
      entry_ctl=0x10203040,
      entry_cout=0x50607080,
      range_start=self.target.crc_range_start,
      range_end=self.target.crc_range_end,
      adjust_address=self.target.crc_adjust_address,
      old_adjust_word=int.from_bytes(adjustment, "little"),
      patched_prefix_sw=self.target.crc_patched_prefix_sw,
      new_adjust_word=self.target.crc_patched_adjust_word,
      original_sw_full=self.target.crc_residue,
      patched_sw_full=self.target.crc_residue,
      original_dcra_raw=self.target.crc_residue,
      patched_dcra_raw=self.target.crc_residue,
      exit_ctl=0x10203040,
      exit_cout=0x50607080,
      sram_echo_length=0,
      sram_echo_crc32=0,
    )

  def _crc_result(self, operation, target_sector, crc_sector, observation):
    values = tuple(getattr(observation, name) for name in (
      "entry_ctl", "entry_cout", "range_start", "range_end", "adjust_address",
      "old_adjust_word", "patched_prefix_sw", "new_adjust_word",
      "original_sw_full", "patched_sw_full", "original_dcra_raw",
      "patched_dcra_raw", "exit_ctl", "exit_cout", "sram_echo_length",
      "sram_echo_crc32",
    ))
    return StreamResult(
      operation=operation,
      sector=None,
      magic_words=(self.target.magic_word, self.target.magic_word),
      statuses=((1, 0),),
      regions=(
        RegionResult(self.target.sector_base, target_sector),
        RegionResult(self.target.crc_sector_base, crc_sector),
      ),
      crc_values=values,
      crc=observation,
    )

  def _writer_result(self, operation, base, sector):
    return StreamResult(
      operation=operation,
      sector=sector,
      magic_words=(self.target.magic_word, self.target.magic_word),
      statuses=tuple((stage, 0) for stage in range(1, 7)),
      regions=(RegionResult(base, sector),),
    )

  def run_patch(self, *, layout):
    from eps_patch.patch import run_patch

    old = self.target.crc_original_adjust_word.to_bytes(4, "little")
    new = self.target.crc_patched_adjust_word.to_bytes(4, "little")
    intermediate = replace(
      self._crc_observation(adjustment=old, staged=self.crc_candidate),
      original_sw_full=0x12345678,
      original_dcra_raw=0x12345678,
    )
    results = [
      self._crc_result(
        OP_CRC_PROBE, self.source_target, self.source_crc,
        self._crc_observation(adjustment=old, staged=self.target_candidate),
      ),
      self._writer_result(
        OP_WRITE_TARGET_CANDIDATE, self.target.sector_base, self.target_candidate,
      ),
      self._crc_result(
        OP_CRC_INTERMEDIATE, self.target_candidate, self.source_crc, intermediate,
      ),
      self._writer_result(
        OP_WRITE_CRC_CANDIDATE, self.target.crc_sector_base, self.crc_candidate,
      ),
      self._crc_result(
        OP_VERIFY_CRC, self.target_candidate, self.crc_candidate,
        self._crc_observation(adjustment=new, staged=self.target_candidate, final=True),
      ),
    ]
    transports = [_PatchTransport(self.identity, result) for result in results]
    result = None
    for _invocation in range(6):
      result = run_patch(
        layout=layout,
        payloads={name: self._payload(name) for name in (
          "crc_probe", "crc_intermediate", "crc_verify", "live_read",
        )},
        templates={
          name: (Path(__file__).resolve().parents[1] / "payload" / "build" / f"{name}.bin").read_bytes()
          for name in ("write_target_candidate", "write_crc_candidate")
        },
        preflight=lambda: None,
        transport_factory=lambda: transports.pop(0),
        confirmation=lambda prompt: prompt,
        power_cycle_checkpoint=lambda _prompt: None,
        target=self.target,
        new_uds=False,
      )
    assert result is not None
    return result

  def create_crc_indeterminate_fixture(self, layout):
    from eps_patch.artifacts import sha256_bytes

    directory = layout.patch_attempt("20260817T010203Z")
    directory.mkdir(parents=True)
    recorded_at = "2026-08-17T01:02:03+00:00"
    states = (
      "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
      "TARGET_COMMITTED", "CRC_PRECHECKED", "CRC_ARMED", "CRC_INDETERMINATE",
    )
    transitions = [
      {
        "sequence": index,
        "result": name,
        "recorded_at": recorded_at,
        "evidence": {} if name == "CRC_INDETERMINATE" else {"state": name},
        **({"error": "offline CRC transport loss"} if name == "CRC_INDETERMINATE" else {}),
      }
      for index, name in enumerate(states)
    ]
    probe = json.loads(layout.probe_report.read_text(encoding="utf-8"))
    state = {
      "schema": 1,
      "workflow": "patch",
      "attempt": directory.name,
      "sequence": len(transitions) - 1,
      "result": "CRC_INDETERMINATE",
      "restore_order": ["crc", "target"],
      "created_at": recorded_at,
      "updated_at": recorded_at,
      "probe_report_sha256": sha256_bytes(json.dumps(
        probe, sort_keys=True, separators=(",", ":"),
      ).encode("utf-8")),
      "automatic_forward_resume": False,
      "automatic_retry": False,
      "transitions": transitions,
      "validation_errors": [],
    }
    (directory / "state.json").write_text(json.dumps(state), encoding="utf-8")
    return self

  def run_restore(self, *, layout):
    from eps_patch.restore import run_restore

    boot_identity = BootloaderIdentity(
      self.identity.boot_software_id, self.identity.panda_serial,
    )
    transports = []
    for base, original, live_target, live_crc in (
      (self.target.crc_sector_base, self.source_crc, self.target_candidate, self.crc_candidate),
      (self.target.sector_base, self.source_target, self.target_candidate, self.source_crc),
    ):
      transports.extend((
        _RestoreTransport(
          boot_identity,
          StreamResult(
            operation=OP_LIVE_READ,
            sector=None,
            magic_words=(self.target.magic_word, self.target.magic_word),
            statuses=((1, 0),),
            regions=(
              RegionResult(self.target.sector_base, live_target),
              RegionResult(self.target.crc_sector_base, live_crc),
            ),
          ),
        ),
        _RestoreTransport(
          boot_identity,
          self._writer_result(OP_RESTORE_SECTOR, base, original),
        ),
      ))

    def transport_factory():
      transport = transports.pop(0)
      original_run = transport.run_payload

      def tracked_run(image, *, operation, new_uds):
        if operation == OP_RESTORE_SECTOR:
          self.restore_writes.append(transport.result.regions[0].base)
        return original_run(image, operation=operation, new_uds=new_uds)

      transport.run_payload = tracked_run
      return transport

    result = None
    for _invocation in range(6):
      result = run_restore(
        layout=layout,
        payloads={"live_read": self._payload("live_read")},
        templates={
          "restore_sector": (
            Path(__file__).resolve().parents[1] / "payload" / "build" / "restore_sector.bin"
          ).read_bytes(),
        },
        preflight=lambda: None,
        transport_factory=transport_factory,
        confirmation=lambda prompt: prompt,
        power_cycle_checkpoint=lambda _prompt: None,
        target=self.target,
        new_uds=False,
      )
      if result.name == "restore-report.json":
        break
    assert result is not None
    return result


def test_probe_patch_restore_lifecycle_without_external_paths(tmp_path):
  layout = ArtifactLayout(tmp_path)
  bench = OfflineBench.original_8965b4512000()

  assert bench.run_probe(layout=layout) == layout.probe_report
  patch_report = bench.run_patch(layout=layout)
  assert json.loads(patch_report.read_text(encoding="utf-8"))["result"] == "PASS"

  incident = bench.create_crc_indeterminate_fixture(layout)
  restore_report = bench.run_restore(layout=layout)
  assert json.loads(restore_report.read_text(encoding="utf-8"))["result"] == "PASS"
  assert incident.restore_writes == [0xF8000, 0x60000]


def test_supplied_legacy_crc_incident_uses_one_corrected_route_writer(tmp_path):
  from eps_patch.patch import run_patch
  from eps_patch.restore import _legacy_crc_trigger_recovery_status

  (
    layout, state_path, target, identity, _target_source, crc_source,
    target_candidate, crc_candidate,
  ) = patch_fx._legacy_crc_trigger_case(tmp_path)
  records = []
  confirmations = []
  power_cycles = []

  def invoke(result):
    return run_patch(
      layout=layout,
      payloads=patch_fx._payloads(),
      templates=patch_fx._templates(),
      preflight=lambda: None,
      transport_factory=lambda: _RoutedTransport(identity, result, records),
      # The public callback returns the displayed transaction only after the
      # CLI has accepted exact uppercase YES.
      confirmation=lambda prompt: confirmations.append(prompt) or prompt,
      power_cycle_checkpoint=lambda prompt: power_cycles.append(prompt),
      target=target,
      new_uds=False,
    )

  pending = json.loads(state_path.read_text(encoding="utf-8"))
  assert _legacy_crc_trigger_recovery_status(pending["transitions"]) == "pending"

  assert invoke(
    patch_fx._live_read_result(target_candidate, crc_source),
  ) == state_path
  reconciled = json.loads(state_path.read_text(encoding="utf-8"))
  assert reconciled["result"] == "CRC_PRECHECKED"
  assert reconciled["power_cycle"] == {
    "completed_state": "CRC_PRECHECKED",
    "next_state": "CRC_ARMED",
  }
  assert confirmations == []

  assert invoke(patch_fx._writer_result(
    OP_WRITE_CRC_CANDIDATE, target.crc_sector_base, crc_candidate,
  )) == state_path
  committed = json.loads(state_path.read_text(encoding="utf-8"))
  assert committed["result"] == "CRC_COMMITTED"
  assert committed["power_cycle"] == {
    "completed_state": "CRC_COMMITTED",
    "next_state": "VERIFY_PENDING",
  }

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
  report_path = invoke(final)
  state = json.loads(state_path.read_text(encoding="utf-8"))
  assert report_path.name == "patch-report.json"
  assert json.loads(report_path.read_text(encoding="utf-8"))["result"] == "PASS"
  assert state["result"] == "PASS"
  assert [transition["result"] for transition in state["transitions"][-5:]] == [
    "CRC_PRECHECKED", "CRC_ARMED", "CRC_COMMITTED", "VERIFY_PENDING", "PASS",
  ]
  assert _legacy_crc_trigger_recovery_status(state["transitions"]) == "consumed"
  assert len(power_cycles) == 2

  crc_writer_records = [
    record for record in records
    if record.operation == OP_WRITE_CRC_CANDIDATE
  ]
  assert [record.operation for record in records] == [
    OP_LIVE_READ, OP_WRITE_CRC_CANDIDATE, OP_VERIFY_CRC,
  ]
  assert len(crc_writer_records) == 1
  assert crc_writer_records[0].actual_base == 0xF8000
  assert crc_writer_records[0].returned_base == 0xF8000
  assert crc_writer_records[0].trigger_frame == bytes.fromhex(
    "31 01 ff 00 45 00 00 0e 00 00 00 00 80 00"
  )
  crc_arms = [
    transition for transition in state["transitions"]
    if transition["result"] == "CRC_ARMED"
  ]
  assert len(confirmations) == 1
  assert confirmations[0].startswith("WRITE-CRC 8965B4512000 0xf8000 ")
  assert crc_arms[-1]["evidence"]["confirmation"] == confirmations[0]


def test_restore_routes_crc_before_target_after_fresh_live_reads(tmp_path):
  from eps_patch.restore import run_restore

  (
    layout, _incident_path, target, identity, target_source, crc_source,
    target_candidate, crc_candidate,
  ) = patch_fx._crc_indeterminate_case(tmp_path)
  records = []
  confirmations = []
  power_cycles = []
  build = Path(__file__).resolve().parents[1] / "payload" / "build"

  def invoke(result):
    return run_restore(
      layout=layout,
      payloads={"live_read": patch_fx._payloads()["live_read"]},
      templates={"restore_sector": (build / "restore_sector.bin").read_bytes()},
      preflight=lambda: None,
      transport_factory=lambda: _RoutedTransport(identity, result, records),
      confirmation=lambda prompt: confirmations.append(prompt) or prompt,
      power_cycle_checkpoint=lambda prompt: power_cycles.append(prompt),
      target=target,
      new_uds=False,
    )

  state_path = invoke(patch_fx._live_read_result(target_candidate, crc_candidate))
  assert json.loads(state_path.read_text(encoding="utf-8"))["result"] == (
    "CRC_LIVE_PRECHECKED"
  )
  assert invoke(patch_fx._writer_result(
    OP_RESTORE_SECTOR, target.crc_sector_base, crc_source,
  )) == state_path
  assert json.loads(state_path.read_text(encoding="utf-8"))["result"] == (
    "CRC_COMMITTED"
  )
  assert invoke(patch_fx._live_read_result(target_candidate, crc_source)) == state_path
  assert json.loads(state_path.read_text(encoding="utf-8"))["result"] == (
    "TARGET_LIVE_PRECHECKED"
  )
  report_path = invoke(patch_fx._writer_result(
    OP_RESTORE_SECTOR, target.sector_base, target_source,
  ))

  report = json.loads(report_path.read_text(encoding="utf-8"))
  state = json.loads((report_path.parent / "state.json").read_text(encoding="utf-8"))
  assert report["result"] == "PASS"
  assert state["completed_sector_bases"] == ["0xf8000", "0x60000"]
  assert [record.operation for record in records] == [
    OP_LIVE_READ, OP_RESTORE_SECTOR, OP_LIVE_READ, OP_RESTORE_SECTOR,
  ]
  writer_records = [
    record for record in records if record.operation == OP_RESTORE_SECTOR
  ]
  assert [record.actual_base for record in writer_records] == [0xF8000, 0x60000]
  assert [record.returned_base for record in writer_records] == [0xF8000, 0x60000]
  assert [record.trigger_frame for record in writer_records] == [
    bytes.fromhex("31 01 ff 00 45 00 00 0e 00 00 00 00 80 00"),
    bytes.fromhex("31 01 ff 00 45 00 00 0e 00 00 00 00 80 00"),
  ]
  assert len(confirmations) == 2
  assert confirmations[0].startswith("RESTORE-SECTOR 8965B4512000 0xf8000 ")
  assert confirmations[1].startswith("RESTORE-SECTOR 8965B4512000 0x60000 ")
  armed = [
    transition["evidence"]["confirmation"]
    for transition in state["transitions"]
    if transition["result"] in {"CRC_ARMED", "TARGET_ARMED"}
  ]
  assert armed == confirmations
  assert len(power_cycles) == 3
