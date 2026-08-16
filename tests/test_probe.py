import binascii
import copy
import hashlib
import struct
from dataclasses import replace
from pathlib import Path

import pytest

from eps_patch.evidence import load_probe_pass
from eps_patch.manifest import TARGET
from eps_patch.paths import ArtifactLayout
from eps_patch.protocol import (
  DCRA_RECORDS,
  DcraObservation,
  FACI_PE_CYCLE_DIAGNOSTICS,
  OP_FACI_PE_CYCLE,
  RegionResult,
  StreamResult,
)
from eps_patch.transport import EcuIdentity


IDLE = (0x80, 0x8000, 0, 0, 0, 0, 0, 0)
UNLOCKED = IDLE[:3] + (1,) + IDLE[4:]
WINDOWS = UNLOCKED[:6] + (1, 1)
CONFIGURED = UNLOCKED[:4] + (1, 0, 1, 1)
FACI_VALUES = IDLE + UNLOCKED + WINDOWS + CONFIGURED + IDLE
REVIEWED_PROBE_ENVELOPE_SHA256 = (
  "a8b4bddce38bfbea34df4088b8827c8c5bd46bad4ab9fe4f764bba157a5338cc"
)


class FakeTransport:
  def __init__(self, identity: EcuIdentity, result: StreamResult):
    self.identity = identity
    self.result = result
    self.operations: list[int] = []

  def __enter__(self):
    return self

  def __exit__(self, *_args):
    return None

  def read_identity(self) -> EcuIdentity:
    return self.identity

  def run_payload(self, image, *, operation: int, new_uds: bool) -> StreamResult:
    assert image.name == "probe_pe_cycle"
    assert new_uds is False
    self.operations.append(operation)
    return self.result


def _identity(target) -> EcuIdentity:
  return EcuIdentity(
    part_number=target.part_number,
    application_software_id=target.application_software_id,
    boot_software_id=target.boot_software_id,
    panda_serial="test-panda",
  )


def _sectors():
  target_sector = bytearray((index * 17 + 3) & 0xFF for index in range(TARGET.sector_length))
  target_sector[TARGET.instruction_offset:TARGET.instruction_offset + 4] = TARGET.original_instruction
  crc_sector = bytearray((index * 29 + 7) & 0xFF for index in range(TARGET.sector_length))
  crc_sector[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = (
    TARGET.crc_original_adjust_word.to_bytes(4, "little")
  )
  magic_offset = TARGET.magic_addresses[1] - TARGET.crc_sector_base
  crc_sector[magic_offset:magic_offset + 4] = TARGET.magic_word.to_bytes(4, "little")
  return bytes(target_sector), bytes(crc_sector)


def _observation(target_sector: bytes, crc_sector: bytes) -> DcraObservation:
  old_adjustment = int.from_bytes(
    crc_sector[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4], "little",
  )
  return DcraObservation(
    entry_ctl=0x10203040,
    entry_cout=0x50607080,
    range_start=TARGET.crc_range_start,
    range_end=TARGET.crc_range_end,
    adjust_address=TARGET.crc_adjust_address,
    old_adjust_word=old_adjustment,
    new_adjust_word=TARGET.crc_patched_adjust_word,
    original_dcra_raw=TARGET.crc_residue,
    patched_dcra_raw=TARGET.crc_residue,
    exit_ctl=0x10203040,
    exit_cout=0x50607080,
  )


def _replace_dcra(result: StreamResult, **changes) -> StreamResult:
  observation = replace(result.dcra, **changes)
  values = tuple(getattr(observation, name.lower()) for name in DCRA_RECORDS)
  return replace(result, dcra=observation, dcra_values=values)


@pytest.fixture
def probe_case(tmp_path: Path):
  from eps_patch.probe import PayloadImage
  from eps_patch.payload import build_envelope, load_built_shellcode

  target_sector, crc_sector = _sectors()
  target = replace(TARGET, original_sha256=hashlib.sha256(target_sector).hexdigest())
  observation = _observation(target_sector, crc_sector)
  values = tuple(getattr(observation, name.lower()) for name in DCRA_RECORDS)
  result = StreamResult(
    operation=OP_FACI_PE_CYCLE,
    sector=None,
    magic_words=(target.magic_word, target.magic_word),
    statuses=((1, 0),),
    faci_values=FACI_VALUES,
    regions=(
      RegionResult(target.sector_base, target_sector),
      RegionResult(target.crc_sector_base, crc_sector),
    ),
    dcra_values=values,
    dcra=observation,
  )
  build = Path(__file__).resolve().parents[1] / "payload" / "build"
  shellcode = load_built_shellcode(build, "probe_pe_cycle")
  envelope = build_envelope(
    shellcode, did_201=bytes(16), did_202=bytes(16), iv=bytes(16),
  )
  assert hashlib.sha256(envelope).hexdigest() == REVIEWED_PROBE_ENVELOPE_SHA256
  payload = PayloadImage(
    name="probe_pe_cycle",
    envelope=envelope,
    sha256=hashlib.sha256(envelope).hexdigest(),
  )
  return ArtifactLayout(tmp_path), target, payload, _identity(target), result


def test_probe_runs_one_payload_and_atomically_installs_complete_pass(probe_case):
  from eps_patch.probe import run_probe

  layout, target, payload, identity, result = probe_case
  transport = FakeTransport(identity, result)

  path = run_probe(
    layout=layout,
    payload=payload,
    preflight=lambda: None,
    transport_factory=lambda: transport,
    target=target,
    new_uds=False,
  )

  assert transport.operations == [OP_FACI_PE_CYCLE]
  assert path == layout.probe_report
  evidence = load_probe_pass(layout, target)
  assert evidence.target_sector == result.regions[0].data
  assert evidence.crc_sector == result.regions[1].data
  assert evidence.report["result"] == "PASS"
  assert evidence.report["payload"] == {
    "name": "probe_pe_cycle", "sha256": REVIEWED_PROBE_ENVELOPE_SHA256,
  }
  assert evidence.report["dcra"]["original_dcra_raw"] == TARGET.crc_residue
  assert evidence.report["host_checks"] == {
    "combined_crc32": binascii.crc32(result.regions[0].data + result.regions[1].data),
    "crc_sector_crc32": binascii.crc32(result.regions[1].data),
    "original_adjust_word": TARGET.crc_original_adjust_word,
    "patched_adjust_word": TARGET.crc_patched_adjust_word,
    "patched_prefix_sw": TARGET.crc_patched_prefix_sw,
    "residue": TARGET.crc_residue,
    "target_sector_crc32": binascii.crc32(result.regions[0].data),
    "target_sector_sha256": hashlib.sha256(result.regions[0].data).hexdigest(),
  }


def test_probe_rejects_arbitrary_self_declared_payload_before_any_side_effect(probe_case):
  from eps_patch.probe import PayloadImage, ProbeError, run_probe

  layout, target, _payload, identity, result = probe_case
  arbitrary = bytes(target.envelope_length)
  payload = PayloadImage(
    name="probe_pe_cycle",
    envelope=arbitrary,
    sha256=hashlib.sha256(arbitrary).hexdigest(),
  )
  events = []

  with pytest.raises(ProbeError, match="reviewed.*envelope"):
    run_probe(
      layout=layout,
      payload=payload,
      preflight=lambda: events.append("preflight"),
      transport_factory=lambda: events.append("transport") or FakeTransport(identity, result),
      target=target,
      new_uds=False,
    )

  assert events == []
  assert not layout.probe_directory.exists()


@pytest.mark.parametrize(
  ("mutation", "message"),
  [
    (lambda identity, result: (identity, replace(result, statuses=((1, 9),))), "primary"),
    (
      lambda identity, result: (
        identity, replace(result, statuses=((1, 0x00100000),)),
      ),
      "cleanup",
    ),
    (
      lambda identity, result: (identity, replace(result, faci_values=result.faci_values[:-1])),
      "diagnostic",
    ),
    (
      lambda identity, result: (
        identity, replace(result, faci_values=(0,) + result.faci_values[1:]),
      ),
      "PRE",
    ),
    (
      lambda identity, result: (
        identity, replace(result, faci_values=result.faci_values[:-1] + (1,)),
      ),
      "RESTORED",
    ),
    (
      lambda identity, result: (
        identity,
        replace(
          result,
          faci_values=result.faci_values[:28] + (0,) + result.faci_values[29:],
        ),
      ),
      "CONFIGURED",
    ),
    (
      lambda identity, result: (
        replace(identity, part_number=b"WRONG"), result,
      ),
      "identity",
    ),
    (
      lambda identity, result: (
        identity,
        replace(
          result,
          regions=(
            replace(result.regions[0], data=bytes([result.regions[0].data[0] ^ 1]) + result.regions[0].data[1:]),
            result.regions[1],
          ),
        ),
      ),
      "target sector",
    ),
    (
      lambda identity, result: (
        identity,
        replace(
          result,
          regions=(
            result.regions[0],
            replace(
              result.regions[1],
              data=(
                result.regions[1].data[:TARGET.crc_adjust_offset]
                + bytes([result.regions[1].data[TARGET.crc_adjust_offset] ^ 1])
                + result.regions[1].data[TARGET.crc_adjust_offset + 1:]
              ),
            ),
          ),
        ),
      ),
      "CRC sector",
    ),
    (
      lambda identity, result: (identity, replace(result, dcra=None)),
      "DCRA observation",
    ),
    (
      lambda identity, result: (
        identity,
        _replace_dcra(result, patched_dcra_raw=0),
      ),
      "DCRA residue",
    ),
  ],
)
def test_probe_failure_never_installs_any_trusted_artifact(probe_case, mutation, message):
  from eps_patch.probe import ProbeError, run_probe

  layout, target, payload, identity, result = probe_case
  changed_identity, changed_result = mutation(identity, copy.deepcopy(result))
  transport = FakeTransport(changed_identity, changed_result)

  with pytest.raises(ProbeError, match=message):
    run_probe(
      layout=layout,
      payload=payload,
      preflight=lambda: None,
      transport_factory=lambda: transport,
      target=target,
      new_uds=False,
    )

  assert not layout.probe_directory.exists()


def test_probe_protocol_layout_is_one_two_region_crc_and_faci_stream():
  assert len(FACI_PE_CYCLE_DIAGNOSTICS) == 40
  assert len(DCRA_RECORDS) == 11
  assert tuple(name.split(".", 1)[0] for name, _address, _width in FACI_PE_CYCLE_DIAGNOSTICS) == (
    ("PRE",) * 8 + ("UNLOCKED",) * 8 + ("WINDOWS",) * 8
    + ("CONFIGURED",) * 8 + ("RESTORED",) * 8
  )


def test_stream_collector_decodes_the_comprehensive_probe_as_one_execution(probe_case):
  from eps_patch.protocol import FrameType, PROTOCOL_VERSION, StreamCollector

  _layout, target, _payload, _identity_value, expected = probe_case
  frames = [
    bytes([FrameType.BEGIN0, PROTOCOL_VERSION, OP_FACI_PE_CYCLE, 0])
    + struct.pack("<I", target.crc_range_start),
    bytes([FrameType.BEGIN1, PROTOCOL_VERSION, OP_FACI_PE_CYCLE, 1])
    + struct.pack("<I", 2),
  ]
  combined = bytearray()
  for slot, region in enumerate(expected.regions):
    frames.extend([
      bytes([FrameType.REGION_BEGIN, PROTOCOL_VERSION, OP_FACI_PE_CYCLE, slot])
      + struct.pack("<I", region.base),
      bytes([FrameType.REGION_LENGTH, PROTOCOL_VERSION, OP_FACI_PE_CYCLE, slot])
      + struct.pack("<I", len(region.data)),
    ])
    frames.extend(
      bytes([FrameType.DATA]) + struct.pack("<H", index) + b"\x00"
      + region.data[index * 4:index * 4 + 4]
      for index in range(len(region.data) // 4)
    )
    frames.append(
      bytes([FrameType.REGION_END, PROTOCOL_VERSION, OP_FACI_PE_CYCLE, slot])
      + struct.pack("<I", binascii.crc32(region.data))
    )
    combined.extend(region.data)
  frames.extend(
    bytes([FrameType.CRC_RECORD, slot, 4, 0]) + struct.pack("<I", value)
    for slot, value in enumerate(expected.dcra_values)
  )
  frames.extend(
    bytes([FrameType.MAGIC, slot, 0, 0]) + struct.pack("<I", value)
    for slot, value in enumerate(expected.magic_words)
  )
  frames.extend(
    bytes([FrameType.DIAGNOSTIC, slot, FACI_PE_CYCLE_DIAGNOSTICS[slot][2], 0])
    + struct.pack("<I", value)
    for slot, value in enumerate(expected.faci_values)
  )
  frames.extend([
    bytes([FrameType.STATUS, 1, 0, 0]) + struct.pack("<I", 0),
    bytes([FrameType.END, 0, 0, 0]) + struct.pack("<I", binascii.crc32(combined)),
  ])

  collector = StreamCollector(expected_operation=OP_FACI_PE_CYCLE)
  for frame in frames:
    collector.consume(target.uds_response_id, target.bus, frame)

  assert collector.finish() == expected
