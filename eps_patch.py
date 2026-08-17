#!/usr/bin/env python3
"""The deliberately small public interface for the EPS patch workflow."""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

from eps_patch.artifacts import ArtifactError
from eps_patch.evidence import EvidenceError
from eps_patch.patch import PatchError, run_patch
from eps_patch.paths import ArtifactLayout, DEFAULT_ARTIFACT_ROOT
from eps_patch.payload import PayloadError, build_envelope, load_built_shellcode
from eps_patch.preflight import PreflightError, run_preflight
from eps_patch.probe import PayloadImage, ProbeError, run_probe
from eps_patch.restore import RestoreError, run_restore
from eps_patch.transport import EcuTransport, TransportError


_BUILD_DIRECTORY = Path(__file__).resolve().parent / "payload" / "build"
_PAYLOAD_NAMES = (
  "probe_pe_cycle",
  "crc_probe",
  "crc_intermediate",
  "crc_verify",
  "ram_echo",
  "live_read",
)
_TEMPLATE_NAMES = (
  "write_target_candidate",
  "write_crc_candidate",
  "restore_sector",
)
_EXPECTED_ERRORS = (
  ArtifactError,
  EvidenceError,
  PreflightError,
  PayloadError,
  TransportError,
  ProbeError,
  PatchError,
  RestoreError,
)


def build_parser() -> argparse.ArgumentParser:
  """Build the intentionally narrow public command surface."""
  parser = argparse.ArgumentParser(description=__doc__)
  commands = parser.add_subparsers(dest="command", required=True)
  for name in ("probe", "patch", "restore"):
    command = commands.add_parser(name)
    command.add_argument("--serial")
  return parser


def _load_payloads() -> SimpleNamespace:
  """Build exact pinned envelopes from the retained reviewed payload binaries."""
  images: dict[str, PayloadImage] = {}
  for name in _PAYLOAD_NAMES:
    shellcode = load_built_shellcode(_BUILD_DIRECTORY, name)
    envelope = build_envelope(
      shellcode,
      did_201=bytes(16),
      did_202=bytes(16),
      iv=bytes(16),
    )
    images[name] = PayloadImage(
      name=name,
      envelope=envelope,
      sha256=hashlib.sha256(envelope).hexdigest(),
    )
  return SimpleNamespace(**images)


def _load_templates() -> SimpleNamespace:
  """Load each writer template through the same pinned payload loader."""
  return SimpleNamespace(**{
    name: load_built_shellcode(_BUILD_DIRECTORY, name)
    for name in _TEMPLATE_NAMES
  })


def dispatch(
  args: argparse.Namespace,
  *,
  layout: ArtifactLayout,
  preflight: Callable[[], object],
  transport_factory: Callable[[], object],
  confirmation: Callable[[str], object],
  power_cycle_checkpoint: Callable[[str], object],
) -> Path:
  """Dispatch one public command with fixed evidence and reviewed inputs."""
  command = getattr(args, "command", None)
  if command == "probe":
    return run_probe(
      layout=layout,
      payload=_load_payloads().probe_pe_cycle,
      preflight=preflight,
      transport_factory=transport_factory,
      new_uds=False,
    )
  if command == "patch":
    return run_patch(
      layout=layout,
      payloads=_load_payloads(),
      templates=_load_templates(),
      preflight=preflight,
      transport_factory=transport_factory,
      confirmation=confirmation,
      power_cycle_checkpoint=power_cycle_checkpoint,
      new_uds=False,
    )
  if command == "restore":
    return run_restore(
      layout=layout,
      payloads=_load_payloads(),
      templates=_load_templates(),
      preflight=preflight,
      transport_factory=transport_factory,
      confirmation=confirmation,
      power_cycle_checkpoint=power_cycle_checkpoint,
      new_uds=False,
    )
  raise ValueError("unknown command")


def main() -> int:
  """Parse, run one workflow, and translate known failures into exit status 2."""
  args = build_parser().parse_args()
  try:
    report = dispatch(
      args,
      layout=ArtifactLayout(DEFAULT_ARTIFACT_ROOT),
      preflight=run_preflight,
      transport_factory=lambda: EcuTransport(serial=args.serial),
      confirmation=input,
      power_cycle_checkpoint=input,
    )
  except _EXPECTED_ERRORS as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    return 2
  print(report)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
