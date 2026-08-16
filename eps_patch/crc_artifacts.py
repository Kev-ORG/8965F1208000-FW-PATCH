"""Immutable evidence files for the two-sector CRC patch workflow.

The probe, destructive payload, and post-cycle verification each have a
separate append-only checkpoint.  Files are installed through the existing
hard-link based artifact writer so a checkpoint is never replaced in place.
"""

from __future__ import annotations

import binascii
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import artifacts
from .artifacts import ArtifactError
from .crc import CrcCandidate


SECTOR_LENGTH = 0x8000
CRC_PATCH_LIFECYCLE_SCHEMA = 1
CRC_PATCH_ARMED_RESULT = "ARMED"
CRC_PATCH_RECOVERY_PAYLOAD_RESULTS = ("PAYLOAD_FAILED", "INDETERMINATE")


@dataclass(frozen=True, slots=True)
class CrcPatchPaths:
  directory: Path
  probe_intent: Path
  target_source: Path
  crc_source: Path
  target_candidate: Path
  crc_candidate: Path
  crc_probe_report: Path
  patch_intent: Path
  target_returned: Path
  crc_returned: Path
  payload_report: Path
  verify_report: Path
  final_report: Path


def _paths(directory: Path) -> CrcPatchPaths:
  return CrcPatchPaths(
    directory=directory,
    probe_intent=directory / "crc-probe-intent.json",
    target_source=directory / "original-sector-0x60000-0x67fff.bin",
    crc_source=directory / "original-sector-0xf8000-0xfffff.bin",
    target_candidate=directory / "candidate-sector-0x60000-0x67fff.bin",
    crc_candidate=directory / "candidate-sector-0xf8000-0xfffff.bin",
    crc_probe_report=directory / "crc-probe-report.json",
    patch_intent=directory / "patch-crc-intent.json",
    target_returned=directory / "returned-sector-0x60000-0x67fff.bin",
    crc_returned=directory / "returned-sector-0xf8000-0xfffff.bin",
    payload_report=directory / "patch-crc-payload-report.json",
    verify_report=directory / "verify-crc-report.json",
    final_report=directory / "patch-crc-report.json",
  )


def _json_bytes(report: dict[str, Any]) -> bytes:
  return (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _install_json(path: Path, report: dict[str, Any]) -> None:
  # Resolve the writer through the module so existing callers' monkeypatches
  # and the legacy writer implementation remain effective.
  artifacts._atomic_create(path, _json_bytes(report))


def _require_sector(sector: bytes, *, name: str) -> None:
  if not isinstance(sector, bytes) or len(sector) != SECTOR_LENGTH:
    raise ArtifactError(f"{name} must contain exactly {SECTOR_LENGTH} bytes")


def _require_phase_a(paths: CrcPatchPaths) -> None:
  required = (
    paths.probe_intent,
    paths.target_source,
    paths.crc_source,
    paths.target_candidate,
    paths.crc_candidate,
    paths.crc_probe_report,
  )
  missing = next((path for path in required if not path.is_file()), None)
  if missing is not None:
    raise ArtifactError(f"CRC probe phase is incomplete: missing {missing}")
  for path, name in (
    (paths.target_source, "target source"),
    (paths.crc_source, "CRC source"),
    (paths.target_candidate, "target candidate"),
    (paths.crc_candidate, "CRC candidate"),
  ):
    if path.stat().st_size != SECTOR_LENGTH:
      raise ArtifactError(f"{name} must contain exactly {SECTOR_LENGTH} bytes")


def _require_sram_recovery_proof(paths: CrcPatchPaths) -> None:
  try:
    raw = paths.crc_probe_report.read_text(encoding="utf-8")
    report = json.loads(raw)
  except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise ArtifactError(f"SRAM recovery proof report cannot be read: {exc}") from exc
  if type(report) is not dict or report.get("result") != "PROBED":
    raise ArtifactError("SRAM recovery proof requires the exact PROBED report")
  proof = report.get("sram_recovery_probe")
  if type(proof) is not dict or set(proof) != {"result", "address", "length", "crc32"}:
    raise ArtifactError("SRAM recovery proof is missing or malformed")
  if (
    proof.get("result") != "PASS"
    or proof.get("address") != "0xfebf2000"
    or type(proof.get("length")) is not int
    or proof.get("length") != SECTOR_LENGTH
  ):
    raise ArtifactError("SRAM recovery proof does not match the reviewed SRAM contract")
  recorded_crc = proof.get("crc32")
  if type(recorded_crc) is not str or re.fullmatch(r"0x[0-9a-f]{8}", recorded_crc) is None:
    raise ArtifactError("SRAM recovery proof CRC32 is malformed")
  try:
    target_source = paths.target_source.read_bytes()
  except OSError as exc:
    raise ArtifactError(f"SRAM recovery proof backup cannot be read: {exc}") from exc
  expected_crc = f"0x{binascii.crc32(target_source):08x}"
  if recorded_crc != expected_crc:
    raise ArtifactError("SRAM recovery proof CRC32 does not match the immutable target backup")


def create_crc_probe_attempt(
  directory: Path, intent: dict[str, Any],
) -> CrcPatchPaths:
  """Create the durable probe intent before any phase-A observation."""
  directory = Path(directory)
  if directory.exists():
    raise ArtifactError(f"artifact directory already exists: {directory}")
  directory.mkdir(parents=True, exist_ok=False)
  paths = _paths(directory)
  try:
    _install_json(paths.probe_intent, intent)
  except Exception:
    try:
      paths.probe_intent.unlink()
    except FileNotFoundError:
      pass
    try:
      directory.rmdir()
    except OSError:
      pass
    raise
  return paths


def finish_crc_probe_attempt(
  paths: CrcPatchPaths,
  target_source: bytes | CrcCandidate | None = None,
  crc_source: bytes | dict[str, Any] | None = None,
  target_candidate: bytes | None = None,
  crc_candidate: bytes | None = None,
  report: dict[str, Any] | None = None,
  *,
  candidate: CrcCandidate | None = None,
) -> Path:
  """Install all immutable phase-A files, returning the probe report path.

  The byte arguments are intentionally explicit for callers that have
  independently validated the live observation.  ``candidate=`` is accepted
  as a convenience for the Task 1 value object; it does not alter the files'
  names or lifecycle.
  """
  # Also accept the natural ``(paths, candidate, report)`` spelling while
  # retaining the documented explicit-byte API.
  if isinstance(target_source, CrcCandidate):
    if candidate is not None:
      raise TypeError("candidate provided twice")
    candidate = target_source
    if report is None and isinstance(crc_source, dict):
      report = crc_source
    target_source = crc_source = None
  if candidate is not None:
    if any(value is not None for value in (target_source, crc_source, target_candidate, crc_candidate)):
      raise TypeError("candidate cannot be combined with explicit sector bytes")
    target_source = candidate.target_source
    crc_source = candidate.crc_source
    target_candidate = candidate.target_final
    crc_candidate = candidate.crc_final
  if report is None:
    raise TypeError("report is required")
  if not isinstance(paths, CrcPatchPaths):
    raise TypeError("paths must be CrcPatchPaths")
  if not paths.probe_intent.is_file():
    raise ArtifactError("CRC probe intent is missing")
  if paths.crc_probe_report.exists():
    raise ArtifactError(f"artifact already exists: {paths.crc_probe_report}")
  sectors = (
    (target_source, paths.target_source, "target source"),
    (crc_source, paths.crc_source, "CRC source"),
    (target_candidate, paths.target_candidate, "target candidate"),
    (crc_candidate, paths.crc_candidate, "CRC candidate"),
  )
  for sector, _path, name in sectors:
    if sector is None:
      raise ArtifactError(f"{name} is required")
    _require_sector(sector, name=name)
  # Validate all inputs before installing the first file, avoiding a partial
  # checkpoint caused by a malformed later sector argument.
  for sector, path, _name in sectors:
    artifacts._atomic_create(path, sector)
  _install_json(paths.crc_probe_report, report)
  return paths.crc_probe_report


def arm_crc_patch(paths: CrcPatchPaths, intent: dict[str, Any]) -> Path:
  """Durably arm the destructive payload only after phase-A is complete."""
  _require_phase_a(paths)
  _require_sram_recovery_proof(paths)
  _install_json(paths.patch_intent, intent)
  return paths.patch_intent


def finish_crc_payload(
  paths: CrcPatchPaths,
  returned_regions: tuple[bytes, bytes] | None,
  report: dict[str, Any],
) -> Path:
  """Install trusted payload readbacks when available, then its report.

  A failed or indeterminate payload can be recorded without readback bytes;
  absent regions are deliberately never synthesized or treated as trusted.
  """
  if not paths.patch_intent.is_file():
    raise ArtifactError("CRC patch is not armed")
  if paths.payload_report.exists():
    raise ArtifactError(f"artifact already exists: {paths.payload_report}")
  if returned_regions is not None:
    if not isinstance(returned_regions, tuple) or len(returned_regions) != 2:
      raise ArtifactError("returned_regions must contain exactly two sectors")
    target_returned, crc_returned = returned_regions
    _require_sector(target_returned, name="target returned sector")
    _require_sector(crc_returned, name="CRC returned sector")
    artifacts._atomic_create(paths.target_returned, target_returned)
    artifacts._atomic_create(paths.crc_returned, crc_returned)
  _install_json(paths.payload_report, report)
  return paths.payload_report


def finish_crc_verify(paths: CrcPatchPaths, report: dict[str, Any]) -> Path:
  """Install the independent post-power-cycle verification report."""
  if not paths.payload_report.is_file():
    raise ArtifactError("CRC payload has not been finalized")
  if paths.final_report.exists():
    raise ArtifactError(f"artifact already exists: {paths.final_report}")
  _install_json(paths.verify_report, report)
  return paths.verify_report


def finish_crc_workflow(paths: CrcPatchPaths, report: dict[str, Any]) -> Path:
  """Install the final aggregate exactly once after a trustworthy payload."""
  if not paths.payload_report.is_file():
    raise ArtifactError("CRC payload has not been finalized")
  _install_json(paths.final_report, report)
  return paths.final_report


__all__ = [
  "CrcPatchPaths",
  "CRC_PATCH_LIFECYCLE_SCHEMA",
  "CRC_PATCH_ARMED_RESULT",
  "CRC_PATCH_RECOVERY_PAYLOAD_RESULTS",
  "create_crc_probe_attempt",
  "finish_crc_probe_attempt",
  "arm_crc_patch",
  "finish_crc_payload",
  "finish_crc_verify",
  "finish_crc_workflow",
]
