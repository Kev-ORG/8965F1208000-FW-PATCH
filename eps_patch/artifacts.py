"""Exact sector validation and immutable, atomic evidence artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .manifest import TARGET, TargetManifest


class ArtifactError(RuntimeError):
  pass


class SectorState(str, Enum):
  ORIGINAL = "ORIGINAL"
  PATCHED = "PATCHED"
  UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ArtifactPaths:
  directory: Path
  backup: Path
  report: Path


@dataclass(frozen=True, slots=True)
class PatchAttemptPaths:
  directory: Path
  intent: Path
  original: Path
  returned: Path
  report: Path


@dataclass(frozen=True, slots=True)
class RestoreAttemptPaths:
  directory: Path
  intent: Path
  original: Path
  patched: Path
  returned: Path
  report: Path


def sha256_bytes(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()


def _require_sector_length(sector: bytes, target: TargetManifest) -> None:
  if len(sector) != target.sector_length:
    raise ArtifactError(f"sector must contain exactly {target.sector_length} bytes")


def classify_sector(sector: bytes, *, target: TargetManifest = TARGET) -> SectorState:
  _require_sector_length(sector, target)
  digest = sha256_bytes(sector)
  context = sector[target.instruction_offset:target.instruction_offset + 4]
  if digest == target.original_sha256 and context == target.original_instruction:
    return SectorState.ORIGINAL
  if digest == target.patched_sha256 and context == target.patched_instruction:
    return SectorState.PATCHED
  return SectorState.UNKNOWN


def validate_exact_patch_diff(
  original: bytes, patched: bytes, *, target: TargetManifest = TARGET,
) -> list[tuple[int, int, int]]:
  _require_sector_length(original, target)
  _require_sector_length(patched, target)
  changes = [
    (target.sector_base + offset, before, after)
    for offset, (before, after) in enumerate(zip(original, patched))
    if before != after
  ]
  expected = [(target.patch_address, 0x31, 0x10)]
  if changes != expected:
    raise ArtifactError(f"expected exactly one RX-state byte change {expected!r}, got {changes!r}")
  if original[target.instruction_offset:target.instruction_offset + 4] != target.original_instruction:
    raise ArtifactError("original instruction context does not match target")
  if patched[target.instruction_offset:target.instruction_offset + 4] != target.patched_instruction:
    raise ArtifactError("patched instruction context does not match target")
  return changes


def _atomic_create(path: Path, content: bytes) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  if path.exists():
    raise ArtifactError(f"artifact already exists: {path}")
  fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
  try:
    with os.fdopen(fd, "wb") as stream:
      stream.write(content)
      stream.flush()
      os.fsync(stream.fileno())
    try:
      os.link(temp_name, path)
    except FileExistsError as exc:
      raise ArtifactError(f"artifact already exists: {path}") from exc
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
      os.fsync(directory_fd)
    finally:
      os.close(directory_fd)
  finally:
    try:
      os.unlink(temp_name)
    except FileNotFoundError:
      pass


def _write_sector_artifacts(
  directory: Path, sector: bytes, report: dict[str, Any], *, report_name: str,
) -> ArtifactPaths:
  _require_sector_length(sector, TARGET)
  if directory.exists():
    raise ArtifactError(f"artifact directory already exists: {directory}")
  directory.mkdir(parents=True, exist_ok=False)
  backup = directory / "sector-0x60000-0x67fff.bin"
  report_path = directory / report_name
  try:
    _atomic_create(backup, sector)
    encoded = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _atomic_create(report_path, encoded)
  except Exception:
    for path in (report_path, backup):
      try:
        path.unlink()
      except FileNotFoundError:
        pass
    try:
      directory.rmdir()
    except OSError:
      pass
    raise
  return ArtifactPaths(directory=directory, backup=backup, report=report_path)


def write_probe_artifacts(directory: Path, sector: bytes, report: dict[str, Any]) -> ArtifactPaths:
  return _write_sector_artifacts(directory, sector, report, report_name="probe-report.json")


def write_faci_unlock_artifacts(
  directory: Path, sector: bytes, report: dict[str, Any],
) -> ArtifactPaths:
  return _write_sector_artifacts(
    directory, sector, report, report_name="faci-unlock-report.json",
  )


def write_faci_pe_cycle_artifacts(
  directory: Path, sector: bytes, report: dict[str, Any],
) -> ArtifactPaths:
  return _write_sector_artifacts(
    directory, sector, report, report_name="faci-pe-cycle-report.json",
  )


def write_verify_artifacts(
  directory: Path, sector: bytes, report: dict[str, Any],
) -> ArtifactPaths:
  return _write_sector_artifacts(directory, sector, report, report_name="verify-report.json")


def write_verify_restore_artifacts(
  directory: Path, sector: bytes, report: dict[str, Any],
) -> ArtifactPaths:
  return _write_sector_artifacts(
    directory, sector, report, report_name="verify-restore-report.json",
  )


def create_patch_attempt(
  directory: Path, original: bytes, intent: dict[str, Any],
) -> PatchAttemptPaths:
  _require_sector_length(original, TARGET)
  if directory.exists():
    raise ArtifactError(f"artifact directory already exists: {directory}")
  directory.mkdir(parents=True, exist_ok=False)
  paths = PatchAttemptPaths(
    directory=directory,
    intent=directory / "patch-intent.json",
    original=directory / "original-sector-0x60000-0x67fff.bin",
    returned=directory / "returned-sector-0x60000-0x67fff.bin",
    report=directory / "patch-report.json",
  )
  try:
    _atomic_create(paths.original, original)
    encoded = (json.dumps(intent, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _atomic_create(paths.intent, encoded)
  except Exception:
    for path in (paths.intent, paths.original):
      try:
        path.unlink()
      except FileNotFoundError:
        pass
    try:
      directory.rmdir()
    except OSError:
      pass
    raise
  return paths


def finish_patch_attempt(
  paths: PatchAttemptPaths, report: dict[str, Any], returned_sector: bytes | None,
) -> Path:
  if paths.report.exists():
    raise ArtifactError(f"artifact already exists: {paths.report}")
  if returned_sector is not None:
    _require_sector_length(returned_sector, TARGET)
    if paths.returned.exists():
      raise ArtifactError(f"artifact already exists: {paths.returned}")
    _atomic_create(paths.returned, returned_sector)
  encoded = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
  _atomic_create(paths.report, encoded)
  return paths.report


def create_restore_attempt(
  directory: Path,
  incident_original: bytes,
  incident_patched: bytes,
  intent: dict[str, Any],
) -> RestoreAttemptPaths:
  """Create a dedicated immutable record before any recovery payload runs."""
  _require_sector_length(incident_original, TARGET)
  _require_sector_length(incident_patched, TARGET)
  if directory.exists():
    raise ArtifactError(f"artifact directory already exists: {directory}")
  directory.mkdir(parents=True, exist_ok=False)
  paths = RestoreAttemptPaths(
    directory=directory,
    intent=directory / "restore-intent.json",
    original=directory / "incident-original-sector-0x60000-0x67fff.bin",
    patched=directory / "incident-patched-sector-0x60000-0x67fff.bin",
    returned=directory / "returned-sector-0x60000-0x67fff.bin",
    report=directory / "restore-report.json",
  )
  encoded = (json.dumps(intent, sort_keys=True, indent=2) + "\n").encode("utf-8")
  try:
    _atomic_create(paths.original, incident_original)
    _atomic_create(paths.patched, incident_patched)
    _atomic_create(paths.intent, encoded)
  except Exception:
    for path in (paths.intent, paths.patched, paths.original):
      try:
        path.unlink()
      except FileNotFoundError:
        pass
    try:
      directory.rmdir()
    except OSError:
      pass
    raise
  return paths


def finish_restore_attempt(
  paths: RestoreAttemptPaths,
  report: dict[str, Any],
  returned_sector: bytes | None,
) -> Path:
  """Finalize one recovery attempt exactly once, optionally with trusted readback."""
  if paths.report.exists():
    raise ArtifactError(f"artifact already exists: {paths.report}")
  if returned_sector is not None:
    _require_sector_length(returned_sector, TARGET)
    if paths.returned.exists():
      raise ArtifactError(f"artifact already exists: {paths.returned}")
    _atomic_create(paths.returned, returned_sector)
  encoded = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
  _atomic_create(paths.report, encoded)
  return paths.report


def write_json_artifact(path: Path, report: dict[str, Any]) -> Path:
  encoded = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
  _atomic_create(path, encoded)
  return path
