"""Atomic installation and fail-closed semantic validation of probe evidence."""

from __future__ import annotations

import ctypes
import binascii
import errno
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .artifacts import sha256_bytes
from .manifest import TargetManifest
from .paths import ArtifactLayout
from .payload import PROBE_PE_CYCLE_ENVELOPE_SHA256
from .protocol import FACI_DIAGNOSTICS
from .transport import EcuIdentity


class EvidenceError(RuntimeError):
  pass


@dataclass(frozen=True, slots=True)
class TrustedProbeEvidence:
  identity: EcuIdentity
  target_sector: bytes
  crc_sector: bytes
  report: dict[str, object]


_SNAPSHOT_NAMES = ("PRE", "UNLOCKED", "WINDOWS", "CONFIGURED", "RESTORED")
_REGISTER_NAMES = tuple(name for name, _address, _width in FACI_DIAGNOSTICS)
_PRE = (0x80, 0x8000, 0, 0, 0, 0, 0, 0)
_EXPECTED_SNAPSHOTS = {
  "PRE": _PRE,
  "UNLOCKED": _PRE[:3] + (1,) + _PRE[4:],
  "WINDOWS": _PRE[:3] + (1,) + _PRE[4:6] + (1, 1),
  "CONFIGURED": _PRE[:3] + (1, 1, 0, 1, 1),
  "RESTORED": _PRE,
}


def install_probe_pass(
  layout: ArtifactLayout,
  target_sector: bytes,
  crc_sector: bytes,
  report: dict[str, object],
  metadata: dict[str, object],
) -> Path:
  """Durably install one complete probe checkpoint, never replacing an existing one."""
  if not isinstance(layout, ArtifactLayout):
    raise TypeError("layout must be an ArtifactLayout")
  _require_bytes(target_sector, "target sector")
  _require_bytes(crc_sector, "CRC sector")
  staging: Path | None = None
  try:
    if layout.probe_directory.exists():
      raise EvidenceError("trusted probe directory already exists")
    report_bytes = _encode_json(report, "report")
    metadata_bytes = _encode_json(metadata, "metadata")
    layout.root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".probe-", dir=layout.root))
    _write_fsynced(staging / layout.probe_report.name, report_bytes)
    _write_fsynced(staging / layout.target_backup.name, target_sector)
    _write_fsynced(staging / layout.crc_backup.name, crc_sector)
    _write_fsynced(staging / layout.recovery_metadata.name, metadata_bytes)
    _fsync_directory(staging)
    try:
      _rename_no_replace(staging, layout.probe_directory)
    except FileExistsError as exc:
      raise EvidenceError("trusted probe directory already exists") from exc
    _fsync_directory(layout.root)
  except EvidenceError:
    _remove_staging(staging)
    raise
  except OSError as exc:
    _remove_staging(staging)
    raise EvidenceError("cannot install probe evidence") from exc
  return layout.probe_report


def load_probe_pass(layout: ArtifactLayout, target: TargetManifest) -> TrustedProbeEvidence:
  """Load only complete, target-compatible, internally consistent PASS evidence."""
  if not isinstance(layout, ArtifactLayout):
    raise TypeError("layout must be an ArtifactLayout")
  if not isinstance(target, TargetManifest):
    raise TypeError("target must be a TargetManifest")
  try:
    target.validate()
  except ValueError as exc:
    raise EvidenceError(f"target manifest is invalid: {exc}") from exc

  report = _read_json(layout.probe_report, "probe report")
  metadata = _read_json(layout.recovery_metadata, "recovery metadata")
  target_sector = _read_bytes(layout.target_backup, "target backup")
  crc_sector = _read_bytes(layout.crc_backup, "CRC backup")
  if len(target_sector) != target.sector_length or len(crc_sector) != target.sector_length:
    raise EvidenceError("probe backups must both contain exactly one sector")
  if sha256_bytes(target_sector) != target.original_sha256:
    raise EvidenceError("target backup is not the target manifest's reviewed original")

  _require_exact_keys(
    report,
    {
      "workflow", "result", "identity", "payload", "new_uds", "sectors",
      "instruction", "snapshots", "dcra", "host_checks", "outcome",
      "validation_errors",
    },
    "probe report",
  )
  if report["workflow"] != "faci-pe-cycle" or report["result"] != "PASS":
    raise EvidenceError("probe report is not a FACI P/E-cycle PASS")
  if type(report["new_uds"]) is not bool or report["new_uds"] is not target.new_uds:
    raise EvidenceError("probe report UDS variant does not match target")

  identity = _parse_identity(report["identity"], target)
  _validate_payload(report["payload"])
  _validate_descriptor(report["sectors"], "target", target.sector_base, target_sector)
  _validate_descriptor(report["sectors"], "crc", target.crc_sector_base, crc_sector)
  _validate_instruction(report["instruction"], target, target_sector)
  _validate_snapshots(report["snapshots"])
  _validate_dcra(report["dcra"], crc_sector, target)
  _validate_host_checks(report["host_checks"], target_sector, crc_sector, target)
  _validate_outcome(report["outcome"], report["validation_errors"])
  _validate_metadata(metadata, report["identity"], report["sectors"])

  return TrustedProbeEvidence(
    identity=identity,
    target_sector=target_sector,
    crc_sector=crc_sector,
    report=report,
  )


def _validate_payload(value: object) -> None:
  payload = _require_object(value, "probe payload")
  _require_exact_keys(payload, {"name", "sha256"}, "probe payload")
  if payload != {
    "name": "probe_pe_cycle", "sha256": PROBE_PE_CYCLE_ENVELOPE_SHA256,
  }:
    raise EvidenceError("probe payload is not the exact reviewed retained envelope")


def _validate_metadata(metadata: object, report_identity: object, report_sectors: object) -> None:
  _require_exact_keys(metadata, {"identity", "target_backup", "crc_backup"}, "recovery metadata")
  if metadata["identity"] != report_identity:
    raise EvidenceError("recovery metadata identity does not match probe report")
  sectors = _require_object(report_sectors, "report sectors")
  if metadata["target_backup"] != sectors.get("target"):
    raise EvidenceError("recovery metadata target backup does not match probe report")
  if metadata["crc_backup"] != sectors.get("crc"):
    raise EvidenceError("recovery metadata CRC backup does not match probe report")


def _parse_identity(value: object, target: TargetManifest) -> EcuIdentity:
  identity = _require_object(value, "report identity")
  _require_exact_keys(
    identity,
    {"part_number", "application_software_id", "boot_software_id", "panda_serial"},
    "report identity",
  )
  part_number = _ascii_bytes(identity["part_number"], "identity part number")
  application = _hex_bytes(identity["application_software_id"], "application software ID")
  boot = _hex_bytes(identity["boot_software_id"], "boot software ID")
  serial = identity["panda_serial"]
  if not isinstance(serial, str):
    raise EvidenceError("Panda serial must be text")
  if (
    part_number != target.part_number
    or application != target.application_software_id
    or boot != target.boot_software_id
  ):
    raise EvidenceError("probe identity does not match target")
  return EcuIdentity(
    part_number=part_number,
    application_software_id=application,
    boot_software_id=boot,
    panda_serial=serial,
  )


def _validate_descriptor(sectors: object, name: str, address: int, data: bytes) -> None:
  sectors = _require_object(sectors, "report sectors")
  _require_exact_keys(sectors, {"target", "crc"}, "report sectors")
  descriptor = _require_object(sectors[name], f"{name} sector descriptor")
  _require_exact_keys(descriptor, {"address", "length", "sha256"}, f"{name} sector descriptor")
  if descriptor["address"] != address or descriptor["length"] != len(data):
    raise EvidenceError(f"{name} sector descriptor has the wrong address or length")
  digest = descriptor["sha256"]
  if not isinstance(digest, str) or digest != sha256_bytes(data):
    raise EvidenceError(f"{name} sector backup does not match its report digest")


def _validate_instruction(value: object, target: TargetManifest, target_sector: bytes) -> None:
  instruction = _require_object(value, "instruction context")
  _require_exact_keys(instruction, {"address", "original"}, "instruction context")
  if instruction["address"] != target.instruction_address:
    raise EvidenceError("instruction context address does not match target")
  try:
    original = bytes.fromhex(str(instruction["original"]))
  except ValueError as exc:
    raise EvidenceError("instruction context is not hexadecimal") from exc
  if original != target.original_instruction:
    raise EvidenceError("report instruction context does not match target")
  start = target.instruction_offset
  if target_sector[start:start + len(original)] != original:
    raise EvidenceError("target backup instruction context does not match report")


def _validate_snapshots(value: object) -> None:
  snapshots = _require_object(value, "FACI snapshots")
  _require_exact_keys(snapshots, set(_SNAPSHOT_NAMES), "FACI snapshots")
  for checkpoint in _SNAPSHOT_NAMES:
    snapshot = _require_object(snapshots[checkpoint], f"{checkpoint} FACI snapshot")
    _require_exact_keys(snapshot, set(_REGISTER_NAMES), f"{checkpoint} FACI snapshot")
    expected = _EXPECTED_SNAPSHOTS[checkpoint]
    for name, wanted in zip(_REGISTER_NAMES, expected):
      if type(snapshot[name]) is not int:
        raise EvidenceError(f"{checkpoint} FACI snapshot has an unexpected {name} value")
      if checkpoint == "CONFIGURED" and name == "REG20":
        continue
      if checkpoint == "CONFIGURED" and name == "REG88":
        if (snapshot[name] & 1) != 1:
          raise EvidenceError("CONFIGURED REG88 bit 0 does not prove P/E entry")
        continue
      if snapshot[name] != wanted:
        raise EvidenceError(f"{checkpoint} FACI snapshot has an unexpected {name} value")


def _validate_outcome(outcome: object, validation_errors: object) -> None:
  outcome = _require_object(outcome, "probe outcome")
  _require_exact_keys(outcome, {"primary_code", "cleanup_code"}, "probe outcome")
  if (
    type(outcome["primary_code"]) is not int
    or type(outcome["cleanup_code"]) is not int
    or outcome["primary_code"] != 0
    or outcome["cleanup_code"] != 0
  ):
    raise EvidenceError("probe outcome or cleanup is nonzero")
  if type(validation_errors) is not list or validation_errors:
    raise EvidenceError("probe report has validation errors")


def _validate_dcra(
  value: object,
  crc_sector: bytes,
  target: TargetManifest,
) -> None:
  record = _require_object(value, "DCRA observation")
  expected_keys = {
    "entry_ctl", "entry_cout", "range_start", "range_end", "adjust_address",
    "old_adjust_word", "new_adjust_word", "original_dcra_raw",
    "patched_dcra_raw", "exit_ctl", "exit_cout",
  }
  _require_exact_keys(record, expected_keys, "DCRA observation")
  if any(type(record[name]) is not int or not 0 <= record[name] <= 0xFFFFFFFF for name in expected_keys):
    raise EvidenceError("DCRA observation values must be unsigned 32-bit integers")
  if (record["range_start"], record["range_end"], record["adjust_address"]) != (
    target.crc_range_start, target.crc_range_end, target.crc_adjust_address,
  ):
    raise EvidenceError("DCRA observation addresses do not match target")
  old_adjustment = int.from_bytes(
    crc_sector[target.crc_adjust_offset:target.crc_adjust_offset + 4], "little",
  )
  if (
    old_adjustment != target.crc_original_adjust_word
    or record["old_adjust_word"] != old_adjustment
  ):
    raise EvidenceError("DCRA observation old adjustment does not match reviewed backup")
  if record["new_adjust_word"] != target.crc_patched_adjust_word:
    raise EvidenceError("DCRA observation patched adjustment is invalid")
  if (
    record["original_dcra_raw"] != target.crc_residue
    or record["patched_dcra_raw"] != target.crc_residue
  ):
    raise EvidenceError("DCRA observation does not satisfy reviewed boot residue")
  if (record["exit_ctl"], record["exit_cout"]) != (
    record["entry_ctl"], record["entry_cout"],
  ):
    raise EvidenceError("DCRA exit state does not match entry state")


def _validate_host_checks(
  value: object,
  target_sector: bytes,
  crc_sector: bytes,
  target: TargetManifest,
) -> None:
  checks = _require_object(value, "host checks")
  expected = {
    "target_sector_sha256": sha256_bytes(target_sector),
    "target_sector_crc32": binascii.crc32(target_sector),
    "crc_sector_crc32": binascii.crc32(crc_sector),
    "combined_crc32": binascii.crc32(target_sector + crc_sector),
    "original_adjust_word": target.crc_original_adjust_word,
    "patched_prefix_sw": target.crc_patched_prefix_sw,
    "patched_adjust_word": target.crc_patched_adjust_word,
    "residue": target.crc_residue,
  }
  _require_exact_keys(checks, set(expected), "host checks")
  if checks != expected:
    raise EvidenceError("host sector or reviewed CRC checks do not match evidence")
  if checks["patched_prefix_sw"] ^ checks["residue"] != checks["patched_adjust_word"]:
    raise EvidenceError("host CRC adjustment formula is invalid")


def _read_json(path: Path, label: str) -> dict[str, object]:
  try:
    value = json.loads(path.read_text(encoding="utf-8"))
  except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise EvidenceError(f"{label} cannot be read") from exc
  return _require_object(value, label)


def _read_bytes(path: Path, label: str) -> bytes:
  try:
    return path.read_bytes()
  except OSError as exc:
    raise EvidenceError(f"{label} cannot be read") from exc


def _encode_json(value: object, label: str) -> bytes:
  if type(value) is not dict:
    raise EvidenceError(f"{label} must be an object")
  try:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
  except (TypeError, ValueError) as exc:
    raise EvidenceError(f"{label} is not JSON serializable") from exc


def _write_fsynced(path: Path, content: bytes) -> None:
  with path.open("xb") as stream:
    stream.write(content)
    stream.flush()
    os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
  descriptor = os.open(path, os.O_RDONLY)
  try:
    os.fsync(descriptor)
  finally:
    os.close(descriptor)


def _remove_staging(staging: Path | None) -> None:
  if staging is None or not staging.exists():
    return
  try:
    shutil.rmtree(staging)
  except OSError:
    pass


def _rename_no_replace(source: Path, destination: Path) -> None:
  """Atomically publish a staged directory without replacing any destination."""
  libc = ctypes.CDLL(None, use_errno=True)
  encoded_source = os.fsencode(source)
  encoded_destination = os.fsencode(destination)
  if sys.platform == "darwin":
    rename = libc.renamex_np
    rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    result = rename(encoded_source, encoded_destination, 0x00000004)  # RENAME_EXCL
  elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
    rename = libc.renameat2
    rename.argtypes = (
      ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    result = rename(-100, encoded_source, -100, encoded_destination, 1)  # RENAME_NOREPLACE
  else:
    raise EvidenceError("platform lacks an atomic no-replace directory rename")
  if result == 0:
    return
  error = ctypes.get_errno()
  if error == errno.EEXIST:
    raise FileExistsError(error, os.strerror(error), destination)
  raise OSError(error, os.strerror(error), destination)


def _require_bytes(value: object, label: str) -> bytes:
  if type(value) is not bytes:
    raise EvidenceError(f"{label} must be bytes")
  return value


def _require_object(value: object, label: str) -> dict[str, object]:
  if type(value) is not dict:
    raise EvidenceError(f"{label} must be an object")
  return value


def _require_exact_keys(value: object, keys: set[str], label: str) -> None:
  mapping = _require_object(value, label)
  if set(mapping) != keys:
    raise EvidenceError(f"{label} has unsupported or missing fields")


def _ascii_bytes(value: object, label: str) -> bytes:
  if not isinstance(value, str):
    raise EvidenceError(f"{label} must be text")
  try:
    return value.encode("ascii")
  except UnicodeEncodeError as exc:
    raise EvidenceError(f"{label} must be ASCII") from exc


def _hex_bytes(value: object, label: str) -> bytes:
  if not isinstance(value, str):
    raise EvidenceError(f"{label} must be hexadecimal text")
  try:
    return bytes.fromhex(value)
  except ValueError as exc:
    raise EvidenceError(f"{label} is not hexadecimal") from exc
