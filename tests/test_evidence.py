import copy
import binascii
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from eps_patch.artifacts import sha256_bytes
from eps_patch.evidence import EvidenceError, _rename_no_replace, install_probe_pass, load_probe_pass
from eps_patch.manifest import TARGET
from eps_patch.paths import ArtifactLayout


REVIEWED_PROBE_ENVELOPE_SHA256 = (
  "ea95db5e7a8c623220f5a164d74aab83dc1c8ba51d83681c7966a51da7aed705"
)
SNAPSHOTS = {
  "PRE": {
    "FPMON": 0x80, "FSTATR": 0x8000, "FASTAT": 0, "FENTRYR": 0,
    "FPROTR": 0, "FAREASELC": 0, "FHVE15": 0, "FHVE3": 0,
  },
  "UNLOCKED": {
    "FPMON": 0x80, "FSTATR": 0x8000, "FASTAT": 0, "FENTRYR": 1,
    "FPROTR": 0, "FAREASELC": 0, "FHVE15": 0, "FHVE3": 0,
  },
  "WINDOWS": {
    "FPMON": 0x80, "FSTATR": 0x8000, "FASTAT": 0, "FENTRYR": 1,
    "FPROTR": 0, "FAREASELC": 0, "FHVE15": 1, "FHVE3": 1,
  },
  "CONFIGURED": {
    "FPMON": 0x80, "FSTATR": 0x8000, "FASTAT": 0, "FENTRYR": 1,
    "FPROTR": 1, "FAREASELC": 0, "FHVE15": 1, "FHVE3": 1,
  },
  "RESTORED": {
    "FPMON": 0x80, "FSTATR": 0x8000, "FASTAT": 0, "FENTRYR": 0,
    "FPROTR": 0, "FAREASELC": 0, "FHVE15": 0, "FHVE3": 0,
  },
}


def descriptor(address: int, data: bytes) -> dict[str, object]:
  return {"address": address, "length": len(data), "sha256": sha256_bytes(data)}


def identity() -> dict[str, str]:
  return {
    "part_number": TARGET.part_number.decode("ascii"),
    "application_software_id": TARGET.application_software_id.hex(),
    "boot_software_id": TARGET.boot_software_id.hex(),
    "panda_serial": "test-panda",
  }


def make_report(target_sector: bytes, crc_sector: bytes) -> dict[str, object]:
  old_adjustment = int.from_bytes(
    crc_sector[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4], "little",
  )
  return {
    "workflow": "faci-pe-cycle",
    "result": "PASS",
    "identity": identity(),
    "payload": {
      "name": "probe_pe_cycle", "sha256": REVIEWED_PROBE_ENVELOPE_SHA256,
    },
    "new_uds": False,
    "sectors": {
      "target": descriptor(TARGET.sector_base, target_sector),
      "crc": descriptor(TARGET.crc_sector_base, crc_sector),
    },
    "instruction": {
      "address": TARGET.instruction_address,
      "original": TARGET.original_instruction.hex(),
    },
    "snapshots": copy.deepcopy(SNAPSHOTS),
    "dcra": {
      "entry_ctl": 0x10203040,
      "entry_cout": 0x50607080,
      "range_start": TARGET.crc_range_start,
      "range_end": TARGET.crc_range_end,
      "adjust_address": TARGET.crc_adjust_address,
      "old_adjust_word": old_adjustment,
      "new_adjust_word": TARGET.crc_patched_adjust_word,
      "original_dcra_raw": TARGET.crc_residue,
      "patched_dcra_raw": TARGET.crc_residue,
      "exit_ctl": 0x10203040,
      "exit_cout": 0x50607080,
    },
    "host_checks": {
      "target_sector_sha256": hashlib.sha256(target_sector).hexdigest(),
      "target_sector_crc32": binascii.crc32(target_sector),
      "crc_sector_crc32": binascii.crc32(crc_sector),
      "combined_crc32": binascii.crc32(target_sector + crc_sector),
      "original_adjust_word": TARGET.crc_original_adjust_word,
      "patched_prefix_sw": TARGET.crc_patched_prefix_sw,
      "patched_adjust_word": TARGET.crc_patched_adjust_word,
      "residue": TARGET.crc_residue,
    },
    "outcome": {"primary_code": 0, "cleanup_code": 0},
    "validation_errors": [],
  }


def make_metadata(target_sector: bytes, crc_sector: bytes) -> dict[str, object]:
  return {
    "identity": identity(),
    "target_backup": descriptor(TARGET.sector_base, target_sector),
    "crc_backup": descriptor(TARGET.crc_sector_base, crc_sector),
  }


@pytest.fixture
def valid_probe(tmp_path: Path):
  target_sector = bytearray((index * 17) & 0xFF for index in range(TARGET.sector_length))
  target_sector[TARGET.instruction_offset:TARGET.instruction_offset + 4] = TARGET.original_instruction
  target_sector = bytes(target_sector)
  target = replace(TARGET, original_sha256=hashlib.sha256(target_sector).hexdigest())
  crc_sector = bytearray((index * 29) & 0xFF for index in range(TARGET.sector_length))
  crc_sector[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = (
    TARGET.crc_original_adjust_word.to_bytes(4, "little")
  )
  magic_offset = TARGET.magic_addresses[1] - TARGET.crc_sector_base
  crc_sector[magic_offset:magic_offset + 4] = TARGET.magic_word.to_bytes(4, "little")
  crc_sector = bytes(crc_sector)
  layout = ArtifactLayout(tmp_path)
  report = make_report(target_sector, crc_sector)
  metadata = make_metadata(target_sector, crc_sector)
  return layout, target, target_sector, crc_sector, report, metadata


def write_probe(layout: ArtifactLayout, target_sector: bytes, crc_sector: bytes, report, metadata) -> None:
  layout.probe_directory.mkdir(parents=True)
  layout.target_backup.write_bytes(target_sector)
  layout.crc_backup.write_bytes(crc_sector)
  layout.probe_report.write_text(json.dumps(report), encoding="utf-8")
  layout.recovery_metadata.write_text(json.dumps(metadata), encoding="utf-8")


def test_installer_atomically_creates_complete_fixed_probe(valid_probe):
  layout, target, target_sector, crc_sector, report, metadata = valid_probe

  result = install_probe_pass(layout, target_sector, crc_sector, report, metadata)

  assert result == layout.probe_report
  assert {path.name for path in layout.probe_directory.iterdir()} == {
    "faci-pe-cycle-report.json", "original-sector-0x88000.bin",
    "original-sector-0xf8000.bin", "recovery-metadata.json",
  }
  assert load_probe_pass(layout, target).target_sector == target_sector
  with pytest.raises(EvidenceError, match="already exists") as exc_info:
    install_probe_pass(layout, target_sector, crc_sector, report, metadata)
  assert str(layout.root) not in str(exc_info.value)


def test_atomic_rename_never_replaces_an_empty_probe_directory(tmp_path: Path):
  """Replacing an empty, concurrent probe directory would silently discard its evidence."""
  staged = tmp_path / "staged"
  final = tmp_path / "probe"
  staged.mkdir()
  (staged / "evidence").write_text("complete", encoding="utf-8")
  final.mkdir()

  with pytest.raises(FileExistsError):
    _rename_no_replace(staged, final)

  assert final.is_dir()
  assert not any(final.iterdir())
  assert staged.is_dir()


def test_semantic_loader_accepts_complete_pass_without_fixed_report_digest(valid_probe):
  layout, target, target_sector, crc_sector, report, metadata = valid_probe
  write_probe(layout, target_sector, crc_sector, report, metadata)

  evidence = load_probe_pass(layout, target)

  assert evidence.identity.part_number == TARGET.part_number
  assert evidence.target_sector == target_sector
  assert evidence.crc_sector == crc_sector
  assert evidence.report["result"] == "PASS"


@pytest.mark.parametrize(
  "mutation",
  [
    lambda report, metadata, target, crc: report.update(result="FAIL"),
    lambda report, metadata, target, crc: report["identity"].update(part_number="wrong"),
    lambda report, metadata, target, crc: report["payload"].update(name="probe"),
    lambda report, metadata, target, crc: report["payload"].update(sha256="0" * 64),
    lambda report, metadata, target, crc: report["snapshots"].pop("RESTORED"),
    lambda report, metadata, target, crc: report["outcome"].update(cleanup_code=1),
    lambda report, metadata, target, crc: report["instruction"].update(original="20e61000"),
    lambda report, metadata, target, crc: report["sectors"]["target"].update(sha256="0" * 64),
    lambda report, metadata, target, crc: metadata["crc_backup"].update(address=TARGET.sector_base),
    lambda report, metadata, target, crc: report.update(new_uds=True),
    lambda report, metadata, target, crc: report["sectors"]["target"].update(address=TARGET.crc_sector_base),
    lambda report, metadata, target, crc: report["sectors"]["crc"].update(length=TARGET.sector_length - 1),
    lambda report, metadata, target, crc: report["snapshots"]["PRE"].update(FPMON=0),
    lambda report, metadata, target, crc: report["snapshots"]["CONFIGURED"].update(FPROTR=0),
    lambda report, metadata, target, crc: report["outcome"].update(primary_code=1),
    lambda report, metadata, target, crc: report["dcra"].update(exit_ctl=1),
    lambda report, metadata, target, crc: report["dcra"].update(original_dcra_raw=0),
    lambda report, metadata, target, crc: report["host_checks"].update(target_sector_crc32=0),
    lambda report, metadata, target, crc: report["host_checks"].update(patched_prefix_sw=0),
  ],
)
def test_semantic_loader_rejects_non_pass_or_mismatched_evidence(valid_probe, mutation):
  layout, target, target_sector, crc_sector, report, metadata = valid_probe
  mutation(report, metadata, target_sector, crc_sector)
  write_probe(layout, target_sector, crc_sector, report, metadata)

  with pytest.raises(EvidenceError):
    load_probe_pass(layout, target)


@pytest.mark.parametrize(
  ("register", "value"),
  (("FPROTR", -1), ("FAREASELC", 0x10000)),
)
def test_semantic_loader_rejects_configured_values_outside_declared_width(
  valid_probe, register, value,
):
  layout, target, target_sector, crc_sector, report, metadata = valid_probe
  report["snapshots"]["CONFIGURED"][register] = value
  write_probe(layout, target_sector, crc_sector, report, metadata)

  with pytest.raises(EvidenceError, match=rf"{register}.*width"):
    load_probe_pass(layout, target)


@pytest.mark.parametrize("kind", ("missing", "malformed", "wrong-backup-size"))
def test_semantic_loader_rejects_unreadable_or_incomplete_evidence(valid_probe, kind):
  layout, target, target_sector, crc_sector, report, metadata = valid_probe
  if kind == "missing":
    pass
  elif kind == "malformed":
    layout.probe_directory.mkdir()
    layout.probe_report.write_text("not json", encoding="utf-8")
  else:
    write_probe(layout, target_sector[:-1], crc_sector, report, metadata)

  with pytest.raises(EvidenceError) as exc_info:
    load_probe_pass(layout, target)
  assert str(layout.root) not in str(exc_info.value)


def test_installer_hides_staging_path_when_file_write_fails(valid_probe, monkeypatch):
  layout, _target, target_sector, crc_sector, report, metadata = valid_probe

  def fail_write(path: Path, content: bytes) -> None:
    raise OSError(f"simulated write failure: {path}")

  monkeypatch.setattr("eps_patch.evidence._write_fsynced", fail_write)

  with pytest.raises(EvidenceError, match="cannot install probe evidence") as exc_info:
    install_probe_pass(layout, target_sector, crc_sector, report, metadata)
  assert str(layout.root) not in str(exc_info.value)


def test_semantic_loader_rejects_backup_with_changed_instruction_context(valid_probe):
  layout, target, target_sector, crc_sector, report, metadata = valid_probe
  changed = bytearray(target_sector)
  changed[TARGET.instruction_offset + 2] ^= 1
  changed = bytes(changed)
  report["sectors"]["target"] = descriptor(TARGET.sector_base, changed)
  metadata["target_backup"] = descriptor(TARGET.sector_base, changed)
  write_probe(layout, changed, crc_sector, report, metadata)
  changed_target = replace(
    target, original_sha256=hashlib.sha256(changed).hexdigest(),
  )

  with pytest.raises(EvidenceError, match="instruction context"):
    load_probe_pass(layout, changed_target)


def test_semantic_loader_rejects_coordinated_target_backup_tampering(valid_probe):
  layout, target, target_sector, crc_sector, report, metadata = valid_probe
  changed = bytes([target_sector[0] ^ 1]) + target_sector[1:]
  report["sectors"]["target"] = descriptor(target.sector_base, changed)
  metadata["target_backup"] = descriptor(target.sector_base, changed)
  report["host_checks"]["target_sector_crc32"] = binascii.crc32(changed)
  report["host_checks"]["combined_crc32"] = binascii.crc32(changed + crc_sector)
  report["host_checks"]["target_sector_sha256"] = hashlib.sha256(changed).hexdigest()
  write_probe(layout, changed, crc_sector, report, metadata)

  with pytest.raises(EvidenceError, match="reviewed original"):
    load_probe_pass(layout, target)
