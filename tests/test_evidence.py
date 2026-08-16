import copy
import json
from pathlib import Path

import pytest

from eps_patch.artifacts import sha256_bytes
from eps_patch.evidence import EvidenceError, _rename_no_replace, install_probe_pass, load_probe_pass
from eps_patch.manifest import TARGET
from eps_patch.paths import ArtifactLayout


SNAPSHOTS = {
  "PRE": {
    "FPMON": 0x80, "FASTAT": 0x8000, "FAESTAT": 0, "REG84": 0,
    "REG88": 0, "REG20": 0, "FLWL": 0, "FLWE": 0,
  },
  "UNLOCKED": {
    "FPMON": 0x80, "FASTAT": 0x8000, "FAESTAT": 0, "REG84": 1,
    "REG88": 0, "REG20": 0, "FLWL": 0, "FLWE": 0,
  },
  "WINDOWS": {
    "FPMON": 0x80, "FASTAT": 0x8000, "FAESTAT": 0, "REG84": 1,
    "REG88": 0, "REG20": 0, "FLWL": 1, "FLWE": 1,
  },
  "CONFIGURED": {
    "FPMON": 0x80, "FASTAT": 0x8000, "FAESTAT": 0, "REG84": 1,
    "REG88": 1, "REG20": 0x3B00, "FLWL": 1, "FLWE": 1,
  },
  "RESTORED": {
    "FPMON": 0x80, "FASTAT": 0x8000, "FAESTAT": 0, "REG84": 0,
    "REG88": 0, "REG20": 0, "FLWL": 0, "FLWE": 0,
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
  return {
    "workflow": "faci-pe-cycle",
    "result": "PASS",
    "identity": identity(),
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
  crc_sector = bytes((index * 29) & 0xFF for index in range(TARGET.sector_length))
  layout = ArtifactLayout(tmp_path)
  report = make_report(bytes(target_sector), crc_sector)
  metadata = make_metadata(bytes(target_sector), crc_sector)
  return layout, bytes(target_sector), crc_sector, report, metadata


def write_probe(layout: ArtifactLayout, target_sector: bytes, crc_sector: bytes, report, metadata) -> None:
  layout.probe_directory.mkdir(parents=True)
  layout.target_backup.write_bytes(target_sector)
  layout.crc_backup.write_bytes(crc_sector)
  layout.probe_report.write_text(json.dumps(report), encoding="utf-8")
  layout.recovery_metadata.write_text(json.dumps(metadata), encoding="utf-8")


def test_installer_atomically_creates_complete_fixed_probe(valid_probe):
  layout, target_sector, crc_sector, report, metadata = valid_probe

  result = install_probe_pass(layout, target_sector, crc_sector, report, metadata)

  assert result == layout.probe_report
  assert {path.name for path in layout.probe_directory.iterdir()} == {
    "faci-pe-cycle-report.json", "original-sector-0x60000.bin",
    "original-sector-0xf8000.bin", "recovery-metadata.json",
  }
  assert load_probe_pass(layout, TARGET).target_sector == target_sector
  with pytest.raises(EvidenceError, match="already exists"):
    install_probe_pass(layout, target_sector, crc_sector, report, metadata)


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
  layout, target_sector, crc_sector, report, metadata = valid_probe
  write_probe(layout, target_sector, crc_sector, report, metadata)

  evidence = load_probe_pass(layout, TARGET)

  assert evidence.identity.part_number == TARGET.part_number
  assert evidence.target_sector == target_sector
  assert evidence.crc_sector == crc_sector
  assert evidence.report["result"] == "PASS"


@pytest.mark.parametrize(
  "mutation",
  [
    lambda report, metadata, target, crc: report.update(result="FAIL"),
    lambda report, metadata, target, crc: report["identity"].update(part_number="wrong"),
    lambda report, metadata, target, crc: report["snapshots"].pop("RESTORED"),
    lambda report, metadata, target, crc: report["outcome"].update(cleanup_code=1),
    lambda report, metadata, target, crc: report["instruction"].update(original="20e61000"),
    lambda report, metadata, target, crc: report["sectors"]["target"].update(sha256="0" * 64),
    lambda report, metadata, target, crc: metadata["crc_backup"].update(address=TARGET.sector_base),
    lambda report, metadata, target, crc: report.update(new_uds=True),
    lambda report, metadata, target, crc: report["sectors"]["target"].update(address=TARGET.crc_sector_base),
    lambda report, metadata, target, crc: report["sectors"]["crc"].update(length=TARGET.sector_length - 1),
    lambda report, metadata, target, crc: report["snapshots"]["PRE"].update(FPMON=0),
    lambda report, metadata, target, crc: report["outcome"].update(primary_code=1),
  ],
)
def test_semantic_loader_rejects_non_pass_or_mismatched_evidence(valid_probe, mutation):
  layout, target_sector, crc_sector, report, metadata = valid_probe
  mutation(report, metadata, target_sector, crc_sector)
  write_probe(layout, target_sector, crc_sector, report, metadata)

  with pytest.raises(EvidenceError):
    load_probe_pass(layout, TARGET)


@pytest.mark.parametrize("kind", ("missing", "malformed", "wrong-backup-size"))
def test_semantic_loader_rejects_unreadable_or_incomplete_evidence(valid_probe, kind):
  layout, target_sector, crc_sector, report, metadata = valid_probe
  if kind == "missing":
    pass
  elif kind == "malformed":
    layout.probe_directory.mkdir()
    layout.probe_report.write_text("not json", encoding="utf-8")
  else:
    write_probe(layout, target_sector[:-1], crc_sector, report, metadata)

  with pytest.raises(EvidenceError):
    load_probe_pass(layout, TARGET)


def test_semantic_loader_rejects_backup_with_changed_instruction_context(valid_probe):
  layout, target_sector, crc_sector, report, metadata = valid_probe
  changed = bytearray(target_sector)
  changed[TARGET.instruction_offset + 2] ^= 1
  changed = bytes(changed)
  report["sectors"]["target"] = descriptor(TARGET.sector_base, changed)
  metadata["target_backup"] = descriptor(TARGET.sector_base, changed)
  write_probe(layout, changed, crc_sector, report, metadata)

  with pytest.raises(EvidenceError, match="instruction context"):
    load_probe_pass(layout, TARGET)
