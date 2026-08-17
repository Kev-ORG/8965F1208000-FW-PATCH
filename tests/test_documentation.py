"""Operator documentation contracts for the comma-local workflow."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_readme_documents_the_complete_comma_local_lifecycle():
  readme = (ROOT / "README.md").read_text(encoding="utf-8")
  normalized = " ".join(readme.split())

  for command in (
    "python3.12 eps_patch.py probe",
    "python3.12 eps_patch.py patch",
    "python3.12 eps_patch.py restore",
  ):
    assert command in readme
  for required in (
    "/data/eps-patch/artifacts",
    "/data/eps-patch/artifacts/failures/last-probe-failure.json",
    "Run `probe` once before `patch` or `restore`.",
    "semantic `PASS`",
    "Panda serial",
    "original target and CRC-sector backups",
    "complete power cycle",
    "rerun the same",
    "target sector (`0x60000`) first, then the CRC sector (`0xf8000`)",
    "CRC sector (`0xf8000`) first, then the target sector (`0x60000`)",
    "external programmer",
    "professional recovery",
    "0xFEBF0000",
    "0x1000",
    "32 KiB sector is never uploaded",
    "at most one ECU payload",
    "TARGET_PRECHECKED",
    "CRC_PRECHECKED",
  ):
    assert required in normalized
  for required in (
    "untrusted diagnostic",
    "does not create `probe` evidence",
  ):
    assert required in normalized
  assert "Press Enter" not in readme

  forbidden = (
    "download the report",
    "upload the report",
    "report hash",
    "report SHA",
    "report sha",
  )
  assert not [phrase for phrase in forbidden if phrase in readme]


def test_root_cause_document_preserves_the_two_sector_safety_rationale():
  document = (ROOT / "docs" / "boot-crc-root-cause.md").read_text(
    encoding="utf-8",
  )

  for required in (
    "0x664e6",
    "0x31",
    "0x10",
    "0x60000",
    "0xf8000",
    "0xffdec",
    "crc",
    "dcra",
    "0x0962887f",
    "0x414f47cc",
  ):
    assert required in document.lower()
