from pathlib import Path

from eps_patch.paths import ArtifactLayout


def test_fixed_layout_uses_one_probe_and_timestamped_attempts(tmp_path: Path):
  """Changing a fixed artifact name or allowing non-timestamped attempt paths is unsafe."""
  layout = ArtifactLayout(tmp_path)

  assert layout.probe_directory == tmp_path / "probe"
  assert layout.probe_report == tmp_path / "probe/faci-pe-cycle-report.json"
  assert layout.target_backup == tmp_path / "probe/original-sector-0x60000.bin"
  assert layout.crc_backup == tmp_path / "probe/original-sector-0xf8000.bin"
  assert layout.recovery_metadata == tmp_path / "probe/recovery-metadata.json"
  assert layout.patch_attempt("20260817T010203Z") == tmp_path / "patch/20260817T010203Z"
  assert layout.restore_attempt("20260817T010204Z") == tmp_path / "restore/20260817T010204Z"
