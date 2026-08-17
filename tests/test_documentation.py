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


def test_readme_is_complete_english_then_complete_chinese():
  """Catch a summary translation, missing chapter, or Chinese-first rewrite."""
  readme = (ROOT / "README.md").read_text(encoding="utf-8")
  headings = (
    "# English",
    "## 0. Risk Warning",
    "## 1. Detailed Operating Guide",
    "## 2. Design Principles and How It Works",
    "## 3. Cross-Compilation and Porting to Other Bench ECUs",
    "## 4. FAQ",
    "# 中文",
    "## 0. 风险警告",
    "## 1. 详细操作指南",
    "## 2. 脚本设计原则和工作原理",
    "## 3. 交叉编译环境与其他台架车型移植",
    "## 4. 常见问题",
  )

  positions = [readme.index(heading) for heading in headings]

  assert positions == sorted(positions)
  assert all(readme.count(heading) == 1 for heading in headings)


def test_readme_documents_sync_restart_build_and_porting_contracts():
  """Catch operator guidance that loses artifacts or reuses ECU-specific data."""
  readme = (ROOT / "README.md").read_text(encoding="utf-8")
  normalized = " ".join(readme.split())

  for required in (
    "rsync -av",
    "/data/eps-patch/app/",
    "/data/eps-patch/artifacts/",
    "reconnect SSH",
    "rerun the same command",
    "重新连接 SSH",
    "重新运行同一条命令",
    "docker build -t v850-gcc:latest v850-cross-build",
    "TOOL_PREFIX=v850-elf- ./build.sh",
    "Ubuntu 22.04",
    "binutils 2.41",
    "GCC 13.2.0",
    "RH850",
    "not portable",
    "不可移植",
  ):
    assert required in normalized
  assert "Press Enter" not in readme
  assert "按 Enter" not in readme


def test_readme_has_matched_recovery_faq_coverage():
  """Catch omission of a recovery decision from either language guide."""
  readme = (ROOT / "README.md").read_text(encoding="utf-8")
  english_start = readme.index("# English")
  chinese_start = readme.index("# 中文")
  english = readme[english_start:chinese_start]
  chinese = readme[chinese_start:]

  assert english.count("\n### Q") == 22
  assert chinese.count("\n### 问") == 22
  for required in (
    "SSH",
    "TARGET_INDETERMINATE",
    "CRC_INDETERMINATE",
    "restore becomes indeterminate",
    "unexpected external power loss",
    "4 KiB",
    "0xE0000",
    "Flash-level PASS",
    "rebuild payload",
    "another RH850",
  ):
    assert required in english
  for required in (
    "SSH",
    "TARGET_INDETERMINATE",
    "CRC_INDETERMINATE",
    "restore 变为不确定状态",
    "意外外部断电",
    "4 KiB",
    "0xE0000",
    "Flash 级 PASS",
    "重新构建 payload",
    "其他 RH850",
  ):
    assert required in chinese


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
