from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def _tracked_repository_paths() -> tuple[Path, ...]:
    result = subprocess.run(
        ("git", "ls-files", "-z"),
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return tuple(
        Path(path)
        for path in result.stdout.decode().split("\0")
        if path
    )


def test_repository_contains_no_local_or_rebuildable_outputs():
    tracked_paths = _tracked_repository_paths()
    forbidden = {".DS_Store", ".pytest_cache", "__pycache__", ".venv"}
    assert not [path for path in tracked_paths if path.name in forbidden]
    forbidden_suffixes = {
        ".o",
        ".elf",
        ".map",
        ".disassembly",
        ".symbols",
        ".sections",
        ".preprocessed",
    }
    assert not [path for path in tracked_paths if path.suffix in forbidden_suffixes]


def test_public_repository_excludes_internal_docs_and_tool_outputs():
    tracked_paths = _tracked_repository_paths()
    forbidden_roots = {"docs", ".superpowers", ".agents", ".codex", "tools"}

    assert not (ROOT / "docs").exists()
    assert not [
        path for path in tracked_paths
        if path.parts and path.parts[0] in forbidden_roots
    ]


def test_gitignore_covers_python_environments_caches_and_local_tools():
    rules = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())

    assert {
        "__pycache__/",
        "*.pyc",
        ".pytest_cache/",
        ".venv/",
        "venv/",
        "env/",
        "/tools/",
        "/.superpowers/",
        "/.agents/",
        "/.codex/",
    } <= rules


def test_reviewed_primitive_package_is_importable():
  from eps_patch import TARGET

  assert TARGET.part_number == b"8965F1208000"


def test_legacy_payload_operations_and_artifact_workflow_are_not_retained():
  import eps_patch.protocol as protocol

  assert not [
    name for name in (
      "OP_" "PROBE", "OP_" "PATCH", "OP_" "FACI_" "UNLOCK",
      "OP_" "PATCH_" "V2", "OP_" "RESTORE", "OP_" "PATCH_" "CRC",
    ) if hasattr(protocol, name)
  ]
  assert not (ROOT / "eps_patch" / "crc_artifacts.py").exists()
