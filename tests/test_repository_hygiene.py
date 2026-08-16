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


def test_reviewed_primitive_package_is_importable():
    from eps_patch import TARGET

    assert TARGET.part_number == b"8965B4512000"
