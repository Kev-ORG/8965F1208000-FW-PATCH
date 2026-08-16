from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_repository_contains_no_local_or_rebuildable_outputs():
    forbidden = {".DS_Store", ".pytest_cache", "__pycache__", ".venv"}
    assert not [path for path in ROOT.rglob("*") if path.name in forbidden]
    forbidden_suffixes = {
        ".o",
        ".elf",
        ".map",
        ".disassembly",
        ".symbols",
        ".sections",
        ".preprocessed",
    }
    assert not [
        path
        for path in (ROOT / "payload").rglob("*")
        if path.suffix in forbidden_suffixes
    ]


def test_reviewed_primitive_package_is_importable():
    from eps_patch import TARGET

    assert TARGET.part_number == b"8965B4512000"
