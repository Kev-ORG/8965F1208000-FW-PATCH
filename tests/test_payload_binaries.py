import hashlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ROOT / "payload"
BUILD = PAYLOAD / "build"
REVIEWED_SOURCES = (
  "probe_pe_cycle.c", "common.h", "protocol.h", "dcra.h", "linker.ld", "build.sh",
)


def require_cross_build() -> None:
  if not BUILD.exists():
    __import__("pytest").skip(
      "reviewed V850 cross-build is unavailable; no binary or manifest was invented",
    )


def test_only_comprehensive_probe_binary_is_retained_and_pinned():
  require_cross_build()
  from eps_patch.payload import BUILT_PAYLOADS

  assert {path.name for path in BUILD.iterdir()} == {"probe_pe_cycle.bin", "manifest.json"}
  binary = (BUILD / "probe_pe_cycle.bin").read_bytes()
  manifest = json.loads((BUILD / "manifest.json").read_text(encoding="utf-8"))
  assert set(manifest["payloads"]) == {"probe_pe_cycle"}
  record = manifest["payloads"]["probe_pe_cycle"]
  assert record["size"] == len(binary) <= 0xFD0
  assert record["sha256"] == hashlib.sha256(binary).hexdigest()
  assert record["entrypoint"] == "0xfebf0000"
  assert BUILT_PAYLOADS["probe_pe_cycle"] == {
    "size": record["size"], "sha256": record["sha256"],
  }
  assert "probe" not in BUILT_PAYLOADS and "probe_unlock" not in BUILT_PAYLOADS


def test_manifest_binds_every_retained_review_source():
  require_cross_build()
  manifest = json.loads((BUILD / "manifest.json").read_text(encoding="utf-8"))
  assert set(manifest["sources"]) == set(REVIEWED_SOURCES)
  for name in REVIEWED_SOURCES:
    assert manifest["sources"][name] == hashlib.sha256((PAYLOAD / name).read_bytes()).hexdigest()
  assert manifest["toolchain"] == {"gcc": "13.2.0", "binutils": "2.41"}


def test_probe_binary_contains_entrypoint_and_exact_original_context():
  require_cross_build()
  binary = (BUILD / "probe_pe_cycle.bin").read_bytes()
  assert binary[:4] != bytes(4)
  assert bytes.fromhex("20 e6 31 00") in binary


def test_retained_binary_loader_accepts_and_validates_entrypoint(tmp_path: Path):
  require_cross_build()
  from eps_patch.payload import PayloadError, load_built_shellcode

  binary = (BUILD / "probe_pe_cycle.bin").read_bytes()
  manifest = json.loads((BUILD / "manifest.json").read_text(encoding="utf-8"))
  (tmp_path / "probe_pe_cycle.bin").write_bytes(binary)
  (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

  assert load_built_shellcode(tmp_path, "probe_pe_cycle") == binary

  manifest["payloads"]["probe_pe_cycle"]["entrypoint"] = "0xfebf0002"
  (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
  with pytest.raises(PayloadError, match="entrypoint"):
    load_built_shellcode(tmp_path, "probe_pe_cycle")
