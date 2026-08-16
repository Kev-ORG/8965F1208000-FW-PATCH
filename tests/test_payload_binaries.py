import hashlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ROOT / "payload"
BUILD = PAYLOAD / "build"
REVIEWED_SOURCES = (
  "probe_pe_cycle.c", "crc_probe.c", "crc_intermediate.c", "crc_verify.c",
  "write_target_candidate.c", "write_crc_candidate.c", "common.h", "protocol.h",
  "dcra.h", "patch_common.h", "patch_protocol.h", "crc_runtime.h",
  "candidate_writer.h", "faci_dual.h", "linker.ld", "linker_intent.ld", "build.sh",
)
RUNTIME_PAYLOADS = {
  "probe_pe_cycle", "crc_probe", "crc_intermediate", "crc_verify",
  "write_target_candidate", "write_crc_candidate",
}


def require_cross_build() -> None:
  if not BUILD.exists():
    __import__("pytest").skip(
      "reviewed V850 cross-build is unavailable; no binary or manifest was invented",
    )


def test_only_probe_and_two_sector_patch_runtime_binaries_are_retained_and_pinned():
  require_cross_build()
  from eps_patch.payload import BUILT_PAYLOADS

  assert {path.name for path in BUILD.iterdir()} == {
    *(f"{name}.bin" for name in RUNTIME_PAYLOADS), "manifest.json",
  }
  manifest = json.loads((BUILD / "manifest.json").read_text(encoding="utf-8"))
  assert set(manifest["payloads"]) == RUNTIME_PAYLOADS
  assert set(BUILT_PAYLOADS) == RUNTIME_PAYLOADS
  for name in RUNTIME_PAYLOADS:
    binary = (BUILD / f"{name}.bin").read_bytes()
    record = manifest["payloads"][name]
    assert record["size"] == len(binary) <= 0xFD0
    assert record["sha256"] == hashlib.sha256(binary).hexdigest()
    assert BUILT_PAYLOADS[name] == {
      "size": record["size"], "sha256": record["sha256"],
    }
  assert manifest["payloads"]["probe_pe_cycle"]["entrypoint"] == "0xfebf0000"
  for name in RUNTIME_PAYLOADS - {"probe_pe_cycle"}:
    assert set(manifest["payloads"][name]) == {"size", "sha256"}
  assert not any((PAYLOAD / name).exists() for name in (
    "patch.c", "patch_v2.c", "patch_crc.c", "linker_patch_crc.ld",
  ))


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
