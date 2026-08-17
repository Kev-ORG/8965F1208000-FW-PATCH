import hashlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ROOT / "payload"
BUILD = PAYLOAD / "build"
REVIEWED_SOURCES = (
  "probe_pe_cycle.c", "crc_probe.c", "crc_intermediate.c", "crc_verify.c",
  "write_target_candidate.c", "write_crc_candidate.c", "ram_echo.c",
  "restore_sector.c", "live_read.c", "common.h", "protocol.h",
  "dcra.h", "patch_common.h", "patch_protocol.h", "crc_runtime.h",
  "candidate_writer.h", "faci_dual.h", "linker.ld", "linker_intent.ld", "build.sh",
)
RUNTIME_PAYLOADS = {
  "probe_pe_cycle", "crc_probe", "crc_intermediate", "crc_verify",
  "write_target_candidate", "write_crc_candidate", "ram_echo", "restore_sector",
  "live_read",
}


def require_cross_build() -> None:
  if not BUILD.exists():
    __import__("pytest").skip(
      "reviewed V850 cross-build is unavailable; no binary or manifest was invented",
    )


def test_only_probe_patch_and_restore_runtime_binaries_are_retained_and_pinned():
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


def test_live_read_build_and_zero_did_envelope_are_exactly_pinned():
  require_cross_build()
  from eps_patch.payload import (
    BUILD_READY_PAYLOADS, BUILT_PAYLOADS, build_envelope, load_built_shellcode,
  )
  from eps_patch.restore import LIVE_READ_ENVELOPE_SHA256

  script = (PAYLOAD / "build.sh").read_text(encoding="utf-8")
  manifest = json.loads((BUILD / "manifest.json").read_text(encoding="utf-8"))
  binary = (BUILD / "live_read.bin").read_bytes()
  expected_binary = {
    "size": 1280,
    "sha256": "3543bbe2ea4077f9cbeb9db31b0bce98636be09ed9017e826bd408eb5058d9ea",
  }
  assert BUILD_READY_PAYLOADS == ()
  assert BUILT_PAYLOADS["live_read"] == expected_binary
  assert manifest["payloads"]["live_read"] == expected_binary
  assert len(binary) == expected_binary["size"]
  assert hashlib.sha256(binary).hexdigest() == expected_binary["sha256"]
  assert load_built_shellcode(BUILD, "live_read") == binary
  assert manifest["sources"]["live_read.c"] == hashlib.sha256(
    (PAYLOAD / "live_read.c").read_bytes(),
  ).hexdigest()
  envelope = build_envelope(
    binary, did_201=bytes(16), did_202=bytes(16), iv=bytes(16),
  )
  expected_envelope_sha256 = (
    "4d102f0c91e7ef8807efcbe48b5bedf8a787e37ff6d3860792b82f35ed4fca2d"
  )
  assert hashlib.sha256(envelope).hexdigest() == expected_envelope_sha256
  assert LIVE_READ_ENVELOPE_SHA256 == expected_envelope_sha256
  assert script.count("write_crc_candidate ram_echo restore_sector live_read") == 2
  assert "! -name live_read.bin" in script
  assert "last_payload=live_read" in script
  assert '[ "$name" = "$last_payload" ] && comma=' in script


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
