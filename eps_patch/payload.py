"""Build and independently verify the bootloader's 4096-byte RAM envelope."""

from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .manifest import TARGET


PAYLOAD_BUILD_SECRET = bytes.fromhex("ba052435f8843f985fd1329d2b6117b0")
SECURITY_ACCESS_SECRET = bytes.fromhex("f05f36b7d78c03e24ab4faef2a57d044")
# The final 48 bytes of the 4 KiB plaintext are bootloader-owned metadata:
# jump target at 0xFD0, descriptor at 0xFE0, CRC at 0xFEC, and CMAC at 0xFF0.
JUMP_ADDRESS_OFFSET = 0xFD0
DESCRIPTOR_OFFSET = 0xFE0
AUTHENTICATOR_OFFSET = 0xFF0
SHELLCODE_LIMIT = JUMP_ADDRESS_OFFSET
PLAINTEXT_BODY_LENGTH = AUTHENTICATOR_OFFSET
PROBE_PE_CYCLE_ENVELOPE_SHA256 = (
  "73e31e97921d4ca1c65c79fb09650744eb81b3a9e6db8493e02efb7629f62a52"
)
BUILT_PAYLOADS = {
  "probe_pe_cycle": {
    "size": 2936,
    "sha256": "7f4c8cc9f4612d53925c4d239fea1dc4b1987676a83f22222b5e45642559f132",
  },
  "crc_probe": {
    "size": 2228,
    "sha256": "2586922b12c8253fe8cbfb7860aa91201682783c6c0f61cd9ccea1aea8197eb0",
  },
  "crc_verify": {
    "size": 1890,
    "sha256": "4662f7160592d26e2fac16415cfd90224c1b7c64741254638ce27cbacb979cc0",
  },
  "crc_intermediate": {
    "size": 2354,
    "sha256": "03dee5c0435f02bf7bb97681c4392defa61ca6d81db46ad7ae820521bef89281",
  },
  "write_target_candidate": {
    "size": 4024,
    "sha256": "b3101d8a2fcb1c262c7d006fde8c156a3a28f7fd6062b8452655c2a0d1b07507",
  },
  "write_crc_candidate": {
    "size": 4028,
    "sha256": "17ba9ca3f1b2adaf25b91b1499437045d3402ac7408b5fbe0a45d8cd16639c40",
  },
  "restore_sector": {
    "size": 3952,
    "sha256": "7b79cf5c13ea58e0fd1bd2766592218c42eb214ea3809b7f604c45cfe4673de0",
  },
  "live_read": {
    "size": 1280,
    "sha256": "3543bbe2ea4077f9cbeb9db31b0bce98636be09ed9017e826bd408eb5058d9ea",
  },
}
BUILD_READY_PAYLOADS: tuple[str, ...] = ()
BUILT_PAYLOAD_ENTRYPOINTS = {
  "probe_pe_cycle": "0xfebf0000",
}

class PayloadError(RuntimeError):
  pass


@dataclass(frozen=True, slots=True)
class IntentLayout:
  """Only byte range a host may specialize in a pinned payload template."""

  offset: int
  size: int


@dataclass(frozen=True, slots=True)
class PayloadTemplateManifest:
  """Source-reviewed record for one exact parameterized shellcode template."""

  name: str
  size: int
  sha256: str
  intent: IntentLayout
  review_sha256: str

  def validate(self) -> None:
    if (
      type(self.name) is not str or not self.name or "\x00" in self.name
      or type(self.size) is not int or self.size <= 0
      or type(self.sha256) is not str or len(self.sha256) != 64
      or any(character not in "0123456789abcdef" for character in self.sha256)
      or type(self.intent) is not IntentLayout
      or type(self.intent.offset) is not int or type(self.intent.size) is not int
      or type(self.review_sha256) is not str or len(self.review_sha256) != 64
      or any(character not in "0123456789abcdef" for character in self.review_sha256)
    ):
      raise PayloadError("payload template manifest fields are not exact reviewed types")
    reviewed = REVIEWED_TEMPLATE_MANIFESTS.get(self.name)
    if reviewed is not self:
      raise PayloadError(
        "payload template manifest is not an exact source-reviewed literal allowlist entry"
      )

    try:
      TARGET.validate()
    except ValueError as exc:
      raise PayloadError(f"payload target intent mapping is invalid: {exc}") from exc
    reviewed_layout = {
      "reviewed-fixture": IntentLayout(0x600, 0x80),
      "restore_sector": IntentLayout(0x600, 0x80),
      "write_target_candidate": IntentLayout(0x600, 0x80),
      "write_crc_candidate": IntentLayout(0x600, 0x80),
    }.get(self.name)
    if (
      self.intent != reviewed_layout
      or self.intent.offset < 0
      or self.intent.offset + self.intent.size > self.size
      or self.intent.offset + self.intent.size > TARGET.envelope_length
      or self.size > SHELLCODE_LIMIT
      or self.size > TARGET.envelope_length
    ):
      raise PayloadError("payload target intent mapping does not match the reviewed envelope")


# Trust is granted only by editing this literal table in source review. There is
# deliberately no public helper that derives or mints a review seal at runtime.
REVIEWED_TEMPLATE_MANIFESTS = MappingProxyType({
  "reviewed-fixture": PayloadTemplateManifest(
    name="reviewed-fixture",
    size=0x800,
    sha256="10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08",
    intent=IntentLayout(offset=0x600, size=0x80),
    review_sha256="1211a79dda5cf58a96e8f2b6be08f04a156a1982723b0623488ada2a444d1c06",
  ),
  "restore_sector": PayloadTemplateManifest(
    name="restore_sector",
    size=3952,
    sha256="7b79cf5c13ea58e0fd1bd2766592218c42eb214ea3809b7f604c45cfe4673de0",
    intent=IntentLayout(offset=0x600, size=0x80),
    review_sha256="7b79cf5c13ea58e0fd1bd2766592218c42eb214ea3809b7f604c45cfe4673de0",
  ),
  "write_target_candidate": PayloadTemplateManifest(
    name="write_target_candidate",
    size=4024,
    sha256="b3101d8a2fcb1c262c7d006fde8c156a3a28f7fd6062b8452655c2a0d1b07507",
    intent=IntentLayout(offset=0x600, size=0x80),
    review_sha256="b3101d8a2fcb1c262c7d006fde8c156a3a28f7fd6062b8452655c2a0d1b07507",
  ),
  "write_crc_candidate": PayloadTemplateManifest(
    name="write_crc_candidate",
    size=4028,
    sha256="17ba9ca3f1b2adaf25b91b1499437045d3402ac7408b5fbe0a45d8cd16639c40",
    intent=IntentLayout(offset=0x600, size=0x80),
    review_sha256="17ba9ca3f1b2adaf25b91b1499437045d3402ac7408b5fbe0a45d8cd16639c40",
  ),
})


def specialize_shellcode(
  template: bytes, *, manifest: PayloadTemplateManifest, intent: bytes,
) -> bytes:
  """Replace exactly one reviewed intent slice and preserve all other bytes."""
  if type(template) is not bytes or type(intent) is not bytes:
    raise PayloadError("payload template and intent must be immutable bytes")
  if not template or len(template) > SHELLCODE_LIMIT:
    raise PayloadError("payload template exceeds the shellcode boundary")
  if type(manifest) is not PayloadTemplateManifest:
    raise PayloadError("payload template manifest has the wrong concrete type")
  manifest.validate()
  if len(template) != manifest.size or not hmac.compare_digest(
    hashlib.sha256(template).hexdigest(), manifest.sha256,
  ):
    raise PayloadError("payload executable bytes do not match the exact template pin")
  if len(intent) != manifest.intent.size:
    raise PayloadError("payload intent does not match the reviewed layout size")
  start = manifest.intent.offset
  end = start + manifest.intent.size
  return template[:start] + intent + template[end:]


@dataclass(frozen=True, slots=True)
class SpecializedPayloadImage:
  """Deterministic envelope bound to one literal-reviewed template and intent."""

  name: str
  template: bytes
  manifest: PayloadTemplateManifest
  intent: bytes
  envelope: bytes
  sha256: str
  sector_base: int

  def validate(self) -> bytes:
    if self.name != self.manifest.name:
      raise PayloadError("specialized payload name does not match its reviewed template")
    if self.sector_base not in (TARGET.sector_base, TARGET.crc_sector_base):
      raise PayloadError("specialized payload sector base is not allowlisted")
    shellcode = specialize_shellcode(
      self.template, manifest=self.manifest, intent=self.intent,
    )
    plaintext = verify_envelope(
      self.envelope, did_201=bytes(16), did_202=bytes(16),
    )
    if plaintext[:len(shellcode)] != shellcode:
      raise PayloadError("specialized envelope does not contain the reviewed shellcode")
    if any(plaintext[len(shellcode):SHELLCODE_LIMIT]):
      raise PayloadError("specialized envelope has nonzero bytes outside the shellcode")
    if not hmac.compare_digest(hashlib.sha256(self.envelope).hexdigest(), self.sha256):
      raise PayloadError("specialized payload envelope SHA-256 mismatch")
    return shellcode


def build_specialized_payload_image(
  *, template: bytes, manifest: PayloadTemplateManifest, intent: bytes,
  sector_base: int,
) -> SpecializedPayloadImage:
  shellcode = specialize_shellcode(template, manifest=manifest, intent=intent)
  envelope = build_envelope(
    shellcode, did_201=bytes(16), did_202=bytes(16), iv=bytes(16),
  )
  image = SpecializedPayloadImage(
    name=manifest.name,
    template=template,
    manifest=manifest,
    intent=intent,
    envelope=envelope,
    sha256=hashlib.sha256(envelope).hexdigest(),
    sector_base=sector_base,
  )
  image.validate()
  return image


def _load_crypto():
  from Crypto.Cipher import AES
  from Crypto.Hash import CMAC

  return AES, CMAC


def load_built_shellcode(build_directory: Path, name: str) -> bytes:
  if name not in BUILT_PAYLOADS:
    raise PayloadError(f"unknown built payload: {name}")
  binary_path = build_directory / f"{name}.bin"
  manifest_path = build_directory / "manifest.json"
  try:
    binary = binary_path.read_bytes()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    recorded = manifest["payloads"][name]
    required_fields = {"size", "sha256"}
    expected_entrypoint = BUILT_PAYLOAD_ENTRYPOINTS.get(name)
    if expected_entrypoint is not None:
      required_fields.add("entrypoint")
    if (
      type(recorded) is not dict or set(recorded) != required_fields
      or type(recorded.get("size")) is not int
      or type(recorded.get("sha256")) is not str
      or (
        expected_entrypoint is not None
        and type(recorded.get("entrypoint")) is not str
      )
    ):
      raise TypeError("payload manifest fields are not exact reviewed types")
    recorded_size = recorded["size"]
    recorded_digest = recorded["sha256"]
    recorded_entrypoint = recorded.get("entrypoint")
  except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
    raise PayloadError(f"cannot load the {name} build artifact: {exc}") from exc

  actual = {"size": len(binary), "sha256": hashlib.sha256(binary).hexdigest()}
  expected = BUILT_PAYLOADS[name]
  if actual != expected:
    raise PayloadError(
      f"{name} binary does not match its pinned size/SHA-256: "
      f"expected {expected}, got {actual}"
    )
  if {"size": recorded_size, "sha256": recorded_digest} != expected:
    raise PayloadError(f"{name} build manifest does not match the pinned binary")
  if recorded_entrypoint != expected_entrypoint:
    raise PayloadError(f"{name} build manifest has the wrong entrypoint")
  if len(binary) > SHELLCODE_LIMIT:
    raise PayloadError(
      f"{name} shellcode overlaps bootloader metadata starting at 0xfd0"
    )
  return binary


def _require_dids(did_201: bytes, did_202: bytes) -> None:
  if len(did_201) != 16:
    raise PayloadError("DID 0x201 must be exactly 16 bytes")
  if len(did_202) != 16:
    raise PayloadError("DID 0x202 must be exactly 16 bytes")


def derive_payload_key(did_201: bytes) -> bytes:
  if len(did_201) != 16:
    raise PayloadError("DID 0x201 must be exactly 16 bytes")
  AES, _CMAC = _load_crypto()
  return AES.new(PAYLOAD_BUILD_SECRET, AES.MODE_ECB).encrypt(did_201)


def build_plaintext(shellcode: bytes, *, did_202: bytes, derived_key: bytes) -> bytes:
  if len(shellcode) > SHELLCODE_LIMIT:
    raise PayloadError("shellcode overlaps bootloader metadata starting at 0xfd0")
  if len(did_202) != 16:
    raise PayloadError("DID 0x202 must be exactly 16 bytes")
  if len(derived_key) != 16:
    raise PayloadError("derived key must be exactly 16 bytes")
  AES, CMAC = _load_crypto()

  body = bytearray(shellcode)
  body.extend(bytes(SHELLCODE_LIMIT - len(body)))
  body.extend(struct.pack("<I", TARGET.ram_address))
  body.extend(bytes(DESCRIPTOR_OFFSET - len(body)))
  body.extend(struct.pack("<I", TARGET.ram_address))
  body.extend(struct.pack("<I", PLAINTEXT_BODY_LENGTH))
  body.extend(bytes(4))
  body.extend(struct.pack("<I", binascii.crc32(body) ^ 0xFFFFFFFF))
  if len(body) != PLAINTEXT_BODY_LENGTH or binascii.crc32(body) != 0xFFFFFFFF:
    raise PayloadError("failed to construct the bootloader CRC-32 residue")

  authenticator = CMAC.new(derived_key, ciphermod=AES)
  authenticator.update(did_202 + body)
  body.extend(authenticator.digest())
  if len(body) != TARGET.envelope_length:
    raise PayloadError("plaintext envelope is not 4096 bytes")
  return bytes(body)


def build_envelope(
  shellcode: bytes,
  *,
  did_201: bytes,
  did_202: bytes,
  iv: bytes | None = None,
) -> bytes:
  _require_dids(did_201, did_202)
  AES, _CMAC = _load_crypto()
  encryption_iv = did_202 if iv is None else iv
  if len(encryption_iv) != 16:
    raise PayloadError("encryption IV must be exactly 16 bytes")
  if encryption_iv != did_202:
    raise PayloadError("encryption IV must equal DID 0x202")
  derived_key = derive_payload_key(did_201)
  plaintext = build_plaintext(shellcode, did_202=did_202, derived_key=derived_key)
  envelope = AES.new(derived_key, AES.MODE_CBC, iv=encryption_iv).encrypt(plaintext)
  if len(envelope) != TARGET.envelope_length:
    raise PayloadError("encrypted envelope is not 4096 bytes")
  return envelope


def verify_envelope(envelope: bytes, *, did_201: bytes, did_202: bytes) -> bytes:
  _require_dids(did_201, did_202)
  AES, CMAC = _load_crypto()
  if len(envelope) != TARGET.envelope_length:
    raise PayloadError("encrypted envelope is not 4096 bytes")
  derived_key = derive_payload_key(did_201)
  plaintext = AES.new(derived_key, AES.MODE_CBC, iv=did_202).decrypt(envelope)
  body, supplied_cmac = plaintext[:PLAINTEXT_BODY_LENGTH], plaintext[PLAINTEXT_BODY_LENGTH:]
  authenticator = CMAC.new(derived_key, ciphermod=AES)
  authenticator.update(did_202 + body)
  if not hmac.compare_digest(supplied_cmac, authenticator.digest()):
    raise PayloadError("payload CMAC verification failed")
  if binascii.crc32(body) != 0xFFFFFFFF:
    raise PayloadError("payload CRC-32 residue verification failed")
  address, size = struct.unpack_from("<II", body, DESCRIPTOR_OFFSET)
  if address != TARGET.ram_address or size != PLAINTEXT_BODY_LENGTH:
    raise PayloadError("payload memory descriptor is invalid")
  if struct.unpack_from("<I", body, SHELLCODE_LIMIT)[0] != TARGET.ram_address:
    raise PayloadError("payload jump address is invalid")
  return plaintext


def random_did_202() -> bytes:
  return secrets.token_bytes(16)
