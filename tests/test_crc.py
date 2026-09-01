import binascii
from dataclasses import replace

import pytest


def test_crc_adjustment_produces_reference_residue():
  """A wrong residue transform must not produce the bootloader's CRC sentinel."""
  from eps_patch.crc import crc32_adjustment

  prefix = b"live-prefix"
  adjustment = crc32_adjustment(binascii.crc32(prefix))

  assert adjustment == bytes.fromhex("a70eef74")
  assert binascii.crc32(prefix + adjustment) == 0xFFFFFFFF


def test_candidate_changes_only_rx_byte_and_crc_word():
  """Candidate construction must preserve all bytes except the planned five writes."""
  from eps_patch.crc import build_crc_candidate

  target = bytearray(0x8000)
  target[0x0C60:0x0C64] = bytes.fromhex("1d 30 e0 d1")
  crc = bytearray([0xA5]) * 0x8000
  crc[0x7E00:0x7E04] = (0x5AA5A55A).to_bytes(4, "little")
  crc[0x7DEC:0x7DF0] = bytes.fromhex("0cd759ad")

  result = build_crc_candidate(bytes(target), bytes(crc), bytes.fromhex("77145fdd"))

  assert result.target_final[0x0C63] == 0x01
  assert result.crc_final[0x7DEC:0x7DF0] == bytes.fromhex("77145fdd")
  assert result.absolute_diffs == (
    (0x88C63, 0xD1, 0x01),
    (0xFFDEC, 0x0C, 0x77), (0xFFDED, 0xD7, 0x14),
    (0xFFDEE, 0x59, 0x5F), (0xFFDEF, 0xAD, 0xDD),
  )


def test_candidate_rejects_an_invalid_replaced_manifest():
  """An invalid manifest must not redirect the public candidate writes."""
  from eps_patch.crc import build_crc_candidate
  from eps_patch.manifest import TARGET

  target = bytearray(0x8000)
  target[0x0C60:0x0C64] = bytes.fromhex("1d 30 e0 d1")
  invalid_target = replace(TARGET, crc_adjust_address=0xFFDE8)

  with pytest.raises(ValueError, match="CRC adjustment word"):
    build_crc_candidate(bytes(target), bytes(0x8000), bytes(4), target=invalid_target)
