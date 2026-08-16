"""Exact two-sector candidate construction for the RX patch and CRC residue."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .manifest import TARGET, TargetManifest


@dataclass(frozen=True, slots=True)
class CrcCandidate:
  target_source: bytes
  target_final: bytes
  crc_source: bytes
  crc_final: bytes
  old_adjustment: bytes
  new_adjustment: bytes
  absolute_diffs: tuple[tuple[int, int, int], ...]


def crc32_adjustment(prefix_crc: int) -> bytes:
  """Return the little-endian word that completes the CRC-32 residue."""
  if isinstance(prefix_crc, bool) or not isinstance(prefix_crc, int) or not 0 <= prefix_crc <= 0xFFFFFFFF:
    raise ValueError("prefix CRC must be one unsigned 32-bit value")
  return struct.pack("<I", prefix_crc ^ 0xFFFFFFFF)


def _require_sector(sector: bytes, *, name: str, target: TargetManifest) -> None:
  if not isinstance(sector, bytes) or len(sector) != target.sector_length:
    raise ValueError(f"{name} must contain exactly {target.sector_length} bytes")


def build_crc_candidate(
  target_sector: bytes,
  crc_sector: bytes,
  candidate_adjustment: bytes,
  target: TargetManifest = TARGET,
) -> CrcCandidate:
  """Apply the sole RX-state byte and the CRC adjustment word to copied sectors."""
  target.validate()
  _require_sector(target_sector, name="target sector", target=target)
  _require_sector(crc_sector, name="CRC sector", target=target)
  if not isinstance(candidate_adjustment, bytes) or len(candidate_adjustment) != 4:
    raise ValueError("CRC adjustment must contain exactly four bytes")
  if target_sector[target.instruction_offset:target.instruction_offset + 4] != target.original_instruction:
    raise ValueError("target sector instruction context does not match the exact original")

  target_final = bytearray(target_sector)
  target_final[target.patch_offset] = target.patched_instruction[2]
  crc_final = bytearray(crc_sector)
  adjustment_offset = target.crc_adjust_offset
  old_adjustment = bytes(crc_final[adjustment_offset:adjustment_offset + 4])
  crc_final[adjustment_offset:adjustment_offset + 4] = candidate_adjustment

  absolute_diffs = tuple(
    (base + offset, before, after)
    for source, final, base in (
      (target_sector, target_final, target.sector_base),
      (crc_sector, crc_final, target.crc_sector_base),
    )
    for offset, (before, after) in enumerate(zip(source, final))
    if before != after
  )
  return CrcCandidate(
    target_source=target_sector,
    target_final=bytes(target_final),
    crc_source=crc_sector,
    crc_final=bytes(crc_final),
    old_adjustment=old_adjustment,
    new_adjustment=candidate_adjustment,
    absolute_diffs=absolute_diffs,
  )
