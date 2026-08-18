import hashlib
from dataclasses import replace

import pytest

from eps_patch.crc import build_crc_candidate
from eps_patch.manifest import TARGET


def _sectors():
  target_source = bytearray([0xA5]) * TARGET.sector_length
  target_source[TARGET.instruction_offset:TARGET.instruction_offset + 4] = (
    TARGET.original_instruction
  )
  crc_source = bytearray([0x5A]) * TARGET.sector_length
  crc_source[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] = (
    TARGET.crc_original_adjust_word.to_bytes(4, "little")
  )
  magic_offset = TARGET.magic_addresses[1] - TARGET.crc_sector_base
  crc_source[magic_offset:magic_offset + 4] = TARGET.magic_word.to_bytes(4, "little")
  return bytes(target_source), bytes(crc_source)


def test_two_sector_candidate_keeps_fixed_direction_and_exact_diff_set():
  target_source, crc_source = _sectors()
  target_candidate = bytearray(target_source)
  target_candidate[TARGET.patch_offset] = TARGET.patched_instruction[3]
  target = replace(
    TARGET,
    original_sha256=hashlib.sha256(target_source).hexdigest(),
    patched_sha256=hashlib.sha256(target_candidate).hexdigest(),
  )

  candidate = build_crc_candidate(
    target_source,
    crc_source,
    target.crc_patched_adjust_word.to_bytes(4, "little"),
    target=target,
  )

  assert candidate.target_final == bytes(target_candidate)
  assert candidate.target_final[TARGET.instruction_offset:TARGET.instruction_offset + 4] == (
    TARGET.patched_instruction
  )
  assert candidate.crc_final[TARGET.crc_adjust_offset:TARGET.crc_adjust_offset + 4] == (
    TARGET.crc_patched_adjust_word.to_bytes(4, "little")
  )
  assert tuple(address for address, _before, _after in candidate.absolute_diffs) == (
    TARGET.patch_address,
    TARGET.crc_adjust_address,
    TARGET.crc_adjust_address + 1,
    TARGET.crc_adjust_address + 2,
    TARGET.crc_adjust_address + 3,
  )


def test_target_precheck_rejects_software_hardware_crc_disagreement(tmp_path):
  from eps_patch.evidence import load_probe_pass
  from eps_patch.patch import PatchError, _candidate_from_probe, _validate_target_precheck
  from eps_patch.paths import ArtifactLayout
  from eps_patch.protocol import OP_CRC_PROBE
  from test_patch import OLD_ADJUSTMENT, _case, _crc_result, _observation

  layout = ArtifactLayout(tmp_path)
  target, _identity, target_source, crc_source, target_candidate, crc_candidate = _case(layout)
  candidate = _candidate_from_probe(load_probe_pass(layout, target), target)
  observation = replace(
    _observation(
      old_adjustment=OLD_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
    ),
    original_dcra_raw=0,
  )

  with pytest.raises(PatchError, match="CRC/software/DCRA"):
    _validate_target_precheck(
      _crc_result(OP_CRC_PROBE, target_source, crc_source, observation),
      candidate,
      target,
    )


def test_final_verify_rejects_any_nonresidue_dcra_result(tmp_path):
  from eps_patch.evidence import load_probe_pass
  from eps_patch.patch import PatchError, _candidate_from_probe, _validate_final_verify
  from eps_patch.paths import ArtifactLayout
  from eps_patch.protocol import OP_VERIFY_CRC
  from test_patch import NEW_ADJUSTMENT, _case, _crc_result, _observation

  layout = ArtifactLayout(tmp_path)
  target, _identity, _target_source, _crc_source, target_candidate, crc_candidate = _case(layout)
  candidate = _candidate_from_probe(load_probe_pass(layout, target), target)
  observation = replace(
    _observation(
      old_adjustment=NEW_ADJUSTMENT,
      target_candidate=target_candidate,
      crc_candidate=crc_candidate,
      final=True,
    ),
    patched_dcra_raw=0,
  )

  with pytest.raises(PatchError, match="CRC/software/DCRA"):
    _validate_final_verify(
      _crc_result(OP_VERIFY_CRC, target_candidate, crc_candidate, observation),
      candidate,
      target,
    )
