import pytest


def test_candidate_writer_image_contains_only_local_candidate_authorization():
  from eps_patch.candidate_writer import CandidateWriterPayloadImage

  fields = CandidateWriterPayloadImage.__dataclass_fields__
  assert "staged_candidate" not in fields
  assert "staged_candidate_sha256" not in fields
  assert {"operation", "sector_base", "intent", "payload"} <= set(fields)


def test_candidate_writer_locks_the_corrected_crc_adjustment_word():
  from eps_patch.candidate_writer import CANDIDATE_ADJUSTMENT

  assert CANDIDATE_ADJUSTMENT == bytes.fromhex("cc474f41")


@pytest.mark.parametrize("operation", (13, 14))
def test_every_writer_fault_boundary_is_one_shot_and_never_passes(operation):
  from eps_patch.candidate_writer import (
    all_candidate_writer_fault_boundaries,
    run_candidate_writer_fault_model,
  )

  expected_base = 0x60000 if operation == 13 else 0xF8000
  other_base = 0xF8000 if operation == 13 else 0x60000
  boundaries = all_candidate_writer_fault_boundaries()
  assert "program:0" in boundaries and "program:127" in boundaries
  assert {
    "intent", "reserved", "fixed-base", "sram", "candidate-crc",
    "live-target-crc", "live-crc-sector-crc", "source-context",
    "candidate-context", "idle-entry",
  } <= set(boundaries)
  for boundary in boundaries:
    result = run_candidate_writer_fault_model(operation=operation, failure=boundary)
    assert result.final_result != "PASS"
    assert result.erase_counts[expected_base] <= 1
    assert result.erase_counts[other_base] == 0
    assert result.programmed_bases <= frozenset((expected_base,))
    assert result.attempts == 1
    assert result.retries == 0


@pytest.mark.parametrize("bad_operation", (True, False, 13.0, 12, 15))
def test_fault_model_rejects_nonexact_writer_operation(bad_operation):
  from eps_patch.candidate_writer import run_candidate_writer_fault_model

  with pytest.raises((TypeError, ValueError)):
    run_candidate_writer_fault_model(operation=bad_operation, failure="precheck")


def test_host_interruption_policy_defaults_to_recovery_and_never_forward_resume():
  from eps_patch.candidate_writer import classify_interruption

  assert classify_interruption(
    stage="target", target_state="candidate", crc_state="source",
  ) == ("RECOVERY_REQUIRED", ("restore-target-source",))
  assert classify_interruption(
    stage="crc-ambiguous", target_state="candidate", crc_state="unknown",
  ) == ("INDETERMINATE", ("classify-read-only",))
  assert classify_interruption(
    stage="crc-ambiguous", target_state="candidate", crc_state="candidate",
  ) == ("VERIFY_PENDING", ("final-read-only-verify",))


@pytest.mark.parametrize(
  "arguments",
  (
    {"stage": "target", "target_state": "unknown", "crc_state": "source"},
    {"stage": "crc-ambiguous", "target_state": "unknown", "crc_state": "unknown"},
  ),
)
def test_unknown_interruption_state_remains_indeterminate(arguments):
  from eps_patch.candidate_writer import classify_interruption

  state, actions = classify_interruption(**arguments)
  assert state == "INDETERMINATE"
  assert "forward" not in " ".join(actions)


@pytest.mark.parametrize(
  ("target_state", "crc_state", "expected"),
  (
    ("candidate", "candidate", ("VERIFY_PENDING", ("final-read-only-verify",))),
    ("candidate", "source", ("RECOVERY_REQUIRED", ("restore-target-source",))),
    ("candidate", "other", ("RECOVERY_REQUIRED", ("restore-crc-source", "restore-target-source"))),
    ("source", "candidate", ("RECOVERY_REQUIRED", ("restore-crc-source",))),
    ("source", "source", ("RECOVERY_COMPLETE", ())),
    ("source", "other", ("RECOVERY_REQUIRED", ("restore-crc-source",))),
    ("other", "candidate", ("RECOVERY_REQUIRED", ("restore-crc-source", "restore-target-source"))),
    ("other", "source", ("RECOVERY_REQUIRED", ("restore-target-source",))),
    ("other", "other", ("RECOVERY_REQUIRED", ("restore-crc-source", "restore-target-source"))),
  ),
)
def test_known_crc_ambiguity_state_matrix_never_forward_resumes(
  target_state, crc_state, expected,
):
  from eps_patch.candidate_writer import classify_interruption

  result = classify_interruption(
    stage="crc-ambiguous", target_state=target_state, crc_state=crc_state,
  )
  assert result == expected
  assert "forward" not in " ".join(result[1])


@pytest.mark.parametrize(
  ("target_state", "crc_state"),
  (
    ("unknown", "source"), ("unknown", "candidate"), ("unknown", "other"),
    ("source", "unknown"), ("candidate", "unknown"), ("other", "unknown"),
    ("unknown", "unknown"),
  ),
)
def test_any_unknown_sector_state_is_indeterminate(target_state, crc_state):
  from eps_patch.candidate_writer import classify_interruption

  state, actions = classify_interruption(
    stage="crc-ambiguous", target_state=target_state, crc_state=crc_state,
  )
  assert state == "INDETERMINATE"
  assert actions == ("classify-read-only",)


def test_recovery_order_is_crc_source_before_target_source_when_both_are_needed():
  from eps_patch.candidate_writer import recovery_actions_for_states

  assert recovery_actions_for_states(
    target_state="other", crc_state="other",
  ) == ("restore-crc-source", "restore-target-source")
