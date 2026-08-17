def test_power_cycle_uses_bilingual_restart_instruction():
  from eps_patch.power import request_power_cycle

  prompts = []

  request_power_cycle("TARGET_COMMITTED", "CRC_PRECHECKED", prompts.append)

  assert len(prompts) == 1
  prompt = prompts[0]
  assert "断电" in prompt
  assert "power" in prompt.lower()
  assert "UDS reset" in prompt
  assert "TARGET_COMMITTED -> CRC_PRECHECKED" in prompt


def test_power_cycle_output_callback_may_return_empty_text():
  from eps_patch.power import request_power_cycle

  prompts = []

  result = request_power_cycle("PROBED", "TARGET_PRECHECKED", lambda prompt: prompts.append(prompt) or "")

  assert result is None
  assert len(prompts) == 1


def test_power_cycle_checkpoint_round_trips_only_the_exact_schema():
  import pytest

  from eps_patch.power import PowerCycleCheckpoint

  checkpoint = PowerCycleCheckpoint("PROBED", "TARGET_PRECHECKED")

  assert PowerCycleCheckpoint.from_dict(checkpoint.as_dict()) == checkpoint
  with pytest.raises(ValueError, match="exact schema"):
    PowerCycleCheckpoint.from_dict({**checkpoint.as_dict(), "extra": True})


def test_power_cycle_instruction_exits_instead_of_waiting_for_enter():
  """Restoring an Enter prompt would make restart-resume impossible."""
  from eps_patch.power import request_power_cycle

  prompts = []

  request_power_cycle("PROBED", "TARGET_PRECHECKED", prompts.append)

  assert len(prompts) == 1
  assert "Press Enter" not in prompts[0]
  assert "按 Enter" not in prompts[0]
  assert "rerun the same command" in prompts[0]
