def test_power_cycle_uses_bilingual_enter_checkpoint():
  from eps_patch.power import request_power_cycle

  prompts = []

  request_power_cycle("TARGET_COMMITTED", "CRC_PRECHECKED", prompts.append)

  assert len(prompts) == 1
  prompt = prompts[0]
  assert "断电" in prompt
  assert "power" in prompt.lower()
  assert "UDS reset" in prompt
  assert "TARGET_COMMITTED -> CRC_PRECHECKED" in prompt


def test_power_cycle_checkpoint_accepts_enter_without_a_phrase():
  from eps_patch.power import request_power_cycle

  prompts = []

  result = request_power_cycle("PROBED", "TARGET_PRECHECKED", lambda prompt: prompts.append(prompt) or "")

  assert result is None
  assert len(prompts) == 1
