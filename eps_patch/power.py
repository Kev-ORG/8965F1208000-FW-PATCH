"""Operator checkpoint for a complete vehicle/EPS power cycle."""

from __future__ import annotations

from collections.abc import Callable


Checkpoint = Callable[[str], object]


def request_power_cycle(
  current_state: str,
  next_state: str,
  checkpoint: Checkpoint,
) -> None:
  """Block for Enter after a prominent bilingual complete-cycle instruction."""
  if not isinstance(current_state, str) or not current_state:
    raise ValueError("current power-cycle state must be non-empty text")
  if not isinstance(next_state, str) or not next_state:
    raise ValueError("next power-cycle state must be non-empty text")
  if not callable(checkpoint):
    raise TypeError("power-cycle checkpoint must be callable")
  prompt = (
    "\n========== COMPLETE EPS POWER CYCLE / EPS 完全断电重启 ==========\n"
    f"{current_state} -> {next_state}\n"
    "请关闭车辆/EPS 电源，等待完全放电，再恢复稳定电源。\n"
    "Switch off vehicle/EPS power, wait for complete discharge, then restore "
    "stable power. A UDS reset is not a substitute.\n"
    "完成后按 Enter / Press Enter only after the complete power cycle: "
  )
  checkpoint(prompt)


__all__ = ["request_power_cycle"]
