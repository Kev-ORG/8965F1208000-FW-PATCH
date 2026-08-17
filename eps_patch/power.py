"""Operator checkpoint for a complete vehicle/EPS power cycle."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


Checkpoint = Callable[[str], object]


@dataclass(frozen=True, slots=True)
class PowerCycleCheckpoint:
  """One explicit, durable successor authorized by a manual power cycle."""

  completed_state: str
  next_state: str

  def __post_init__(self) -> None:
    if not isinstance(self.completed_state, str) or not self.completed_state:
      raise ValueError("completed power-cycle state must be non-empty text")
    if not isinstance(self.next_state, str) or not self.next_state:
      raise ValueError("next power-cycle state must be non-empty text")

  def as_dict(self) -> dict[str, str]:
    return {
      "completed_state": self.completed_state,
      "next_state": self.next_state,
    }

  @classmethod
  def from_dict(cls, value: object) -> PowerCycleCheckpoint:
    if type(value) is not dict or set(value) != {"completed_state", "next_state"}:
      raise ValueError("power-cycle checkpoint does not have the exact schema")
    return cls(
      completed_state=value["completed_state"],
      next_state=value["next_state"],
    )


def request_power_cycle(
  current_state: str,
  next_state: str,
  checkpoint: Checkpoint,
) -> None:
  """Emit a prominent bilingual complete-cycle instruction without blocking."""
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
    "完成后让 comma 重新启动，再重新运行同一命令。\n"
    "After comma restarts, rerun the same command.\n"
  )
  checkpoint(prompt)


__all__ = ["PowerCycleCheckpoint", "request_power_cycle"]
