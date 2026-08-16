"""Fail-closed host checks performed before opening Panda hardware."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Sequence


class PreflightError(RuntimeError):
  pass


@dataclass(frozen=True, slots=True)
class Check:
  name: str
  ok: bool
  detail: str


@dataclass(frozen=True, slots=True)
class PreflightResult:
  items: tuple[Check, ...]

  @property
  def ok(self) -> bool:
    return all(item.ok for item in self.items)


Runner = Callable[[list[str]], object]
ImportChecker = Callable[[str], bool]


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
  return subprocess.run(command, capture_output=True, text=True, check=False)


def _default_import_available(name: str) -> bool:
  try:
    return importlib.util.find_spec(name) is not None
  except ModuleNotFoundError:
    return False


def run_preflight(
  *,
  version_info: Sequence[int] = sys.version_info,
  runner: Runner = _default_runner,
  import_available: ImportChecker = _default_import_available,
) -> PreflightResult:
  items: list[Check] = []
  version = tuple(version_info[:3])
  version_ok = (3, 12, 3) <= version < (3, 13, 0)
  items.append(Check("python", version_ok, ".".join(str(v) for v in version_info[:3])))
  if not version_ok:
    raise PreflightError("hardware commands require openpilot Python 3.12.3 or newer and <3.13")

  for dependency in ("panda", "opendbc.car.uds", "opendbc.car.isotp", "Crypto.Cipher.AES"):
    available = import_available(dependency)
    items.append(Check(f"import:{dependency}", available, "available" if available else "missing"))
    if not available:
      raise PreflightError(f"required dependency is missing: {dependency}")

  commands = (
    (["tmux", "has-session", "-t", "comma"], "comma tmux session"),
    (["pidof", "pandad"], "native pandad"),
    (["pgrep", "-f", r"selfdrive\.pandad\.pandad"], "Python pandad wrapper"),
  )
  for command, label in commands:
    try:
      result = runner(command)
    except FileNotFoundError as exc:
      raise PreflightError(f"required process-check tool is missing: {command[0]}") from exc
    try:
      returncode = int(getattr(result, "returncode"))
    except (AttributeError, TypeError, ValueError) as exc:
      raise PreflightError(f"{label} process check result is indeterminate") from exc
    stdout = str(getattr(result, "stdout", ""))
    if returncode not in (0, 1) or (returncode == 1 and stdout.strip()):
      raise PreflightError(
        f"{label} process check is indeterminate (return code {returncode})"
      )
    running = returncode == 0
    items.append(Check(label, not running, "running" if running else "not running"))
    if running:
      raise PreflightError(
        f"{label} is still running; run `tmux kill-session -t comma`, then verify "
        "both `pidof pandad` and `pgrep -f selfdrive.pandad.pandad` return no process"
      )
  return PreflightResult(tuple(items))
