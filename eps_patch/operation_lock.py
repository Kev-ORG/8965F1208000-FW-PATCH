"""One process-wide lock shared by patch and restore hardware workflows."""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager

from .paths import ArtifactLayout


class OperationBusyError(RuntimeError):
  """Another patch or restore process currently owns the hardware workflow."""


def _fsync_directory(path) -> None:
  descriptor = os.open(path, os.O_RDONLY)
  try:
    os.fsync(descriptor)
  finally:
    os.close(descriptor)


@contextmanager
def exclusive_operation(layout: ArtifactLayout, workflow: str):
  """Hold one nonblocking advisory lock for a complete hardware workflow."""
  if not isinstance(layout, ArtifactLayout):
    raise TypeError("operation lock layout must be an ArtifactLayout")
  if type(workflow) is not str or not workflow:
    raise TypeError("operation lock workflow must be non-empty text")
  root_existed = layout.root.exists()
  layout.root.mkdir(parents=True, exist_ok=True)
  if not root_existed:
    _fsync_directory(layout.root.parent)
  lock_path = layout.root / ".operation.lock"
  lock_existed = lock_path.exists()
  descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
  try:
    if not lock_existed:
      os.fsync(descriptor)
      _fsync_directory(layout.root)
    try:
      fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
      raise OperationBusyError(
        "another patch or restore operation is already running"
      ) from exc
    try:
      yield
    finally:
      fcntl.flock(descriptor, fcntl.LOCK_UN)
  finally:
    os.close(descriptor)


__all__ = ["OperationBusyError", "exclusive_operation"]
