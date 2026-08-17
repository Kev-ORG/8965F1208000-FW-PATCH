"""Atomic primitives retained for fixed comma-local evidence files."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path


class ArtifactError(RuntimeError):
  pass


def sha256_bytes(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()


def _atomic_create(path: Path, content: bytes) -> None:
  """Install one immutable file and synchronise its containing directory."""
  path.parent.mkdir(parents=True, exist_ok=True)
  if path.exists():
    raise ArtifactError(f"artifact already exists: {path}")
  fd, temp_name = tempfile.mkstemp(
    prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
  )
  try:
    with os.fdopen(fd, "wb") as stream:
      stream.write(content)
      stream.flush()
      os.fsync(stream.fileno())
    try:
      os.link(temp_name, path)
    except FileExistsError as exc:
      raise ArtifactError(f"artifact already exists: {path}") from exc
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
      os.fsync(directory_fd)
    finally:
      os.close(directory_fd)
  finally:
    try:
      os.unlink(temp_name)
    except FileNotFoundError:
      pass
