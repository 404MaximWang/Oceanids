"""Filesystem helpers: atomic text writes (temp file + os.replace)."""

import os
import tempfile
from pathlib import Path


def atomic_write_text(path: Path, content: str) -> Path:
    """Write ``content`` to ``path`` atomically: readers never see a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return path
