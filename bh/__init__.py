import os as _os
from pathlib import Path as _Path


def _load_env() -> None:
    for base in (_Path(__file__).resolve().parent.parent, _Path.cwd()):
        f = base / ".env"
        if not f.is_file():
            continue
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            if k.startswith("export "):
                k = k[7:].strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in _os.environ:
                _os.environ[k] = v


_load_env()