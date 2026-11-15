"""Repository acquisition.

Full blobless clone - no sparse checkout - so cross-directory Solidity
imports resolve. Re-running over an existing checkout updates in place
instead of dying on 'destination path already exists'.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

RETRIES = 3


class CloneError(RuntimeError):
    """Raised when a repository cannot be acquired."""


def _git(*args, cwd=None):
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _quarantine(dest: Path) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest.rename(dest.with_name(f"{dest.name}.bak-{stamp}"))


def _default_ref(dest: Path):
    ref = _git(
        "-C", str(dest), "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"
    ).stdout.strip()
    if ref:
        return ref.replace("refs/remotes/", "")
    for cand in ("origin/main", "origin/master"):
        if _git("-C", str(dest), "rev-parse", "--verify", "--quiet", cand).returncode == 0:
            return cand
    out = _git(
        "-C", str(dest), "for-each-ref", "--format=%(refname:short)",
        "refs/remotes/origin",
    ).stdout.split()
    return out[0] if out else None

def _bootstrap(dest: Path) -> None:
    if (dest / "package.json").is_file() and not (dest / "node_modules").is_dir():
        npm = shutil.which("npm")
        if not npm:
            print(f"WARN {dest.name}: package.json but no npm - build will fail")
            return
        print(f"installing npm deps for {dest.name} (one-time)")
        subprocess.run(
            [npm, "install", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=dest, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
    mods = dest / "node_modules"
    if mods.is_dir():
        maps = [
            f"{s}/=node_modules/{s}/\n"
            for s in ("@openzeppelin", "@uniswap", "@chainlink", "@balancer-labs")
            if (mods / s).is_dir()
        ]
        if maps:
            (dest / "remappings.txt").write_text("".join(maps), encoding="utf-8")
    if not shutil.which("vyper"):
        print(f"NOTE {dest.name}: vyper not on PATH - Vyper sources will not compile")

def _update(dest: Path, branch=None) -> None:
    _git("-C", str(dest), "config", "core.sparseCheckout", "false")
    _git("-C", str(dest), "sparse-checkout", "disable")
    f = _git("-C", str(dest), "fetch", "--all", "--prune", "--tags")
    if f.returncode != 0:
        print(f"WARN {dest.name}: fetch failed: {f.stderr.strip()[:200]}")
    target = branch or _default_ref(dest)
    if not target:
        raise CloneError(f"{dest.name}: cannot resolve a default branch")
    if not target.startswith("origin/"):
        target = f"origin/{target}"
    r = _git("-C", str(dest), "reset", "--hard", target)
    if r.returncode != 0:
        print(f"WARN {dest.name}: reset to {target} failed: {r.stderr.strip()[:200]}")
        _git("-C", str(dest), "checkout", "-f", target)
    _git("-C", str(dest), "clean", "-fdx")
    if not any(dest.rglob("*.sol")):
        print(f"WARN {dest.name}: no .sol files after update - checkout incomplete")


def clone_repo(url: str, branch=None, dest=None) -> Path:
    if dest is None:
        dest, branch = branch, None
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        if (dest / ".git").is_dir():
            _update(dest, branch)
            return dest
        if any(dest.iterdir()):
            _quarantine(dest)
        else:
            dest.rmdir()

    args = ["clone", "--filter=blob:none"]
    if branch:
        args += ["--branch", branch]
    args += [url, str(dest)]

    last = None
    for attempt in range(1, RETRIES + 1):
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        r = _git(*args)
        if r.returncode == 0:
            return dest
        last = r
        time.sleep(2 * attempt)

    detail = ((last.stderr or last.stdout) if last else "").strip()[:800]
    raise CloneError(f"clone failed after {RETRIES} attempts: {url}\n{detail}")


def sparse_clone(url: str, dest, paths=None) -> Path:
    """Compat alias - sparse paths are filtered at scan time now."""
    return clone_repo(url, None, dest)