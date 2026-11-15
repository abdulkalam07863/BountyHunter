from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..util import have_tool, log, run_cmd, short_hash

SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
       "informational": "info", "info": "info", "optimization": "info"}


def _norm(s):
    return SEV.get(str(s or "").lower(), "medium")


def _f(title, sev, tool, **kw):
    return {"title": title, "severity": _norm(sev), "confidence": kw.get("confidence", "medium"),
            "category": kw.get("category", "solidity"), "cwe": kw.get("cwe"),
            "file": kw.get("file"), "line": kw.get("line"), "code": kw.get("code"),
            "detail": kw.get("detail", ""), "remediation": kw.get("remediation", ""),
            "tool": tool, "economic": kw.get("economic", 2), "references": kw.get("references", []),
            "fingerprint": short_hash(f"{tool}:{kw.get('file')}:{kw.get('line')}:{title}")}


def forge_build(repo: Path, cfg):
    if not have_tool("forge"):
        return [], {"tool": "forge-build", "status": "missing"}
    if cfg.solidity.get("install_foundry_deps", True):
        run_cmd(["forge", "install", "foundry-rs/forge-std", "--no-commit"], cwd=repo, timeout=900)
    res = run_cmd(["forge", "build", "--sizes"], cwd=repo, timeout=int(cfg.audit.get("tool_timeout", 1800)))
    findings = []
    if not res["ok"]:
        findings.append(_f("Compilation failure", "high", "forge-build", category="build",
                           detail=(res["err"] or res["out"])[:1500], economic=1))
    return findings, {"tool": "forge-build", "status": "ok" if res["ok"] else f"rc={res['rc']}",
                      "dur": res["dur"], "err": (res["err"] or "")[:400]}


def slither(repo: Path, cfg):
    if not have_tool("slither"):
        return [], {"tool": "slither", "status": "missing"}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out = tf.name
    cmd = ["slither", ".", "--json", out,
           "--filter-paths", "mocks|test|lib|interfaces|node_modules",
           "--compile-force-framework", "foundry"]
    if cfg.solidity.get("slither_detectors"):
        cmd += ["--detect", cfg.solidity["slither_detectors"]]
    res = run_cmd(cmd, cwd=repo, timeout=int(cfg.audit.get("tool_timeout", 2400)))
    findings = []
    try:
        data = json.loads(Path(out).read_text(encoding="utf-8", errors="replace") or "{}")
        for d in (data.get("results", {}) or {}).get("detectors", []):
            el = (d.get("elements") or [{}])[0]
            sm = el.get("source_mapping", {})
            findings.append(_f(d.get("check", "slither"), d.get("impact"), "slither",
                               confidence=(d.get("confidence") or "medium").lower(),
                               cwe=(d.get("cwe") or "") or None,
                               file=sm.get("filename_relative"),
                               line=(sm.get("lines") or [None])[0],
                               detail=d.get("description", "")[:1500]))
    except Exception as exc:
        log.warning("slither parse: %s", exc)
    finally:
        Path(out).unlink(missing_ok=True)
    return findings, {"tool": "slither", "status": "ok" if res["ok"] else f"rc={res['rc']}",
                      "dur": res["dur"], "err": (res["err"] or "")[:400]}


def aderyn(repo: Path, cfg):
    if not have_tool("aderyn"):
        return [], {"tool": "aderyn", "status": "missing"}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out = tf.name
    res = run_cmd(["aderyn", "-o", out, "."], cwd=repo, timeout=int(cfg.audit.get("tool_timeout", 1800)))
    findings = []
    try:
        data = json.loads(Path(out).read_text(encoding="utf-8", errors="replace") or "{}")
        for d in (data.get("high_issues", {}).get("issues", [])
                  + data.get("medium_issues", {}).get("issues", [])
                  + data.get("low_issues", {}).get("issues", [])):
            findings.append(_f(d.get("title", "aderyn"), d.get("severity"), "aderyn",
                               file=d.get("contract_path"), line=d.get("line_no"),
                               detail=d.get("description", "")[:1200],
                               remediation=d.get("remediation", "")))
    except Exception as exc:
        log.warning("aderyn parse: %s", exc)
    finally:
        Path(out).unlink(missing_ok=True)
    return findings, {"tool": "aderyn", "status": "ok", "dur": res["dur"]}


def mythril(repo: Path, cfg):
    if not have_tool("myth"):
        return [], {"tool": "mythril", "status": "missing"}
    findings, dur = [], 0.0
    for sol in list(repo.rglob("*.sol"))[:25]:
        if any(p in {"mocks", "test", "lib"} for p in sol.parts):
            continue
        res = run_cmd(["myth", "analyze", str(sol), "-o", "json", "--execution-timeout", "120"],
                      cwd=repo, timeout=400)
        dur += res["dur"]
        try:
            for issue in json.loads(res["out"] or "{}").get("issues", []):
                findings.append(_f(issue.get("title", "mythril"), issue.get("severity"), "mythril",
                                   file=str(sol.relative_to(repo)),
                                   detail=issue.get("description", "")[:900],
                                   remediation=issue.get("remediation", "")))
        except Exception:
            continue
    return findings, {"tool": "mythril", "status": "ok", "dur": round(dur, 1)}


def echidna(repo: Path, cfg):
    if not have_tool("echidna"):
        return [], {"tool": "echidna", "status": "missing"}
    contracts = [p for p in repo.rglob("*.sol") if "test" in p.name.lower()]
    if not contracts:
        return [], {"tool": "echidna", "status": "skipped: no property tests"}
    res = run_cmd(["echidna", str(contracts[0]), "--contract", contracts[0].stem,
                   "--test-limit", "50000"], cwd=repo, timeout=1800)
    findings = [_f(f"Property violated: {l.strip()[:120]}", "high", "echidna",
                   category="invariant", file=contracts[0].name, detail=l.strip(), economic=3)
                for l in res["out"].splitlines() if "failed!" in l.lower()]
    return findings, {"tool": "echidna", "status": "ok", "dur": res["dur"]}


RUNNERS = {"slither": slither, "aderyn": aderyn, "mythril": mythril,
           "forge_build": forge_build, "echidna": echidna}
