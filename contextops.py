#!/usr/bin/env python3
"""ContextOps: capture a repository's file context into shareable bundles.

The tool walks a target repository and produces two artifacts:
  - context.md   (human-readable)
  - context.json (machine-readable)

Sensitive values (tokens, AWS keys, DB passwords, .env entries) are detected,
highlighted, and REDACTED -- their raw values are never copied into the bundle.
Files explicitly marked confidential ("do not ingest") and binary assets are
excluded, with the reason recorded.

Output is written to a simulated S3 layout (a local folder stands in for the
bucket for now), never inside the scanned repository:

  <out>/context_<project>/<pushed-by-user>_<UTC-datetime>/{context.md,context.json}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone

TOOL_VERSION = "1.0.0"

# Files/dirs that are never part of the captured context.
SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".idea", ".vscode"}

# Extensions treated as binary assets (excluded from content capture).
BINARY_EXTENSIONS = {
    ".bin", ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".class", ".pyc",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".jar",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".woff", ".woff2", ".ttf",
    ".xlsx", ".xls", ".docx", ".pptx",
}

# Map of file extension -> markdown fence language hint.
LANGUAGE_BY_EXT = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".tsx": "tsx", ".jsx": "jsx", ".java": "java", ".go": "go",
    ".rb": "ruby", ".rs": "rust", ".c": "c", ".cpp": "cpp", ".h": "c",
    ".cs": "csharp", ".php": "php", ".sh": "bash", ".bash": "bash",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".toml": "toml",
    ".ini": "ini", ".cfg": "ini", ".env": "ini",
    ".md": "markdown", ".html": "html", ".css": "css", ".sql": "sql",
    ".xml": "xml",
}

# Markers that flag a file as confidential / not-for-ingestion.
CONFIDENTIAL_MARKERS = [
    "confidential",
    "do not distribute",
    "not for ingestion",
    "trade secret",
    "do-not-ingest",
]

REDACTED = "***REDACTED***"


# --------------------------------------------------------------------------- #
# Git / pusher metadata
# --------------------------------------------------------------------------- #
def _git(repo: str, *args: str) -> str | None:
    """Run a git command in `repo`; return stripped stdout or None on failure."""
    try:
        out = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def get_pusher(repo: str) -> dict:
    """Return the author of the latest commit (the user who pushed changes)."""
    raw = _git(repo, "log", "-1", "--format=%an|%ae|%ad")
    if not raw or "|" not in raw:
        return {"name": "unknown", "email": "", "date": ""}
    name, email, date = (raw.split("|", 2) + ["", ""])[:3]
    return {"name": name or "unknown", "email": email, "date": date}


def get_commit(repo: str) -> str:
    """Return the short HEAD commit sha, or 'unknown'."""
    return _git(repo, "rev-parse", "--short", "HEAD") or "unknown"


# --------------------------------------------------------------------------- #
# File walking & classification
# --------------------------------------------------------------------------- #
def walk_files(repo: str) -> list[str]:
    """Return repo-relative paths of all files, skipping ignored directories."""
    collected: list[str] = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            abs_path = os.path.join(root, name)
            rel = os.path.relpath(abs_path, repo).replace(os.sep, "/")
            collected.append(rel)
    return sorted(collected)


def language_for(rel_path: str) -> str:
    base = os.path.basename(rel_path)
    if base == ".env" or base.startswith(".env"):
        return "ini"
    _, ext = os.path.splitext(rel_path)
    return LANGUAGE_BY_EXT.get(ext.lower(), "")


def is_binary(abs_path: str) -> bool:
    """Detect binaries by extension, then by sniffing for NUL bytes."""
    _, ext = os.path.splitext(abs_path)
    if ext.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(abs_path, "rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return True
    return b"\x00" in chunk


def find_confidential(text: str) -> str | None:
    """Return the matched confidential marker if present, else None."""
    lowered = text.lower()
    for marker in CONFIDENTIAL_MARKERS:
        if marker in lowered:
            return marker
    return None


# --------------------------------------------------------------------------- #
# Secret detection & redaction
# --------------------------------------------------------------------------- #
# Each entry: (type label, compiled regex). The value to redact must be in a
# named group "val" when present; otherwise the whole match is redacted.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"(?P<val>AKIA[0-9A-Z]{16})")),
    (
        "sentry_dsn",
        re.compile(r"(?P<val>https://[^@\s]+@[^/\s]*ingest\.sentry\.io/\d+)"),
    ),
    (
        "provider_token",
        re.compile(
            r"(?P<val>(?:mvs_live_sk_|sk_live_|sk-|ghp_|xox[baprs]-)"
            r"[A-Za-z0-9_\-]{8,})"
        ),
    ),
    (
        "keyed_secret",
        re.compile(
            r"(?i)(?P<key>api[_-]?token|api[_-]?key|access[_-]?key(?:[_-]?id)?|"
            r"secret(?:[_-]?access[_-]?key)?|client[_-]?secret|password|passwd|"
            r"pwd|token|dsn)"
            r"(?P<sep>\s*[:=]\s*)"
            r"(?P<q>[\"']?)(?P<val>[^\"'\s#][^\"'\n#]*?)(?P=q)\s*$",
            re.MULTILINE,
        ),
    ),
]

# Values that look like placeholders and should not be treated as live secrets.
PLACEHOLDER_VALUES = {"", "null", "none", "changeme", "example", "redacted",
                      "***redacted***", "todo", "xxx", "your-token-here"}


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'").lower()
    return v in PLACEHOLDER_VALUES or v.startswith("${") or v.startswith("<")


def _value_is_secretish(value: str, quoted: bool) -> bool:
    """Decide whether a `key = value` value is a real secret literal.

    Quoted values are treated as literals. Unquoted values must look like a
    credential token (no spaces/brackets/parens) so ordinary code such as
    ``token = get_token()`` is not mistaken for a secret.
    """
    v = value.strip().strip("\"'")
    if not v or _is_placeholder(v):
        return False
    if quoted:
        return True
    if any(c in v for c in "()[]{} \t"):
        return False
    return re.fullmatch(r"[A-Za-z0-9_\-+/=.@:#~]{6,}", v) is not None


def _accept_match(label: str, m: re.Match) -> bool:
    """Whether a regex match should be treated as a secret finding."""
    value = m.group("val")
    if not value or _is_placeholder(value):
        return False
    if label == "keyed_secret":
        return _value_is_secretish(value, bool(m.groupdict().get("q")))
    return True


def scan_secrets(text: str, is_env: bool) -> list[dict]:
    """Return secret findings: list of {type, line, key, preview}.

    `preview` is intentionally non-reversible (only a short masked hint),
    so the findings themselves never leak the secret.
    """
    findings: list[dict] = []
    seen: set[tuple[int, str]] = set()

    def line_of(index: int) -> int:
        return text.count("\n", 0, index) + 1

    for label, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if not _accept_match(label, m):
                continue
            value = m.group("val")
            line = line_of(m.start("val"))
            key = m.groupdict().get("key")
            dedupe = (line, value)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            findings.append(
                {
                    "type": label,
                    "line": line,
                    "key": key,
                    "preview": _mask(value),
                }
            )

    if is_env:
        for i, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if _is_placeholder(value):
                continue
            if any(f["line"] == i for f in findings):
                continue
            findings.append(
                {
                    "type": "env_var",
                    "line": i,
                    "key": key.strip(),
                    "preview": _mask(value.strip()),
                }
            )

    findings.sort(key=lambda f: (f["line"], f["type"]))
    return findings


def _mask(value: str) -> str:
    """Produce a short, non-reversible hint for a secret value."""
    v = value.strip().strip("\"'")
    if len(v) <= 4:
        return "*" * len(v)
    return f"{v[:2]}{'*' * 6}{v[-2:]} (len={len(v)})"


def redact(text: str, is_env: bool) -> str:
    """Replace detected secret values with the REDACTED marker, keeping keys."""
    redacted = text

    for label, pattern in SECRET_PATTERNS:
        def _sub(m: re.Match, _label: str = label) -> str:
            if not _accept_match(_label, m):
                return m.group(0)
            return m.group(0).replace(m.group("val"), REDACTED)

        redacted = pattern.sub(_sub, redacted)

    if is_env:
        out_lines = []
        for raw in redacted.splitlines():
            stripped = raw.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key, _, value = raw.partition("=")
                if not _is_placeholder(value) and REDACTED not in value:
                    raw = f"{key}={REDACTED}"
            out_lines.append(raw)
        redacted = "\n".join(out_lines)
        if text.endswith("\n"):
            redacted += "\n"

    return redacted


# --------------------------------------------------------------------------- #
# Model assembly
# --------------------------------------------------------------------------- #
def build_file_record(repo: str, rel_path: str) -> dict:
    abs_path = os.path.join(repo, rel_path)
    try:
        size = os.path.getsize(abs_path)
    except OSError:
        size = 0

    record = {
        "path": rel_path,
        "language": language_for(rel_path),
        "status": "included",
        "reason": None,
        "sha256": None,
        "size_bytes": size,
        "secret_findings": [],
        "content": None,
    }

    # Binary assets: excluded, content not captured.
    if is_binary(abs_path):
        record["status"] = "excluded"
        record["reason"] = "binary"
        record["sha256"] = _sha256_file(abs_path)
        return record

    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        record["status"] = "excluded"
        record["reason"] = f"unreadable: {exc}"
        return record

    record["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()

    # Confidential / do-not-ingest files: excluded, content withheld.
    marker = find_confidential(text)
    if marker:
        record["status"] = "excluded"
        record["reason"] = f'confidential (marker: "{marker}")'
        return record

    base = os.path.basename(rel_path)
    is_env = base == ".env" or base.startswith(".env")
    findings = scan_secrets(text, is_env)

    if findings:
        record["status"] = "redacted"
        record["reason"] = "secret values redacted (file still included)"
        record["secret_findings"] = findings
        record["content"] = redact(text, is_env)
    else:
        record["content"] = text

    return record


def _sha256_file(abs_path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(abs_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def build_context(repo: str, project: str) -> dict:
    files = [build_file_record(repo, rel) for rel in walk_files(repo)]

    sensitive_index = [
        {"path": f["path"], "type": finding["type"], "line": finding["line"]}
        for f in files
        for finding in f["secret_findings"]
    ]

    summary = {
        "total_files": len(files),
        "included": sum(1 for f in files if f["status"] == "included"),
        "redacted": sum(1 for f in files if f["status"] == "redacted"),
        "excluded": sum(1 for f in files if f["status"] == "excluded"),
        "secret_findings": len(sensitive_index),
    }

    return {
        "project": project,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "pushed_by": get_pusher(repo),
        "git_commit": get_commit(repo),
        "summary": summary,
        "files": files,
        "sensitive_index": sensitive_index,
    }


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #
def _safe_tag(value: str) -> str:
    """Make a string safe for use in a file/dir name."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-") or "unknown"


def render_markdown(ctx: dict) -> str:
    lines: list[str] = []
    a = lines.append

    a(f"# Project Context: `{ctx['project']}`")
    a("")
    a(f"> Generated by ContextOps v{ctx['tool_version']} on "
      f"{ctx['generated_at_utc']}.")
    a("> Secrets are detected and **redacted**; confidential and binary files "
      "are excluded.")
    a("")
    pb = ctx["pushed_by"]
    pushed = pb["name"] + (f" <{pb['email']}>" if pb["email"] else "")
    a(f"- **Pushed by:** {pushed}")
    if pb.get("date"):
        a(f"- **Last commit date:** {pb['date']}")
    a(f"- **Commit:** `{ctx['git_commit']}`")
    s = ctx["summary"]
    a(f"- **Files:** {s['total_files']} total — {s['included']} included, "
      f"{s['redacted']} redacted, {s['excluded']} excluded")
    a("")

    # Sensitive findings.
    a("## Sensitive findings")
    a("")
    if ctx["sensitive_index"]:
        a("Detected secrets (values redacted in this bundle):")
        a("")
        a("| File | Line | Type | Hint |")
        a("| --- | --- | --- | --- |")
        finding_by_path: dict[str, list[dict]] = {}
        for f in ctx["files"]:
            if f["secret_findings"]:
                finding_by_path[f["path"]] = f["secret_findings"]
        for path, findings in finding_by_path.items():
            for fnd in findings:
                a(f"| `{path}` | {fnd['line']} | {fnd['type']} | "
                  f"`{fnd['preview']}` |")
    else:
        a("No secrets detected.")
    a("")

    # Excluded / redacted.
    a("## Excluded / redacted")
    a("")
    flagged = [f for f in ctx["files"] if f["status"] in ("excluded", "redacted")]
    if flagged:
        a("| File | Status | Reason |")
        a("| --- | --- | --- |")
        for f in flagged:
            a(f"| `{f['path']}` | {f['status']} | {f['reason']} |")
    else:
        a("None.")
    a("")

    # Included files tree (everything not excluded).
    a("## Included files")
    a("")
    a("```")
    for f in ctx["files"]:
        if f["status"] != "excluded":
            a(f["path"])
    a("```")
    a("")

    # File contents.
    a("## File contents")
    a("")
    for f in ctx["files"]:
        if f["content"] is None:
            continue
        a(f"### `{f['path']}`")
        if f["status"] == "redacted":
            a("")
            a("> Secret values in this file have been redacted.")
        a("")
        lang = f["language"] or ""
        a(f"```{lang}")
        a(f["content"].rstrip("\n"))
        a("```")
        a("")

    return "\n".join(lines) + "\n"


def write_bundle(ctx: dict, out_root: str) -> str:
    project_dir = os.path.join(out_root, f"context_{_safe_tag(ctx['project'])}")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%SZ")
    tag = f"{_safe_tag(ctx['pushed_by']['name'])}_{stamp}"
    context_dir = os.path.join(project_dir, tag)
    os.makedirs(context_dir, exist_ok=True)

    json_path = os.path.join(context_dir, "context.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(ctx, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    md_path = os.path.join(context_dir, "context.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(ctx))

    return context_dir


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="contextops",
        description="Capture a repository's context into redacted, shareable "
                    "bundles and write them to a simulated S3 layout.",
    )
    parser.add_argument(
        "--repo",
        default="context-bundle",
        help="Path to the repository to scan (default: context-bundle).",
    )
    parser.add_argument(
        "--project",
        default=None,
        help="Project name for the output folder "
             "(default: scanned repo's directory name).",
    )
    parser.add_argument(
        "--out",
        default="s3-bucket",
        help="Simulated S3 bucket root directory (default: s3-bucket).",
    )
    args = parser.parse_args(argv)

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(repo):
        parser.error(f"repo not found: {repo}")

    project = args.project or os.path.basename(os.path.normpath(repo))
    ctx = build_context(repo, project)
    context_dir = write_bundle(ctx, os.path.abspath(args.out))

    s = ctx["summary"]
    print(f"ContextOps bundle written to: {context_dir}")
    print(f"  project:   {ctx['project']}")
    print(f"  pushed by: {ctx['pushed_by']['name']}")
    print(f"  files:     {s['total_files']} total "
          f"({s['included']} included, {s['redacted']} redacted, "
          f"{s['excluded']} excluded)")
    print(f"  secrets:   {s['secret_findings']} flagged and redacted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
