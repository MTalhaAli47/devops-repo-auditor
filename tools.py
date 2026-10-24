
"""Read-only tools for inspecting a local Git repository."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


MAX_FILES = 5_000
MAX_FILE_BYTES = 200_000
MAX_MATCHES = 100
MAX_LOG_ENTRIES = 30


SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (
        \b(?:
            aws_secret_access_key |
            secret_access_key |
            aws_access_key_id |
            access_key_id |
            api[_-]?key |
            access[_-]?token |
            auth[_-]?token |
            client[_-]?secret |
            private[_-]?key |
            password |
            passwd |
            secret |
            token |
            bearer |
            authorization |
            credential |
            credentials
        )\b
        \s*[:=]\s*
    )
    (?:
        "([^"]*)" |
        '([^']*)' |
        (Bearer\s+)?([^\s,;#]+)
    )
    """
)

TOKEN_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
]


def redact_content(content: str) -> str:
    """Redact likely credentials while preserving original line numbers."""
    lines = content.splitlines()
    redacted = []
    in_private_key = False

    for line in lines:
        if "-----BEGIN " in line and "PRIVATE KEY-----" in line:
            in_private_key = True
            redacted.append(line)
            continue

        if in_private_key:
            if "-----END " in line and "PRIVATE KEY-----" in line:
                redacted.append(line)
                in_private_key = False
            else:
                redacted.append("[REDACTED PRIVATE KEY]")
            continue

        # Handle Authorization: Bearer <token> before generic assignments.
        line = re.sub(
            r"(?i)(\bauthorization\s*[:=]\s*)Bearer\s+[^\s,;#]+",
            r"\1[REDACTED]",
            line,
        )

        line = SECRET_ASSIGNMENT_RE.sub(
            lambda match: match.group(1) + "[REDACTED]",
            line,
        )

        for pattern in TOKEN_PATTERNS:
            line = pattern.sub("[REDACTED]", line)

        redacted.append(line)

    return "\n".join(redacted)


IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}


class ToolError(Exception):
    """Raised when a repository inspection tool cannot run safely."""


def _repo_root(repo_path: str | Path) -> Path:
    """Resolve and validate the repository directory."""
    root = Path(repo_path).resolve()

    if not root.is_dir():
        raise ToolError("Repository directory does not exist.")

    return root


def _safe_file(root: Path, relative_path: str) -> Path:
    """Resolve a repository-relative path without allowing traversal."""
    candidate = Path(relative_path)

    if candidate.is_absolute():
        raise ToolError("Absolute paths are not allowed.")

    resolved = (root / candidate).resolve()

    try:
        resolved.relative_to(root)
    except ValueError:
        raise ToolError("Path escapes the repository root.") from None

    if not resolved.is_file():
        raise ToolError(f"Not a regular file: {relative_path}")

    return resolved


def _safe_directory(root: Path, relative_path: str) -> Path:
    """Resolve a directory contained inside the repository."""
    candidate = Path(relative_path)

    if candidate.is_absolute():
        raise ToolError("Absolute paths are not allowed.")

    resolved = (root / candidate).resolve()

    try:
        resolved.relative_to(root)
    except ValueError:
        raise ToolError("Path escapes the repository root.") from None

    if not resolved.is_dir():
        raise ToolError(f"Not a directory: {relative_path}")

    return resolved


def list_files(
    repo_path: str | Path,
    subdirectory: str = ".",
    limit: int = MAX_FILES,
) -> dict:
    """List repository files without entering ignored directories."""
    root = _repo_root(repo_path)
    start = (
        root
        if subdirectory == "."
        else _safe_directory(root, subdirectory)
    )

    if not 1 <= limit <= MAX_FILES:
        raise ToolError(f"limit must be between 1 and {MAX_FILES}.")

    files = []
    truncated = False

    for current, dirs, filenames in os.walk(start, followlinks=False):
        current_path = Path(current)

        dirs[:] = sorted(
            name
            for name in dirs
            if name not in IGNORED_DIRS
            and not (current_path / name).is_symlink()
        )

        for name in sorted(filenames):
            path = current_path / name

            if path.is_symlink():
                continue

            if len(files) >= limit:
                truncated = True
                break

            files.append(path.relative_to(root).as_posix())

        if truncated:
            break

    return {
        "files": files,
        "count": len(files),
        "truncated": truncated,
    }


def read_file(
    repo_path: str | Path,
    path: str,
) -> dict:
    """Read a bounded UTF-8 text file and include line numbers."""
    root = _repo_root(repo_path)
    target = _safe_file(root, path)

    if target.stat().st_size > MAX_FILE_BYTES:
        raise ToolError(
            f"File exceeds the {MAX_FILE_BYTES}-byte size limit."
        )

    try:
        content = target.read_text(encoding="utf-8")
        content = redact_content(content)
    except UnicodeDecodeError:
        raise ToolError("File is not valid UTF-8 text.") from None
    except OSError as exc:
        raise ToolError(
            f"Could not read file ({type(exc).__name__})."
        ) from None

    numbered = [
        f"{number}: {line}"
        for number, line in enumerate(content.splitlines(), start=1)
    ]

    return {
        "path": target.relative_to(root).as_posix(),
        "line_count": len(numbered),
        "content": "\n".join(numbered),
    }


def search_code(
    repo_path: str | Path,
    pattern: str,
    limit: int = MAX_MATCHES,
) -> dict:
    """Search text files using a regular expression."""
    root = _repo_root(repo_path)

    if not pattern or len(pattern) > 300:
        raise ToolError("Pattern must contain 1–300 characters.")

    if not 1 <= limit <= MAX_MATCHES:
        raise ToolError(f"limit must be between 1 and {MAX_MATCHES}.")

    try:
        expression = re.compile(pattern, re.IGNORECASE)
    except re.error:
        raise ToolError("Invalid regular expression.") from None

    inventory = list_files(root)
    matches = []
    truncated = False

    for relative_path in inventory["files"]:
        target = _safe_file(root, relative_path)

        try:
            if target.stat().st_size > MAX_FILE_BYTES:
                continue

            content = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        lines = redact_content(content).splitlines()

        for number, line in enumerate(lines, start=1):
            if not expression.search(line):
                continue

            if len(matches) >= limit:
                truncated = True
                break

            matches.append(
                {
                    "file": relative_path,
                    "line": number,
                    "text": line[:300],
                }
            )

        if truncated:
            break

    return {
        "pattern": pattern,
        "matches": matches,
        "count": len(matches),
        "truncated": truncated or inventory["truncated"],
    }


def git_log(
    repo_path: str | Path,
    limit: int = 10,
) -> dict:
    """Return recent commit metadata without changing the repository."""
    root = _repo_root(repo_path)

    if not 1 <= limit <= MAX_LOG_ENTRIES:
        raise ToolError(
            f"limit must be between 1 and {MAX_LOG_ENTRIES}."
        )

    command = [
        "git",
        "-C",
        str(root),
        "log",
        f"-n{limit}",
        "--format=%h%x09%cs%x09%s",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ToolError("Git log timed out.") from None
    except OSError as exc:
        raise ToolError(
            f"Git log could not start ({type(exc).__name__})."
        ) from None

    if result.returncode != 0:
        raise ToolError(
            "Git log could not run. Is this directory a Git repository?"
        )

    commits = []

    for line in result.stdout.splitlines():
        parts = line.split("\t", 2)

        if len(parts) == 3:
            commits.append(
                {
                    "hash": parts[0],
                    "date": parts[1],
                    "subject": redact_content(parts[2])[:300],
                }
            )

    return {
        "commits": commits,
        "count": len(commits),
    }
