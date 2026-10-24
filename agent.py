
"""CLI entry point for the DevOps repository auditor."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from llm_client import GeminiClient, LLMError
from prompts import build_audit_prompt
from tools import (
    ToolError,
    git_log,
    list_files,
    read_file,
    redact_content,
    search_code,
)

CLONE_TIMEOUT_SECONDS = 120

REPORT_FIELDS = (
    "rule_id",
    "category",
    "severity",
    "file",
    "line",
    "description",
    "evidence",
    "recommendation",
)
TEXT_FIELDS = (
    "rule_id",
    "category",
    "description",
    "evidence",
    "recommendation",
)
VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# Additional patterns for common credential formats. These are applied
# to final finding text as defense in depth; they cannot identify every
# possible secret format.
EXTRA_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"
    ),
)


TOOL_SCHEMAS = [
    {
        "type": "function",
        "name": "list_files",
        "description": (
            "List repository files and discover relevant DevOps configuration. "
            "Use this first to understand repository structure."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "subdirectory": {
                    "type": "string",
                    "description": (
                        "Repository-relative directory to list; use '.' for root."
                    ),
                }
            },
        },
    },
    {
        "type": "function",
        "name": "read_file",
        "description": (
            "Read a text file from the repository. Returns numbered lines "
            "with likely secrets redacted. Read files before reporting findings."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Repository-relative file path.",
                }
            },
            "required": ["path"],
        },
    },
    {
        "type": "function",
        "name": "search_code",
        "description": (
            "Search repository text using a regular expression. Use this to "
            "locate security-sensitive settings or configuration patterns, "
            "then read relevant files to confirm evidence."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regular expression to search for.",
                }
            },
            "required": ["pattern"],
        },
    },
    {
        "type": "function",
        "name": "git_log",
        "description": (
            "Inspect recent commit subjects and dates for relevant delivery "
            "or configuration context. This does not modify the repository."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
]


def validate_github_url(url: str) -> str:
    """Accept public GitHub HTTPS repository URLs only."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Provide a public GitHub HTTPS repository URL.")

    try:
        parsed = urlparse(url.strip())
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid GitHub repository URL.") from None

    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Provide a public GitHub HTTPS URL, such as "
            "https://github.com/owner/repository."
        )

    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise ValueError(
            "The URL must point directly to a repository, "
            "for example https://github.com/owner/repository."
        )

    owner, repository = parts
    repository = repository.removesuffix(".git")

    # Reject malformed path components instead of silently normalizing them.
    component_pattern = re.compile(r"^[A-Za-z0-9_.-]+$")
    if (
        not component_pattern.fullmatch(owner)
        or not component_pattern.fullmatch(repository)
        or owner in {".", ".."}
        or repository in {".", ".."}
    ):
        raise ValueError("Invalid GitHub repository path.")

    return f"https://github.com/{owner}/{repository}.git"


def clone_repository(url: str, destination: Path) -> None:
    """Clone a repository without checking out submodules or running its code."""
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-recurse-submodules",
        "--",
        url,
        str(destination),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            check=False,
            env={
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_LFS_SKIP_SMUDGE": "1",
            },
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Repository clone timed out.") from None
    except OSError as exc:
        raise RuntimeError(
            f"Could not start Git ({type(exc).__name__})."
        ) from None

    if result.returncode != 0:
        # Do not print raw Git output, which could disclose sensitive data.
        raise RuntimeError(
            "Git could not clone this repository. Check the URL, "
            "network connection, and public repository access."
        )


def _sanitize_finding_text(value: str) -> str:
    """Redact likely secrets before a finding is written to the report."""
    sanitized = redact_content(value)

    for pattern in EXTRA_SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED]", sanitized)

    return sanitized.strip()


def validate_report(raw_response: str, repository_url: str) -> dict:
    """Parse, sanitize and validate the required JSON report structure."""
    try:
        report = json.loads(raw_response)
    except (json.JSONDecodeError, TypeError):
        raise ValueError("The model did not return valid JSON.") from None

    if not isinstance(report, dict):
        raise ValueError("The report must be a JSON object.")

    violations = report.get("violations")
    if not isinstance(violations, list):
        raise ValueError("'violations' must be a JSON array.")

    clean_violations = []
    required_fields = set(REPORT_FIELDS)

    for index, violation in enumerate(violations):
        if not isinstance(violation, dict):
            raise ValueError(f"Violation {index} must be a JSON object.")

        missing = required_fields - violation.keys()
        if missing:
            raise ValueError(
                f"Violation {index} is missing required fields."
            )

        severity = violation["severity"]
        if (
            not isinstance(severity, str)
            or severity not in VALID_SEVERITIES
        ):
            raise ValueError(
                f"Violation {index} has an invalid severity."
            )

        sanitized_fields = {}
        for field in TEXT_FIELDS:
            value = violation[field]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Violation {index} has an invalid '{field}' value."
                )

            sanitized = _sanitize_finding_text(value)
            if not sanitized:
                raise ValueError(
                    f"Violation {index} has an empty '{field}' after sanitization."
                )
            sanitized_fields[field] = sanitized

        file_value = violation["file"]
        if file_value is not None:
            if not isinstance(file_value, str) or not file_value.strip():
                raise ValueError(
                    f"Violation {index} has an invalid file value."
                )

            # Paths must be repository-relative, not absolute or traversal paths.
            normalized = file_value.replace("\\", "/")
            path_parts = normalized.split("/")
            if (
                normalized.startswith("/")
                or re.match(r"^[A-Za-z]:", normalized)
                or any(part == ".." for part in path_parts)
            ):
                raise ValueError(
                    f"Violation {index} has an invalid repository-relative path."
                )
            file_value = normalized

        line = violation["line"]
        if line is not None and (
            not isinstance(line, int)
            or isinstance(line, bool)
            or line < 1
        ):
            raise ValueError(
                f"Violation {index} has an invalid line number."
            )

        clean_violations.append(
            {
                "rule_id": sanitized_fields["rule_id"],
                "category": sanitized_fields["category"],
                "severity": severity,
                "file": file_value,
                "line": line,
                "description": sanitized_fields["description"],
                "evidence": sanitized_fields["evidence"],
                "recommendation": sanitized_fields["recommendation"],
            }
        )

    return {
        "repository": repository_url,
        "violations": clean_violations,
    }


def audit_repository(repository_url: str) -> dict:
    """Clone, inspect and audit one public GitHub repository."""
    safe_url = validate_github_url(repository_url)

    with tempfile.TemporaryDirectory(prefix="devops-audit-") as temp_dir:
        repo_path = Path(temp_dir) / "repository"
        clone_repository(safe_url, repo_path)

        handlers = {
            "list_files": lambda subdirectory=".": list_files(
                repo_path, subdirectory=subdirectory
            ),
            "read_file": lambda path: read_file(repo_path, path),
            "search_code": lambda pattern: search_code(repo_path, pattern),
            "git_log": lambda: git_log(repo_path),
        }

        client = GeminiClient()
        prompt = build_audit_prompt(safe_url)

        raw_response = client.run_with_tools(
            prompt=prompt,
            tool_schemas=TOOL_SCHEMAS,
            tool_handlers=handlers,
        )

        return validate_report(raw_response, safe_url)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit a public GitHub repository for DevOps issues."
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Public GitHub repository HTTPS URL.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to the JSON report to create.",
    )
    args = parser.parse_args()

    output_path = Path(args.output).expanduser().resolve()

    try:
        report = audit_repository(args.repo)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except (ValueError, RuntimeError, LLMError, ToolError) as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"Could not write report ({type(exc).__name__}).",
            file=sys.stderr,
        )
        return 1

    print(f"Audit report written to: {output_path}")
    print(f"Findings: {len(report['violations'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
