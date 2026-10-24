
"""Tests for repository inspection tools and secret redaction."""

import subprocess

import pytest

from tools import (
    ToolError,
    git_log,
    list_files,
    read_file,
    redact_content,
    search_code,
)


@pytest.fixture
def repo(tmp_path):
    """Create a small local Git repository for testing."""
    (tmp_path / "app.py").write_text(
        'API_KEY = "example-placeholder"\nprint("hello")\n',
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text(
        "# Example project\n",
        encoding="utf-8",
    )
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.txt").write_text(
        "ignore me",
        encoding="utf-8",
    )

    subprocess.run(
        ["git", "init", "-q", str(tmp_path)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "app.py", "README.md"],
        check=True,
    )
    subprocess.run(
        [
            "git", "-C", str(tmp_path),
            "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid",
            "commit", "-qm", "Initial test commit",
        ],
        check=True,
    )

    return tmp_path


def test_list_files_excludes_virtual_environment(repo):
    result = list_files(repo)

    assert "app.py" in result["files"]
    assert "README.md" in result["files"]
    assert not any(
        path.startswith(".venv/") for path in result["files"]
    )


def test_read_file_includes_line_numbers(repo):
    result = read_file(repo, "app.py")

    assert "1: API_KEY" in result["content"]
    assert "2: print" in result["content"]
    assert result["line_count"] == 2


def test_read_file_blocks_path_traversal(repo):
    with pytest.raises(ToolError):
        read_file(repo, "../outside.txt")


def test_search_code_returns_matching_line(repo):
    result = search_code(repo, r"API_KEY\s*=")

    assert result["count"] == 1
    assert result["matches"][0]["file"] == "app.py"
    assert result["matches"][0]["line"] == 1


def test_git_log_returns_commit(repo):
    result = git_log(repo)

    assert result["count"] == 1
    assert result["commits"][0]["subject"] == "Initial test commit"


def test_read_file_redacts_secret_values(repo):
    secret_file = repo / "config.env"
    secret_file.write_text(
        'API_KEY="sensitive-example-value"\n'
        "password=another-sensitive-value\n",
        encoding="utf-8",
    )

    result = read_file(repo, "config.env")
    content = result["content"]

    assert "sensitive-example-value" not in content
    assert "another-sensitive-value" not in content
    assert "[REDACTED]" in content
    assert "1:" in content
    assert "2:" in content


def test_redact_aws_credentials():
    content = (
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=example-secret-value\n"
        "Authorization: Bearer example-bearer-token\n"
    )

    result = redact_content(content)

    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "example-secret-value" not in result
    assert "example-bearer-token" not in result
    assert "[REDACTED]" in result


def test_redact_quoted_credentials():
    content = (
        'client_secret = "quoted-secret-example"\n'
        "password: 'quoted-password-example'\n"
    )

    result = redact_content(content)

    assert "quoted-secret-example" not in result
    assert "quoted-password-example" not in result


def test_redact_private_key_body():
    content = (
        "-----BEGIN PRIVATE KEY-----\n"
        "private-key-body-example\n"
        "-----END PRIVATE KEY-----\n"
    )

    result = redact_content(content)

    assert "private-key-body-example" not in result
    assert "[REDACTED PRIVATE KEY]" in result
