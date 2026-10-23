
import pytest

from agent import validate_github_url, validate_report


def test_accepts_github_repository_url():
    assert validate_github_url(
        "https://github.com/example/project"
    ) == "https://github.com/example/project.git"


def test_accepts_github_url_with_git_suffix():
    assert validate_github_url(
        "https://github.com/example/project.git"
    ) == "https://github.com/example/project.git"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/project",
        "https://example.com/example/project",
        "https://github.com/example",
        "https://user:password@github.com/example/project",
        "https://github.com/example/project?token=secret",
        "https://github.com/example/project/issues",
    ],
)
def test_rejects_invalid_repository_urls(url):
    with pytest.raises(ValueError):
        validate_github_url(url)


def test_accepts_empty_violations_report():
    report = validate_report(
        '{"repository":"ignored","violations":[]}',
        "https://github.com/example/project",
    )

    assert report == {
        "repository": "https://github.com/example/project",
        "violations": [],
    }


def test_validates_finding_fields():
    finding = {
        "rule_id": "DOCKER001",
        "category": "Container Security",
        "severity": "high",
        "file": "Dockerfile",
        "line": 4,
        "description": "The container runs as root.",
        "evidence": "USER root",
        "recommendation": "Configure a non-root user.",
    }

    report = validate_report(
        __import__("json").dumps(
            {"repository": "ignored", "violations": [finding]}
        ),
        "https://github.com/example/project",
    )

    assert report["violations"][0]["rule_id"] == "DOCKER001"
    assert report["violations"][0]["line"] == 4


@pytest.mark.parametrize(
    "raw_report",
    [
        "not json",
        '{"repository":"example","violations":{}}',
        '{"repository":"example","violations":[{"severity":"urgent"}]}',
        (
            '{"repository":"example","violations":['
            '{"rule_id":"X","category":"Y","severity":"urgent",'
            '"file":null,"line":null,"description":"bad",'
            '"evidence":"evidence","recommendation":"fix"}]}'
        ),
    ],
)
def test_rejects_malformed_reports(raw_report):
    with pytest.raises(ValueError):
        validate_report(raw_report, "https://github.com/example/project")
