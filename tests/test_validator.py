"""Automated tests for SARIF input validation."""

import json
from pathlib import Path

import pytest

from src.validator import SarifValidationError, validate_sarif


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def test_valid_sarif_fixture_is_accepted():
    report = validate_sarif(FIXTURES / "valid.sarif")
    assert report["version"] == "2.1.0"
    assert isinstance(report["runs"], list)


def test_unsupported_version_is_rejected_with_clear_message():
    path = FIXTURES / "invalid_wrong_version.sarif"
    with pytest.raises(SarifValidationError, match="unsupported SARIF version") as exc:
        validate_sarif(path)
    assert str(path) in str(exc.value)
    assert "2.1.0" in str(exc.value)


def test_invalid_runs_type_is_rejected():
    path = FIXTURES / "invalid_wrong_runs_type.sarif"
    with pytest.raises(SarifValidationError, match="schema validation failed") as exc:
        validate_sarif(path)
    assert str(path) in str(exc.value)
    assert "runs" in str(exc.value)


def test_malformed_json_is_rejected_with_location():
    path = FIXTURES / "malformed.json"
    with pytest.raises(SarifValidationError, match="malformed JSON") as exc:
        validate_sarif(path)
    assert str(path) in str(exc.value)
    assert "line" in str(exc.value)


def test_missing_required_runs_field_is_rejected(tmp_path):
    path = tmp_path / "missing_runs.sarif"
    path.write_text(json.dumps({"version": "2.1.0"}), encoding="utf-8")
    with pytest.raises(SarifValidationError, match="required property") as exc:
        validate_sarif(path)
    assert "runs" in str(exc.value)


def test_missing_input_file_is_rejected(tmp_path):
    path = tmp_path / "does-not-exist.sarif"
    with pytest.raises(SarifValidationError, match="does not exist") as exc:
        validate_sarif(path)
    assert str(path) in str(exc.value)


def test_non_file_input_is_rejected(tmp_path):
    # A directory exists but cannot be opened as a SARIF JSON report.
    with pytest.raises(SarifValidationError, match="not a regular file"):
        validate_sarif(tmp_path)



def test_unreadable_input_file_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "unreadable.sarif"
    path.write_text('{"version": "2.1.0", "runs": []}', encoding="utf-8")
    original_open = Path.open

    def deny_input_open(self, *args, **kwargs):
        if self == path:
            raise PermissionError("permission denied for test")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_input_open)
    with pytest.raises(SarifValidationError, match="unable to read input file") as exc:
        validate_sarif(path)
    assert str(path) in str(exc.value)
