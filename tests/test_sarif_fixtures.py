import json
from pathlib import Path

from jsonschema import Draft7Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "sarif-schema-2.1.0.json"
FIXTURES = ROOT / "fixtures"


def load_schema():
    with SCHEMA_PATH.open(encoding="utf-8") as file:
        schema = json.load(file)

    Draft7Validator.check_schema(schema)
    return schema


def test_valid_sarif_fixture_passes_schema():
    schema = load_schema()

    with (FIXTURES / "valid.sarif").open(encoding="utf-8") as file:
        report = json.load(file)

    errors = list(Draft7Validator(schema).iter_errors(report))
    assert errors == []


def test_wrong_version_fixture_fails_schema():
    schema = load_schema()

    with (FIXTURES / "invalid_wrong_version.sarif").open(encoding="utf-8") as file:
        report = json.load(file)

    errors = list(Draft7Validator(schema).iter_errors(report))
    assert errors


def test_wrong_runs_type_fixture_fails_schema():
    schema = load_schema()

    with (FIXTURES / "invalid_wrong_runs_type.sarif").open(encoding="utf-8") as file:
        report = json.load(file)

    errors = list(Draft7Validator(schema).iter_errors(report))
    assert errors


def test_malformed_json_fixture_cannot_be_parsed():
    import pytest

    with (FIXTURES / "malformed.json").open(encoding="utf-8") as file:
        with pytest.raises(json.JSONDecodeError):
            json.load(file)
