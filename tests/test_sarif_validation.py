
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "sarif-schema-2.1.0.json"
FIXTURES = ROOT / "fixtures"


@pytest.fixture(scope="module")
def validator():
    with SCHEMA_PATH.open(encoding="utf-8-sig") as file:
        schema = json.load(file)

    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def load_json(path):
    with path.open(encoding="utf-8-sig") as file:
        return json.load(file)


def test_valid_sarif_passes_schema(validator):
    report = load_json(FIXTURES / "valid.sarif")
    errors = list(validator.iter_errors(report))

    assert report["version"] == "2.1.0"
    assert errors == []


def test_wrong_version_fails_schema(validator):
    report = load_json(FIXTURES / "invalid_wrong_version.sarif")
    errors = list(validator.iter_errors(report))

    assert errors, "Wrong SARIF version should fail validation"


def test_wrong_runs_type_fails_schema(validator):
    report = load_json(FIXTURES / "invalid_wrong_runs_type.sarif")
    errors = list(validator.iter_errors(report))

    assert errors, "Invalid runs type should fail validation"


def test_malformed_json_cannot_be_parsed():
    with pytest.raises(json.JSONDecodeError):
        load_json(FIXTURES / "malformed.json")


def test_missing_input_file_raises_file_not_found():
    missing_file = FIXTURES / "does_not_exist.sarif"

    with pytest.raises(FileNotFoundError):
        load_json(missing_file)
