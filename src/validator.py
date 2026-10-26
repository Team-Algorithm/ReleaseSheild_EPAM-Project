"""Validation of scanner reports against the official SARIF 2.1.0 schema."""

import json
from pathlib import Path
from typing import Any, Dict, Union

from jsonschema import FormatChecker
from jsonschema.validators import validator_for

PathLike = Union[str, Path]
SARIF_VERSION = "2.1.0"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "sarif-schema-2.1.0.json"


class SarifValidationError(ValueError):
    """Raised when a SARIF report cannot be read or fails validation."""


def validate_sarif(path: PathLike, schema_path: PathLike = DEFAULT_SCHEMA_PATH) -> Dict[str, Any]:
    """Load and validate a SARIF 2.1.0 report.

    Args:
        path: Path to the scanner report.
        schema_path: Path to the official SARIF 2.1.0 JSON Schema. Primarily
            configurable for tests and alternate repository layouts.

    Returns:
        The parsed SARIF report as a dictionary when valid.

    Raises:
        SarifValidationError: If the input is missing, unreadable, malformed,
            uses an unsupported SARIF version, or violates the SARIF schema.
    """
    report_path = Path(path)

    if not report_path.exists():
        raise SarifValidationError(f"{report_path}: input file does not exist")
    if not report_path.is_file():
        raise SarifValidationError(f"{report_path}: input path is not a regular file")

    try:
        with report_path.open("r", encoding="utf-8") as input_file:
            report = json.load(input_file)
    except json.JSONDecodeError as exc:
        raise SarifValidationError(
            f"{report_path}: malformed JSON at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise SarifValidationError(
            f"{report_path}: unable to read input file: {exc}"
        ) from exc

    if isinstance(report, dict) and "version" in report:
        version = report["version"]
        if version != SARIF_VERSION:
            raise SarifValidationError(
                f"{report_path}: unsupported SARIF version {version!r}; "
                f"expected {SARIF_VERSION!r}"
            )

    schema_file = Path(schema_path)
    try:
        with schema_file.open("r", encoding="utf-8") as input_file:
            schema = json.load(input_file)
        validator_class = validator_for(schema)
        validator_class.check_schema(schema)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SarifValidationError(
            f"{report_path}: unable to load SARIF schema from {schema_file}: {exc}"
        ) from exc

    validator = validator_class(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(report),
        key=lambda error: (list(map(str, error.absolute_path)), error.message),
    )
    if errors:
        details = []
        for error in errors[:3]:
            location = error.json_path
            details.append(f"{location}: {error.message}")
        extra = f" (and {len(errors) - 3} more error(s))" if len(errors) > 3 else ""
        raise SarifValidationError(
            f"{report_path}: SARIF 2.1.0 schema validation failed: "
            + "; ".join(details)
            + extra
        )

    return report
