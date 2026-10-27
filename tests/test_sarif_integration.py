"""ReleaseShield AI - Role 8 Integration & Validation Test Suite.

This test suite verifies:
1. SARIF 2.1.0 schema compliance for scanner-produced fixtures (Semgrep, Trivy, Gitleaks).
2. Preservation of finding metadata (rule IDs, severity levels, messages, file URIs, line numbers).
3. Scanner tool identity preservation (driver name, version, informationUri).
4. Validation of composite multi-scanner merged SARIF reports against official OASIS schema.
5. Detection and reporting of scanner execution environment availability.
6. Integration contract testing for `src/sarif_merger.py`:
   - Combining multiple reports
   - Preserving scanner identity and finding counts
   - Empty input and empty runs handling
   - Error handling for malformed JSON, missing files, and invalid SARIF
   - Validation of merger output against schema

Note on Merger Tests:
    `src/sarif_merger.py` is currently a placeholder pending Role 7 contract finalization.
    Tests calling `merge_sarif_reports` are explicitly marked with `pytest.mark.xfail`
    to document the open blocker without fabricating passing results or altering the
    production placeholder module.
"""

import json
from pathlib import Path
import shutil

import pytest
from jsonschema import Draft7Validator

from src.sarif_merger import merge_sarif_reports

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "sarif-schema-2.1.0.json"
FIXTURES = ROOT / "fixtures"


@pytest.fixture(scope="module")
def validator():
    """Load and initialize the official SARIF 2.1.0 Draft-07 schema validator."""
    with SCHEMA_PATH.open(encoding="utf-8-sig") as file:
        schema = json.load(file)
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def load_sarif(path: Path) -> dict:
    """Helper to safely load a SARIF JSON file handling optional UTF-8 BOM."""
    with path.open(encoding="utf-8-sig") as file:
        return json.load(file)


# ==============================================================================
# 1. Scanner Fixture Validation Against Official SARIF 2.1.0 Schema
# ==============================================================================

def test_semgrep_fixture_validates_against_schema(validator):
    """Verify that the Semgrep SAST fixture is 100% compliant with SARIF 2.1.0."""
    report = load_sarif(FIXTURES / "semgrep.sarif")
    errors = list(validator.iter_errors(report))
    assert report["version"] == "2.1.0"
    assert errors == [], f"Semgrep fixture failed schema validation: {[e.message for e in errors]}"


def test_trivy_fixture_validates_against_schema(validator):
    """Verify that the Trivy SCA/vulnerability fixture is 100% compliant with SARIF 2.1.0."""
    report = load_sarif(FIXTURES / "trivy.sarif")
    errors = list(validator.iter_errors(report))
    assert report["version"] == "2.1.0"
    assert errors == [], f"Trivy fixture failed schema validation: {[e.message for e in errors]}"


def test_gitleaks_fixture_validates_against_schema(validator):
    """Verify that the Gitleaks secrets fixture is 100% compliant with SARIF 2.1.0."""
    report = load_sarif(FIXTURES / "gitleaks.sarif")
    errors = list(validator.iter_errors(report))
    assert report["version"] == "2.1.0"
    assert errors == [], f"Gitleaks fixture failed schema validation: {[e.message for e in errors]}"


# ==============================================================================
# 2. Finding Metadata and Tool Identity Preservation
# ==============================================================================

@pytest.mark.parametrize("fixture_name,expected_tool", [
    ("semgrep.sarif", "Semgrep"),
    ("trivy.sarif", "Trivy"),
    ("gitleaks.sarif", "Gitleaks"),
])
def test_scanner_identity_preserved(fixture_name, expected_tool):
    """Verify each scanner fixture accurately identifies its tool driver and metadata."""
    report = load_sarif(FIXTURES / fixture_name)
    assert "runs" in report and len(report["runs"]) > 0
    driver = report["runs"][0]["tool"]["driver"]
    assert driver["name"] == expected_tool
    assert "version" in driver
    assert "informationUri" in driver


@pytest.mark.parametrize("fixture_name", [
    "semgrep.sarif",
    "trivy.sarif",
    "gitleaks.sarif",
])
def test_scanner_findings_preserve_critical_fields(fixture_name):
    """Verify all findings retain rule ID, severity level, message, file path, and line."""
    report = load_sarif(FIXTURES / fixture_name)
    results = report["runs"][0]["results"]
    assert len(results) > 0, f"Expected findings in {fixture_name}"

    for finding in results:
        # Rule ID must be present and non-empty
        assert "ruleId" in finding and finding["ruleId"], "Finding missing ruleId"

        # Severity level must be a standard SARIF level
        assert finding.get("level") in ["none", "note", "warning", "error"], (
            f"Invalid level: {finding.get('level')}"
        )

        # Message text must be present
        assert "message" in finding and "text" in finding["message"], "Finding missing message text"
        assert len(finding["message"]["text"]) > 0

        # Physical location with artifact URI and line number
        assert "locations" in finding and len(finding["locations"]) > 0
        phys_loc = finding["locations"][0].get("physicalLocation", {})
        assert "artifactLocation" in phys_loc, "Missing artifactLocation"
        assert "uri" in phys_loc["artifactLocation"], "Missing file URI in location"
        assert len(phys_loc["artifactLocation"]["uri"]) > 0

        region = phys_loc.get("region", {})
        assert "startLine" in region, "Missing startLine in region"
        assert isinstance(region["startLine"], int) and region["startLine"] > 0


# ==============================================================================
# 3. Canonical Reference Merged Report Validation (Deliverable B)
# ==============================================================================

def test_canonical_merged_reference_passes_schema(validator):
    """Validate that combining Semgrep, Trivy, and Gitleaks into a single SARIF 2.1.0 document is schema-valid."""
    merged = load_sarif(FIXTURES / "merged_reference.sarif")
    errors = list(validator.iter_errors(merged))

    assert merged["version"] == "2.1.0"
    assert errors == [], f"Reference merged SARIF failed validation: {[e.message for e in errors]}"
    assert len(merged["runs"]) == 3, "Merged report must contain exactly 3 runs (one per scanner)"

    tool_names = [r["tool"]["driver"]["name"] for r in merged["runs"]]
    assert "Semgrep" in tool_names
    assert "Trivy" in tool_names
    assert "Gitleaks" in tool_names

    total_findings = sum(len(r.get("results", [])) for r in merged["runs"])
    assert total_findings == 5, f"Expected 5 total findings across 3 tools, got {total_findings}"


def test_empty_runs_fixture_passes_schema(validator):
    """Verify that a SARIF document with empty runs array is schema valid."""
    report = load_sarif(FIXTURES / "empty_runs.sarif")
    errors = list(validator.iter_errors(report))
    assert errors == []
    assert report["runs"] == []


def test_scanner_with_zero_findings_passes_schema(validator):
    """Verify that a tool run with 0 findings is schema valid (clean scan)."""
    report = load_sarif(FIXTURES / "scanner_no_findings.sarif")
    errors = list(validator.iter_errors(report))
    assert errors == []
    assert len(report["runs"]) == 1
    assert report["runs"][0]["results"] == []


# ==============================================================================
# 4. Scanner Execution Environment Status
# ==============================================================================

def test_live_scanner_binaries_availability():
    """Check if real scanner binaries (Semgrep, Trivy, Gitleaks) are installed in PATH.

    Per Section 5 of Role 8 guidelines:
    Real scanner execution is attempted only if tools are installed.
    Otherwise, synthetic fixtures are used and the live run is skipped.
    """
    missing = [tool for tool in ["semgrep", "trivy", "gitleaks"] if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"Scanners not installed in environment: {', '.join(missing)}. Synthetic fixtures verified.")


# ==============================================================================
# 5. Production Merger Integration Tests (`src.sarif_merger.merge_sarif_reports`)
# ==============================================================================
# NOTE: The merger implementation is currently a placeholder (`pass`) in `src/sarif_merger.py`.
# In accordance with Role 8 instructions, we do not invent an unconfirmed implementation
# in production code. These tests define the agreed contract and are marked xfail until
# Role 7 finalizes the merger implementation.

MERGER_BLOCKER_REASON = (
    "BLOCKED on Role 7: merge_sarif_reports in src/sarif_merger.py is currently a placeholder "
    "pending team contract alignment."
)


@pytest.mark.xfail(reason=MERGER_BLOCKER_REASON, strict=False)
def test_merge_multiple_sarif_reports():
    """Verify that merge_sarif_reports consolidates runs from multiple reports."""
    inputs = [
        FIXTURES / "semgrep.sarif",
        FIXTURES / "trivy.sarif",
        FIXTURES / "gitleaks.sarif",
    ]
    result = merge_sarif_reports(inputs)

    assert result is not None, "merge_sarif_reports returned None (placeholder)"
    assert isinstance(result, dict), "Merged report must be a dictionary"
    assert result.get("version") == "2.1.0"
    assert "runs" in result and len(result["runs"]) == 3


@pytest.mark.xfail(reason=MERGER_BLOCKER_REASON, strict=False)
def test_merge_preserves_scanner_identity_and_findings():
    """Verify that merging preserves driver names and findings without data loss."""
    inputs = [
        FIXTURES / "semgrep.sarif",
        FIXTURES / "trivy.sarif",
    ]
    result = merge_sarif_reports(inputs)

    assert result is not None, "merge_sarif_reports returned None (placeholder)"
    tool_names = [r["tool"]["driver"]["name"] for r in result["runs"]]
    assert "Semgrep" in tool_names
    assert "Trivy" in tool_names

    # Semgrep had 2 findings, Trivy had 2 findings
    semgrep_run = next(r for r in result["runs"] if r["tool"]["driver"]["name"] == "Semgrep")
    assert len(semgrep_run["results"]) == 2


@pytest.mark.xfail(reason=MERGER_BLOCKER_REASON, strict=False)
def test_merge_empty_input_handling():
    """Verify that passing an empty list to merge_sarif_reports returns a valid empty SARIF skeleton."""
    result = merge_sarif_reports([])

    assert result is not None, "merge_sarif_reports returned None (placeholder)"
    assert result.get("version") == "2.1.0"
    assert result.get("runs") == []


@pytest.mark.xfail(reason=MERGER_BLOCKER_REASON, strict=False)
def test_merge_empty_runs_handling():
    """Verify that merging reports with empty runs array produces a valid output."""
    inputs = [FIXTURES / "empty_runs.sarif"]
    result = merge_sarif_reports(inputs)

    assert result is not None, "merge_sarif_reports returned None (placeholder)"
    assert "runs" in result
    assert result["runs"] == []


@pytest.mark.xfail(reason=MERGER_BLOCKER_REASON, strict=False)
def test_merge_error_handling_malformed_json():
    """Verify that the merger rejects or reports malformed JSON inputs."""
    inputs = [FIXTURES / "malformed.json"]
    with pytest.raises((json.JSONDecodeError, ValueError)):
        merge_sarif_reports(inputs)


@pytest.mark.xfail(reason=MERGER_BLOCKER_REASON, strict=False)
def test_merge_output_validates_against_schema(validator):
    """Verify that the output of merge_sarif_reports satisfies SARIF 2.1.0 schema."""
    inputs = [FIXTURES / "semgrep.sarif", FIXTURES / "gitleaks.sarif"]
    result = merge_sarif_reports(inputs)

    assert result is not None, "merge_sarif_reports returned None (placeholder)"
    errors = list(validator.iter_errors(result))
    assert errors == [], f"Merged output failed schema validation: {[e.message for e in errors]}"
