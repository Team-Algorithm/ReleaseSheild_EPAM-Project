# ReleaseShield AI â€” End-to-End Integration Test Report

## 1. Executive Summary

| Parameter | Details |
|---|---|
| **Project** | ReleaseShield AI |
| **Branch** | `sarif-merger` |
| **Testing Role** | Role 8 â€” Integration & Validation |
| **Test Date** | October 27, 2026 |
| **Environment** | Windows 11 / Windows PowerShell, Python 3.15.2 (`.venv`), pytest 9.1.1, jsonschema 4.26.0 |
| **Total Test Count** | 24 tests collected across 2 test modules |
| **Overall Result** | **17 PASSED, 1 SKIPPED, 6 XFAILED** (0.34s execution time) |
| **Schema Standard** | OASIS SARIF 2.1.0 (`schemas/sarif-schema-2.1.0.json`, Draft-07 Validator) |

---

## 2. Test Execution Commands & Verified Outputs

### 2.1 Existing Validation Suite Execution

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_sarif_validation.py -v
```

**Observed Terminal Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.15.2, pytest-9.1.1, pluggy-1.7.0 -- C:\Users\Anisha Dhanwani\Documents\ReleaseShield\ReleaseSheild_EPAM-Project\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\Anisha Dhanwani\Documents\ReleaseShield\ReleaseSheild_EPAM-Project
collecting ... collected 5 items

tests/test_sarif_validation.py::test_valid_sarif_passes_schema PASSED    [ 20%]
tests/test_sarif_validation.py::test_wrong_version_fails_schema PASSED   [ 40%]
tests/test_sarif_validation.py::test_wrong_runs_type_fails_schema PASSED [ 60%]
tests/test_sarif_validation.py::test_malformed_json_cannot_be_parsed PASSED [ 80%]
tests/test_sarif_validation.py::test_missing_input_file_raises_file_not_found PASSED [100%]

============================== 5 passed in 0.25s ==============================
```

---

### 2.2 Integration Suite Execution (`tests/test_sarif_integration.py`)

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_sarif_integration.py -v
```

**Observed Terminal Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.15.2, pytest-9.1.1, pluggy-1.7.0 -- C:\Users\Anisha Dhanwani\Documents\ReleaseShield\ReleaseSheild_EPAM-Project\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\Anisha Dhanwani\Documents\ReleaseShield\ReleaseSheild_EPAM-Project
collecting ... collected 19 items

tests/test_sarif_integration.py::test_semgrep_fixture_validates_against_schema PASSED [  5%]
tests/test_sarif_integration.py::test_trivy_fixture_validates_against_schema PASSED [ 10%]
tests/test_sarif_integration.py::test_gitleaks_fixture_validates_against_schema PASSED [ 15%]
tests/test_sarif_integration.py::test_scanner_identity_preserved[semgrep.sarif-Semgrep] PASSED [ 21%]
tests/test_sarif_integration.py::test_scanner_identity_preserved[trivy.sarif-Trivy] PASSED [ 26%]
tests/test_sarif_integration.py::test_scanner_identity_preserved[gitleaks.sarif-Gitleaks] PASSED [ 31%]
tests/test_sarif_integration.py::test_scanner_findings_preserve_critical_fields[semgrep.sarif] PASSED [ 36%]
tests/test_sarif_integration.py::test_scanner_findings_preserve_critical_fields[trivy.sarif] PASSED [ 42%]
tests/test_sarif_integration.py::test_scanner_findings_preserve_critical_fields[gitleaks.sarif] PASSED [ 47%]
tests/test_sarif_integration.py::test_canonical_merged_reference_passes_schema PASSED [ 52%]
tests/test_sarif_integration.py::test_empty_runs_fixture_passes_schema PASSED [ 57%]
tests/test_sarif_integration.py::test_scanner_with_zero_findings_passes_schema PASSED [ 63%]
tests/test_sarif_integration.py::test_live_scanner_binaries_availability SKIPPED [ 68%]
tests/test_sarif_integration.py::test_merge_multiple_sarif_reports XFAIL [ 73%]
tests/test_sarif_integration.py::test_merge_preserves_scanner_identity_and_findings XFAIL [ 78%]
tests/test_sarif_integration.py::test_merge_empty_input_handling XFAIL   [ 84%]
tests/test_sarif_integration.py::test_merge_empty_runs_handling XFAIL    [ 89%]
tests/test_sarif_integration.py::test_merge_error_handling_malformed_json XFAIL [ 94%]
tests/test_sarif_integration.py::test_merge_output_validates_against_schema XFAIL [100%]

================== 12 passed, 1 skipped, 6 xfailed in 0.52s ===================
```

---

### 2.3 Combined Full Test Suite Execution

```powershell
& .\.venv\Scripts\python.exe -m pytest -v
```

**Observed Terminal Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.15.2, pytest-9.1.1, pluggy-1.7.0 -- C:\Users\Anisha Dhanwani\Documents\ReleaseShield\ReleaseSheild_EPAM-Project\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\Anisha Dhanwani\Documents\ReleaseShield\ReleaseSheild_EPAM-Project
collecting ... collected 24 items

tests/test_sarif_integration.py::test_semgrep_fixture_validates_against_schema PASSED [  4%]
tests/test_sarif_integration.py::test_trivy_fixture_validates_against_schema PASSED [  8%]
tests/test_sarif_integration.py::test_gitleaks_fixture_validates_against_schema PASSED [ 12%]
tests/test_sarif_integration.py::test_scanner_identity_preserved[semgrep.sarif-Semgrep] PASSED [ 16%]
tests/test_sarif_integration.py::test_scanner_identity_preserved[trivy.sarif-Trivy] PASSED [ 20%]
tests/test_sarif_integration.py::test_scanner_identity_preserved[gitleaks.sarif-Gitleaks] PASSED [ 25%]
tests/test_sarif_integration.py::test_scanner_findings_preserve_critical_fields[semgrep.sarif] PASSED [ 29%]
tests/test_sarif_integration.py::test_scanner_findings_preserve_critical_fields[trivy.sarif] PASSED [ 33%]
tests/test_sarif_integration.py::test_scanner_findings_preserve_critical_fields[gitleaks.sarif] PASSED [ 37%]
tests/test_sarif_integration.py::test_canonical_merged_reference_passes_schema PASSED [ 41%]
tests/test_sarif_integration.py::test_empty_runs_fixture_passes_schema PASSED [ 45%]
tests/test_sarif_integration.py::test_scanner_with_zero_findings_passes_schema PASSED [ 50%]
tests/test_sarif_integration.py::test_live_scanner_binaries_availability SKIPPED [ 54%]
tests/test_sarif_integration.py::test_merge_multiple_sarif_reports XFAIL [ 58%]
tests/test_sarif_integration.py::test_merge_preserves_scanner_identity_and_findings XFAIL [ 62%]
tests/test_sarif_integration.py::test_merge_empty_input_handling XFAIL   [ 66%]
tests/test_sarif_integration.py::test_merge_empty_runs_handling XFAIL    [ 70%]
tests/test_sarif_integration.py::test_merge_error_handling_malformed_json XFAIL [ 75%]
tests/test_sarif_integration.py::test_merge_output_validates_against_schema XFAIL [ 79%]
tests/test_sarif_validation.py::test_valid_sarif_passes_schema PASSED    [ 83%]
tests/test_sarif_validation.py::test_wrong_version_fails_schema PASSED   [ 87%]
tests/test_sarif_validation.py::test_wrong_runs_type_fails_schema PASSED [ 91%]
tests/test_sarif_validation.py::test_malformed_json_cannot_be_parsed PASSED [ 95%]
tests/test_sarif_validation.py::test_missing_input_file_raises_file_not_found PASSED [100%]

================== 17 passed, 1 skipped, 6 xfailed in 0.34s ===================
```

---

## 3. Workflows Tested & Verified

### Workflow A: SARIF 2.1.0 Schema Validation (100% Passed)
- Validated individual SARIF documents against OASIS SARIF 2.1.0 Draft-07 JSON Schema.
- Verified that invalid versions (e.g., `"1.0.0"`) are caught by the validator.
- Verified that non-array `"runs"` properties trigger validation errors.
- Verified that malformed JSON triggers `json.JSONDecodeError`.
- Verified that missing files trigger `FileNotFoundError`.

### Workflow B: Scanner Representation & Metadata Preservation (100% Passed)
- Tested realistic synthetic fixtures representing:
  - **Semgrep** (SAST findings: SQL injection, command injection)
  - **Trivy** (SCA vulnerability findings: Axios SSRF CVE-2023-45133, Semver ReDoS CVE-2022-25883)
  - **Gitleaks** (Secret findings: AWS Access Key ID exposed)
- Tested and proved preservation of:
  - Scanner identity (`tool.driver.name`, `version`, `informationUri`)
  - Finding rule IDs (`ruleId` present and non-empty)
  - Finding severity levels (`level` in `["none", "note", "warning", "error"]`)
  - Finding messages (`message.text` present and non-empty)
  - Finding physical locations (`artifactLocation.uri` present)
  - Finding line numbers (`region.startLine` positive integer)

### Workflow C: Multi-Tool Merged SARIF Compliance (100% Passed)
- Validated a composite canonical SARIF document (`fixtures/merged_reference.sarif`) containing runs from all three security tools.
- Proved that combining multiple distinct tool runs into a single `runs` array is fully compliant with the OASIS SARIF 2.1.0 standard with **0 validation errors**.

### Workflow D: Live Scanner Binary Execution (Skipped / Blocked)
- Evaluated presence of CLI binaries for Semgrep, Trivy, and Gitleaks in system PATH.
- Binaries were not found on the local host.
- Test gracefully skipped with explicit documentation per Role 8 guidelines.

### Workflow E: Production SARIF Merger Integration (6 Tests XFAILED / Blocked)
- Executed integration tests against `src/sarif_merger.py` (`merge_sarif_reports`).
- `merge_sarif_reports` is currently a starter placeholder returning `None`.
- Tests accurately recorded as `XFAIL` pending Role 7 implementation.

---

## 4. Scanner Execution Status

| Tool | Category | Local Binary Found? | Status in Integration Test |
|---|---|---|---|
| **Semgrep** | SAST | No | Represented via validated fixture `fixtures/semgrep.sarif` |
| **Trivy** | SCA | No | Represented via validated fixture `fixtures/trivy.sarif` |
| **Gitleaks** | Secrets | No | Represented via validated fixture `fixtures/gitleaks.sarif` |

> **Certification:** No end-to-end live scanner execution occurred because the CLI scanner binaries are not installed in the Windows environment. All scanner integration testing was performed using strictly validated, schema-compliant synthetic fixtures.

---

## 5. End-to-End Merging Status

- **Component:** `src/sarif_merger.py`
- **Function:** `merge_sarif_reports(*args, **kwargs)`
- **Current Implementation:** `pass` (returns `None`)
- **Status:** **BLOCKED**
- **Impact:** Automated programmatic merging of SARIF files cannot occur until Role 7 provides the implementation. The integration test suite is fully prepared to validate the implementation as soon as it is committed.

---

## 6. Summary of Blockers & Required Team Actions

1. **Role 7 Deliverable Blocker:** Implement `merge_sarif_reports` in `src/sarif_merger.py` to consume input report paths/dictionaries and return a consolidated SARIF 2.1.0 document.
2. **DevOps / Environment Blocker (Role 2):** Provision Semgrep, Trivy, and Gitleaks binaries in the CI/local environment to enable live scanner execution tests.
3. **Frontend CLI Toolchain:** Node/npm not available in PATH on the host terminal session; requires environment PATH configuration to build the frontend package.
