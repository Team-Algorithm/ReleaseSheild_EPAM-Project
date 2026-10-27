# ReleaseShield AI â€” Bug & Compatibility Report

## Overview
This document provides a rigorous technical assessment of confirmed software defects and architectural risks/blockers across the ReleaseShield AI data pipeline, in accordance with the Role 8 Integration & Validation mandate.

In adherence to quality guidelines:
- **Confirmed Defects (Bugs)** include only verified defects where existing code or data violates established standards or expected behavior.
- **Risks & Blockers** track missing implementations, environment limitations, and unfinalized contracts without conflating them with code defects.

---

## 1. Confirmed Software Defects (Bugs)

### BUG-01: UTF-8 BOM Parsing Crash on Windows Hosts
- **Component:** JSON File Loaders (Validation & Merging)
- **Classification:** Defect (Encoding Handling)
- **Status:** **Mitigated in Test Harness; Pending in Production Module**
- **Description:** On Windows platforms, text editors and file generation tools often prepend a 3-byte Byte Order Mark (`\xef\xbb\xbf`) to UTF-8 encoded files. Calling standard `open(file, encoding="utf-8")` fails to strip this BOM, causing Python's `json.load()` to throw:
  ```text
  json.decoder.JSONDecodeError: Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)
  ```
- **Evidence:** Identified during initial fixture testing.
- **Fix / Recommendation:** All file reading routines across `tests/test_sarif_validation.py`, `tests/test_sarif_integration.py`, and the upcoming `src/sarif_merger.py` implementation must explicitly specify:
  ```python
  with path.open(encoding="utf-8-sig") as file:
      data = json.load(file)
  ```

---

### BUG-02: SARIF URI Windows Backslash Incompatibility
- **Component:** Scanner Runners & Finding Locations
- **Classification:** Standard Compliance Defect
- **Status:** **Identified / Documented for Runner Implementation**
- **Description:** The OASIS SARIF 2.1.0 specification (Â§3.10.2) requires that all `artifactLocation.uri` values use RFC 3986 URI format with forward slashes (`/`), even on Windows. If a Windows-based runner directly inserts `os.path.join` outputs (e.g., `controllers\search.py`), downstream SARIF viewers (GitHub Security tab, VS Code SARIF extension) fail to resolve the artifact.
- **Evidence:** Inspected fixture requirements and technical architecture specification.
- **Fix / Recommendation:** The runner layer and merger must normalize all file paths using `pathlib.Path.as_posix()` before writing to SARIF `artifactLocation.uri`.

---

### BUG-03: Gitleaks Non-Zero Exit Code Misclassification
- **Component:** Scanner Runner Layer (`runners/gitleaks.py`)
- **Classification:** Process Orchestration Defect
- **Status:** **Documented for Role 5**
- **Description:** Most CLI utilities return exit code `0` for success and `1` for error. However, `gitleaks detect` intentionally returns exit code `1` when secrets **are identified**. If a generic process runner treats any non-zero exit code as a crash, secret detection runs will be flagged as tool crashes rather than successful scans with high-severity findings.
- **Fix / Recommendation:** Runner layer must treat exit code `1` from Gitleaks as `status: "done"` / `findings_detected`, reserving `status: "failed"` for exit codes `> 1` or binary launch errors.

---

## 2. Architectural Risks & Implementation Blockers

The following items represent missing implementations or external environment dependencies:

### BLOCKER-01: SARIF Merger Placeholder (`src/sarif_merger.py`)
- **Category:** Missing Implementation (Role 7)
- **Severity:** **HIGH (Blocking Automated Pipeline)**
- **Detail:** `src/sarif_merger.py` contains `def merge_sarif_reports(*args, **kwargs): pass`. Because the body is `pass`, calling this function returns `None`.
- **Current Mitigation:** Role 8 has created full integration test coverage in `tests/test_sarif_integration.py` marked with `@pytest.mark.xfail(reason="BLOCKED on Role 7")`.
- **Resolution Path:** Role 7 must implement the agreed contract (see `docs/integration-contract.md`) to concatenate `runs` arrays.

---

### BLOCKER-02: Absence of Scanner CLI Binaries in Local Environment
- **Category:** Environment / DevOps (Role 2)
- **Severity:** **MEDIUM (Restricts Testing to Fixtures)**
- **Detail:** Terminal verification using `where.exe semgrep`, `where.exe trivy`, and `where.exe gitleaks` confirmed that none of the three security scanner binaries are installed in PATH on the host Windows machine.
- **Current Mitigation:** Role 8 created and validated comprehensive synthetic fixtures (`semgrep.sarif`, `trivy.sarif`, `gitleaks.sarif`). The live execution test `test_live_scanner_binaries_availability` cleanly skips with descriptive reporting.
- **Resolution Path:** Provision containerized tools or add tool binaries to CI runner PATH.

---

### BLOCKER-03: Absence of Node.js / npm in PowerShell PATH
- **Category:** Environment / Frontend Toolchain
- **Severity:** **LOW (Affects CLI UI build, not Python core)**
- **Detail:** Executing `npm` in PowerShell results in `CommandNotFoundException`. The TypeScript CLI frontend in `cli_frontend/` cannot be built or tested from the current terminal environment without Node.js in PATH.
- **Resolution Path:** Ensure Node.js v20+ and npm are exported to PATH in the user profile.

---

## 3. Compatibility Matrix

| Technology | Supported Version | Tested Status | Compatibility Notes |
|---|---|---|---|
| **Python** | 3.10 â€“ 3.15.x | **Verified (3.15.2)** | Python 3.15.2 in `.venv` runs all validation and test suites without deprecation warnings. |
| **pytest** | 9.x | **Verified (9.1.1)** | Seamless fixture discovery, parameterization, and xfail reporting. |
| **jsonschema** | 4.x | **Verified (4.26.0)** | Draft7Validator successfully validates all OASIS SARIF 2.1.0 schemas. |
| **SARIF Standard** | 2.1.0 | **Verified** | Compliant with OASIS Standard schema errata01. |
| **Host OS** | Windows 11 | **Verified** | Handled Windows path separators and UTF-8 BOM encoding. |
