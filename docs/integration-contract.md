# ReleaseShield AI â€” Integration Contract Specification

## Status: Working Specification / Proposal
**Author:** Role 8 â€” Integration & Validation
**Target:** Sprint 1 Data Pipeline & Layer Interfaces
**Standard Reference:** OASIS SARIF 2.1.0 (Static Analysis Results Interchange Format)

---

## 1. Architectural Overview & Data Flow

ReleaseShield AI follows a 3-layer decoupled architecture:

```text
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  LAYER 1: RUNNERS                                      â”‚
â”‚  Trivy (SCA), Semgrep (SAST), Gitleaks (Secrets)       â”‚
â”‚  Output: Individual native SARIF 2.1.0 files           â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                           â”‚ [Interface 1: Runner Output]
                           â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  LAYER 2: DATA & PIPELINE                              â”‚
â”‚                                                        â”‚
â”‚  Step 2A: SARIF Validation (Role 6)                    â”‚
â”‚  [Interface 2: Schema Validation Contract]             â”‚
â”‚                                                        â”‚
â”‚  Step 2B: SARIF Merger (Role 7)                        â”‚
â”‚  [Interface 3: Merger Contract (PROPOSED)]             â”‚
â”‚                                                        â”‚
â”‚  Step 2C: Summary Builder (Role 8 / Core)              â”‚
â”‚  [Interface 4: Summary Object Contract]                â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                           â”‚ [Interface 5: Display Contract]
                           â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  LAYER 3: DISPLAY & CLI                                â”‚
â”‚  Terminal UI, Progress View, Summary Table, JSON       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## 2. Interface 1: Scanner Runners to Raw SARIF Output

### 2.1 Native SARIF Generation
Unlike legacy static analysis tools requiring custom converter scripts, modern security scanners produce OASIS SARIF 2.1.0 output natively:

| Scanner | Category | Target Invocation Command | Native SARIF Flag |
|---|---|---|---|
| **Trivy** | SCA & Config | `trivy fs --format sarif --output trivy.sarif <repo>` | `--format sarif` |
| **Semgrep** | SAST | `semgrep scan --sarif --output semgrep.sarif <repo>` | `--sarif` |
| **Gitleaks** | Secrets | `gitleaks detect --source <repo> --report-format sarif --report-path gitleaks.sarif` | `--report-format sarif` |

> **Contract Rule 1.1:** No custom intermediate conversion module is required. Scanners must be configured to output valid SARIF 2.1.0 directly.

### 2.2 Scanner Exit Codes & Process Termination
Different tools use exit codes differently:
- **Trivy:** Exit code `0` on success (even with findings by default), `>0` on runtime failure.
- **Semgrep:** Exit code `0` on clean or findings, `1` on unhandled error.
- **Gitleaks:** Exit code `0` when no secrets found; exit code `1` when secrets **are detected** (this is normal detection, not a software crash); `>1` on runtime error.

> **Contract Rule 1.2:** The runner layer must distinguish between **findings detected** (valid scan) and **binary failure/missing executable** (runner error).

---

## 3. Interface 2: SARIF Validation Layer (Role 6)

### 3.1 Contract Specification
- **Function:** `validate_sarif(report_source: str | Path | dict) -> tuple[bool, list[str]]`
- **Schema:** `schemas/sarif-schema-2.1.0.json` (Draft-07 OASIS standard)
- **Input:**
  - File path to SARIF document (`str` or `pathlib.Path`) OR pre-parsed dictionary (`dict`).
  - Encoding must support UTF-8 and UTF-8 with BOM (`encoding="utf-8-sig"`).
- **Output:**
  - `is_valid: bool` â€” `True` if document satisfies schema; `False` otherwise.
  - `errors: list[str]` â€” descriptive messages of schema violations if invalid; empty list if valid.

### 3.2 Required Edge Case Behavior
1. **Missing Files:** Must raise `FileNotFoundError` if input path does not exist.
2. **Malformed JSON:** Must raise `json.JSONDecodeError` or return `(False, ["Malformed JSON syntax"])`.
3. **Invalid Version:** Any SARIF version other than `"2.1.0"` must return `(False, [...])`.
4. **Invalid Runs Type:** Root property `"runs"` must be a JSON array. Any other type fails validation.
5. **Empty Runs:** An empty runs array (`"runs": []`) is valid SARIF.

---

## 4. Interface 3: SARIF Merger Layer (Role 7)

### 4.1 Current Status: STARTER PLACEHOLDER
As of Sprint 1, `src/sarif_merger.py` defines:
```python
def merge_sarif_reports(*args, **kwargs):
    pass
```
Implementation logic is deferred pending the alignment of the proposals below.

### 4.2 Proposed Merger Contracts (Under Review)

#### Proposal A: File-Path Based Signature (Recommended for Pipeline Isolation)
```python
def merge_sarif_reports(
    report_paths: list[str | Path],
    output_path: str | Path | None = None
) -> dict:
    """Read validated SARIF files from disk, merge runs, and optionally write to output_path.

    Args:
        report_paths: List of existing file paths to valid SARIF documents.
        output_path: Optional destination path to write the merged SARIF JSON.

    Returns:
        The consolidated SARIF document as a Python dictionary.
    """
```

#### Proposal B: In-Memory Dictionary Signature
```python
def merge_sarif_reports(reports: list[dict]) -> dict:
    """Combine already-parsed SARIF dictionaries into a single document.

    Args:
        reports: List of in-memory validated SARIF dictionaries.

    Returns:
        The consolidated SARIF document as a Python dictionary.
    """
```

#### Proposal C: Dual Input Contract (Most Flexible)
The merger inspects items: if `isinstance(item, (str, Path))`, loads from disk; if `isinstance(item, dict)`, processes in memory.

### 4.3 Agreed Merging Rules
1. **Top-Level Structure:**
   - `"version"`: strictly `"2.1.0"`
   - `"$schema"`: strictly `"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"`
2. **Runs Concatenation:**
   - All `run` objects from each input report are appended to the consolidated report's `"runs"` list via `list.extend()`.
   - Original `tool.driver` names, versions, rules, results, locations, and fingerprints must remain byte-intact without mutation or filtering.
3. **Empty Input Handling (Proposal):**
   - If `report_paths == []`, return a valid empty SARIF skeleton:
     ```json
     {
       "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
       "version": "2.1.0",
       "runs": []
     }
     ```
4. **Partial Failure Strategy (Proposal):**
   - If 1 of 3 reports is corrupted or unreadable, the merger should log a warning, exclude the damaged report, and merge the remaining valid reports, setting an execution flag indicating partial degradation.

---

## 5. Interface 4: Summary Builder (Role 8 / Layer 2 Core)

### 5.1 Severity Normalization Contract (Sprint 1 Rule)
The SARIF standard defines four result levels: `"error"`, `"warning"`, `"note"`, and `"none"`.
For Sprint 1, ReleaseShield normalizes these to user-facing severity counts as follows:

| SARIF `result.level` | ReleaseShield CLI Severity | Note |
|---|---|---|
| `"error"` | **High** | Critical / High security impact |
| `"warning"` | **Medium** | Medium severity flaw |
| `"note"` | **Low** | Informational / Low risk |
| `"none"` (or unset) | **Low** | Unclassified / Low risk |

### 5.2 Summary Data Object Contract
The summary object produced by Layer 2 and consumed by Layer 3:

```json
{
  "total_time_seconds": 42.0,
  "tools": {
    "trivy":   { "status": "done", "high": 12, "medium": 20, "low": 10, "total": 42, "duration": 18.2 },
    "semgrep": { "status": "done", "high": 11, "medium": 15, "low":  5, "total": 31, "duration": 41.7 },
    "gitleaks":{ "status": "done", "high":  3, "medium":  0, "low":  0, "total":  3, "duration": 6.9 }
  },
  "total_counts": {
    "high": 26,
    "medium": 35,
    "low": 15,
    "total": 76
  },
  "sarif_path": "./results/result.sarif"
}
```

---

## 6. Interface 5: CLI & Display Layer (Layer 3)

### 6.1 Invocation Contract
- `releaseshield scan <target_path> [options]`
- Options:
  - `--tools <trivy,semgrep,gitleaks|all>`: Specific tools to execute.
  - `--out <path>`: Destination path for merged SARIF report (default: `./results/result.sarif`).
  - `--json`: Emit machine-readable JSON summary to stdout (suppresses interactive UI).
  - `--fail <tool>`: Testing flag to simulate scanner failure.

### 6.2 Exit Code Contract
- `0`: Scan finished; all selected tools completed or completed with findings.
- `1`: One or more selected tools suffered a fatal execution failure (e.g., binary missing, disk I/O failure).

---

## 7. Open Architectural Decisions & Handoff Checklist

| Item | Status | Action Required |
|---|---|---|
| Dual input contract (paths vs dicts) | Proposed | Role 7 & Role 9 alignment |
| Partial failure mode (skip vs fail) | Proposed | Project Lead confirmation |
| Output writing location (`./results`) | Confirmed | Default directory created if missing |
| Native SARIF schema verification | Confirmed | Enforced via `schemas/sarif-schema-2.1.0.json` |
