# SARIF Merger Developer Notes & Python Fundamentals

These notes serve as a foundational guide for working with JSON data, Python collections, and SARIF structures. They are tailored for beginners learning how Python represents and manipulates security report data.

---

## 1. What Is JSON?
**JSON (JavaScript Object Notation)** is a lightweight, human-readable data format used to transmit structured data between applications.

Key characteristics:
- It stores data as key-value pairs (like `"name": "Semgrep"`) and ordered lists (like `[1, 2, 3]`).
- It is text-based and language-agnostic, making it the universal standard for modern REST APIs and file formats like SARIF.
- Python provides a built-in module named `json` to convert between JSON text strings and Python native objects.

```python
import json

# Converting JSON text to Python data
json_text = '{"scanner": "Trivy", "findings_count": 5}'
data = json.loads(json_text)
```

---

## 2. Python Dictionaries and Lists

In Python, JSON objects map directly to **dictionaries (`dict`)**, and JSON arrays map directly to **lists (`list`)**.

### Dictionaries (`dict`)
- A collection of key-value pairs enclosed in curly braces `{}`.
- Used to represent objects with named properties.
- Values are accessed by their key name.

```python
tool_info = {
    "name": "Semgrep",
    "version": "1.45.0"
}
print(tool_info["name"])  # Output: Semgrep
```

### Lists (`list`)
- An ordered collection of items enclosed in square brackets `[]`.
- Items can be accessed by their index (starting at `0`).
- Lists can hold numbers, strings, or even other dictionaries.

```python
scanners = ["Trivy", "Semgrep", "Gitleaks"]
print(scanners[0])  # Output: Trivy
```

---

## 3. How to Read the `runs` Array from a Report Dictionary

In SARIF, the top-level report is a dictionary that contains a key named `"runs"`. The value associated with `"runs"` is a list of run objects.

### Accessing `runs` Safely in Python

```python
# Illustrative snippet (simplified for learning)
report = {
    "version": "2.1.0",
    "runs": [
        {"tool": {"driver": {"name": "Trivy"}}}
    ]
}

# Method 1: Direct indexing (raises KeyError if 'runs' does not exist)
runs_list = report["runs"]

# Method 2: Using .get() (safer, returns a default value if key is missing)
runs_list = report.get("runs", [])
```

Using `.get("runs", [])` ensures our code will not crash with a `KeyError` if a report dictionary happens to be missing the `"runs"` key.

---

## 4. Understanding `list.append()` vs. `list.extend()`

When combining lists in Python, understanding the difference between `append()` and `extend()` is critical.

### `list.append(item)`
- Adds its argument as a **single element** to the end of the list.
- If you append a list to another list, you get a **nested list** (a list inside a list).

```python
all_runs = ["run_1"]
trivy_runs = ["run_2", "run_3"]

all_runs.append(trivy_runs)
print(all_runs)
# Output: ['run_1', ['run_2', 'run_3']]  <-- Nested! Not what we want for SARIF.
```

### `list.extend(iterable)`
- Iterates over its argument, adding **each item individually** to the list.
- It flattens the items into a single unified list.

```python
all_runs = ["run_1"]
trivy_runs = ["run_2", "run_3"]

all_runs.extend(trivy_runs)
print(all_runs)
# Output: ['run_1', 'run_2', 'run_3']   <-- Flat list! Exactly what SARIF expects.
```

> **Rule for SARIF Merging:** Because each report has a list of runs (`report["runs"]`), we use `extend()` (or list concatenation `+`) so that all individual run objects end up in a single flat list under `consolidated_report["runs"]`.

---

## 5. Illustrative Example: Combining Two Lists of Runs

> **Note:** The following code uses simplified mockup data to demonstrate the list-merging concept. These are illustrative fragments, not complete or schema-valid SARIF documents.

```python
# Simplified mock report from Scanner A
report_a = {
    "version": "2.1.0",
    "runs": [
        {"scanner_id": "semgrep", "issues": 2}
    ]
}

# Simplified mock report from Scanner B
report_b = {
    "version": "2.1.0",
    "runs": [
        {"scanner_id": "trivy", "issues": 4}
    ]
}

# Step 1: Initialize an empty list for consolidated runs
combined_runs = []

# Step 2: Extract and extend runs from each report
combined_runs.extend(report_a.get("runs", []))
combined_runs.extend(report_b.get("runs", []))

# Step 3: Place combined runs into the consolidated structure
consolidated_report = {
    "version": "2.1.0",
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "runs": combined_runs
}

print(f"Total runs merged: {len(consolidated_report['runs'])}")
# Output: Total runs merged: 2
```

---

## 6. Why Preserve Original Run Objects and Nested Metadata?

Each `run` object inside a SARIF document contains deeply nested information produced by the scanner, including:
- **`tool.driver`**: Scanner name, version, documentation URI, and rule definitions.
- **`results`**: Each specific vulnerability found (rule ID, message, severity level).
- **`locations`**: Physical file paths, start lines, end lines, and column numbers.
- **`fingerprints`**: Unique hashes (e.g., `primaryLocationLineHash`) used for tracking findings across commits and suppressing false positives.

### Why We Never Strip or Reformat This Data in the Merger:
1. **Downstream Correlation:** Later components (such as correlation algorithms or database ingestion layers) rely on scanner-specific hashes and rule IDs.
2. **Schema Compliance:** SARIF readers (like GitHub Security tab or VS Code SARIF viewer) expect standard sub-objects. If the merger omits or modifies fields, third-party viewers may fail to parse the report.
3. **Auditability & Traceability:** Developers need to verify exactly what version of a rule flagged an issue and inspect the raw evidence supplied by the tool.
