# ReleaseShield SARIF Input Contract

## 1. Standard

- SARIF version: 2.1.0
- Schema: schemas/sarif-schema-2.1.0.json
- Input format: JSON SARIF report

## 2. Validation Requirements

Before a report is passed to the merger:

1. The file must exist and be readable.
2. The file must contain valid JSON.
3. The report must conform to the official SARIF 2.1.0 schema.
4. The report version must be 2.1.0.
5. The top-level runs property must have a valid SARIF structure.
6. Invalid reports must be rejected with a clear error message.

## 3. Merger Expectations

- The merger should receive only validated reports.
- It should preserve scanner identity, rule information,
  finding locations, and available metadata.
- It should combine the runs from the validated reports.
- The consolidated output should conform to SARIF 2.1.0.

## 4. Current Test Fixtures

- fixtures/valid.sarif
- fixtures/invalid_wrong_version.sarif
- fixtures/invalid_wrong_runs_type.sarif
- fixtures/malformed.json

## 5. Current Validation Test Results

All four fixture scenarios passed the initial schema-validation check.
These checks were run using a temporary Python script.
Automated regression tests are still to be added.
