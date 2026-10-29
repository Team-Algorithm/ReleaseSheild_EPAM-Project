

# ReleaseShield AI — Quick Start & Run Guide

This guide walks you through setting up dependencies and launching the ReleaseShield AI interactive CLI terminal.

---

## 📋 Prerequisites

- **Node.js**: v20.0.0 or later (`node -v`)
- **npm**: v10.0.0 or later (`npm -v`)
- Any modern terminal (PowerShell, Command Prompt, macOS Terminal, or Linux bash/zsh)

---

## 🚀 Quick Launch (One-Liner)

From the project root:

```bash
cd cli_frontend && npm install && npm run dev
```

---

## 🛠 Step-by-Step Instructions

### Step 1: Open Terminal & Navigate to `cli_frontend`

```bash
cd cli_frontend
```

### Step 2: Install Workspace Dependencies

```bash
npm install
```

### Step 3: Launch the CLI

#### Option A: Development Mode (Fastest — Instant Launch via `tsx`)
```bash
npm run dev
```

#### Option B: Production Mode (Build & Run Compiled Bundle)
```bash
npm run build
npm start
```

#### Option C: Global Command Mode (Run `releaseshield` directly from anywhere)
If you want to type `releaseshield` directly in your terminal at any time without `npm run dev`:

```bash
# Build and link the package once:
npm run build
cd packages/cli && npm link

# Now launch it anytime from any folder:
releaseshield
```

---

## 🎮 Inside the Interactive CLI

Once the terminal interface loads, try the following commands:

| Command | Description |
|---|---|
| `/help` | Display list of all available commands |
| `/tools` | Show status of configured security scanners |
| `/scan` | Open interactive checklist to select tools & run simulated scan |
| `/scan --tools trivy,semgrep` | Skip checklist and scan with specific tools |
| `/scan --fail gitleaks` | Simulate a failure mode (gitleaks fails, other scanners continue) |
| `/results` | Re-display summary table of the latest scan |
| `/findings` | Browse security findings with pagination (<kbd>n</kbd> for next, <kbd>p</kbd> for prev) |
| `/findings --severity high` | Filter findings by severity (`high`, `medium`, `low`) |
| `/findings --tool semgrep` | Filter findings by tool (`semgrep`, `trivy`, `gitleaks`) |
| `/clear` | Clear the output area |
| `/quit` | Exit cleanly without needing <kbd>Ctrl</kbd>+<kbd>C</kbd> |

---

# Non-Interactive Mode

ReleaseShield can be used directly from the terminal without opening the interactive UI.

This is useful when you want to run a scan with a single command and get the results as JSON.

## Run a Scan

```bash
releaseshield scan <repository-path> --tools all --json
```

Replace `<repository-path>` with the path of the repository you want to scan.

### Example

```bash
releaseshield scan ./NodeGoat --tools all --json
```

Here:

- `scan` — starts a security scan.
- `./NodeGoat` — the repository you want to scan. Replace this with your own repository path.
- `--tools all` — runs all supported security scanning tools.
- `--json` — displays the results in JSON format.

## Select Specific Tools

You can choose which tools to run instead of running all tools.

```bash
releaseshield scan ./NodeGoat --tools trivy,semgrep --json
```

This runs only Trivy and Semgrep.

Supported tools depend on the tools configured in ReleaseShield.

## Save the Results

You can save the JSON output to a file:

```bash
releaseshield scan ./NodeGoat --tools all --json > results.json
```

This creates a `results.json` file containing the scan results.

## Test Scanner Failure

ReleaseShield provides `--fail` to simulate a scanner failure for testing.

For example:

```bash
releaseshield scan ./NodeGoat --tools all --json --fail gitleaks
```

This simulates a Gitleaks failure so you can check how ReleaseShield handles scanner errors.

Use this only for **testing and development**. Do not use `--fail` during a real security scan because it intentionally simulates a failure.

For a real scan, use:

```bash
releaseshield scan ./NodeGoat --tools all --json
```

## Exit Codes

ReleaseShield returns an exit code when the scan finishes:

- `0` — all selected scanner tools completed successfully.
- `1` — one or more scanner tools failed.

These exit codes allow scripts and automated systems to know whether the scan completed successfully.

## View Help

To see the available commands and options:

```bash
releaseshield --help
```

During local development, you can also use:

```bash
node packages/cli/dist/index.js --help
```

## Quick Reference

```bash
# Open interactive mode
releaseshield

# Run a scan
releaseshield scan <repository-path> --tools all --json

# Run selected tools
releaseshield scan <repository-path> --tools trivy,semgrep --json

# Save results
releaseshield scan <repository-path> --tools all --json > results.json

# Test a scanner failure
releaseshield scan <repository-path> --tools all --json --fail gitleaks

# Show help
releaseshield --help
```

---

## 💡 Tips & Shortcuts

- **Exit Anytime**: Press <kbd>Ctrl</kbd>+<kbd>C</kbd> or type `/quit`.
- **Command History**: Use <kbd>↑</kbd> and <kbd>↓</kbd> in the prompt box to recall previously typed commands.
- **Narrow Terminal**: On screens smaller than 80 columns, the findings table automatically drops `Medium` and `Low` columns to prevent wrapping.
- **NO_COLOR**: Set `NO_COLOR=1` in your environment to disable all terminal colors.
