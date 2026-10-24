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

## 🤖 Non-Interactive Mode (For CI/CD & Headless Automation)

To run a scan headlessly and receive pure JSON output with exit codes (`0` for success, `1` for failures):

```bash
# Output JSON to stdout
node packages/cli/dist/index.js scan ./NodeGoat --tools all --json

# Save JSON report to file
node packages/cli/dist/index.js scan ./NodeGoat --tools all --json > report.json
```

---

## 💡 Tips & Shortcuts

- **Exit Anytime**: Press <kbd>Ctrl</kbd>+<kbd>C</kbd> or type `/quit`.
- **Command History**: Use <kbd>↑</kbd> and <kbd>↓</kbd> in the prompt box to recall previously typed commands.
- **Narrow Terminal**: On screens smaller than 80 columns, the findings table automatically drops `Medium` and `Low` columns to prevent wrapping.
- **NO_COLOR**: Set `NO_COLOR=1` in your environment to disable all terminal colors.
