import type { ToolName, ScanSummary } from "@releaseshield/core";
import { runScan } from "@releaseshield/core";

export interface CliScanArgs {
  repo?: string;
  tools: ToolName[];
  json: boolean;
  failTool?: ToolName;
}

export function parseCliArgs(argv: string[]): {
  isScanCommand: boolean;
  isHelp: boolean;
  args: CliScanArgs;
} {
  const args = argv.slice(2);
  let isScanCommand = false;
  let isHelp = false;
  let repo: string | undefined;
  let tools: ToolName[] = ["trivy", "semgrep", "gitleaks"];
  let json = false;
  let failTool: ToolName | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "scan") {
      isScanCommand = true;
    } else if (arg === "--help" || arg === "-h" || arg === "help") {
      isHelp = true;
    } else if (arg === "--json") {
      json = true;
    } else if (arg.startsWith("--tools=")) {
      const val = arg.slice(8);
      tools = parseToolsArg(val);
    } else if (arg === "--tools") {
      const toolTokens: string[] = [];
      while (i + 1 < args.length && !args[i + 1].startsWith("-")) {
        toolTokens.push(args[++i]);
      }
      if (toolTokens.length > 0) {
        tools = parseToolsArg(toolTokens.join(","));
      }
    } else if (arg.startsWith("--fail=")) {
      const val = arg.slice(7);
      failTool = validateTool(val);
    } else if (arg === "--fail") {
      if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
        failTool = validateTool(args[++i]);
      }
    } else if (!arg.startsWith("-") && !repo && isScanCommand) {
      repo = arg;
    }
  }

  return {
    isScanCommand,
    isHelp,
    args: { repo, tools, json, failTool },
  };
}

function parseToolsArg(val: string): ToolName[] {
  if (val === "all") {
    return ["trivy", "semgrep", "gitleaks"];
  }
  const split = val.split(",").map((s) => s.trim().toLowerCase());
  const valid: ToolName[] = [];
  for (const t of split) {
    if (t === "trivy" || t === "semgrep" || t === "gitleaks") {
      valid.push(t);
    }
  }
  return valid.length > 0 ? valid : ["trivy", "semgrep", "gitleaks"];
}

function validateTool(val: string): ToolName | undefined {
  const t = val.trim().toLowerCase();
  if (t === "trivy" || t === "semgrep" || t === "gitleaks") {
    return t;
  }
  return undefined;
}

export async function runNonInteractiveScan(
  options: CliScanArgs,
): Promise<number> {
  const summary: ScanSummary = await runScan(options.tools, undefined, {
    failTool: options.failTool,
    targetPath: options.repo,
  });

  if (options.json) {
    // Output valid JSON with no colors to stdout
    process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  } else {
    process.stdout.write(`Scan completed for ${options.repo ?? "."}\n`);
    for (const t of summary.tools) {
      process.stdout.write(
        `  ${t.tool}: ${t.status} (${t.durationSec.toFixed(1)}s)\n`,
      );
    }
    process.stdout.write(`Total time: ${summary.totalDurationSec}s\n`);
    if (summary.savedPath) {
      process.stdout.write(`Saved: ${summary.savedPath}\n`);
    } else {
      process.stdout.write("No report saved\n");
    }
  }

  const anyFailed = summary.tools.some((t) => t.status === "failed");
  return anyFailed ? 1 : 0;
}
