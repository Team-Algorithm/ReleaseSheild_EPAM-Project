import { describe, it, expect } from "vitest";
import * as path from "path";
import * as fs from "fs";
import { CommandRegistry } from "../src/commands/registry.js";
import { registerDefaultCommands } from "../src/commands/handlers.js";
import { parseCommand } from "../src/commands/parser.js";
import { parseCliArgs, runNonInteractiveScan } from "../src/nonInteractive.js";

describe("Repository Selection & Validation", () => {
  it("registers /repo in CommandRegistry with usage and description", () => {
    const reg = new CommandRegistry();
    let currentRepo = ".";
    registerDefaultCommands(reg, {
      registry: reg,
      setOutput: () => {},
      exitApp: () => {},
      setPromptDisabled: () => {},
      onScanComplete: () => {},
      getLastSummary: () => null,
      getCurrentRepo: () => currentRepo,
      setCurrentRepo: (r) => {
        currentRepo = r;
      },
    });

    const repoCmd = reg.get("repo");
    expect(repoCmd).toBeDefined();
    expect(repoCmd?.name).toBe("repo");
    expect(repoCmd?.usage).toContain("/repo");
    expect(repoCmd?.description).toContain("repository");
  });

  it("updates session repository path when valid directory is passed", () => {
    const reg = new CommandRegistry();
    let currentRepo = ".";
    let lastOutput: any = null;

    registerDefaultCommands(reg, {
      registry: reg,
      setOutput: (node) => {
        lastOutput = node;
      },
      exitApp: () => {},
      setPromptDisabled: () => {},
      onScanComplete: () => {},
      getLastSummary: () => null,
      getCurrentRepo: () => currentRepo,
      setCurrentRepo: (r) => {
        currentRepo = r;
      },
    });

    const targetDir = path.resolve(".");
    const cmd = parseCommand(`/repo "${targetDir}"`);
    reg.get("repo")?.handler(cmd);

    expect(currentRepo).toBe(targetDir);
    expect(process.env.RELEASESHIELD_REPO).toBe(targetDir);
  });

  it("rejects non-existent directory with an error message", () => {
    const reg = new CommandRegistry();
    let currentRepo = ".";
    let lastOutput: any = null;

    registerDefaultCommands(reg, {
      registry: reg,
      setOutput: (node) => {
        lastOutput = node;
      },
      exitApp: () => {},
      setPromptDisabled: () => {},
      onScanComplete: () => {},
      getLastSummary: () => null,
      getCurrentRepo: () => currentRepo,
      setCurrentRepo: (r) => {
        currentRepo = r;
      },
    });

    const badPath = path.resolve("./does_not_exist_xyz_987");
    const cmd = parseCommand(`/repo "${badPath}"`);
    reg.get("repo")?.handler(cmd);

    // currentRepo should NOT change
    expect(currentRepo).toBe(".");
    expect(lastOutput).not.toBeNull();
  });

  it("rejects files that are not directories", () => {
    const reg = new CommandRegistry();
    let currentRepo = ".";
    let lastOutput: any = null;

    registerDefaultCommands(reg, {
      registry: reg,
      setOutput: (node) => {
        lastOutput = node;
      },
      exitApp: () => {},
      setPromptDisabled: () => {},
      onScanComplete: () => {},
      getLastSummary: () => null,
      getCurrentRepo: () => currentRepo,
      setCurrentRepo: (r) => {
        currentRepo = r;
      },
    });

    const filePath = path.resolve("./package.json");
    const cmd = parseCommand(`/repo "${filePath}"`);
    reg.get("repo")?.handler(cmd);

    expect(currentRepo).toBe(".");
    expect(lastOutput).not.toBeNull();
  });

  it("validates repository path in non-interactive scan mode", async () => {
    const exitCode = await runNonInteractiveScan({
      repo: "./non_existent_dir_99999",
      tools: ["trivy"],
      json: true,
    });

    expect(exitCode).toBe(1);
  });

  it("recognizes Git URLs via isGitUrl", async () => {
    const { isGitUrl } = await import("@releaseshield/core");
    expect(isGitUrl("https://github.com/octocat/Hello-World")).toBe(true);
    expect(isGitUrl("https://github.com/octocat/Hello-World.git")).toBe(true);
    expect(isGitUrl("git@github.com:octocat/Hello-World.git")).toBe(true);
    expect(isGitUrl("C:\\local\\path\\to\\project")).toBe(false);
    expect(isGitUrl("./relative/path")).toBe(false);
    expect(isGitUrl("")).toBe(false);
  });
});


