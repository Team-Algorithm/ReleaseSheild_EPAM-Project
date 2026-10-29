import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { spawnSync } from "child_process";

export interface CloneResult {
  success: boolean;
  path?: string;
  error?: string;
}

/**
 * Checks whether a given string is a valid GitHub or remote Git repository URL.
 */
export function isGitUrl(str: string): boolean {
  if (!str) return false;
  const trimmed = str.trim();
  return (
    /^(https?:\/\/|git@)github\.com\/[\w.-]+\/[\w.-]+(\.git)?\/?$/i.test(trimmed) ||
    /^(https?:\/\/|git@)[\w.-]+[:/][\w.-]+\/[\w.-]+(\.git)?\/?$/i.test(trimmed)
  );
}

/**
 * Clones a remote Git repository into a local cache directory safely using argument arrays.
 */
export function cloneGitRepo(
  url: string,
  customBaseDir?: string,
): CloneResult {
  try {
    const trimmedUrl = url.trim().replace(/\/+$/, "");
    const rawName = trimmedUrl.split("/").pop()?.replace(/\.git$/i, "") || "cloned-repo";
    const safeName = rawName.replace(/[^a-zA-Z0-9._-]/g, "_");
    const baseDir = customBaseDir || path.join(os.tmpdir(), "releaseshield-repos");
    const targetDir = path.join(baseDir, safeName);

    // If already cloned and contains .git, return existing clone
    if (fs.existsSync(targetDir) && fs.existsSync(path.join(targetDir, ".git"))) {
      return { success: true, path: targetDir };
    }

    fs.mkdirSync(baseDir, { recursive: true });

    const proc = spawnSync("git", ["clone", "--depth", "1", trimmedUrl, targetDir], {
      stdio: ["ignore", "pipe", "pipe"],
      encoding: "utf-8",
      shell: false,
    });

    if (proc.status === 0 && fs.existsSync(targetDir)) {
      return { success: true, path: targetDir };
    }

    const errorMsg =
      proc.stderr?.trim() ||
      proc.error?.message ||
      `git clone failed with exit code ${proc.status}`;

    return { success: false, error: errorMsg };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

