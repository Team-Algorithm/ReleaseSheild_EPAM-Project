import type { ParsedCommand } from './parser.js';

export interface CommandContext {
  [key: string]: any;
}

export interface CommandEntry {
  name: string;
  description: string;
  usage: string;
  handler: (cmd: ParsedCommand, ctx?: CommandContext) => Promise<void> | void;
}

export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }

  return dp[m][n];
}

export class CommandRegistry {
  private commands: Map<string, CommandEntry> = new Map();

  register(command: CommandEntry): void {
    const key = command.name.toLowerCase().replace(/^\//, '');
    this.commands.set(key, command);
  }

  get(name: string): CommandEntry | undefined {
    const key = name.toLowerCase().replace(/^\//, '');
    return this.commands.get(key);
  }

  getAll(): CommandEntry[] {
    return Array.from(this.commands.values());
  }

  suggestClosest(inputName: string): CommandEntry | undefined {
    const clean = inputName.toLowerCase().replace(/^\//, '');
    let closest: CommandEntry | undefined;
    let minDistance = Infinity;

    for (const [name, entry] of this.commands.entries()) {
      const dist = levenshteinDistance(clean, name);
      if (dist < minDistance && dist <= 3) {
        minDistance = dist;
        closest = entry;
      }
    }

    return closest;
  }
}
