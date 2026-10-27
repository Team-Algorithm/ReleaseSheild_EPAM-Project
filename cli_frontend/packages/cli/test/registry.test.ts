import { describe, it, expect } from "vitest";
import {
  CommandRegistry,
  levenshteinDistance,
} from "../src/commands/registry.js";

describe("levenshteinDistance", () => {
  it("calculates distance between identical strings as 0", () => {
    expect(levenshteinDistance("scan", "scan")).toBe(0);
  });

  it("calculates distance for single insertion/deletion/substitution", () => {
    expect(levenshteinDistance("scna", "scan")).toBe(2);
    expect(levenshteinDistance("hlp", "help")).toBe(1);
    expect(levenshteinDistance("tols", "tools")).toBe(1);
  });
});

describe("CommandRegistry", () => {
  it("registers and retrieves commands case-insensitively", () => {
    const registry = new CommandRegistry();
    const cmd = {
      name: "scan",
      description: "Run security scan",
      usage: "/scan",
      handler: () => {},
    };

    registry.register(cmd);

    expect(registry.get("scan")).toBe(cmd);
    expect(registry.get("/scan")).toBe(cmd);
    expect(registry.get("SCAN")).toBe(cmd);
    expect(registry.get("/SCAN")).toBe(cmd);
  });

  it("lists all registered commands via getAll()", () => {
    const registry = new CommandRegistry();
    registry.register({
      name: "help",
      description: "Help",
      usage: "/help",
      handler: () => {},
    });
    registry.register({
      name: "tools",
      description: "Tools",
      usage: "/tools",
      handler: () => {},
    });

    const all = registry.getAll();
    expect(all.length).toBe(2);
    expect(all.map((c) => c.name)).toEqual(["help", "tools"]);
  });

  it("suggests closest command on typo", () => {
    const registry = new CommandRegistry();
    registry.register({
      name: "scan",
      description: "Scan",
      usage: "/scan",
      handler: () => {},
    });
    registry.register({
      name: "tools",
      description: "Tools",
      usage: "/tools",
      handler: () => {},
    });
    registry.register({
      name: "help",
      description: "Help",
      usage: "/help",
      handler: () => {},
    });

    expect(registry.suggestClosest("scna")?.name).toBe("scan");
    expect(registry.suggestClosest("/scna")?.name).toBe("scan");
    expect(registry.suggestClosest("hlpe")?.name).toBe("help");
    expect(registry.suggestClosest("tols")?.name).toBe("tools");
  });

  it("returns undefined if no command is close enough", () => {
    const registry = new CommandRegistry();
    registry.register({
      name: "scan",
      description: "Scan",
      usage: "/scan",
      handler: () => {},
    });

    expect(registry.suggestClosest("xyz123456")).toBeUndefined();
  });
});
