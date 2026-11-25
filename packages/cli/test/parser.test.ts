import { describe, it, expect } from "vitest";
import { parseCommand } from "../src/commands/parser.js";

describe("parseCommand", () => {
  it("handles empty or whitespace string", () => {
    expect(parseCommand("")).toEqual({
      raw: "",
      name: "",
      args: [],
      flags: {},
    });
    expect(parseCommand("   ")).toEqual({
      raw: "",
      name: "",
      args: [],
      flags: {},
    });
  });

  it("parses command name without leading slash", () => {
    const res = parseCommand("scan");
    expect(res.name).toBe("scan");
    expect(res.args).toEqual([]);
    expect(res.flags).toEqual({});
  });

  it("parses command name with leading slash", () => {
    const res = parseCommand("/scan");
    expect(res.name).toBe("scan");
    expect(res.args).toEqual([]);
    expect(res.flags).toEqual({});
  });

  it("parses positional arguments", () => {
    const res = parseCommand("/scan ./NodeGoat");
    expect(res.name).toBe("scan");
    expect(res.args).toEqual(["./NodeGoat"]);
  });

  it("parses boolean flags", () => {
    const res = parseCommand("/scan --json");
    expect(res.flags["json"]).toBe(true);
  });

  it("parses value flags separated by space", () => {
    const res = parseCommand("/findings --severity high");
    expect(res.flags["severity"]).toBe("high");
  });

  it("parses value flags separated by equal sign", () => {
    const res = parseCommand("/findings --severity=medium");
    expect(res.flags["severity"]).toBe("medium");
  });

  it("parses comma-separated flags as an array", () => {
    const res = parseCommand("/scan --tools trivy,semgrep");
    expect(res.flags["tools"]).toEqual(["trivy", "semgrep"]);
  });

  it("parses quoted arguments with spaces", () => {
    const res = parseCommand('/scan "my project folder" --tool="special tool"');
    expect(res.args).toEqual(["my project folder"]);
    expect(res.flags["tool"]).toBe("special tool");
  });
});
