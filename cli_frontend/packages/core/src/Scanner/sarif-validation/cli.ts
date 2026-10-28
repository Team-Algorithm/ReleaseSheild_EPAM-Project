#!/usr/bin/env node
import { mergeSarifFiles } from "./merger.js";
import { SarifValidationError, validateSarif } from "./validator.js";

function usage(): never {
  console.error(
    "Usage:\n  sarif-check <input.sarif> [--schema <schema.json>]\n" +
    "  sarif-merge <output.sarif> <input1.sarif> <input2.sarif> [...] [--schema <schema.json>]",
  );
  process.exit(2);
}

function takeSchema(args: string[]): { args: string[]; schema?: string } {
  const index = args.indexOf("--schema");
  if (index < 0) return { args };
  if (!args[index + 1]) usage();
  const schema = args[index + 1];
  return { args: args.filter((_, i) => i !== index && i !== index + 1), schema };
}

const [command, ...rawArgs] = process.argv.slice(2);
const parsed = takeSchema(rawArgs);

try {
  if (command === "check") {
    if (parsed.args.length !== 1) usage();
    validateSarif(parsed.args[0], parsed.schema);
    console.log(`VALID: ${parsed.args[0]} conforms to SARIF 2.1.0.`);
  } else if (command === "merge") {
    if (parsed.args.length < 2) usage();
    const [output, ...inputs] = parsed.args;
    mergeSarifFiles(inputs, { schemaPath: parsed.schema, outputPath: output });
    console.log(`MERGED ${inputs.length} report(s) -> ${output}`);
  } else {
    usage();
  }
} catch (error) {
  const message =
    error instanceof SarifValidationError || error instanceof Error
      ? error.message
      : String(error);
  console.error(`ERROR: ${message}`);
  process.exitCode = 1;
}
