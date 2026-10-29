export {
  validateSarifDetailed,
  validateSarif,
  assertValidSarif,
  SarifValidationError,
  type SarifValidationErrorDetail,
  type SarifValidationResult,
} from "./validator.js";

export {
  parseSarif,
  readSarifFile,
  writeSarifFile,
} from "./parser.js";

export {
  sarifLevelToSeverity,
  countFindings,
  normalizeToolName,
  extractFindings,
  SarifExtractionError,
  type RuleMetadata,
} from "./findings.js";

export {
  mergeSarif,
  buildSummary,
  SarifMergeError,
} from "./merger.js";

