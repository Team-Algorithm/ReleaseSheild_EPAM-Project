export interface ParsedCommand {
  raw: string;
  name: string;
  args: string[];
  flags: Record<string, string | boolean | string[]>;
}

export function parseCommand(input: string): ParsedCommand {
  const trimmed = input.trim();
  if (!trimmed) {
    return { raw: '', name: '', args: [], flags: {} };
  }

  // Tokenize while respecting quotes if any
  const tokens: string[] = [];
  const regex = /[^\s"']+|"([^"]*)"|'([^']*)'/g;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(trimmed)) !== null) {
    if (match[1] !== undefined) {
      tokens.push(match[1]);
    } else if (match[2] !== undefined) {
      tokens.push(match[2]);
    } else {
      tokens.push(match[0]);
    }
  }

  if (tokens.length === 0) {
    return { raw: trimmed, name: '', args: [], flags: {} };
  }

  // First token is command name, strip leading slash
  const rawName = tokens[0];
  const name = rawName.startsWith('/') ? rawName.slice(1) : rawName;
  const args: string[] = [];
  const flags: Record<string, string | boolean | string[]> = {};

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.startsWith('--')) {
      const equalIndex = token.indexOf('=');
      let flagKey: string;
      let flagVal: string | boolean;

      if (equalIndex !== -1) {
        flagKey = token.slice(2, equalIndex);
        const inlineVal = token.slice(equalIndex + 1).replace(/^["']|["']$/g, '');
        if (inlineVal === '' && i + 1 < tokens.length && !tokens[i + 1].startsWith('--')) {
          flagVal = tokens[++i];
        } else {
          flagVal = inlineVal;
        }
      } else {
        flagKey = token.slice(2);
        // Lookahead to see if next token is a value (not starting with --)
        if (i + 1 < tokens.length && !tokens[i + 1].startsWith('--')) {
          flagVal = tokens[i + 1];
          i++;
        } else {
          flagVal = true;
        }
      }

      // If value contains comma, split into string array
      if (typeof flagVal === 'string' && flagVal.includes(',')) {
        flags[flagKey] = flagVal.split(',').map((s) => s.trim()).filter(Boolean);
      } else {
        flags[flagKey] = flagVal;
      }
    } else {
      args.push(token);
    }
  }

  return {
    raw: trimmed,
    name,
    args,
    flags
  };
}
