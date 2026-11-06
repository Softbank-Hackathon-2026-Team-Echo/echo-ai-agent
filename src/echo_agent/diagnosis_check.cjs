// Parse only. Customer JavaScript is NEVER executed (no runInContext/runInThisContext).
// Python extracts classic inline scripts and preserves their HTML line offsets.
"use strict";
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(process.argv[2] || 0, "utf8"));
const issues = [];
for (const script of input.scripts) {
  try {
    new vm.Script(script.code, { filename: script.path, lineOffset: script.lineOffset });
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    const first = String(error.stack).split("\n")[0];
    const match = /:(\d+)$/.exec(first);
    issues.push({ path: script.path, line: match ? Number(match[1]) : script.lineOffset + 1,
                  message: String(error.message).slice(0, 300) });
  }
}
process.stdout.write(JSON.stringify({ version: process.version, issues }) + "\n");
process.exitCode = issues.length ? 1 : 0;
