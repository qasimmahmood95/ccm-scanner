/**
 * Regenerates the golden report files.
 *
 * Run `npm run goldens:update` after an intentional change to the report shape
 * or renderers, then review the diff — the golden files are the record of what
 * the tool actually emits.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { renderJson, renderSummary } from "../src/report/index.js";
import { GOLDEN_DIR, GOLDEN_JSON, GOLDEN_MD, buildStubReport } from "../test/support/stubs.js";

const report = buildStubReport();

mkdirSync(GOLDEN_DIR, { recursive: true });
writeFileSync(GOLDEN_JSON, renderJson(report), "utf8");
writeFileSync(GOLDEN_MD, renderSummary(report), "utf8");

process.stdout.write("golden files updated\n");
