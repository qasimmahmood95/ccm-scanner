import { readFileSync } from "node:fs";
import { allChecks } from "../../src/controls/index.js";
import { createRegistry, evaluate, ingestTerraformPlan, type Verdict } from "../../src/index.js";

/**
 * The full verdict stream for a fixture, rendered as stable text.
 *
 * The existing goldens are built from stub checks, so they pin the *renderers*
 * and nothing about what a real check concludes. Every evidence regression this
 * project has had — a Pass citing an empty CIDR list, a satellite described as
 * holding logs it does not hold, a reason asserting an attribute was unknown
 * when it was merely absent — was invisible to the suite because no golden
 * covered real output. This one does.
 *
 * Reasons and evidence are included verbatim: the report is the deliverable,
 * and a sentence that misdescribes the input is a defect in it.
 */
export const FIXTURE_GOLDEN_DIR = new URL("../__golden__/", import.meta.url);

export function scanFixture(fixture: string): readonly Verdict[] {
  const raw = readFileSync(new URL(`../../fixtures/${fixture}`, import.meta.url), "utf8");
  const { model } = ingestTerraformPlan(raw, fixture);
  return evaluate(createRegistry(allChecks).select(), model);
}

function renderEvidence(verdict: Verdict): readonly string[] {
  return verdict.evidence.map((item) => {
    const attribute = item.attribute === undefined ? "" : `.${item.attribute}`;
    const expected = item.expected === undefined ? "" : `\n      expected: ${item.expected}`;
    return (
      `    - ${item.resourceAddress}${attribute}\n` +
      `      observed: ${JSON.stringify(item.observed)}${expected}`
    );
  });
}

/** Deterministic text for one fixture's verdicts, ready to compare to a golden. */
export function renderVerdicts(fixture: string): string {
  const lines = [`# ${fixture}`, ""];
  for (const verdict of scanFixture(fixture)) {
    lines.push(`${verdict.status.toUpperCase()}  ${verdict.ccmId}  ${verdict.checkId}`);
    lines.push(`    title: ${verdict.ccmTitle}`);
    if (verdict.reason !== undefined) {
      lines.push(`    reason: ${verdict.reason}`);
    }
    lines.push(...renderEvidence(verdict));
    lines.push("");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export const FIXTURES = [
  "compliant/terraform-plan.json",
  "non-compliant/terraform-plan.json",
] as const;

/**
 * One golden per fixture. The whole path is flattened rather than just its
 * first segment, so a second fixture in the same directory gets its own file
 * instead of silently overwriting the first's.
 */
export function goldenPath(fixture: string): URL {
  const slug = fixture.replace(/\.json$/, "").replaceAll("/", "--");
  return new URL(`${slug}-verdicts.txt`, FIXTURE_GOLDEN_DIR);
}
