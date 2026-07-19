import { CCM_DOMAIN_TITLES, domainOfCcmId, type CcmDomain } from "../model/ccm.js";
import type { Status, Verdict } from "../model/verdict.js";
import { compareStrings } from "../util/compare.js";
import { toJsonSafe } from "../util/json-safe.js";
import { groupByControl, statusOfControl } from "./build.js";
import type { Report } from "./types.js";

const STATUS_LABEL: Readonly<Record<Status, string>> = {
  pass: "PASS",
  fail: "FAIL",
  not_applicable: "N/A",
};

/**
 * Resource addresses, attribute values and reasons originate from the scanned
 * infrastructure, so for Markdown purposes they are untrusted. A newline is the
 * dangerous one: it ends the current construct and lets arbitrary text become
 * new document structure — a forged "PASS" section inside a failing report.
 * Everything untrusted is flattened to a single line before it is emitted.
 */
function flatten(text: string): string {
  return text.replace(/\r?\n/g, " ");
}

/** Escapes a value for use inside a Markdown table cell. */
function tableCell(text: string): string {
  return flatten(text).replace(/\|/g, "\\|");
}

/** Wraps text in a fence longer than any backtick run it contains (CommonMark). */
function codeSpan(text: string): string {
  const flat = flatten(text);
  const longestRun = (flat.match(/`+/g) ?? []).reduce((max, run) => Math.max(max, run.length), 0);
  const fence = "`".repeat(longestRun + 1);
  const padded = flat.startsWith("`") || flat.endsWith("`") ? ` ${flat} ` : flat;
  return `${fence}${padded}${fence}`;
}

function formatValue(value: unknown): string {
  return JSON.stringify(toJsonSafe(value)) ?? "null";
}

function domainHeading(domain: CcmDomain): string {
  return `${domain} — ${CCM_DOMAIN_TITLES[domain]}`;
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function countsSentence(report: Report): string {
  const { controls, findings } = report;
  return (
    `${plural(controls.total, "control")} assessed: ${controls.pass} pass, ` +
    `${controls.fail} fail, ${controls.notApplicable} not applicable ` +
    `(from ${plural(findings.total, "finding")})`
  );
}

/** Groups a control's verdicts by the check that produced them, in stable order. */
function groupByCheck(verdicts: readonly Verdict[]): ReadonlyMap<string, Verdict[]> {
  const groups = new Map<string, Verdict[]>();
  for (const verdict of verdicts) {
    const existing = groups.get(verdict.checkId);
    if (existing === undefined) {
      groups.set(verdict.checkId, [verdict]);
    } else {
      existing.push(verdict);
    }
  }
  return new Map([...groups.entries()].sort(([a], [b]) => compareStrings(a, b)));
}

function renderEvidence(verdict: Verdict, lines: string[]): void {
  if (verdict.reason !== undefined) {
    lines.push(`Reason: ${flatten(verdict.reason)}`);
    lines.push("");
  }
  for (const item of verdict.evidence) {
    const where =
      item.attribute === undefined
        ? codeSpan(item.resourceAddress)
        : `${codeSpan(item.resourceAddress)} — ${codeSpan(item.attribute)}`;
    lines.push(`- ${where}`);
    lines.push(`  - observed: ${codeSpan(formatValue(item.observed))}`);
    if (item.expected !== undefined) {
      lines.push(`  - expected: ${flatten(item.expected)}`);
    }
  }
  if (verdict.evidence.length > 0) {
    lines.push("");
  }
}

/** Renders a Fail or N/A control in full: every check, reason and piece of evidence. */
function renderControl(status: Status, verdicts: readonly Verdict[], lines: string[]): void {
  const first = verdicts[0];
  if (first === undefined) {
    return;
  }

  lines.push(`### ${STATUS_LABEL[status]} · ${first.ccmId} ${flatten(first.ccmTitle)}`);
  lines.push("");

  for (const [checkId, group] of groupByCheck(verdicts)) {
    lines.push(`Check: ${codeSpan(checkId)}`);
    lines.push("");
    for (const verdict of group) {
      renderEvidence(verdict, lines);
    }
  }
}

/**
 * Renders a passing control compactly, but still one line per check so that
 * per-check traceability survives, and so a not-applicable check inside an
 * otherwise-passing control still shows its reason.
 */
function renderPassingControl(verdicts: readonly Verdict[], lines: string[]): void {
  const first = verdicts[0];
  if (first === undefined) {
    return;
  }

  lines.push(`- ${first.ccmId} ${flatten(first.ccmTitle)}`);
  for (const [checkId, group] of groupByCheck(verdicts)) {
    const status = statusOfControl(group);
    if (status === "not_applicable") {
      const reason = group.find((verdict) => verdict.reason !== undefined)?.reason ?? "";
      lines.push(`  - ${codeSpan(checkId)} — not applicable: ${flatten(reason)}`);
    } else {
      lines.push(
        `  - ${codeSpan(checkId)} — ${plural(group.length, "finding")} (${STATUS_LABEL[status].toLowerCase()})`,
      );
    }
  }
}

/**
 * Renders the human-readable companion to the JSON report: grouped by CCM
 * domain, with roll-up counts and every failing or not-applicable control
 * expanded with its evidence or reason. Pure and deterministic — no clock, no
 * locale-sensitive formatting.
 */
export function renderSummary(report: Report): string {
  const lines: string[] = [];

  lines.push("# ccm-scanner report");
  lines.push("");
  lines.push(`**Result: ${report.headline.toUpperCase()}** — ${countsSentence(report)}`);
  lines.push("");
  lines.push("| Field | Value |");
  lines.push("| --- | --- |");
  lines.push(
    `| Tool | ${tableCell(`${report.metadata.tool.name} ${report.metadata.tool.version}`)} |`,
  );
  lines.push(`| CCM version | ${tableCell(report.metadata.ccmVersion)} |`);
  lines.push(`| Input | ${tableCell(codeSpan(report.metadata.input.source))} |`);
  lines.push(`| Input digest | ${tableCell(codeSpan(`sha256:${report.metadata.input.digest}`))} |`);
  lines.push(`| Generated | ${tableCell(report.metadata.generatedAt)} |`);
  lines.push("");

  if (report.domains.length > 0) {
    lines.push("## Coverage by domain");
    lines.push("");
    lines.push("| Domain | Controls | Pass | Fail | N/A | Findings |");
    lines.push("| --- | ---: | ---: | ---: | ---: | ---: |");
    for (const rollup of report.domains) {
      lines.push(
        `| ${tableCell(domainHeading(rollup.domain))} | ${rollup.controls.total} | ` +
          `${rollup.controls.pass} | ${rollup.controls.fail} | ` +
          `${rollup.controls.notApplicable} | ${rollup.findings.total} |`,
      );
    }
    lines.push("");
  }

  for (const rollup of report.domains) {
    const inDomain = report.verdicts.filter(
      (verdict) => domainOfCcmId(verdict.ccmId) === rollup.domain,
    );
    lines.push(`## ${domainHeading(rollup.domain)}`);
    lines.push("");

    const passing: Verdict[][] = [];
    for (const [, verdicts] of groupByControl(inDomain)) {
      const status = statusOfControl(verdicts);
      if (status === "pass") {
        passing.push(verdicts);
      } else {
        renderControl(status, verdicts, lines);
      }
    }

    if (passing.length > 0) {
      lines.push("### Passing");
      lines.push("");
      for (const verdicts of passing) {
        renderPassingControl(verdicts, lines);
      }
      lines.push("");
    }
  }

  if (report.verdicts.length === 0) {
    lines.push("_No controls were evaluated._");
    lines.push("");
  }

  const text = lines.join("\n");
  return text.endsWith("\n") ? text : `${text}\n`;
}
