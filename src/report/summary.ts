import { CCM_DOMAIN_TITLES, domainOfCcmId, type CcmDomain } from "../model/ccm.js";
import type { Status, Verdict } from "../model/verdict.js";
import type { Report } from "./types.js";

const STATUS_LABEL: Readonly<Record<Status, string>> = {
  pass: "PASS",
  fail: "FAIL",
  not_applicable: "N/A",
};

/** Within a domain: failures first, then not-applicable, then a compact pass list. */
const DETAILED_STATUSES = ["fail", "not_applicable"] as const;

function formatValue(value: unknown): string {
  if (value === undefined) {
    return "null";
  }
  return JSON.stringify(value) ?? "null";
}

function domainHeading(domain: CcmDomain): string {
  return `${domain} — ${CCM_DOMAIN_TITLES[domain]}`;
}

function countsSentence(report: Report): string {
  const { pass, fail, notApplicable, total } = report.totals;
  const noun = total === 1 ? "control" : "controls";
  return `${pass} pass, ${fail} fail, ${notApplicable} not applicable (${total} ${noun})`;
}

/** Renders a Fail or N/A verdict in full: the check, its reason, and its evidence. */
function renderDetailed(verdict: Verdict, lines: string[]): void {
  lines.push(`### ${STATUS_LABEL[verdict.status]} · ${verdict.ccmId} ${verdict.ccmTitle}`);
  lines.push("");
  lines.push(`Check: \`${verdict.checkId}\``);
  lines.push("");

  if (verdict.reason !== undefined) {
    lines.push(`Reason: ${verdict.reason}`);
    lines.push("");
  }

  for (const item of verdict.evidence) {
    const where =
      item.attribute === undefined
        ? `\`${item.resourceAddress}\``
        : `\`${item.resourceAddress}\` — \`${item.attribute}\``;
    lines.push(`- ${where}`);
    lines.push(`  - observed: \`${formatValue(item.observed)}\``);
    if (item.expected !== undefined) {
      lines.push(`  - expected: ${item.expected}`);
    }
  }
  if (verdict.evidence.length > 0) {
    lines.push("");
  }
}

/**
 * Renders the human-readable companion to the JSON report: grouped by CCM
 * domain, with roll-up counts and every Fail / N/A expanded with its evidence
 * or reason. Pure and deterministic — no clock, no locale-sensitive formatting.
 */
export function renderSummary(report: Report): string {
  const lines: string[] = [];

  lines.push("# ccm-scanner report");
  lines.push("");
  lines.push(`**Result: ${report.headline.toUpperCase()}** — ${countsSentence(report)}`);
  lines.push("");
  lines.push("| Field | Value |");
  lines.push("| --- | --- |");
  lines.push(`| Tool | ${report.metadata.tool.name} ${report.metadata.tool.version} |`);
  lines.push(`| CCM version | ${report.metadata.ccmVersion} |`);
  lines.push(`| Input | \`${report.metadata.input.source}\` |`);
  lines.push(`| Input digest | \`sha256:${report.metadata.input.digest}\` |`);
  lines.push(`| Generated | ${report.metadata.generatedAt} |`);
  lines.push("");

  if (report.domains.length > 0) {
    lines.push("## Coverage by domain");
    lines.push("");
    lines.push("| Domain | Pass | Fail | N/A | Total |");
    lines.push("| --- | ---: | ---: | ---: | ---: |");
    for (const rollup of report.domains) {
      lines.push(
        `| ${domainHeading(rollup.domain)} | ${rollup.pass} | ${rollup.fail} | ` +
          `${rollup.notApplicable} | ${rollup.total} |`,
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

    for (const status of DETAILED_STATUSES) {
      for (const verdict of inDomain.filter((candidate) => candidate.status === status)) {
        renderDetailed(verdict, lines);
      }
    }

    const passing = inDomain.filter((verdict) => verdict.status === "pass");
    if (passing.length > 0) {
      lines.push("### Passing");
      lines.push("");
      for (const verdict of passing) {
        lines.push(`- ${verdict.ccmId} ${verdict.ccmTitle} (\`${verdict.checkId}\`)`);
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
