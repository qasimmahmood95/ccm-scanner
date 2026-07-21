/**
 * The scan pipeline, with no I/O in it.
 *
 * Reading the input and writing the evidence pack happen in `index.ts`; this
 * takes the document as a string and returns the artifacts to write. That keeps
 * the whole pipeline testable without a filesystem, and keeps the read-only
 * posture legible: nothing here can reach a file, a process or a network.
 */
import { allChecks } from "../controls/index.js";
import { createRegistry, evaluate, type ValidatedCheck } from "../engine/index.js";
import { ingest } from "../ingest/index.js";
import { CCM_VERSION } from "../model/ccm.js";
import { buildReport, redactSensitive, renderJson, renderSummary } from "../report/index.js";
import type { Report, ToolInfo } from "../report/index.js";
import { sha256Hex } from "../util/digest.js";
import { UsageError, type ControlSelection, type ScanOptions } from "./options.js";

/** A file the CLI should write, relative to `--out`. */
export interface Artifact {
  readonly name: string;
  readonly contents: string;
}

export interface ScanResult {
  readonly report: Report;
  readonly artifacts: readonly Artifact[];
  /** 0 = nothing failed (or `--fail-on none`); 1 = at least one control failed. */
  readonly exitCode: number;
}

export interface ScanRequest {
  /** The input document, already read. */
  readonly raw: string;
  /** How the input is identified in the report, e.g. `terraform-plan:plan.json`. */
  readonly source: string;
  readonly options: ScanOptions;
  readonly tool: ToolInfo;
  /** Injected so a report is reproducible for a fixed input and timestamp. */
  readonly generatedAt: string;
}

/**
 * Resolves the selector to a check list.
 *
 * The registry's selector is a conjunction — a check must match every field
 * given — so domains and control ids are selected separately and unioned here.
 * Selecting each independently also keeps the registry's own error messages,
 * which name the domain or control that matched nothing.
 */
function selectChecks(selection: ControlSelection): readonly ValidatedCheck[] {
  const registry = createRegistry(allChecks);
  if (selection.kind === "all") {
    return registry.select();
  }

  const wanted = new Set<string>();
  if (selection.domains.length > 0) {
    for (const check of registry.select({ domains: selection.domains })) {
      wanted.add(check.checkId);
    }
  }
  if (selection.ccmIds.length > 0) {
    for (const check of registry.select({ ccmIds: selection.ccmIds })) {
      wanted.add(check.checkId);
    }
  }
  // `select()` refuses a selector that matches nothing; this is the same guard
  // for the union, which reaches `select()` only through its parts. A selection
  // that resolved to no checks would otherwise produce a report with no
  // verdicts, headline "pass" and exit code 0 — a vacuous clean bill of health.
  if (wanted.size === 0) {
    throw new UsageError("--controls matched no registered checks.");
  }

  // Filtered from the registry's own ordering rather than from insertion order,
  // so the selection is deterministic however it was spelled.
  return registry.checks.filter((check) => wanted.has(check.checkId));
}

export function runScan(request: ScanRequest): ScanResult {
  const { raw, source, options, tool, generatedAt } = request;

  const checks = selectChecks(options.controls);
  const { model, warnings } = ingest(raw, source, options.inputFormat);
  const verdicts = evaluate(checks, model);

  // Redact before building, so no renderer can emit a value Terraform marked
  // sensitive and no future renderer has to remember to.
  const report = buildReport(
    redactSensitive(verdicts, model),
    {
      tool,
      ccmVersion: CCM_VERSION,
      input: { source, digest: sha256Hex(raw) },
      generatedAt,
    },
    warnings,
  );

  const artifacts: Artifact[] = [];
  if (options.format === "json" || options.format === "both") {
    artifacts.push({ name: "report.json", contents: renderJson(report) });
  }
  if (options.format === "md" || options.format === "both") {
    artifacts.push({ name: "summary.md", contents: renderSummary(report) });
  }

  return {
    report,
    artifacts,
    // A failing control is the only thing that changes the exit code. Warnings
    // do not: they say the input was not fully read, which is reported in the
    // artifact rather than escalated into a build failure.
    exitCode: report.headline === "fail" && options.failOn === "fail" ? 1 : 0,
  };
}

/** Re-exported so `index.ts` can distinguish user error from a scanner bug. */
export { UsageError };
