/**
 * Stub scaffolding for M1.
 *
 * These are NOT real controls — they exist only to exercise the registry,
 * engine, and renderers before the actual checks land in M3/M4. They use real
 * CCM ids so the rendered golden report is representative.
 *
 * The model deliberately contains TWO buckets so that one control (CEK-03)
 * produces two findings: that is what keeps the controls-vs-findings
 * distinction honest in the golden files.
 */
import {
  CCM_VERSION,
  buildReport,
  createRegistry,
  evaluate,
  fail,
  notApplicable,
  pass,
  resourcesOfType,
  sha256Hex,
  type Check,
  type ControlRef,
  type Report,
  type ResourceModel,
  type RunMetadata,
} from "../../src/index.js";

export const stubModel: ResourceModel = {
  source: "memory:stub-model",
  resources: [
    {
      address: "aws_s3_bucket.archive",
      type: "aws_s3_bucket",
      name: "archive",
      provider: "aws",
      unknownAttributes: [],
      sensitiveAttributes: [],
      attributes: {
        bucket: "example-archive",
        server_side_encryption: "aws:kms",
      },
    },
    {
      address: "aws_s3_bucket.logs",
      type: "aws_s3_bucket",
      name: "logs",
      provider: "aws",
      unknownAttributes: [],
      sensitiveAttributes: [],
      attributes: {
        bucket: "example-logs",
        server_side_encryption: "aws:kms",
      },
    },
    {
      address: "aws_security_group.web",
      type: "aws_security_group",
      name: "web",
      provider: "aws",
      unknownAttributes: [],
      sensitiveAttributes: [],
      attributes: {
        ingress: [{ from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] }],
      },
    },
  ],
};

const CEK_03: ControlRef = {
  ccmId: "CEK-03",
  ccmTitle: "Data Encryption",
  checkId: "cek/encryption-at-rest",
};

const IVS_03: ControlRef = {
  ccmId: "IVS-03",
  ccmTitle: "Network Security",
  checkId: "ivs/no-open-admin-ports",
};

const IAM_08: ControlRef = {
  ccmId: "IAM-08",
  ccmTitle: "User Access Review",
  checkId: "iam/na-process-control",
};

const encryptionAtRest: Check = {
  ...CEK_03,
  run: (model) =>
    resourcesOfType(model, "aws_s3_bucket").map((resource) =>
      pass([
        {
          resourceAddress: resource.address,
          attribute: "server_side_encryption",
          observed: resource.attributes.server_side_encryption,
          expected: "server-side encryption enabled",
        },
      ]),
    ),
};

const noOpenAdminPorts: Check = {
  ...IVS_03,
  run: (model) =>
    resourcesOfType(model, "aws_security_group").map((resource) =>
      fail([
        {
          resourceAddress: resource.address,
          attribute: "ingress",
          observed: resource.attributes.ingress,
          expected: "no ingress from 0.0.0.0/0 to an administrative port",
        },
      ]),
    ),
};

const userAccessReview: Check = {
  ...IAM_08,
  run: () => [
    notApplicable(
      "Periodic access review is a process control with no signal in declarative infrastructure.",
    ),
  ],
};

/** Deliberately not in ccmId order, so tests can prove ordering is normalised. */
export const stubChecks: readonly Check[] = [noOpenAdminPorts, userAccessReview, encryptionAtRest];

/** Fixed metadata — the timestamp is injected so reports stay reproducible. */
export const fixedMetadata: RunMetadata = {
  tool: { name: "ccm-scanner", version: "0.0.0-test" },
  ccmVersion: CCM_VERSION,
  input: {
    source: stubModel.source,
    digest: sha256Hex(JSON.stringify(stubModel)),
  },
  generatedAt: "2026-01-01T00:00:00.000Z",
};

/** The canonical report used by the golden-file tests and the golden generator. */
export function buildStubReport(warnings: readonly string[] = []): Report {
  const registry = createRegistry(stubChecks);
  return buildReport(evaluate(registry.select(), stubModel), fixedMetadata, warnings);
}

export const GOLDEN_DIR = new URL("../__golden__/", import.meta.url);
export const GOLDEN_JSON = new URL("report.json", GOLDEN_DIR);
export const GOLDEN_MD = new URL("report.md", GOLDEN_DIR);
