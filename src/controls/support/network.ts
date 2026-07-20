/**
 * Normalising AWS security-group ingress into one shape.
 *
 * Terraform expresses the same rule three ways — inline `ingress` blocks on
 * `aws_security_group`, standalone `aws_security_group_rule`, and the newer
 * `aws_vpc_security_group_ingress_rule` — with different attribute names for
 * the same concepts. Checks should reason about ports and CIDRs, not about
 * which resource type happened to declare them.
 */
import {
  isUnknown,
  resourcesOfType,
  type Resource,
  type ResourceModel,
} from "../../model/resource.js";
import { readAttribute } from "./attributes.js";

/**
 * Ports whose exposure to the whole internet is the finding, not the context.
 * Remote administration and database wire protocols: reachable from anywhere
 * means the only thing standing between the internet and the host is a
 * credential.
 */
export const SENSITIVE_PORTS: readonly number[] = [22, 3389, 3306, 5432, 1433, 27017, 6379];

/** CIDRs that mean "from anywhere". */
const WORLD_CIDRS = new Set(["0.0.0.0/0", "::/0"]);

const MAX_PORT = 65535;

/** Protocol values meaning "every protocol", so TCP is included. */
const ALL_PROTOCOLS = new Set(["-1", "all"]);

/**
 * The only protocols that actually carry ports. Terraform accepts a name or an
 * IANA number, so both forms are listed.
 */
const PORT_PROTOCOLS = new Set(["tcp", "udp", "sctp", "6", "17", "132"]);

/**
 * Protocols whose `from_port`/`to_port` are not ports.
 *
 * ICMP reuses the fields for type and code, so reading `from_port: 8` as
 * "port 8" and testing it against the sensitive list would be comparing
 * unrelated numbers. The rest have no port concept at all, and Terraform makes
 * the port fields optional for them.
 */
const PORTLESS_PROTOCOLS = new Set([
  "icmp",
  "icmpv6",
  "1",
  "58",
  "esp",
  "ah",
  "gre",
  "50",
  "51",
  "47",
]);

/** One ingress rule, whatever declared it. */
export interface IngressRule {
  /** Resource address, with a block index when the rule was inline. */
  readonly source: string;
  /** The attribute an evidence entry should cite. */
  readonly attribute: string;
  readonly fromPort: number | undefined;
  readonly toPort: number | undefined;
  /** Lowercased; `-1` means every protocol. */
  readonly protocol: string;
  readonly cidrs: readonly string[];
}

/**
 * An ingress rule we could not judge, and why.
 *
 * The cause is carried for the same reason `correlate.ts` carries one: a
 * reason that says "not known until apply" about an attribute that is merely
 * absent, or present and malformed, misdescribes the input it is quoting.
 */
export interface UnreadableRule {
  readonly source: string;
  readonly attribute: string;
  readonly cause: "unknown" | "unreadable" | "unrecognised";
}

export interface IngressScan {
  readonly rules: readonly IngressRule[];
  readonly unreadable: readonly UnreadableRule[];
}

function asPort(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isInteger(value)) {
    return value;
  }
  // Terraform sometimes carries ports as strings.
  if (typeof value === "string" && /^-?\d+$/.test(value)) {
    return Number.parseInt(value, 10);
  }
  return undefined;
}

function asCidrList(value: unknown): readonly string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry): entry is string => typeof entry === "string");
}

/**
 * Terraform accepts a protocol as a name or an IANA number, so a numeric value
 * is legitimate. Anything else is unreadable — and must stay `undefined` rather
 * than defaulting to `-1`, which means *every protocol* and would fabricate a
 * "all ports open to the world" failure out of a missing field.
 */
function asProtocol(value: unknown): string | undefined {
  if (typeof value === "string" && value !== "") {
    return value.toLowerCase();
  }
  return typeof value === "number" ? String(value) : undefined;
}

/**
 * Accepts a rule only if the fields the verdict depends on are readable.
 *
 * A rule missing its protocol, or missing its ports where the protocol makes
 * ports meaningful, cannot be judged either way — reporting it as compliant
 * would be a Pass with nothing behind it.
 */
function classify(
  rule: Omit<IngressRule, "protocol"> & { readonly protocol: string | undefined },
  into: { rules: IngressRule[]; unreadable: UnreadableRule[] },
): void {
  if (rule.protocol === undefined) {
    into.unreadable.push({ source: rule.source, attribute: "protocol", cause: "unreadable" });
    return;
  }
  const settled: IngressRule = { ...rule, protocol: rule.protocol };

  // Recognised by allowlist, exactly as CEK-04 treats TLS policies: a protocol
  // we have not classified must not be assumed portless, because that would
  // silently exempt it from the whole check.
  if (
    !ALL_PROTOCOLS.has(settled.protocol) &&
    !PORT_PROTOCOLS.has(settled.protocol) &&
    !PORTLESS_PROTOCOLS.has(settled.protocol)
  ) {
    into.unreadable.push({
      source: settled.source,
      attribute: "protocol",
      cause: "unrecognised",
    });
    return;
  }

  const portsMatter = PORT_PROTOCOLS.has(settled.protocol);
  if (portsMatter && (settled.fromPort === undefined || settled.toPort === undefined)) {
    // Name the ports, not the CIDR attribute this rule happens to be filed
    // under — the CIDR was read perfectly well.
    into.unreadable.push({
      source: settled.source,
      attribute: settled.fromPort === undefined ? "from_port" : "to_port",
      cause: "unreadable",
    });
    return;
  }
  into.rules.push(settled);
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** Inline `ingress` blocks on `aws_security_group` / `aws_default_security_group`. */
function inlineRules(resource: Resource, attribute: string): IngressScan {
  if (isUnknown(resource, attribute)) {
    return { rules: [], unreadable: [{ source: resource.address, attribute, cause: "unknown" }] };
  }
  const read = readAttribute(resource, attribute);
  if (read.kind !== "value") {
    return { rules: [], unreadable: [] };
  }
  const blocks = Array.isArray(read.value) ? read.value : [read.value];
  const rules: IngressRule[] = [];
  const unreadable: UnreadableRule[] = [];

  blocks.forEach((block, index) => {
    const fields = record(block);
    const cited = `${attribute}[${String(index)}]`;
    if (fields === undefined) {
      unreadable.push({ source: resource.address, attribute: cited, cause: "unreadable" });
      return;
    }
    classify(
      {
        source: resource.address,
        attribute: cited,
        fromPort: asPort(fields.from_port),
        toPort: asPort(fields.to_port),
        protocol: asProtocol(fields.protocol),
        cidrs: [...asCidrList(fields.cidr_blocks), ...asCidrList(fields.ipv6_cidr_blocks)],
      },
      { rules, unreadable },
    );
  });

  return { rules, unreadable };
}

/**
 * Builds the one rule a standalone resource declares.
 *
 * Every attribute the verdict reads must be guarded for unknown-ness —
 * including both CIDR families. Missing one produces a Pass whose evidence is
 * an empty CIDR list, which is a claim of compliance derived from a value the
 * input never supplied.
 */
function singleRule(
  resource: Resource,
  guarded: readonly string[],
  build: (read: (name: string) => unknown) => Omit<IngressRule, "protocol"> & {
    readonly protocol: string | undefined;
  },
): IngressScan {
  for (const attribute of guarded) {
    if (isUnknown(resource, attribute)) {
      return { rules: [], unreadable: [{ source: resource.address, attribute, cause: "unknown" }] };
    }
  }
  const read = (name: string): unknown => {
    const value = readAttribute(resource, name);
    return value.kind === "value" ? value.value : undefined;
  };
  const rules: IngressRule[] = [];
  const unreadable: UnreadableRule[] = [];
  classify(build(read), { rules, unreadable });
  return { rules, unreadable };
}

function standaloneRule(resource: Resource): IngressScan {
  return singleRule(
    resource,
    ["from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks", "protocol"],
    (read) => ({
      source: resource.address,
      attribute: "cidr_blocks",
      fromPort: asPort(read("from_port")),
      toPort: asPort(read("to_port")),
      protocol: asProtocol(read("protocol")),
      cidrs: [...asCidrList(read("cidr_blocks")), ...asCidrList(read("ipv6_cidr_blocks"))],
    }),
  );
}

function vpcIngressRule(resource: Resource): IngressScan {
  return singleRule(
    resource,
    ["from_port", "to_port", "cidr_ipv4", "cidr_ipv6", "ip_protocol"],
    (read) => ({
      source: resource.address,
      attribute: "cidr_ipv4",
      fromPort: asPort(read("from_port")),
      toPort: asPort(read("to_port")),
      protocol: asProtocol(read("ip_protocol")),
      cidrs: [...asCidrList(read("cidr_ipv4")), ...asCidrList(read("cidr_ipv6"))],
    }),
  );
}

/** Every ingress rule in the model, from all three declaration styles. */
export function collectIngressRules(model: ResourceModel): IngressScan {
  const rules: IngressRule[] = [];
  const unreadable: UnreadableRule[] = [];
  const absorb = (scan: IngressScan): void => {
    rules.push(...scan.rules);
    unreadable.push(...scan.unreadable);
  };

  // The default security group's rules are ingress rules too — an open port on
  // the group everything falls back to is worse, not out of scope.
  for (const type of ["aws_security_group", "aws_default_security_group"]) {
    for (const group of resourcesOfType(model, type)) {
      absorb(inlineRules(group, "ingress"));
    }
  }
  for (const rule of resourcesOfType(model, "aws_security_group_rule")) {
    // The same resource type declares egress too, and an egress rule to the
    // world is ordinary. But only an explicit "egress" is safe to drop: an
    // unknown or unrecognised type means we do not know whether we are looking
    // at an ingress rule, and silently skipping it would let a world-open :22
    // rule pass unexamined.
    const type = readAttribute(rule, "type");
    const direction = type.kind === "value" ? type.value : undefined;
    if (direction === "egress") {
      continue;
    }
    if (direction === "ingress") {
      absorb(standaloneRule(rule));
    } else {
      unreadable.push({
        source: rule.address,
        attribute: "type",
        cause: type.kind === "unknown" ? "unknown" : "unreadable",
      });
    }
  }
  for (const rule of resourcesOfType(model, "aws_vpc_security_group_ingress_rule")) {
    absorb(vpcIngressRule(rule));
  }

  return { rules, unreadable };
}

/** True when the rule admits traffic from anywhere on the internet. */
export function openToWorld(rule: IngressRule): boolean {
  return rule.cidrs.some((cidr) => WORLD_CIDRS.has(cidr.trim()));
}

/** True when the rule's protocol makes its port fields real ports. */
function hasPortSemantics(rule: IngressRule): boolean {
  return PORT_PROTOCOLS.has(rule.protocol);
}

/** True when the rule covers every port — either explicitly or by protocol. */
export function coversAllPorts(rule: IngressRule): boolean {
  if (ALL_PROTOCOLS.has(rule.protocol)) {
    return true;
  }
  if (!hasPortSemantics(rule)) {
    return false;
  }
  return rule.fromPort === 0 && rule.toPort === MAX_PORT;
}

/**
 * Which sensitive ports a rule's range reaches.
 *
 * The range is tested for *overlap*, not equality: `from_port: 20, to_port: 25`
 * never equals 22 but certainly reaches it.
 */
export function sensitivePortsCovered(rule: IngressRule): readonly number[] {
  if (ALL_PROTOCOLS.has(rule.protocol)) {
    return SENSITIVE_PORTS;
  }
  if (!hasPortSemantics(rule) || rule.fromPort === undefined || rule.toPort === undefined) {
    return [];
  }
  const low = Math.min(rule.fromPort, rule.toPort);
  const high = Math.max(rule.fromPort, rule.toPort);
  return SENSITIVE_PORTS.filter((port) => port >= low && port <= high);
}
