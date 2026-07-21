# ADR-0004 — A scanner-native snapshot format, produced outside the tool

- **Status:** Accepted
- **Date:** 2026-07-21
- **Supersedes / relates to:** ADR-0002 (why read-only IaC scanning is the default)

## Context

M6 adds a second lane: run the same checks over what a cloud account *actually*
looks like, not only over what Terraform intends. Two decisions follow from
that, and both touch the hard constraints.

**What does the tool consume?** The obvious answer is "raw AWS API output" —
`aws ec2 describe-security-groups`, an AWS Config export. The checks, however,
consume a `ResourceModel` whose vocabulary is *Terraform resource types and
attribute names* (`aws_s3_bucket`, `enable_key_rotation`). Something must map
one onto the other.

**Who calls AWS?** Making the tool issue the calls itself is convenient and
would let it produce the snapshot in one step.

## Decision

**A scanner-native snapshot format.** A snapshot is a JSON document carrying a
`ccmScannerSnapshot` version marker and a flat list of resources in the model's
own vocabulary:

```json
{
  "ccmScannerSnapshot": "1",
  "source": "aws:123456789012:eu-west-2",
  "capturedAt": "2026-07-21T00:00:00Z",
  "resources": [
    { "address": "aws_s3_bucket.logs", "type": "aws_s3_bucket",
      "attributes": { "bucket": "example-logs" } }
  ]
}
```

**The tool issues no cloud calls.** Producing a snapshot is a documented step
the operator runs with their own read-only credentials. The scanner reads a
file, exactly as it does in the Terraform lane.

## Why

**The mapping has to exist somewhere, and this is where it can be audited.**
Whether the tool converts `DescribeSecurityGroups` internally or the operator
does it in a documented pipeline, the same translation happens. Putting it in a
declared, hand-writable format makes it reviewable, diffable and testable, and
it means a snapshot can be attached to an audit alongside the report that was
derived from it. An opaque internal mapping could not be checked by the person
relying on the verdict.

**It keeps hard constraint 2 structural rather than aspirational.** With no SDK
and no call sites, the tool cannot ask for credentials — there is no code path
to review, no profile to misconfigure, no risk of a future change quietly
acquiring write scope. ADR-0002 argued the read-only posture should be a
property of the code; this keeps it that way in the lane most likely to erode
it. The scanner still takes its input as a *string*, so the adapter cannot
reach the filesystem either.

**It keeps the checks honest across lanes.** Because both adapters produce the
same `ResourceModel`, every check runs unchanged and a divergence between lanes
is a real divergence, not an artefact of two check implementations. This is
asserted, not assumed: `test/ingest/snapshot.test.ts` scans equivalent
Terraform and snapshot fixtures and requires identical verdicts.

## Consequence worth stating plainly

**A snapshot has no unknown-until-apply, so it can decide controls a plan
cannot.** Terraform writes a not-yet-computed value as `null`, and the whole
`unknownAttributes` mechanism exists so a check does not read that as "not
configured" (hard constraint 5). Observed state has no such category: every
value is one the account has.

So the same infrastructure can yield `not_applicable` from a plan and `fail`
from a snapshot. That is the lane working. The committed fixtures contain
exactly one such case — an EBS volume whose `encrypted` flag is unknown at plan
time and observed `false` in the snapshot — and the test asserts both the
agreement everywhere else *and* that single documented divergence, so it cannot
drift into an unexplained inconsistency.

## Alternatives considered

**Consume AWS Config / API output directly.** Rejected for v1: it moves the
CCM-relevant mapping inside the tool where an auditor cannot see it, and it
would make the fixtures enormous without making them clearer. Worth revisiting
as a *converter* that emits this format — the format is the interface, so a
converter needs no change to the scanner.

**Have the tool call AWS behind a read-only profile flag.** Rejected for v1 on
constraint grounds above. If it is ever added it needs its own ADR, must be
opt-in, and must not become a CI dependency (hard constraint 3).

**Reuse the Terraform state format.** Rejected: it would tie the snapshot to
Terraform's schema for data that did not come from Terraform, and it carries
plan-specific machinery (`after_unknown`) that is meaningless for observed
state — the very distinction this ADR is careful to preserve.
