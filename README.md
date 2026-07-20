# ccm-scanner

> Read-only compliance scanner: audit Terraform (`terraform show -json`) — or a
> read-only cloud snapshot — against a curated subset of the **CSA Cloud Controls
> Matrix (CCM v4.0)**, and get an **audit-ready report** where every control is
> **Pass**, **Fail**, or **Not-Applicable**, each verdict carrying its CCM control
> ID and the evidence it was derived from.

> **Status — milestone M6, feature-complete for v1.** The engine, the
> four-domain control slice, the CLI, the evidence pack and the read-only
> cloud-snapshot lane are all implemented and run headlessly over committed
> fixtures. See the [milestone plan](docs/milestone-plan.md) for what is
> deliberately out of scope.

## Why this exists

Infrastructure-as-code is where much of a cloud's security posture is actually
decided, and CCM is the cloud-native control framework a CCSK/CCM assessment speaks
in. `ccm-scanner` maps a curated slice of CCM onto concrete, checkable IaC signals
and emits the result as a reproducible evidence pack — the same audit-trail spirit
as a test-evidence-pack.

## What it is / what it isn't

- **Is:** a read-only scanner over declarative infrastructure, with an auditable
  mapping from CCM controls to concrete checks.
- **Isn't:** a full CCM implementation, an enforcement gate that mutates state, a
  live-account posture manager, or a substitute for a formal CCM assessment.
  Coverage is a deliberately curated slice.

See [`CLAUDE.md`](CLAUDE.md) for the full architecture and hard constraints.

## Scope (v1)

A coherent slice across four CCM v4.0 domains, on the **AWS** Terraform provider:

| Domain                             | CCM | Examples of what gets checked                                             |
| ---------------------------------- | --- | ------------------------------------------------------------------------ |
| Identity & Access Management       | IAM | no wildcard `*:*` allow; no wildcard role trust; strong password policy   |
| Logging & Monitoring               | LOG | multi-region CloudTrail; log-file validation; VPC flow logs              |
| Cryptography & Key Management      | CEK | encryption at rest (S3/EBS/RDS); TLS enforced; KMS key rotation          |
| Infrastructure & Network Security  | IVS | no world-open admin ports; S3 public-access block; RDS not public       |

Controls that cannot be evidenced from IaC are reported **Not-Applicable with a
reason** — never guessed. The full table is the source of truth:
[`docs/control-mapping.md`](docs/control-mapping.md).

## Usage

```bash
npm install && npm run build
node dist/cli/index.js scan --input plan.json
```

The input is the JSON that `terraform show -json` produces — of a **saved plan
file** or of **state**:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json     # what this tool reads
```

Note this is *not* `terraform plan -json`, which emits a newline-delimited log
stream rather than a plan representation. The scanner detects that mistake and
names the right command.

### Options

```bash
ccm-scanner scan --input plan.json --controls all --format md --fail-on fail
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--input` | _required_ | `terraform show -json` output to scan |
| `--controls` | `all` | `all`, domains (`iam,log,cek,ivs`), or ids (`IAM-05,CEK-12`) |
| `--format` | `md` | `json`, `md`, or `both` (`both` requires `--out`) |
| `--out` | stdout | Directory for the evidence pack |
| `--fail-on` | `fail` | `none` reports failures without a non-zero exit |
| `--generated-at` | now | Fix the report timestamp, for reproducible output |

`--controls` reads as a **union**: `--controls iam,CEK-12` scans the whole IAM
domain *plus* CEK-12. A selector that matches nothing is a usage error rather
than an empty, passing scan.

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | No control failed — or failures were found and `--fail-on none` was passed |
| `1` | At least one control failed |
| `2` | Usage error: bad flag, unreadable input, selector matching nothing |

Warnings never change the exit code. They mean the scanner could not fully read
its input, which is recorded *in* the report rather than escalated into a build
failure.

### The evidence pack

With `--out`, the scanner writes:

- **`report.json`** — the machine-readable evidence pack, validated against
  [`schemas/report.schema.json`](schemas/report.schema.json). Run metadata, the
  pinned CCM version, a sha256 of the input, per-domain roll-ups at both control
  and finding granularity, and every verdict with its evidence.
- **`summary.md`** — the human-readable summary, grouped by domain, with each
  `Fail` and `N/A` expanded with its evidence or reason.

Both are **byte-reproducible** for a fixed input and `--generated-at`, which is
what makes the pack usable as an audit artifact rather than a snapshot of a
moment. Values Terraform marks sensitive are redacted before either document is
rendered.

```bash
ccm-scanner scan -i plan.json --format both --out ./report
# FAIL: 13 failed, 0 passed, 9 not applicable across 22 controls.
# Evidence pack written to /path/to/report
```

## Point it at your own infrastructure

Both lanes are local workflows. Neither is a CI dependency, and neither needs
write credentials.

### Your homelab Terraform

```bash
cd ~/infra/my-homelab
terraform plan -out=tfplan          # no apply; the plan file is not executed
terraform show -json tfplan > plan.json
ccm-scanner scan --input plan.json --format both --out ./ccm-report
```

Reading a plan is the safer default: it shows what *would* exist, and a plan
does not resolve secrets that only exist after apply. To audit what actually
exists, point it at state instead — same command, same output:

```bash
terraform show -json > state.json    # current state, no changes made
ccm-scanner scan --input state.json --out ./ccm-report
```

Expect **not-applicable** verdicts on a create plan: Terraform cannot know an
id or a computed flag until apply, and the scanner declines rather than
guessing. That is not a gap in the scan — it is the plan genuinely not knowing.
The snapshot lane below resolves exactly those.

### A read-only cloud snapshot

The scanner issues no cloud calls at all — you produce the snapshot, so the tool
never needs credentials of any kind ([ADR-0004](docs/adr/0004-snapshot-lane.md)).

**1. Grant a least-privilege read-only role.** These are the only permissions
the documented commands need. There is no write action in this policy, and no
`iam:*` beyond reading account settings:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CcmScannerReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "iam:GetAccountPasswordPolicy",
        "iam:GetPolicyVersion",
        "iam:ListPolicies",
        "iam:ListRoles",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",
        "rds:DescribeDBInstances",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    }
  ]
}
```

AWS's managed `SecurityAudit` policy also covers these if you prefer a managed
one; it is broader than necessary.

**2. Produce a snapshot.** A snapshot is a JSON document in the scanner's own
vocabulary — the same resource types and attribute names the Terraform lane
produces, so every check runs unchanged:

```json
{
  "ccmScannerSnapshot": "1",
  "source": "aws:123456789012:eu-west-2",
  "capturedAt": "2026-07-21T00:00:00Z",
  "resources": [
    {
      "address": "aws_s3_bucket.logs",
      "type": "aws_s3_bucket",
      "attributes": { "bucket": "example-logs" }
    },
    {
      "address": "aws_kms_key.main",
      "type": "aws_kms_key",
      "attributes": {
        "enable_key_rotation": true,
        "customer_master_key_spec": "SYMMETRIC_DEFAULT"
      }
    }
  ]
}
```

Each entry needs an `address` (any unique string), a `type` matching the
Terraform resource type the checks look for, and the `attributes` those checks
read. `sensitiveAttributes` is optional and marks values to redact.
`docs/control-mapping.md` lists the exact attribute each check reads, and
`fixtures/snapshot/` holds two worked examples.

Build one with the read-only calls above — for instance, KMS key rotation:

```bash
aws kms list-keys --query 'Keys[].KeyId' --output text   | tr '	' '
'   | while read -r id; do
      aws kms get-key-rotation-status --key-id "$id"         --query "{address: 'aws_kms_key.$id', type: 'aws_kms_key',
                  attributes: {enable_key_rotation: KeyRotationEnabled}}"
    done
```

**3. Scan it.** The format is detected automatically:

```bash
ccm-scanner scan --input snapshot.json --format both --out ./ccm-report
```

Use `--input-format snapshot` to override detection.

**A snapshot decides things a plan cannot.** Observed state has no
unknown-until-apply, so a control that a create plan reports as *not-applicable*
may legitimately **fail** against a snapshot of the same infrastructure. That is
the lane working — see ADR-0004.

## Hard constraints

1. Read-only, always — never mutates infrastructure or cloud state.
2. Never requires write credentials.
3. Fixtures ship in-repo; real cloud access is a documented local lane, not a CI
   dependency.
4. Curated subset, honestly scoped.
5. If a control can't be checked from the input, it's Not-Applicable with a reason.

## Development

```bash
npm install        # installs the toolchain and wires git hooks (husky)
npm run typecheck  # tsc --noEmit (strict)
npm run lint       # eslint
npm run format     # prettier --write
npm test           # vitest
npm run build      # tsc -> dist/
npm run scan       # run the CLI from source via tsx
npm run verify:fixtures  # build, then assert the CLI's exit codes over fixtures
npm run samples:update   # regenerate docs/samples/
```

Conventions: TypeScript strict ESM, vitest, eslint + prettier, Conventional Commits
(commitlint), gitleaks (pre-commit + CI). One PR per milestone.

## Documentation

- [`CLAUDE.md`](CLAUDE.md) — architecture, constraints, contributor guide
- [`docs/milestone-plan.md`](docs/milestone-plan.md) — roadmap (one PR per milestone)
- [`docs/control-mapping.md`](docs/control-mapping.md) — CCM control → check (source of truth)
- [`docs/adr/`](docs/adr/) — architecture decision records
- [`docs/samples/`](docs/samples/) — committed sample evidence packs
- [`SECURITY.md`](SECURITY.md) — read-only posture, redaction limits, disclosure

## License

[MIT](LICENSE).
