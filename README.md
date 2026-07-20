# ccm-scanner

> Read-only compliance scanner: audit Terraform (`terraform show -json`) — or a
> read-only cloud snapshot — against a curated subset of the **CSA Cloud Controls
> Matrix (CCM v4.0)**, and get an **audit-ready report** where every control is
> **Pass**, **Fail**, or **Not-Applicable**, each verdict carrying its CCM control
> ID and the evidence it was derived from.

> **Status — milestone M5.** The engine, the four-domain control slice, the CLI
> and the evidence pack are implemented and run headlessly over the committed
> fixtures. The read-only cloud-snapshot lane lands in M6 — see the
> [milestone plan](docs/milestone-plan.md). Anything marked _(planned)_ below is
> not implemented yet.

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

### Homelab / real-account lane _(planned — M6)_

Pointing the scanner at your own homelab Terraform, or at a **read-only** cloud
snapshot, is a documented local workflow — never a CI dependency, and never
requiring write credentials.

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
```

Conventions: TypeScript strict ESM, vitest, eslint + prettier, Conventional Commits
(commitlint), gitleaks (pre-commit + CI). One PR per milestone.

## Documentation

- [`CLAUDE.md`](CLAUDE.md) — architecture, constraints, contributor guide
- [`docs/milestone-plan.md`](docs/milestone-plan.md) — roadmap (one PR per milestone)
- [`docs/control-mapping.md`](docs/control-mapping.md) — CCM control → check (source of truth)
- [`docs/adr/`](docs/adr/) — architecture decision records

## License

[MIT](LICENSE).
