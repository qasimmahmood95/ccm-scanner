# ccm-scanner

> Read-only compliance scanner: audit Terraform (HCL or `plan`/`show -json`) — or a
> read-only cloud snapshot — against a curated subset of the **CSA Cloud Controls
> Matrix (CCM v4.0)**, and get an **audit-ready report** where every control is
> **Pass**, **Fail**, or **Not-Applicable**, each verdict carrying its CCM control
> ID and the evidence it was derived from.

> **Status — early scaffold (milestone M0).** Governance, toolchain, and the
> auditable control mapping are in place. The scanner engine and the checks land in
> the milestones that follow — see the [milestone plan](docs/milestone-plan.md).
> Commands marked _(planned)_ below are not implemented yet.

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

## Planned usage

_(planned — CLI lands in M5)_

```bash
ccm-scanner scan \
  --input <plan.json | hcl-dir/ | snapshot.json> \
  --controls <iam,log,cek,ivs | IAM-05,CEK-12 | all> \
  --format json|md|both \
  --out ./report \
  --fail-on fail|none
```

Exit code is **0** when there are no `Fail` verdicts, **non-zero** when any control
`Fail`s (unless `--fail-on none`) — so CI can run it headlessly against fixtures.

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
npm run scan       # run the (stub) CLI via tsx
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
