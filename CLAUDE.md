# CLAUDE.md — ccm-scanner

> Guidance for Claude Code (and human contributors) working in this repo.
> Read this before writing code. The **Hard constraints** section is non-negotiable.

## Mission

`ccm-scanner` audits infrastructure-as-code (Terraform HCL or plan JSON) or a
read-only cloud snapshot against a **curated subset** of the CSA Cloud Controls
Matrix (CCM v4.0), and emits an **audit-ready compliance report**: every control
is reported as **Pass**, **Fail**, or **Not-Applicable**, each verdict carrying
its **CCM control ID** and the **evidence** the verdict was derived from.

The report is the deliverable. It is machine-readable (versioned JSON) plus a
human-readable summary, in the same audit-trail spirit as a test-evidence-pack.

## What this is / what it is not

- **Is:** a read-only compliance *scanner* over declarative infrastructure, with
  an auditable mapping from CCM controls to concrete checks.
- **Is not:** a full CCM implementation, a policy-as-code enforcement gate that
  mutates state, a live-account posture manager, or a substitute for a formal
  CCM assessment. Coverage is a **deliberately curated slice**, not the whole
  matrix.

## Hard constraints (non-negotiable)

These are invariants. A change that violates one is wrong regardless of how
convenient it is. They are the subject of ADR-0002.

1. **Read-only, always.** The tool never mutates infrastructure or cloud state.
   It parses files and JSON and (in the documented cloud lane) issues only
   read-only describe/list calls. No `terraform apply`, no writes, ever.
2. **Never requires write credentials.** No code path asks for, accepts, or
   benefits from write-capable credentials. The cloud lane is documented to work
   with a least-privilege **read-only** role/profile only.
3. **Fixtures ship in-repo; real cloud access is a local lane.** CI runs entirely
   against committed fixtures. Pointing the scanner at a real account or a
   homelab is a **documented local workflow**, never a CI dependency.
4. **Curated subset, honestly scoped.** We cover a coherent slice (IAM, Logging &
   Monitoring, Encryption, Network Security). We do not pretend to cover controls
   we do not check.
5. **If a control can't be checked from the input, it is Not-Applicable with a
   reason — never a guess.** A `Fail` means we have evidence of non-compliance; a
   `Pass` means we have evidence of compliance; anything else is `NotApplicable`
   with a human-readable reason. We never infer a Pass/Fail we cannot evidence.

## Architecture

A single, linear, side-effect-free pipeline. Each stage is independently testable.

```
        ingest              normalize            evaluate              report
Terraform HCL/plan JSON ─▶  ResourceModel  ─▶  ControlRegistry  ─▶  Report (JSON)
Cloud snapshot (JSON)   ─▶  (provider-       (checks emit         + human summary
                            agnostic)         Verdicts)            + evidence pack
```

- **Ingest** — adapters turn an input (`terraform show -json`, of a saved plan
  file or of state — note *not* `terraform plan -json`, which is a log stream —
  an
  HCL directory, or a read-only cloud snapshot) into a normalized model. Adapters
  are the *only* code that knows about input formats.
- **ResourceModel** — a provider-agnostic, typed graph of resources keyed by
  address, with attributes. Checks consume this and nothing else, so the same
  check runs over Terraform *and* over a cloud snapshot unchanged.
- **ControlRegistry** — each CCM control in scope registers one or more **checks**.
  A check is a pure function `(ResourceModel) => Verdict[]`.
- **Report** — the engine collects verdicts into a `Report` and renders it to
  versioned JSON + a human-readable summary + an evidence pack.

Purity rule: **checks and renderers must be pure and deterministic** — same input
⇒ byte-identical report (modulo an explicit, injected timestamp). This is what
makes the evidence pack reproducible and the golden-file tests meaningful.

## Repository layout (target)

```
ccm-scanner/
├── CLAUDE.md                     # this file
├── README.md                     # usage, homelab lane, cloud snapshot lane
├── SECURITY.md                   # read-only posture, reporting
├── docs/
│   ├── milestone-plan.md         # the roadmap (one PR per milestone)
│   ├── control-mapping.md        # CCM control → concrete check (auditable)
│   └── adr/                      # architecture decision records
│       ├── 0001-why-ccm.md
│       ├── 0002-why-read-only-iac-default.md
│       └── 0003-auditable-control-mappings.md
├── schemas/                      # published JSON Schema for the report
├── src/
│   ├── cli/                      # commander CLI surface
│   ├── ingest/                   # terraform-plan, terraform-hcl, snapshot adapters
│   ├── model/                    # ResourceModel + types
│   ├── controls/                 # one module per CCM domain (iam, log, cek, ivs)
│   ├── engine/                   # registry + evaluation
│   ├── report/                   # json + summary + evidence-pack renderers
│   └── index.ts
├── fixtures/
│   ├── compliant/                # should produce zero Fails
│   └── non-compliant/            # each fixture trips a known control ID
└── test/                         # vitest unit + golden-file tests
```

## Tech stack & conventions

- **Language:** TypeScript, **strict** mode, **ESM** (`"type": "module"`,
  `moduleResolution: "NodeNext"`). No `any` escapes without a written reason.
- **Runtime:** Node LTS.
- **Tests:** **vitest**. Unit tests per check; golden-file tests for report output.
- **Lint/format:** **eslint + prettier**. CI fails on lint errors or unformatted
  code.
- **Commits:** **Conventional Commits** (`feat:`, `fix:`, `docs:`, `chore:`,
  `test:`, `refactor:`…), enforced by commitlint.
- **Branching / PRs:** **one PR per milestone** (see `docs/milestone-plan.md`).
  Each PR passes the subagent gates below before it opens.
- **Secrets:** **gitleaks** runs as a pre-commit hook **and** in CI. No secrets,
  keys, tokens, or real account identifiers in the repo — fixtures use obviously
  fake values.
- **Provider scope (v1):** the **AWS** Terraform provider, where the crispest
  IaC-checkable signals live and which matches a typical homelab-on-cloud setup.
  The ResourceModel and registry are provider-agnostic so Azure/GCP can follow.

## Commands (target interface)

These are the intended npm scripts; they are implemented starting in M0/M1.

```bash
npm run build          # tsc → dist/
npm run typecheck      # tsc --noEmit
npm run lint           # eslint
npm run format         # prettier --write
npm test               # vitest run
npm run scan -- --input fixtures/non-compliant/... --format both
```

Target CLI (M5):

```bash
ccm-scanner scan \
  --input <plan.json | hcl-dir/ | snapshot.json> \
  --controls <iam,log,cek,ivs | IAM-05,CEK-12 | all> \
  --format json|md|both \
  --out ./report \
  --fail-on fail|none
```

Exit codes are deterministic: **0** when there are no `Fail` verdicts (Pass/NA
only), **non-zero** when any control `Fail`s — unless `--fail-on none`. This is
what lets CI run the scanner headlessly against fixtures.

## Control model & verdicts

A **Verdict** is the atomic unit of the report:

```ts
type Status = "pass" | "fail" | "not_applicable";

interface Evidence {
  resourceAddress: string;   // e.g. aws_security_group.web
  attribute?: string;        // e.g. ingress[0].cidr_blocks
  observed: unknown;         // what we actually saw
  expected?: string;         // what compliance requires (human-readable)
}

interface Verdict {
  ccmId: string;             // e.g. "IVS-03" — MUST match docs/control-mapping.md
  ccmTitle: string;          // verbatim CCM v4.0 title
  checkId: string;           // e.g. "ivs/no-open-admin-ports" — stable <domain>/<slug>
  status: Status;
  evidence: Evidence[];      // required for pass/fail
  reason?: string;           // REQUIRED when status = not_applicable
}
```

Rules:
- Every `ccmId` used in code **must** have a row in `docs/control-mapping.md`.
- `checkId` is a stable `<domain>/<slug>` identifier and **must not** embed the
  CCM control number (which CCM renumbers between versions) — see ADR-0003.
- `pass`/`fail` verdicts **must** carry evidence. `not_applicable` **must** carry
  a `reason`.
- Titles are copied verbatim from CCM v4.0 (see provenance in the mapping doc).

## Report format

Two renderings of the same underlying `Report`:

1. **Machine-readable JSON** — validated against `schemas/report.schema.json`.
   Includes run metadata (tool version, CCM version, input digest, timestamp),
   the full verdict list, and per-domain roll-ups. This *is* the evidence pack.
2. **Human-readable summary** — grouped by CCM domain, with Pass/Fail/NA counts,
   a headline verdict, and each `Fail`/`NA` expanded with its evidence/reason.

## Adding or changing a control (the auditable workflow)

This workflow is what ADR-0003 commits us to. Follow it exactly:

1. Add or edit the row in **`docs/control-mapping.md`**: CCM ID, verbatim title,
   check ID, what is checked, evidence source, verdict logic, coverage class.
2. Implement the check in `src/controls/<domain>/`, using the **same** `ccmId`,
   `ccmTitle`, and `checkId` as the mapping row. The mapping table is the source
   of truth; code must not diverge from it.
3. Add a **compliant** and a **non-compliant** fixture that exercise the check.
4. If the control cannot be evidenced from the input, register it as
   `not_applicable` with a reason instead of writing a heuristic guess.
5. A test asserts the non-compliant fixture is flagged with the **correct CCM ID**.

## Subagent gates

Per the project conventions, PRs pass through subagents before merge:

- **Code-review subagent** — runs before **every** milestone PR opens. Reviews
  the diff for correctness, the hard constraints (esp. read-only), scope creep,
  and mapping/code consistency.
- **Verification subagent** — for any milestone that adds or changes checks (and
  the cloud-snapshot lane): from a **clean checkout**, runs the scanner against
  both compliant and non-compliant fixtures and confirms the non-compliant ones
  are flagged **with the correct control IDs**, and the compliant ones are clean.

Do not open a milestone PR until its applicable gates have passed.

## CI expectations

CI is headless and fixture-only:

- lint, typecheck, unit tests, golden-file tests
- gitleaks
- **scanner-against-fixtures**: run the scanner over `fixtures/` and assert exit
  code + that each non-compliant fixture trips its expected control ID
  (introduced in M3, expanded each milestone thereafter)

CI never touches a real cloud account.

## Security posture

- Read-only by construction (see Hard constraints).
- No write credentials, ever. The cloud lane documents a least-privilege
  read-only role only.
- gitleaks pre-commit + CI. Fixtures contain only fake identifiers.
- Report `SECURITY.md` for the disclosure process (added in M6).

## Pointers

- Roadmap: [`docs/milestone-plan.md`](docs/milestone-plan.md)
- Control mapping (source of truth): [`docs/control-mapping.md`](docs/control-mapping.md)
- Decisions: [`docs/adr/`](docs/adr/)
