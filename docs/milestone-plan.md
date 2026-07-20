# Milestone Plan — ccm-scanner

**One PR per milestone.** Each PR passes its subagent gates (code-review always;
verification wherever checks or the cloud lane change) before it opens. Every PR
uses Conventional Commits and keeps CI green.

Legend for gates:
- 🔍 **CR** = code-review subagent (mandatory on every milestone).
- ✅ **VER** = verification subagent: clean checkout → run scanner over compliant
  **and** non-compliant fixtures → confirm non-compliant flagged with correct CCM IDs.

---

## M0 — Governance & scaffolding
*docs + tooling only; no scanner logic.*

**Goal:** lock in the guardrails and toolchain so every later change lands in a
consistent, auditable frame.

**Deliverables**
- `CLAUDE.md`, `docs/milestone-plan.md`, `docs/control-mapping.md` *(this deliverable set — under review now).*
- TypeScript **strict ESM** config (`tsconfig`, `package.json` with `"type":"module"`).
- **vitest**, **eslint + prettier**, **commitlint** (Conventional Commits).
- **gitleaks** pre-commit hook **and** CI job.
- CI workflow skeleton: lint, typecheck, test, gitleaks.
- The three required ADRs:
  - `0001-why-ccm.md` — why CCM as the control framework.
  - `0002-why-read-only-iac-default.md` — why read-only IaC scanning over
    live-account scanning as the default.
  - `0003-auditable-control-mappings.md` — how control mappings are kept
    auditable, incl. the pinned CCM version and verbatim-title provenance rule.
- `LICENSE`, `README` skeleton, `src/index.ts` with a `--version` stub.

**Exit criteria:** `npm run lint && npm run typecheck && npm test` green on the
scaffold; CI green; gitleaks passes; three ADRs merged.

**Gates:** 🔍 CR.

---

## M1 — Domain model & report engine
*the abstractions + both renderers, proven with stub checks.*

**Goal:** the control/verdict/report core, and the machine + human report
outputs, provable before any real check exists.

**Deliverables**
- Types: `Status`, `Evidence`, `Verdict`, `Control`, `Check`, `Report`
  (as specified in `CLAUDE.md`).
- `ControlRegistry` + evaluation engine: runs `Check`s over a `ResourceModel`.
- **JSON report emitter** with a versioned, published `schemas/report.schema.json`.
- **Human-readable summary** renderer (grouped by domain, Pass/Fail/NA counts,
  headline verdict, expanded evidence/reasons).
- Golden-file tests for both renderers, using 1–2 stub checks over an in-memory
  model. Determinism enforced (injected timestamp).

**Exit criteria:** engine emits both report formats from stub checks; report
validates against the schema; golden tests pass.

**Gates:** 🔍 CR.

---

## M2 — Terraform ingestion
*turn Terraform into the normalized model checks consume.*

**Goal:** the `ResourceModel` and the adapters that populate it.

**Deliverables**
- **Primary adapter:** `terraform show -json` ingester — of a saved plan file
  (`terraform plan -out=tfplan && terraform show -json tfplan`) or of state.
  Not `terraform plan -json`, which emits newline-delimited log messages rather
  than the plan representation.
  (reliable, provider-versioned JSON).
- **Secondary/stretch:** HCL directory ingestion, with documented limitations
  (unresolved variables/expressions are surfaced, not guessed).
- Provider-agnostic `ResourceModel`: typed resource nodes keyed by address,
  attributes, provider metadata.
- Raw fixtures (both compliant and non-compliant plan JSON).
- Ingestion unit tests (including malformed-input handling).
- **Read-only invariant:** adapters only read files/JSON; no terraform execution
  that mutates state.

**Exit criteria:** sample plan JSON loads into `ResourceModel`; parse/round-trip
tests pass.

**Gates:** 🔍 CR.

---

## M3 — Checks: IAM & Encryption (CEK)
*first real coverage — the domains with the crispest IaC signals.*

**Goal:** implement and evidence the IAM + CEK slice of the mapping table.

**Deliverables**
- Checks: **IAM-05**, **IAM-16**, **IAM-02/IAM-15** (password policy),
  **CEK-03** (at-rest + in-transit), **CEK-04**, **CEK-12** — each registered
  with its CCM ID + evidence, matching `docs/control-mapping.md`.
- Explicit `not_applicable` registrations with reasons: **IAM-03**, **IAM-08**,
  **CEK-01**, **CEK-14** (demonstrates honest scoping).
- Compliant + non-compliant fixtures per check.
- **Fixtures-as-gate, in two halves.** The *control-ID* half lands here and runs
  in CI through `npm test`: `test/controls/fixtures.test.ts` scans both fixtures
  and asserts the compliant one is clean while the non-compliant one is flagged
  with the correct CCM ids, and `fixture coverage (ADR-0003)` asserts every
  Yes/Partial control has both a failing and a passing case. The *exit-code*
  half needs a CLI to have an exit code, so it defers to **M5**.

**Exit criteria:** every non-compliant fixture is flagged with the correct CCM
ID; compliant fixtures produce zero Fails; NA controls report NA with reasons.

**Gates:** 🔍 CR + ✅ VER.

---

## M4 — Checks: Logging & Monitoring (LOG) & Network Security (IVS)
*complete the four-domain slice.*

**Goal:** implement and evidence the LOG + IVS slice.

**Deliverables**
- Checks: **LOG-07**, **LOG-02**, **LOG-04**, **LOG-03** (VPC flow logs);
  **IVS-03** (open admin ports + S3 public-access-block + RDS not public),
  **IVS-06** (default SG locked down + public/private separation).
- Explicit `not_applicable` registrations with reasons: **LOG-05**, **LOG-06**,
  **IVS-04**, **IVS-08**.
- Compliant + non-compliant fixtures per check; CI job extended.

**Exit criteria:** same shape as M3 for these controls. Full curated subset now
live end-to-end over fixtures.

**Gates:** 🔍 CR + ✅ VER.

---

## M5 — CLI & evidence-pack report
*the user-facing surface and the audit-trail deliverable.*

**Goal:** the `scan` CLI and the reproducible evidence pack.

**Deliverables**
- `ccm-scanner scan` (commander): `--input`, `--controls` (subset selection by
  domain or CCM ID), `--format json|md|both`, `--out`, `--fail-on fail|none`.
- Deterministic exit codes (0 when no Fails; non-zero on any Fail unless
  `--fail-on none`).
- **Evidence pack**: timestamped run metadata, tool version, pinned CCM version,
  input digest, per-control evidence — reproducible/deterministic, in the
  test-evidence-pack spirit.
- CI switches to invoking the CLI. README usage section.

**Exit criteria:** CLI runs end-to-end over fixtures; evidence pack is
byte-reproducible for a fixed input+timestamp; CI drives the CLI.

**Gates:** 🔍 CR + ✅ VER.

---

## M6 — Cloud snapshot lane & homelab docs
*the documented, read-only live lane — never a CI dependency.*

**Goal:** run the identical checks over a read-only cloud snapshot, and document
the homelab workflow.

**Deliverables**
- **Snapshot adapter:** consume a JSON snapshot (e.g. AWS Config export or
  read-only `describe`/`list` output) into the same `ResourceModel`, so all
  checks run unchanged.
- The exact **least-privilege read-only** role/policy and commands used to
  produce a snapshot are documented; the tool needs no write credentials and
  (v1) issues no cloud calls itself — snapshot generation is an explicit,
  documented step. Any future in-tool read calls go behind a read-only profile
  flag and are specified in an ADR.
- README: **"Point it at your homelab Terraform"** (local lane, step-by-step) +
  **"Generate a read-only snapshot"**.
- Committed sample reports; `SECURITY.md`.

**Exit criteria:** snapshot lane produces the same verdicts as the equivalent
Terraform; a fresh-clone walkthrough of the docs succeeds; no write credentials
anywhere in the repo or docs.

**Gates:** 🔍 CR + ✅ VER (snapshot fixtures).

---

## Sequencing notes

- The four-domain slice is intentionally split **M3 (IAM+CEK)** then
  **M4 (LOG+IVS)** so each PR stays reviewable. If a single milestone's diff
  grows too large, split by domain — the one-PR-per-milestone rule is about
  coherent, shippable units, not artificial batching.
- CI's scanner-against-fixtures gate exists from **M3 onward**, so every
  subsequent milestone is continuously validated against the fixtures.
- Provider scope stays **AWS** for v1 (see `CLAUDE.md`); multi-provider is
  explicitly out of scope for this plan.
