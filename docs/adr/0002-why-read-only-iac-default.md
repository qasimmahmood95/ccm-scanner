# ADR-0002: Read-only IaC scanning is the default; live accounts are a read-only snapshot lane

**Status:** Accepted
**Date:** 2026-07-19
**Deciders:** Project maintainer

## Context

`ccm-scanner` can learn about an environment's posture from three possible
sources:

1. **Declarative IaC** — parse Terraform HCL or `plan`/`show -json`.
2. **A live account** — call cloud provider APIs and inspect actual state.
3. **A snapshot** — a read-only export of live state, serialized to JSON, scanned
   offline.

The choice of *default* source shapes the tool's security posture, its
determinism, whether CI can run it headlessly, and how the evidence pack behaves.
This decision is tightly bound to the project's **hard constraints** (see
`CLAUDE.md`): read-only always, never requires write credentials, CI runs against
committed fixtures, real cloud access is a documented local lane — never a CI
dependency.

Forces at play:

- **Security posture.** The strongest possible claim is "the tool never holds
  write credentials, and cannot mutate anything." The default lane should make
  that claim trivially true.
- **Determinism / reproducibility.** The report *is* an evidence pack; the same
  input must produce a byte-identical report. Live API responses vary run to run.
- **CI-headless.** CI must run the scanner with no cloud account and no secrets.
- **Shift-left value.** Catching a misconfiguration in a Terraform plan — before
  `apply` — is more valuable than finding it after it is live.
- **Drift.** Live state can diverge from code; IaC alone cannot see that.

## Decision

**IaC parsing is the default and the CI lane.** The scanner's core consumes
Terraform (`plan`/`show -json` primary; HCL secondary) and normalizes it into the
provider-agnostic `ResourceModel`.

A live account is reached **only** through a **read-only snapshot lane**: an
operator produces a JSON snapshot out-of-band using a least-privilege read-only
role, and the scanner ingests that snapshot into the *same* `ResourceModel`, so
every check runs unchanged. In v1 the tool itself makes **no cloud API calls at
all** — snapshot generation is an explicit, documented operator step. Any future
in-tool read calls must go behind an explicit read-only profile flag and are the
subject of their own ADR. **No code path ever accepts write credentials.**

## Options Considered

### Option A: IaC-first, snapshot lane for live state (chosen)
| Dimension | Assessment |
|-----------|------------|
| Write credentials | None, ever |
| Read credentials in tool | None in v1 (snapshot generated out-of-band) |
| Determinism | High — pure function of file input |
| CI-headless | Yes |
| Detects drift | No (documented limitation; snapshot lane recovers most) |
| Shift-left | Yes — pre-`apply` |

**Pros:** the read-only claim is structural, not procedural; hermetic,
reproducible CI; evidence packs are byte-reproducible; catches issues before
deploy. The snapshot lane recovers most live-state value without the tool taking
custody of credentials or making network calls.
**Cons:** the default lane cannot see drift between code and deployed reality;
the snapshot lane needs an out-of-band generation step.

### Option B: Live-account-first (tool calls cloud APIs directly)
| Dimension | Assessment |
|-----------|------------|
| Write credentials | Still none — but the tool now handles credentials |
| Read credentials in tool | Required |
| Determinism | Low — responses vary; pagination, eventual consistency |
| CI-headless | No — needs an account |
| Detects drift | Yes — sees actual state |
| Shift-left | No — post-deploy only |

**Pros:** authoritative on real state; detects drift and out-of-band changes.
**Cons:** requires credential custody (even if read-only), which pulls the
project toward exactly the risk its hard constraints forbid; non-deterministic,
so the evidence pack is no longer reproducible; cannot run in CI without an
account; couples the tool to cloud availability and rate limits.

### Option C: Both, co-equal, from day one
| Dimension | Assessment |
|-----------|------------|
| Write credentials | None |
| Read credentials in tool | Required for the live half |
| Determinism | Mixed |
| CI-headless | Partial |
| Detects drift | Yes |
| Shift-left | Yes |

**Pros:** most complete coverage.
**Cons:** doubles the surface and the security-review burden up front; forces
credential handling into v1; blurs the clean "no cloud calls in the tool"
posture. Premature for a curated-subset v1.

## Trade-off Analysis

The core trade is **drift-detection vs. determinism + zero-credential posture.**
IaC-first forfeits drift detection by default but buys three things the project
explicitly values: a structurally-true read-only guarantee, a reproducible
evidence pack, and hermetic CI. The **snapshot lane** is the deliberate
compromise — it recovers most of the live-state value (you are scanning *real*
exported state) while keeping credential custody and network calls *out* of the
tool. Live-first API scanning was rejected as the default precisely because it
trades away determinism and the clean security posture that make the evidence
pack credible in the first place.

Framing it as *shift-left plus optional snapshot* also matches how the tool is
meant to be used: in a pipeline against a plan, and locally against a homelab's
Terraform or a read-only export.

## Consequences

- **Easier:** the security story is trivial to state and verify ("no write
  credentials in the repo or any code path; v1 makes no cloud calls"); CI is
  hermetic; evidence packs are byte-reproducible for a fixed input + timestamp;
  the same checks run over Terraform and over a snapshot with zero changes.
- **Harder:** the default lane does not detect drift between code and deployed
  state — this is a **documented limitation**, partially mitigated by the
  snapshot lane; producing a snapshot is a manual, documented operator step.
- **Revisit when:** we want in-tool read-only API calls (new ADR, read-only
  profile flag, still no write creds); or drift detection becomes a first-class
  requirement.

## Action Items

1. [ ] Implement the Terraform ingestion + `ResourceModel` (M2).
2. [ ] Implement the read-only snapshot adapter into the same model (M6).
3. [ ] Document the least-privilege read-only role and the exact commands to
   generate a snapshot; assert in review that no write credential is ever
   requested or accepted (M6).
4. [ ] Add a CI/test assertion (or lint rule) guarding against the introduction
   of any cloud-write or credential-write code path.
