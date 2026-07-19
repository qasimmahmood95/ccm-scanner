# ADR-0003: Keep the CCM control → check mapping auditable

**Status:** Accepted
**Date:** 2026-07-19
**Deciders:** Project maintainer

## Context

The entire credibility of `ccm-scanner` rests on one artifact: the mapping from
CCM controls to the concrete checks that evidence them. If that mapping drifts
from the code, cites wrong control IDs, paraphrases titles, or silently guesses a
verdict it cannot evidence, every report it produces is worthless as audit
evidence. This is the risk ADR-0003 exists to manage.

Forces at play:

- **Traceability.** A reviewer must be able to follow any line in a report back
  through: evidence → check → control → framework version, mechanically.
- **No drift.** The human-readable mapping and the executable checks must not be
  allowed to disagree.
- **Provenance.** Control IDs and titles must be verifiably faithful to a *pinned*
  version of CCM, not "roughly CCM".
- **Honest scope.** Controls we cannot evidence from the input must be declared
  Not-Applicable *with a reason*, never guessed — and that decision must itself be
  visible and reviewable.

## Decision

Adopt a **docs-as-source-of-truth mapping, enforced by tests**, with the
following concrete rules:

1. **Single source of truth.** `docs/control-mapping.md` is authoritative. Every
   control registered in `src/controls/` carries a `ccmId`, `ccmTitle`, and
   `checkId` **identical** to its row in that table. The table, not the code, is
   the citation of record.

2. **Pinned version + verbatim titles.** The mapping targets **CCM v4.0**, pinned
   to patch release **v4.0.13** (the current v4.0.x line as of this ADR). Control
   titles are copied **verbatim** from CCM v4.0.13 and validated against the
   **official CSA CCM spreadsheet** before release — online mirrors are drafting
   aids, not the citation of record. The pinned version string is embedded in
   every generated report's metadata.

3. **Stable, version-independent check IDs.** A `checkId` is
   `"<domain>/<slug>"` — the CCM *domain* code (`iam`, `log`, `cek`, `ivs`,
   stable across CCM v4.x) plus a semantic slug (e.g. `ivs/no-open-admin-ports`).
   It deliberately **does not embed the CCM control number**, which CCM renumbers
   between versions (v4.1 alone shifts IAM-13 → IAM-12). A check's identity is
   therefore permanent: a framework re-baseline changes a control's `ccmId` /
   `ccmTitle` in one place — the mapping table and the control's metadata —
   without renaming checks, fixtures, or golden files. Traceability is not lost:
   every `Verdict` carries `checkId`, `ccmId`, and `ccmTitle` together, the
   mapping table lists the `checkId` per control, and reports may render a
   combined label such as `IAM-16 · no-wildcard-trust` from the current mapping.

4. **Enforced parity (tests, not discipline).** A test walks the control registry
   and asserts:
   - every `ccmId` in code has exactly one matching row in the mapping table;
   - `ccmTitle` in code is byte-identical to the table (and, at release, to the
     official spreadsheet snapshot);
   - `checkId` follows the `<domain>/<slug>` convention and matches its row;
   - every **Yes/Partial** control has ≥1 compliant **and** ≥1 non-compliant
     fixture;
   - every non-compliant fixture is flagged with its **expected** `ccmId`;
   - every `not_applicable` verdict carries a non-empty `reason`.

5. **Explicit Not-Applicable.** Controls that cannot be evidenced from the input
   are registered as `not_applicable` with a reason and appear as rows in the
   mapping table (coverage class **NA**). The scoping decision is thereby a
   reviewable artifact, not an omission.

6. **Change workflow.** Adding or changing a control follows the fixed order in
   `CLAUDE.md`: edit the mapping row first → implement/adjust the check with the
   same IDs → add compliant + non-compliant fixtures → add the ID-assertion test.
   The verification subagent re-runs this from a clean checkout before the PR.

## Options Considered

### Option A: Docs-as-source-of-truth + tests enforcing parity (chosen)
| Dimension | Assessment |
|-----------|------------|
| Auditability | High — the reviewed artifact is human-authored and diff-friendly |
| Drift risk | Low — parity is a test, not a habit |
| Overhead | Medium — a mapping row + fixtures per control |
| Reviewer trust | High — provenance is explicit and pinned |

**Pros:** the artifact an auditor reads is the artifact of record; drift is caught
by CI; provenance is explicit and version-pinned.
**Cons:** some duplication between the table and the registry (reconciled by the
parity test); discipline needed to edit the table first.

### Option B: Code-as-source-of-truth, generate the docs
| Dimension | Assessment |
|-----------|------------|
| Auditability | Medium — the auditable artifact is now generated |
| Drift risk | Very low (single source) |
| Overhead | Low |
| Reviewer trust | Medium — reviewers must trust the generator |

**Pros:** no duplication; impossible for docs and code to disagree.
**Cons:** the human-auditable mapping becomes a build output, which is weaker for
external review and provenance. **Partially adopted as a cross-check:** a test may
*generate* a mapping view from the registry and diff it against the hand-authored
table — using generation to *verify*, not to *replace*, the source of truth.

### Option C: No enforcement (convention only)
| Dimension | Assessment |
|-----------|------------|
| Auditability | Low |
| Drift risk | High |
| Overhead | None |
| Reviewer trust | Low |

**Pros:** zero tooling.
**Cons:** the mapping and code drift on the first busy day. Rejected.

## Trade-off Analysis

The real choice is *where the source of truth lives* and *how drift is
prevented*. A human-authored table is the most auditable artifact but drifts
from code unless something enforces parity; generated docs never drift but are a
weaker object of review. We take the human-authored table as the source of truth
**and** add a generated cross-check test, getting the auditability of Option A
with much of the drift-safety of Option B. Pure convention (Option C) was never
viable for a tool whose output is meant to be audit evidence.

## Consequences

- **Easier:** any report line is mechanically traceable to a pinned framework
  version; reviewers audit one table; CI refuses drift, wrong IDs, paraphrased
  titles, unevidenced verdicts, and reasonless NAs.
- **Harder:** every control costs a mapping row plus a compliant and a
  non-compliant fixture; contributors must edit the table before the code; at
  release someone must diff titles against the official CSA spreadsheet.
- **Revisit when:** we re-baseline to CCM v4.1 — cheap by design: re-pin the
  version string, re-validate/edit the affected `ccmId`/`ccmTitle` cells, and
  regenerate golden files; the version-independent check IDs mean **no cascading
  renames** of checks or fixtures. Both lines are accepted through December 2027,
  so this is deferred, not urgent. Also revisit if we add a provider and the
  evidence-source column grows a second dialect.

## Action Items

1. [ ] Land `docs/control-mapping.md` as the source of truth (in this deliverable).
2. [ ] Implement the registry-vs-mapping parity test (M1/M3).
3. [ ] Implement the non-compliant-fixture → expected-`ccmId` assertions (M3+).
4. [ ] Embed the pinned CCM version (`v4.0.13`) in report metadata (M1).
5. [ ] Add a release checklist item: validate all in-scope titles against the
   official CSA CCM v4.0.13 spreadsheet and snapshot them for the parity test.
