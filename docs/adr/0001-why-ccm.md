# ADR-0001: Adopt the CSA Cloud Controls Matrix (CCM) v4.0 as the control framework

**Status:** Accepted
**Date:** 2026-07-19
**Deciders:** Project maintainer

## Context

`ccm-scanner` reports compliance verdicts against *some* control framework. That
choice is load-bearing: it fixes the vocabulary of control IDs in every report,
determines how traceable a verdict is to the wider assurance ecosystem, governs
whether we may redistribute control text in a public repo, and decides how well
the project aligns with the CCSK/CCM body of knowledge (an explicit portfolio
goal for this repo).

Forces at play:

- **Cloud-native.** The subject is cloud infrastructure-as-code; the framework
  should already be expressed in cloud terms rather than retrofitted.
- **Addressable, stable IDs.** Every verdict must cite a durable identifier that
  a reviewer can look up.
- **Auditable and cross-referenced.** Reviewers should be able to trace a control
  outward to adjacent frameworks (CIS, NIST, ISO, SOC 2).
- **Redistributable.** Control IDs and titles must be quotable in an open repo
  without licensing friction.
- **Portfolio alignment.** The repo is meant to map onto the CCSK/CCM syllabus
  and reuse the compliance-and-audit thesis from prior work.

## Decision

Adopt the **CSA Cloud Controls Matrix (CCM), v4.0 line**, as the organizing
control framework, using a **deliberately curated subset** (see
`docs/control-mapping.md`). Reports are keyed by CCM control IDs; concrete checks
are the *evidence* for those controls, not the framework itself. The exact patch
release and the provenance rules that keep the mapping honest are the subject of
**ADR-0003**.

## Options Considered

### Option A: CSA CCM v4.0 (chosen)
| Dimension | Assessment |
|-----------|------------|
| Cloud-nativeness | High — purpose-built for cloud |
| ID stability | High — stable `DOM-NN` control IDs |
| Cross-mapping | High — ships mappings to CIS, NIST 800-53, ISO 27001, SOC 2 |
| Redistributability | Good — IDs/titles freely quotable; free reference mirrors exist |
| Portfolio/CCSK fit | Direct — this *is* the CCSK/CCM syllabus |

**Pros:** cloud-native control catalog; stable, addressable IDs; built-in
cross-framework mappings make future multi-framework output a data problem, not a
re-architecture; directly on-syllabus for CCSK.
**Cons:** controls are written at a governance altitude, so each must be
translated into a concrete check; many controls are process/policy and not
checkable from IaC at all.

### Option B: CIS Benchmarks (AWS Foundations)
| Dimension | Assessment |
|-----------|------------|
| Cloud-nativeness | High, but vendor-specific |
| ID stability | High |
| Cross-mapping | Low — a hardening guide, not a control catalog |
| Redistributability | Restricted licensing on benchmark text |
| Portfolio/CCSK fit | Indirect |

**Pros:** extremely prescriptive and directly checkable — almost 1:1 with
scanner logic.
**Cons:** it is a *hardening benchmark*, not a governance control framework;
AWS-specific; weaker as an audit vocabulary. In practice we *use* CIS-style
checks as the implementation of CCM controls.

### Option C: NIST SP 800-53
| Dimension | Assessment |
|-----------|------------|
| Cloud-nativeness | Low — general-purpose, US-gov oriented |
| ID stability | High |
| Cross-mapping | High |
| Redistributability | Good (public domain) |
| Portfolio/CCSK fit | Indirect |

**Pros:** comprehensive, authoritative, public-domain.
**Cons:** heavy and not cloud-native; the control catalog is large and much of it
is irrelevant to IaC scanning; off-syllabus for the CCSK narrative.

### Option D: ISO/IEC 27001 Annex A
| Dimension | Assessment |
|-----------|------------|
| Cloud-nativeness | Low |
| ID stability | High |
| Cross-mapping | Medium |
| Redistributability | Poor — standard text is copyrighted |
| Portfolio/CCSK fit | Indirect |

**Pros:** widely recognized certification standard.
**Cons:** governance-altitude controls, not granular enough for concrete IaC
checks; redistribution constraints on the text; off-syllabus.

## Trade-off Analysis

The decisive insight is one of **altitude**. CCM operates at the
control-framework altitude; CIS Benchmarks operate at the concrete-check
altitude. They are complementary, not competing — we adopt CCM as the framework
and implement many of its controls using CIS-style checks. CCM's shipped
cross-mappings mean a CCM verdict can later be re-expressed against CIS, NIST, or
ISO without re-architecting the engine; the reverse (starting from CIS) would
lock us to a vendor hardening guide with no governance vocabulary.

NIST 800-53 and ISO 27001 are heavier, less cloud-native, and — for ISO —
constrained on text redistribution. Neither serves the CCSK-alignment goal.

**On version:** CCM **v4.1** was released 2025-11-06 (207 controls, 11 new). We
nonetheless baseline on the **v4.0 line** (pinned v4.0.13) for v1. Rationale: our
entire value proposition is *auditable, independently verifiable* mappings, and
the v4.0 line has the mature ecosystem that supports that — published
cross-mappings and free reference mirrors that a reviewer can check without a
gated download. v4.0.x is also what current CCSK study materials and third-party
mappings reference. v4.1 *does* change our in-scope domains (it removed one IAM
control and renumbered from there — e.g. IAM-13 → IAM-12 — and added LOG
controls), and at the time of writing CSA's official v4.0.13 → v4.1 control
mapping is still being produced; migrating now would mean working from immature
reference data, against the auditability thesis. Both lines are accepted through
**December 2027**, so there is no urgency. We therefore treat **v4.1 migration as
tracked future work** (trigger: the Dec-2027 deadline and publication of the
official mapping), kept cheap by the version-independent check IDs defined in
ADR-0003. The pinned patch and provenance rules are in ADR-0003.

## Consequences

- **Easier:** every verdict carries a stable, on-syllabus control ID; future
  multi-framework reporting becomes a mapping-data exercise via CCM's
  cross-references; control titles are freely quotable in the repo.
- **Harder:** CCM controls must each be translated into a concrete check
  (that translation lives in `docs/control-mapping.md` and is the subject of
  ADR-0003); a meaningful fraction of CCM is process/policy and therefore
  **Not-Applicable** from IaC — we surface those explicitly rather than hide the
  gap.
- **Revisit when:** we re-baseline to CCM v4.1; we add non-AWS providers; or we
  decide to emit parallel CIS/NIST verdicts using CCM's cross-mappings.

## Action Items

1. [x] Verify the four in-scope domains' control IDs and titles against a CCM
   v4.0 reference (IAM, LOG, CEK, IVS — done during mapping).
2. [x] Pin the exact CCM v4.0 patch release (v4.0.13) and provenance rules in
   **ADR-0003**.
3. [ ] Open a future ADR to evaluate migrating from CCM v4.0.13 to v4.1 — trigger:
   the December 2027 transition deadline and publication of CSA's official
   v4.0.13 → v4.1 control mapping.
