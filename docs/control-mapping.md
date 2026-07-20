# Control Mapping — CCM v4.0 → concrete checks

**This table is the source of truth.** Code in `src/controls/` must use the exact
`CCM ID`, verbatim `Control Title`, and `Check ID` recorded here. Any divergence
between code and this table is a bug (see the auditable-control workflow in
`CLAUDE.md` and ADR-0003).

## Provenance & version

- **Framework:** CSA Cloud Controls Matrix, **v4.0**, pinned to patch release
  **v4.0.13** (see **ADR-0001** for why the v4.0 line, **ADR-0003** for the pin).
  The pinned version string is echoed in every generated report's metadata.
- **Newer line exists:** CCM **v4.1** shipped 2025-11-06; migrating to it is
  tracked as future work (ADR-0001), not a v1 dependency. Both CCM v4.0.x and
  v4.1 are accepted through **December 2027**, so there is no urgency — the
  migration trigger is that deadline (and CSA publishing the official
  v4.0.13 → v4.1 control mapping).
- **Verbatim titles:** control titles below are copied **verbatim** from CCM
  v4.0.13 and, before release, validated against the official CSA CCM spreadsheet
  — the authoritative source. The online mirrors used during drafting are
  convenience references, not the citation of record.
- **Provider scope (v1):** AWS Terraform provider. Evidence sources reference AWS
  resource types; the check logic is provider-agnostic and keyed off the
  normalized `ResourceModel`.

## Check ID convention

A `checkId` is **`<domain>/<slug>`**: the CCM **domain** code (`iam`, `log`,
`cek`, `ivs` — stable across CCM v4.x) plus a semantic slug for what the check
does. It deliberately **does not embed the CCM control number**. CCM renumbers
individual controls between versions (e.g. v4.1 shifts IAM-13 → IAM-12), so
binding a check's identity to a control number would force cascading renames of
checks, fixtures, and golden files on every framework bump. Keeping `checkId`
stable — and carrying the volatile `ccmId`/`ccmTitle` in their own columns —
means a re-baseline (e.g. to v4.1) edits only those columns. Traceability is
preserved because every `Verdict` carries `checkId`, `ccmId`, and `ccmTitle`
together; reports may render a combined label such as `IAM-16 · no-wildcard-trust`
from the current mapping. See **ADR-0003**.

## Coverage classes

| Class | Meaning |
|---|---|
| **Yes** | Fully checkable from IaC. Produces `pass` or `fail` with evidence. |
| **Partial** | The IaC-visible portion is checked; the runtime/process portion is out of reach. Produces `pass`/`fail` for what is visible, and notes the gap. |
| **NA** | Not checkable from the input at all. Always registered as `not_applicable` **with a reason** — never guessed. Included here to make the scoping decision explicit and auditable. |

`Verdict logic` reads as: **FAIL when …**, otherwise **PASS** (unless stated NA).

## Two rules that keep verdicts honest

**Account-scoped absence is NA, not FAIL.** If a control is governed by an
account-level singleton (password policy, CloudTrail) and the input declares no
such resource, we report `not_applicable` with a reason. The account may well
set it outside this Terraform, and we scan the input, not the account — calling
that a Fail would be inferring non-compliance we cannot evidence (hard
constraint 5). The reason names exactly what was looked for, so the gap is
visible rather than buried. The same applies to resource-scoped controls when
the input declares no resource of that type.

**Unknown-until-apply is NA, not a guess.** Terraform writes a value it cannot
compute until apply as `null`, which is indistinguishable from "never set".
Checks must consult `isUnknown()` (populated from `resource_changes[].change.after_unknown`)
and report `not_applicable` rather than read the `null` as "not configured".

---

## IAM — Identity & Access Management

| CCM ID | Control Title (CCM v4.0) | Check ID | What the scanner checks | Evidence source (AWS / Terraform) | Verdict logic | Coverage |
|---|---|---|---|---|---|---|
| **IAM-05** | Least Privilege | `iam/no-wildcard-allow` | No IAM policy `Allow` statement grants `Action:"*"` **and** `Resource:"*"`. A statement using `NotAction`/`NotResource` is **NA** — an inverted matcher's effective permissions cannot be evaluated by this predicate. | `aws_iam_policy.policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_iam_group_policy` (managed resources only — ingest drops data sources, so `data.aws_iam_policy_document` is never seen) | **FAIL** if any Allow stmt has both action `*` and resource `*`. | Yes |
| **IAM-16** | Authorization Mechanisms | `iam/no-wildcard-trust` | Role trust policies don't allow a wildcard principal unless a condition genuinely narrows *who*. Reported **NA**, not Pass, when the condition constrains something else (transport, region); when it is negated (`StringNotEquals`) or a presence test (`Null`); when any of its values matches every principal — AWS ORs a key's values, so the condition is only as narrow as its **widest** one; or when it uses `...IfExists` on a key that some principals do not carry, which admits exactly those principals. | `aws_iam_role.assume_role_policy` (`Principal` / `Principal.AWS` = `*`, `Condition`) | **FAIL** if principal is `*`/`AWS:*` with no `Condition`. | Yes |
| **IAM-02** | Strong Password Policy and Procedures | `iam/account-password-policy` | Password *strength*: min length ≥ 14, and upper/lower/number/symbol all required. Thresholds are config. | `aws_iam_account_password_policy.minimum_password_length`, `.require_*` | **FAIL** if declared and weaker than configured. **NA** if no policy resource is declared — see *account-scoped absence* below. | Yes |
| **IAM-15** | Passwords Management | `iam/password-lifecycle` | Password *lifecycle*: reuse prevention ≥ 24 and maximum age ≤ 90 days. Split from IAM-02 because a check carries exactly one control id, so a control sharing another's check would never be reported. | `aws_iam_account_password_policy.password_reuse_prevention`, `.max_password_age` | **FAIL** if declared and weaker than configured. **NA** if no policy resource is declared. | Yes |
| **IAM-14** | Strong Authentication | `iam/mfa-enforcement-present` | An MFA-enforcing policy condition (`aws:MultiFactorAuthPresent`) is present on privileged access. | IAM policy documents with a `Bool`/`BoolIfExists`/`Null` MFA condition. The operator decides the sense: `Deny` + `Bool:false` and `Deny` + `Null:true` both enforce; the inverses grant *when MFA is absent* and are **NA**. | **PASS** if MFA-enforcement condition found; **NA** (reason: per-principal MFA enrollment is account runtime state) if none can be found. | Partial |
| **IAM-03** | Identity Inventory | `iam/na-runtime-inventory` | — | — | **NA** — a complete identity inventory requires enumerating live account principals; an IaC module is not authoritative for all identities. *(Becomes checkable in the cloud-snapshot lane.)* | NA |
| **IAM-08** | User Access Review | `iam/na-process-control` | — | — | **NA** — periodic access-review is a temporal/process control with no signal in declarative infrastructure. | NA |

---

## LOG — Logging & Monitoring

| CCM ID | Control Title (CCM v4.0) | Check ID | What the scanner checks | Evidence source (AWS / Terraform) | Verdict logic | Coverage |
|---|---|---|---|---|---|---|
| **LOG-07** | Logging Scope | `log/cloudtrail-multi-region` | Every declared CloudTrail trail is multi-region and includes global service events. | `aws_cloudtrail.is_multi_region_trail`, `.include_global_service_events` | **FAIL** if a declared trail is single-region or excludes global service events — an evidenced failure stands even when a *sibling* flag is unknown, since a single-region trail is single-region either way. **NA** if the input declares no trail (a trail is account-scoped and usually lives in a separate audit module, so absence here is not evidence of absence in the account — *account-scoped absence*, below), or if no requirement is unmet but one is not known until apply. | Yes |
| **LOG-02** | Audit Logs Protection | `log/cloudtrail-log-validation` | Log-file validation is on for each declared trail, and that trail's log bucket — resolved by `s3_bucket_name` — is encrypted and carries a full public-access block. | `aws_cloudtrail.enable_log_file_validation`, `.s3_bucket_name`; `aws_s3_bucket_server_side_encryption_configuration` + `aws_s3_bucket_public_access_block` on the log bucket | **FAIL** if validation is off/absent, or the log bucket is unencrypted or not fully public-access-blocked. **NA** if no trail is declared, or the log bucket is not declared in this input (it is commonly a separate module) — the bucket's protection cannot be evidenced from a name alone. | Yes |
| **LOG-04** | Audit Logs Access and Accountability | `log/cloudtrail-accountability` | Each declared trail delivers to CloudWatch Logs, **or** its log bucket has server access logging. Either alone satisfies the control, so an unknown CloudWatch ARN does not stop the bucket being examined. | `aws_cloudtrail.cloud_watch_logs_group_arn`; `aws_s3_bucket_logging` on the log bucket | **FAIL** if a trail has neither CloudWatch Logs integration nor access logging on its log bucket. **NA** if no trail is declared; if the log bucket is absent from this input so the access-logging half cannot be evidenced; or if the CloudWatch ARN is not known until apply *and* the bucket is unlogged, since the ARN may be set once applied. | Partial |
| **LOG-03** | Security Monitoring and Alerting | `log/vpc-flow-logs` | Every declared VPC has a VPC Flow Log targeting it, correlated by `vpc_id`. A flow log scoped to a subnet or ENI leaves `vpc_id` absent and is simply not a VPC-level flow log — it neither covers a VPC nor casts doubt on one. | `aws_flow_log.vpc_id` referencing each `aws_vpc` | **FAIL** if a declared VPC has no flow log. **NA** if the input declares no VPC, or a flow log's `vpc_id` is *not known until apply* — a create plan reports the id as unknown, so the correlation cannot be resolved and a Fail would be a guess. Note absent ≠ unknown here. *(Alarm/response tuning is runtime — noted, not asserted.)* | Partial |
| **LOG-05** | Audit Logs Monitoring and Response | `log/na-operational` | — | — | **NA** — monitoring-and-response is an operational activity, not a declarative artifact. | NA |
| **LOG-06** | Clock Synchronization | `log/na-host-runtime` | — | — | **NA** — NTP/clock sync is host/runtime configuration, not expressed in the infrastructure graph. | NA |

---

## CEK — Cryptography, Encryption & Key Management

| CCM ID | Control Title (CCM v4.0) | Check ID | What the scanner checks | Evidence source (AWS / Terraform) | Verdict logic | Coverage |
|---|---|---|---|---|---|---|
| **CEK-03** | Data Encryption | `cek/encryption-at-rest` | All in-scope storage encrypts at rest. S3 keeps encryption in a separate resource, correlated by bucket **name**; when a correlator's name is not known until apply the bucket is **NA**, not failed. | `aws_s3_bucket_server_side_encryption_configuration`; `aws_ebs_volume.encrypted`; `aws_db_instance.storage_encrypted`; `aws_rds_cluster.storage_encrypted` | **FAIL** if any in-scope storage resource lacks encryption at rest. | Yes |
| **CEK-03** | Data Encryption *(in transit)* | `cek/tls-enforced` | S3 buckets deny non-TLS access. The deny must apply to every principal, cover `s3:*`, and name this bucket's objects — a deny scoped to another bucket or one prefix does not enforce TLS here. | `aws_s3_bucket_policy` with `Deny` on `aws:SecureTransport = false` (`Bool`/`BoolIfExists`) | **FAIL** if a bucket has no such statement. **NA** if the policy document is unreadable or not known until apply. | Yes |
| **CEK-04** | Encryption Algorithm | `cek/approved-algorithms` | SSE algorithm and ELB TLS policy are checked against an **allowlist**, never a denylist: an unrecognised TLS policy is **NA**, not Pass, so a newly-added weak policy cannot slip through. | `...sse_algorithm`; `aws_lb_listener.ssl_policy` | **FAIL** if a disallowed SSE algorithm or a known-weak `ssl_policy` (permits TLS 1.0/1.1) is used. **NA** for an unrecognised policy. | Yes |
| **CEK-12** | Key Rotation | `cek/kms-key-rotation` | Customer-managed symmetric KMS keys have automatic rotation enabled. | `aws_kms_key.enable_key_rotation` | **FAIL** if any customer-managed CMK has rotation disabled/unset. | Yes |
| **CEK-01** | Encryption and Key Management Policy and Procedures | `cek/na-governance` | — | — | **NA** — a policy-and-procedures document is governance, not infrastructure. | NA |
| **CEK-14** | Key Destruction | `cek/na-lifecycle-runtime` | — | — | **NA** — key destruction is a runtime lifecycle operation; `deletion_window_in_days` hints at intent but does not evidence destruction. | NA |

---

## IVS — Infrastructure & Virtualization Security (network security slice)

| CCM ID | Control Title (CCM v4.0) | Check ID | What the scanner checks | Evidence source (AWS / Terraform) | Verdict logic | Coverage |
|---|---|---|---|---|---|---|
| **IVS-03** | Network Security | `ivs/no-open-admin-ports` | No security-group ingress from `0.0.0.0/0` or `::/0` reaches a sensitive/admin port (22, 3389, 3306, 5432, 1433, 27017, 6379), and no world-open rule opens all ports. A port *range* is checked for overlap, not equality; `protocol = "-1"` means every port; ICMP is excluded from port analysis because it reuses `from_port`/`to_port` as type and code. The three declaration styles are normalised before any judgement is made. **Limitation:** world-openness is matched on the literal CIDRs `0.0.0.0/0` and `::/0`, so an equivalent split range (`0.0.0.0/1` + `128.0.0.0/1`) is not detected. | `aws_security_group.ingress`, `aws_default_security_group.ingress`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule` | **FAIL** if any world-open ingress covers a sensitive port or all ports. Port list is config. **NA** if the input declares no ingress rules, or a rule's ports, protocol, CIDRs or `type` are not known until apply — including an unreadable protocol, which must never default to "every protocol". | Yes |
| **IVS-03** | Network Security *(exposure)* | `ivs/s3-public-access-block` | Every S3 bucket is covered by a public-access block with all four flags enabled, correlated by bucket **name**; no RDS instance is publicly accessible. Aurora is covered via `aws_rds_cluster_instance`, which is where the endpoint lives. | `aws_s3_bucket_public_access_block.block_public_acls`/`.block_public_policy`/`.ignore_public_acls`/`.restrict_public_buckets`; `aws_db_instance.publicly_accessible`, `aws_rds_cluster_instance.publicly_accessible` | **FAIL** if a bucket has no public-access block or one with any flag off, or an RDS instance is publicly accessible. **NA** where the correlator is not known until apply, or neither resource type is declared. Uncertainty is scoped to the bucket it concerns — an unknown flag on one bucket does not make any other bucket NA. | Yes |
| **IVS-06** | Segmentation and Segregation | `ivs/default-sg-locked-down` | The default security group carries no ingress or egress rules; workloads use purpose-built SGs. | `aws_default_security_group` (empty `ingress`/`egress`), correlated to `aws_vpc.id` by `vpc_id` | **FAIL** if an adopted default SG defines any rule. **NA**, naming the VPC, for each declared VPC whose default SG this input does not adopt: AWS creates that group with allow-all-from-itself ingress and allow-all egress, and those rules are not visible here. Leaving it unmanaged is not evidence either way, but it is not silence either. | Yes |
| **IVS-04** | OS Hardening and Base Controls | `ivs/na-host-config` | — | — | **NA** — OS/AMI hardening lives inside the image/host, below the infrastructure graph. | NA |
| **IVS-08** | Network Architecture Documentation | `ivs/na-documentation` | — | — | **NA** — a documentation deliverable, not a checkable resource attribute. | NA |

---

## Summary of the initial curated subset

- **Checkable (Yes/Partial), evidenced by checks:** IAM-05, IAM-16, IAM-02
  (+IAM-15), IAM-14; LOG-07, LOG-02, LOG-04, LOG-03; CEK-03 (at rest + in
  transit), CEK-04, CEK-12; IVS-03 (ports + exposure), IVS-06.
- **Explicitly Not-Applicable, with reasons:** IAM-03, IAM-08; LOG-05, LOG-06;
  CEK-01, CEK-14; IVS-04, IVS-08.

This is a deliberate slice across four CCM domains, chosen so that (a) every
"Yes" check has a crisp, demonstrable Terraform signal with a matching
non-compliant fixture, and (b) the "NA" rows make the boundary of IaC-based
assessment explicit rather than papering over it. It is **not** an attempt to
implement all of CCM.
