# ccm-scanner report

**Result: PASS** — 22 controls assessed: 14 pass, 0 fail, 8 not applicable (from 29 findings)

| Field | Value |
| --- | --- |
| Tool | ccm-scanner 0.1.0 |
| CCM version | v4.0.13 |
| Input | `fixtures/compliant/terraform-plan.json` |
| Input digest | `sha256:00b94601f7c1e76e755c9c3df98892ea4e51570f753fc1f9b1ba463a0bdb381b` |
| Generated | 2026-07-21T00:00:00.000Z |

## Coverage by domain

| Domain | Controls | Pass | Fail | N/A | Findings |
| --- | ---: | ---: | ---: | ---: | ---: |
| IAM — Identity & Access Management | 7 | 5 | 0 | 2 | 8 |
| LOG — Logging & Monitoring | 6 | 4 | 0 | 2 | 6 |
| CEK — Cryptography, Encryption & Key Management | 5 | 3 | 0 | 2 | 9 |
| IVS — Infrastructure & Virtualization Security | 4 | 2 | 0 | 2 | 6 |

## IAM — Identity & Access Management

### N/A · IAM-03 Identity Inventory

Check: `iam/na-runtime-inventory`

Reason: A complete identity inventory requires enumerating the live account's principals. An IaC module is not authoritative for identities created outside it. Becomes checkable in the cloud-snapshot lane.

### N/A · IAM-08 User Access Review

Check: `iam/na-process-control`

Reason: Periodic access review is a temporal, process control. Declarative infrastructure carries no signal of whether or when a review happened.

### Passing

- IAM-02 Strong Password Policy and Procedures
  - `iam/account-password-policy` — 1 finding (pass)
- IAM-05 Least Privilege
  - `iam/no-wildcard-allow` — 2 findings (pass)
- IAM-14 Strong Authentication
  - `iam/mfa-enforcement-present` — 1 finding (pass)
- IAM-15 Passwords Management
  - `iam/password-lifecycle` — 1 finding (pass)
- IAM-16 Authorization Mechanisms
  - `iam/no-wildcard-trust` — 1 finding (pass)

## LOG — Logging & Monitoring

### N/A · LOG-05 Audit Logs Monitoring and Response

Check: `log/na-operational`

Reason: Monitoring logs and responding to what they show is an operational activity. Declarative infrastructure can show that a log exists, never that anyone acted on it.

### N/A · LOG-06 Clock Synchronization

Check: `log/na-host-runtime`

Reason: NTP and clock synchronisation are configured inside the host or image, below the infrastructure graph this scanner reads.

### Passing

- LOG-02 Audit Logs Protection
  - `log/cloudtrail-log-validation` — 1 finding (pass)
- LOG-03 Security Monitoring and Alerting
  - `log/vpc-flow-logs` — 1 finding (pass)
- LOG-04 Audit Logs Access and Accountability
  - `log/cloudtrail-accountability` — 1 finding (pass)
- LOG-07 Logging Scope
  - `log/cloudtrail-multi-region` — 1 finding (pass)

## CEK — Cryptography, Encryption & Key Management

### N/A · CEK-01 Encryption and Key Management Policy and Procedures

Check: `cek/na-governance`

Reason: A policy-and-procedures document is a governance artifact. Declarative infrastructure carries no signal of whether one exists or is followed.

### N/A · CEK-14 Key Destruction

Check: `cek/na-lifecycle-runtime`

Reason: Key destruction is a runtime lifecycle operation. deletion_window_in_days states intent but does not evidence that a key was ever destroyed.

### Passing

- CEK-03 Data Encryption
  - `cek/encryption-at-rest` — 2 findings (pass)
  - `cek/tls-enforced` — 2 findings (pass)
- CEK-04 Encryption Algorithm
  - `cek/approved-algorithms` — 2 findings (pass)
- CEK-12 Key Rotation
  - `cek/kms-key-rotation` — 1 finding (pass)

## IVS — Infrastructure & Virtualization Security

### N/A · IVS-04 OS Hardening and Base Controls

Check: `ivs/na-host-config`

Reason: OS and AMI hardening lives inside the image or host. An instance declaration names an AMI but carries no signal of how that image was built or configured.

### N/A · IVS-08 Network Architecture Documentation

Check: `ivs/na-documentation`

Reason: Network architecture documentation is a written deliverable reviewed by people. No resource attribute evidences whether it exists or is current.

### Passing

- IVS-03 Network Security
  - `ivs/no-open-admin-ports` — 1 finding (pass)
  - `ivs/s3-public-access-block` — 2 findings (pass)
- IVS-06 Segmentation and Segregation
  - `ivs/default-sg-locked-down` — 1 finding (pass)
