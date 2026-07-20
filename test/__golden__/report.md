# ccm-scanner report

**Result: FAIL** — 3 controls assessed: 1 pass, 1 fail, 1 not applicable (from 4 findings)

| Field | Value |
| --- | --- |
| Tool | ccm-scanner 0.0.0-test |
| CCM version | v4.0.13 |
| Input | `memory:stub-model` |
| Input digest | `sha256:2b5d03420fcf2f7f1de7072b0cd1bae69c4a3fa0853ee18fd4a6c2d7ad7bd8eb` |
| Generated | 2026-01-01T00:00:00.000Z |

## Coverage by domain

| Domain | Controls | Pass | Fail | N/A | Findings |
| --- | ---: | ---: | ---: | ---: | ---: |
| IAM — Identity & Access Management | 1 | 0 | 0 | 1 | 1 |
| CEK — Cryptography, Encryption & Key Management | 1 | 1 | 0 | 0 | 2 |
| IVS — Infrastructure & Virtualization Security | 1 | 0 | 1 | 0 | 1 |

## IAM — Identity & Access Management

### N/A · IAM-08 User Access Review

Check: `iam/na-process-control`

Reason: Periodic access review is a process control with no signal in declarative infrastructure.

## CEK — Cryptography, Encryption & Key Management

### Passing

- CEK-03 Data Encryption
  - `cek/encryption-at-rest` — 2 findings (pass)

## IVS — Infrastructure & Virtualization Security

### FAIL · IVS-03 Network Security

Check: `ivs/no-open-admin-ports`

- `aws_security_group.web` — `ingress`
  - observed: `[{"from_port":22,"to_port":22,"cidr_blocks":["0.0.0.0/0"]}]`
  - expected: no ingress from 0.0.0.0/0 to an administrative port
