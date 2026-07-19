# ccm-scanner report

**Result: FAIL** — 1 pass, 1 fail, 1 not applicable (3 controls)

| Field | Value |
| --- | --- |
| Tool | ccm-scanner 0.0.0-test |
| CCM version | v4.0.13 |
| Input | `memory:stub-model` |
| Input digest | `sha256:e6444fe4dfac319680e39b1262a64fbdf017cfba57cf4b7a795c8dc00b9bcc87` |
| Generated | 2026-01-01T00:00:00.000Z |

## Coverage by domain

| Domain | Pass | Fail | N/A | Total |
| --- | ---: | ---: | ---: | ---: |
| IAM — Identity & Access Management | 0 | 0 | 1 | 1 |
| CEK — Cryptography, Encryption & Key Management | 1 | 0 | 0 | 1 |
| IVS — Infrastructure & Virtualization Security | 0 | 1 | 0 | 1 |

## IAM — Identity & Access Management

### N/A · IAM-08 User Access Review

Check: `iam/na-process-control`

Reason: Periodic access review is a process control with no signal in declarative infrastructure.

## CEK — Cryptography, Encryption & Key Management

### Passing

- CEK-03 Data Encryption (`cek/encryption-at-rest`)

## IVS — Infrastructure & Virtualization Security

### FAIL · IVS-03 Network Security

Check: `ivs/no-open-admin-ports`

- `aws_security_group.web` — `ingress`
  - observed: `[{"from_port":22,"to_port":22,"cidr_blocks":["0.0.0.0/0"]}]`
  - expected: no ingress from 0.0.0.0/0 to an administrative port
