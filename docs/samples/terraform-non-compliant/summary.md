# ccm-scanner report

**Result: FAIL** — 22 controls assessed: 0 pass, 13 fail, 9 not applicable (from 35 findings)

| Field | Value |
| --- | --- |
| Tool | ccm-scanner 0.1.0 |
| CCM version | v4.0.13 |
| Input | `fixtures/non-compliant/terraform-plan.json` |
| Input digest | `sha256:8960a7e348c2472a909c149c0d081f005cc496d9ccc2493f136671faf4f8a101` |
| Generated | 2026-07-21T00:00:00.000Z |

## Coverage by domain

| Domain | Controls | Pass | Fail | N/A | Findings |
| --- | ---: | ---: | ---: | ---: | ---: |
| IAM — Identity & Access Management | 7 | 0 | 4 | 3 | 7 |
| LOG — Logging & Monitoring | 6 | 0 | 4 | 2 | 8 |
| CEK — Cryptography, Encryption & Key Management | 5 | 0 | 3 | 2 | 11 |
| IVS — Infrastructure & Virtualization Security | 4 | 0 | 2 | 2 | 9 |

## IAM — Identity & Access Management

### FAIL · IAM-02 Strong Password Policy and Procedures

Check: `iam/account-password-policy`

- `aws_iam_account_password_policy.weak` — `minimum_password_length`
  - observed: `8`
  - expected: at least 14 characters
- `aws_iam_account_password_policy.weak` — `require_uppercase_characters`
  - observed: `false`
  - expected: true
- `aws_iam_account_password_policy.weak` — `require_lowercase_characters`
  - observed: `true`
  - expected: true
- `aws_iam_account_password_policy.weak` — `require_numbers`
  - observed: `true`
  - expected: true
- `aws_iam_account_password_policy.weak` — `require_symbols`
  - observed: `false`
  - expected: true

### N/A · IAM-03 Identity Inventory

Check: `iam/na-runtime-inventory`

Reason: A complete identity inventory requires enumerating the live account's principals. An IaC module is not authoritative for identities created outside it. Becomes checkable in the cloud-snapshot lane.

### FAIL · IAM-05 Least Privilege

Check: `iam/no-wildcard-allow`

- `aws_iam_policy.admin` — `policy`
  - observed: `[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]`
  - expected: no Allow statement pairing a wildcard action with a wildcard resource

### N/A · IAM-08 User Access Review

Check: `iam/na-process-control`

Reason: Periodic access review is a temporal, process control. Declarative infrastructure carries no signal of whether or when a review happened.

### N/A · IAM-14 Strong Authentication

Check: `iam/mfa-enforcement-present`

Reason: No policy in this input requires aws:MultiFactorAuthPresent, and per-principal MFA enrolment is account runtime state that declarative infrastructure cannot show.

### FAIL · IAM-15 Passwords Management

Check: `iam/password-lifecycle`

- `aws_iam_account_password_policy.weak` — `password_reuse_prevention`
  - observed: `2`
  - expected: at least 24 previous passwords remembered
- `aws_iam_account_password_policy.weak` — `max_password_age`
  - observed: `0`
  - expected: expiry of 90 days or fewer

### FAIL · IAM-16 Authorization Mechanisms

Check: `iam/no-wildcard-trust`

- `aws_iam_role.public` — `assume_role_policy`
  - observed: `[{"Principal":["*"]}]`
  - expected: no unconditioned Allow for a wildcard principal

## LOG — Logging & Monitoring

### FAIL · LOG-02 Audit Logs Protection

Check: `log/cloudtrail-log-validation`

- `aws_cloudtrail.regional` — `enable_log_file_validation`
  - observed: `false`
  - expected: true

### FAIL · LOG-03 Security Monitoring and Alerting

Check: `log/vpc-flow-logs`

- `aws_vpc.main` — `id`
  - observed: `"no aws_flow_log targets \"vpc-0badc0ffee1234567\""`
  - expected: a VPC flow log capturing this VPC's traffic

- `aws_vpc.secondary` — `id`
  - observed: `"no aws_flow_log targets \"vpc-0badc0ffee7654321\""`
  - expected: a VPC flow log capturing this VPC's traffic

- `aws_vpc.tertiary` — `id`
  - observed: `"no aws_flow_log targets \"vpc-0badc0ffeeabcdef0\""`
  - expected: a VPC flow log capturing this VPC's traffic

### FAIL · LOG-04 Audit Logs Access and Accountability

Check: `log/cloudtrail-accountability`

- `aws_cloudtrail.regional` — `cloud_watch_logs_group_arn`
  - observed: `null`
  - expected: delivery to CloudWatch Logs, or access logging on the log bucket
- `module.storage.aws_s3_bucket.public` — `bucket`
  - observed: `"holds the logs of aws_cloudtrail.regional but has no server access logging"`
  - expected: delivery to CloudWatch Logs, or access logging on the log bucket

### N/A · LOG-05 Audit Logs Monitoring and Response

Check: `log/na-operational`

Reason: Monitoring logs and responding to what they show is an operational activity. Declarative infrastructure can show that a log exists, never that anyone acted on it.

### N/A · LOG-06 Clock Synchronization

Check: `log/na-host-runtime`

Reason: NTP and clock synchronisation are configured inside the host or image, below the infrastructure graph this scanner reads.

### FAIL · LOG-07 Logging Scope

Check: `log/cloudtrail-multi-region`

- `aws_cloudtrail.regional` — `is_multi_region_trail`
  - observed: `false`
  - expected: true
- `aws_cloudtrail.regional` — `include_global_service_events`
  - observed: `false`
  - expected: true

## CEK — Cryptography, Encryption & Key Management

### N/A · CEK-01 Encryption and Key Management Policy and Procedures

Check: `cek/na-governance`

Reason: A policy-and-procedures document is a governance artifact. Declarative infrastructure carries no signal of whether one exists or is followed.

### FAIL · CEK-03 Data Encryption

Check: `cek/encryption-at-rest`

Reason: aws_ebs_volume.data.encrypted is not known until apply, so this input cannot evidence the control either way

- `module.storage.aws_db_instance.main` — `storage_encrypted`
  - observed: `false`
  - expected: true

- `module.storage.aws_s3_bucket.public` — `bucket`
  - observed: `"no aws_s3_bucket_server_side_encryption_configuration targets \"example-non-compliant-public\""`
  - expected: server-side encryption configured for the bucket

- `module.storage.aws_s3_bucket.weak_algorithm` — `bucket`
  - observed: `"covered by an aws_s3_bucket_server_side_encryption_configuration"`
  - expected: server-side encryption configured for the bucket

Check: `cek/tls-enforced`

- `module.storage.aws_s3_bucket.public` — `bucket`
  - observed: `"no aws_s3_bucket_policy denies non-TLS access to \"example-non-compliant-public\""`
  - expected: a policy denying every principal when aws:SecureTransport is false

- `module.storage.aws_s3_bucket.weak_algorithm` — `bucket`
  - observed: `"no aws_s3_bucket_policy denies non-TLS access to \"example-non-compliant-weak\""`
  - expected: a policy denying every principal when aws:SecureTransport is false

### FAIL · CEK-04 Encryption Algorithm

Check: `cek/approved-algorithms`

- `aws_lb_listener.legacy` — `ssl_policy`
  - observed: `"ELBSecurityPolicy-TLS-1-0-2015-04"`
  - expected: a TLS policy permitting only TLS 1.2 or better

- `module.storage.aws_s3_bucket_server_side_encryption_configuration.weak_algorithm` — `rule[].apply_server_side_encryption_by_default.sse_algorithm`
  - observed: `["AES128"]`
  - expected: one of aws:kms, aws:kms:dsse, AES256

### FAIL · CEK-12 Key Rotation

Check: `cek/kms-key-rotation`

- `aws_kms_key.unrotated` — `enable_key_rotation`
  - observed: `false`
  - expected: true

### N/A · CEK-14 Key Destruction

Check: `cek/na-lifecycle-runtime`

Reason: Key destruction is a runtime lifecycle operation. deletion_window_in_days states intent but does not evidence that a key was ever destroyed.

## IVS — Infrastructure & Virtualization Security

### FAIL · IVS-03 Network Security

Check: `ivs/no-open-admin-ports`

- `aws_security_group.admin` — `ingress[0]`
  - observed: `{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"],"exposure":"sensitive port(s) 22 open to the world"}`
  - expected: no ingress from 0.0.0.0/0 or ::/0 to ports 22, 3389, 3306, 5432, 1433, 27017, 6379

Check: `ivs/s3-public-access-block`

- `module.storage.aws_db_instance.main` — `publicly_accessible`
  - observed: `true`
  - expected: false

- `module.storage.aws_s3_bucket.public` — `bucket`
  - observed: `"no aws_s3_bucket_public_access_block enables all four flags for \"example-non-compliant-public\""`
  - expected: all of block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets set to true

- `module.storage.aws_s3_bucket.weak_algorithm` — `bucket`
  - observed: `"no aws_s3_bucket_public_access_block enables all four flags for \"example-non-compliant-weak\""`
  - expected: all of block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets set to true

### N/A · IVS-04 OS Hardening and Base Controls

Check: `ivs/na-host-config`

Reason: OS and AMI hardening lives inside the image or host. An instance declaration names an AMI but carries no signal of how that image was built or configured.

### FAIL · IVS-06 Segmentation and Segregation

Check: `ivs/default-sg-locked-down`

Reason: This input declares 3 VPC(s) but only 2 of them are covered by a declared aws_default_security_group, so at least 1 default security group(s) keep the rules AWS created them with. Which VPCs cannot be said: a aws_default_security_group declares no vpc_id, so which VPC it adopts is not stated, so they cannot be matched to the groups that adopt them.

- `aws_default_security_group.default` — `ingress`
  - observed: `[{"from_port":0,"to_port":0,"protocol":"-1","self":true,"cidr_blocks":[]}]`
  - expected: no rules
- `aws_default_security_group.default` — `egress`
  - observed: `"no rules"`
  - expected: no rules

- `aws_default_security_group.unscoped` — `ingress`
  - observed: `"no rules"`
  - expected: no rules
- `aws_default_security_group.unscoped` — `egress`
  - observed: `"no rules"`
  - expected: no rules

### N/A · IVS-08 Network Architecture Documentation

Check: `ivs/na-documentation`

Reason: Network architecture documentation is a written deliverable reviewed by people. No resource attribute evidences whether it exists or is current.
