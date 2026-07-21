# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/qasimmahmood95/ccm-scanner/security/advisories/new)
rather than opening a public issue. Include what you did, what happened, and
what you expected. I will acknowledge within a few days.

This is a portfolio project, not a supported product: there is no SLA and no
bug bounty. It is still worth reporting — a compliance tool that reports the
wrong thing is a security problem, and I would rather know.

## Posture

The whole design point is that this tool cannot do damage to what it audits.

**It is read-only by construction, not by policy.** The scanner takes its input
as a *string*. Every adapter, check and renderer is a pure function over that
string; none can reach the filesystem, a process or a network. The only I/O in
the codebase is in `src/cli/main.ts`: it reads the file named by `--input` and
writes the evidence pack to the directory named by `--out`. Nothing writes to
the input, executes Terraform, or calls a cloud API.

**It never needs credentials.** There is no cloud SDK in the dependency tree and
no call site to configure, so there is nothing to grant. The cloud lane consumes
a snapshot the operator produced themselves; see [ADR-0004](docs/adr/0004-snapshot-lane.md)
for why that is a deliberate constraint rather than an unfinished feature.

**CI never touches a cloud account.** Every job runs against fixtures committed
to this repository. Pointing the scanner at a real account is a documented local
workflow.

## Handling your data

**Reports can contain infrastructure detail.** An evidence pack names resource
addresses, attribute values, CIDR blocks and policy fragments. That is the point
— a verdict without evidence is an assertion — but it means a report is roughly
as sensitive as the configuration it describes. Treat it accordingly before
attaching it to a ticket or committing it.

**Values the input marks sensitive are redacted.** `terraform show -json` of
*state* puts real secrets in `values` and marks them in `sensitive_values`; a
snapshot marks them with `sensitiveAttributes`. Either way `ccm-scanner` honours
those marks before any renderer runs, so a marked value never reaches either
output format.

The limits are worth stating, because a control that overstates itself is worse
than one that does not exist. Redaction covers an evidence entry that cites a
sensitive attribute, and sensitive keys found while walking an object- or
array-valued observation. It does **not** cover:

- a secret in a value the input never marked sensitive — including anything in
  a snapshot, where the marks are whatever the producer wrote;
- a secret a check interpolated into free text (checks must not do this, and
  none does);
- **the `--input` path itself**, which is echoed into the report as
  `metadata.input.source`.

Scanning `terraform show -json` of a *plan file* rather than of state avoids
most of this: a plan does not resolve secrets that only exist post-apply.

## Snapshots

A snapshot you generate is a description of your infrastructure and should be
handled like one. The documented commands use read-only AWS calls and a
least-privilege policy — see the README's snapshot section. Do not commit real
snapshots to a public repository; the ones in `fixtures/` use obviously fake
account ids and identifiers, and `gitleaks` runs as a pre-commit hook and in CI
to keep it that way.

## Supported versions

Pre-1.0: fixes land on `main` only.
