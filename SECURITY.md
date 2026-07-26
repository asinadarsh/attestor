# Security policy

## Reporting a vulnerability

Report privately via [GitHub Security Advisories](https://github.com/asinadarsh/attestor/security/advisories/new).
Please do not open a public issue for a vulnerability first.

Include a proof of concept if you have one — for this project that usually
means a ledger that `attestor verify` accepts but should not, or one it
rejects but should not. A failing test against `packages/attestor/test/` is
the ideal report.

This is a personal project, not a funded product: expect a first response
within a week, and no bug bounty.

## What counts as a vulnerability

**In scope** — anything that breaks the claims in the README's threat model:

- A tampered ledger that verifies clean (`exit 0`): edited, reordered, or
  deleted entries; a rewritten history that reproduces its Merkle roots; a
  forged or substituted Rekor anchor accepted as authentic.
- A ledger that fails verification despite never being modified (a false
  tamper report is a real defect — it destroys the tool's usefulness as
  evidence).
- Recording gaps that leave no trace: traffic relayed by the proxy or
  transmitted by the SDK that never reaches the ledger and produces no `gap`
  marker, in either `block` or `continue` mode.
- Redaction that leaks: recovering a redacted payload from what survives on
  the line, or a redaction that silently invalidates the chain.
- Key handling: private keys written world-readable, leaked to logs, or a
  rotation chain that accepts a key an attacker introduced.

**Out of scope** — these are disclosed limitations, not bugs:

- Compromise of the host *during* recording. The recorder signs what it is
  shown; lies fed to it are faithfully attested.
- Forgery after signing-key theft, going forward from the theft. Anchored
  history still cannot be rewritten; that is the actual claim.
- Truncation of entries after the last anchored checkpoint (the ANCHOR LAG
  window, ≤64 entries / 60 s by default). Reported, not prevented.
- Anything requiring Sigstore/Rekor itself to be compromised.
- Windows-specific failures. Windows is unsupported for now (POSIX fsync and
  lockfile assumptions).

If you are unsure whether something is in scope, report it — a limitation
that is easy to mistake for a guarantee is itself worth fixing, in the docs
if not in the code.
