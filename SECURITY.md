# Security Policy

XSOC CORP runs an active bug bounty program covering the QSIG family,
including QSIG-3P. We welcome responsible disclosure from cryptographers,
security researchers, and engineers.

## Reporting a Vulnerability

Email reports to **security@xsoccorp.com**.

- Subject line should begin with `[QSIG-3P SECURITY]`.
- Include a description, reproduction steps, expected vs observed behavior,
  and any test vectors or PoC code.
- Encrypted reports: PGP key fingerprint and download available at
  `xsoccorp.com/security`.

We acknowledge receipt within 48 hours and provide a triage decision within
7 calendar days. Critical-severity reports trigger same-day acknowledgment.

## Scope

QSIG-3P bounty scope covers:

- Protocol orchestration in `xsoc-sig-3p` (signer, holder, verifier roles)
- Wire format parsing and serialization (`SignedTransfer`)
- Replay protection via `tx_seq` monotonicity
- Trait abstractions (`QsigSignBackend`, `MacBackend`) and their contracts

Out of scope for this bounty (covered separately under
`xsoccorp.com/q-sig-security-bounty`):

- The underlying 30-byte QSIG signature primitive
- The wave-engine MAC primitive
- DSKAG pairwise key derivation

For findings spanning both, reference both bounties; rewards are not duplicated
but the higher tier applies.

Mock backends in `src/mock.rs` are HMAC-SHA256 placeholders for testing only
and are not in scope. Findings against the mocks should be reframed as
findings against the trait contracts they implement.

## Severity and Reward

QSIG-3P shares the QSIG bounty pool. The initial 0.05 BTC allocation is fully
awarded. Reports received now are acknowledged with public credit in the release
notes and in the advisory for the affected version, and XSOC will post a new
funded cycle here when one opens. The tiers below define the severity
classification applied at triage, and the amounts apply during a funded cycle.

| Tier | Reward | Examples |
|------|--------|----------|
| Critical     | 0.025 BTC + co-authorship credit on relevant publications | Forgery against an honest verifier; replay bypass that defeats `tx_seq` monotonicity; cross-pair confusion |
| Significant  | 0.015 BTC | Wire-format malleability accepted by verifier; state-corruption that persists across restarts |
| Moderate     | 0.01 BTC  | DoS against signer/holder/verifier; type confusion in protocol state machine |
| Informational| Recognition in changelog and security acknowledgments | Documentation gaps with security implications |

Co-authorship credit is offered at the reporter's option for Critical findings
that lead to a public security advisory or paper revision.

## Out of Scope

- Issues in upstream dependencies (report upstream; we proxy via `cargo audit`)
- Performance issues without a security impact
- Findings against mock backends only
- Theoretical attacks without a working PoC
- Social-engineering attacks against XSOC personnel

## Disclosure Process

We follow coordinated disclosure with a 90-day window from acknowledged
report to public disclosure. The window is extended on request when a fix
requires additional engineering or coordination with downstream consumers.

Reporters can request CVE assignment for credit. We publish a security
advisory in the repository's `Security` tab and reference it from release
notes.

## Safe Harbor

We will not pursue legal action against researchers acting in good faith
who:

- Comply with this policy
- Avoid privacy violations, service disruption, and data destruction
- Give us a reasonable window to respond before public disclosure
- Do not exploit findings beyond what is necessary to demonstrate the issue

## Credits

Researchers credited under this program are listed in
[CREDITS.md](CREDITS.md) in this repository, and at
https://www.xsoccorp.com/q-sig-security-bounty.

Credit is published once the reporting identity is confirmed. We ask for a
public artifact under the account the credit will name, carrying a string we
supply, which ties the handle being credited and the party reporting to the
same holder. Tell us how you want to be credited when you report.
