# Credits

Researchers whose findings were accepted under the XSOC-QSIG recognition
program and carried into a release of this crate.

Each entry gives the name or handle the researcher chose, the finding, the
release that carried the fix, and the date the report was received. The same
list is published at
[xsoccorp.com/q-sig-security-bounty/credits](https://www.xsoccorp.com/q-sig-security-bounty/credits).

| Researcher | Finding | Release | Received |
|---|---|---|---|
| [tokenistq](https://github.com/tokenistq) | `tx_seq` allocation was scoped to the holder channel while replay enforcement is scoped to the P1-P3 pair, so two holders on one pair received the same sequence number | [0.2.0](CHANGELOG.md#020---2026-10-04) | 2026-10-04 |

## How credit is published

Accepted findings are acknowledged in three places: this file, the release
notes in [CHANGELOG.md](CHANGELOG.md) for the version carrying the fix, and the
Zenodo record for the affected specification.

Credit is published once the reporting identity is confirmed. XSOC asks for a
public artifact under the account the credit will name, carrying a string XSOC
supplies, which ties the handle being credited and the party reporting to the
same holder. Entries awaiting that confirmation are held rather than published
provisionally.

## Earlier cycles

Stephen Thwaits ran the initial XSOC-QSIG cryptanalytic cycle against the
single-pair primitive.
