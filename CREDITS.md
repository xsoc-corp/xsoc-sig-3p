# Credits

Researchers whose findings were accepted under the XSOC-QSIG recognition
program and carried into a release of this crate.

Each entry gives the name or handle the researcher chose, the finding, the
release that carried the fix, and the date the report was received. The same
list is published at
[xsoccorp.com/q-sig-security-bounty](https://www.xsoccorp.com/q-sig-security-bounty).

| Researcher | Finding | Release | Received |
|---|---|---|---|
| [tokenistq](https://github.com/tokenistq) | `tx_seq` allocation was scoped to the holder channel while replay enforcement is scoped to the P1-P3 pair, so two holders on one pair received the same sequence number | [0.2.0](CHANGELOG.md#020---2026-10-04) | 2026-10-04 |
| [Ibnu76](https://github.com/ibnu76) | `PairSequencer` still derived `Clone` and implemented `Default`, so one pair could hold two allocators through a path reachable without any `clone()` call | [0.3.0](CHANGELOG.md#030---2026-10-06) | 2026-10-06 |
| [Ibnu76](https://github.com/ibnu76) | The signature covered the message alone, leaving `tx_seq` outside what P1 authorized | [0.4.0](CHANGELOG.md#040---2026-10-06) | 2026-10-06 |
| [Ibnu76](https://github.com/ibnu76) | The IC tag input lacked the `DST_IC` domain separator required by specification 3.3 step 3 | [0.4.0](CHANGELOG.md#040---2026-10-06) | 2026-10-06 |
| [Ibnu76](https://github.com/ibnu76) | The wire length prefix was 8 bytes for 74 bytes of overhead, where the specification fixes 4 bytes and 70 | [0.4.0](CHANGELOG.md#040---2026-10-06) | 2026-10-06 |

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
