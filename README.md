# xsoc-sig-3p

Reference library for the XSOC-QSIG three-party transferable transaction signature protocol (QSIG-3P).

## What this repository is

This is the public, Apache-2.0 reference implementation of the QSIG-3P protocol. It contains the full protocol logic, the role state machines (`Signer`, `Holder`, `Verifier`), transaction sequencing, and the transferability construction that binds an originator's authorization to a verifier who does not hold the originator's pairwise key.

The cryptographic backends in this repository are mock backends by design. `MockSign` and `MockMac` in `src/mock.rs` are HMAC-SHA256 placeholders, isolated to a single module and used only by the tests and benchmarks. They exist so that this repository can be public, cloned, built, and exercised by anyone without access to XSOC's proprietary cryptographic core.

The protocol logic in this repository is real. The cryptographic backends in this repository are not the production primitives. See the boundary below.

## Trade-secret boundary

| Component | Status |
|---|---|
| QSIG-3P protocol logic, role state machines, sequencing, transferability construction | Public, Apache-2.0, in this repository |
| `QsigSignBackend` and `MacBackend` trait definitions | Public, Apache-2.0, in this repository |
| `MockSign` / `MockMac` (HMAC-SHA256 test backends) | Public, test-only, in this repository |
| DSKAG wave engine, key-derivation construction, and the production backends that implement the traits above | Proprietary trade secret. Not in this repository. Available under license from XSOC. |

The production cryptographic backends implement the same `QsigSignBackend` and `MacBackend` traits defined here, over the DSKAG-rooted construction. They are maintained in a separate, private repository and are subject to export control (ECCN 5D002.C1) and licensing. The mock backends in this repository produce structurally valid output for protocol testing but are not the production primitives and must not be used in production or cited for production performance or security characteristics.

## Production capability

The full production QSIG-3P capability, with the DSKAG-rooted signing and wave-engine MAC backends, is implemented, tested, and available under license from XSOC. Production deployment substitutes the licensed backends for the mock backends in this repository by implementing the same two traits, with no change to the protocol logic. Contact licensing@xsoccorp.com.

## Building and testing

```
cargo build
cargo test
cargo bench
```

Tests and benchmarks run against the mock backends. Benchmark numbers from this repository reflect the HMAC-SHA256 mocks and must not be cited as production figures.

## Security claim

XSOC-QSIG is a post-quantum symmetric transaction signature primitive. The signing path contains no asymmetric primitive and therefore has no Shor exposure. The construction is computationally secure, with an EUF-CMA forgery bound of 2^-128 in standard mode and 2^-256 in extended mode. It is a designated-verifier construction: verification is performed by a party holding the pairwise key rather than a published public key. It is not a public-key digital signature and does not provide non-repudiation against arbitrary third parties.

The formal security analysis, including the security model, reductions, and assumptions, is in the DSKAG-IT-SIG specification: https://doi.org/10.5281/zenodo.19639166

## License

Apache-2.0. See LICENSE.

The Apache-2.0 license applies to the contents of this repository. It does not extend to the DSKAG construction or the production backends, which are proprietary to XSOC and licensed separately.
