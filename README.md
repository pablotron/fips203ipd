# fips203ipd

[C11][] implementation of the KEM512, KEM768, and KEM1024 parameter sets
from the [initial FIPS 203 initial public draft (IPD)][fips203ipd].

Notes:

- Coefficients are reduced modulo Q during polynomial deserialization, as per
  [this discussion][pqc-forum-decode-comment].
- Randomness for `keygen()` and `encaps()` is specified as a function
  parameter.
- This implementation is focused on correctness and is not optimized.
- Uses [my SHA-3 implementation][sha3-mine].
- Test suite is built-in to `fips203ipd.c` (see bottom of file).

Use `make` to build a minimal sample application, and `make test` to run
the test suite.

## Examples

The top-level file `main.c` is a simple application which runs KEM512,
KEM768, and KEM1024 self tests.

A minimal example application which does a single key exchange with
KEM512 in available as `examples/0-hello-kem/`.

API documentation is available in `fips203ipd.h`.

## References

* [FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions][fips202]
* [FIPS 203 (IPD): Module-Lattice-Based Key-Encapsulation Mechanism Standard][fips203ipd]

[c11]: https://en.wikipedia.org/wiki/C11_(C_standard_revision)
  "ISO/IEC 9899:2011"
[SHA-3]: https://en.wikipedia.org/wiki/SHA-3
  "Secure Hash Algorithm 3"
[sha3-mine]: https://github.com/pablotron/sha3
  "My FIPS 202 (SHA-3) implementation."
[fips203ipd]: https://csrc.nist.gov/pubs/fips/203/ipd
  "FIPS 203 (Initial Public Draft): Module-Lattice-Based Key-Encapsulation Mechanism Standard"
[fips202]: https://csrc.nist.gov/pubs/fips/202/final
  "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
[pqc-forum-decode-comment]: https://groups.google.com/a/list.nist.gov/d/msgid/pqc-forum/ZRQvPT7kQ51NIRyJ%40disp3269
  "pqc-forum mailing list discussion about reducing coefficients modulo Q during deserialization."
