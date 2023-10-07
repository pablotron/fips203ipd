# fips203ipd

[C11][] implementation of the KEM512, KEM768, and KEM1024 parameter sets
from the [initial FIPS 203 initial public draft (IPD)][fips203ipd].

[FIPS 203][fips203ipd] is (or will be) [NIST's][nist] standardized
version of [Kyber][], a post-quantum [key encapsulation mechanism
(KEM)][kem].

Notes on this implementation:

- Coefficients are reduced modulo Q during polynomial deserialization, as per
  [this discussion][pqc-forum-decode-comment].
- This implementation is focused on correctness and is not optimized.
  In particular, there is no SIMD optimization and the rounding math
  uses (constant-time) lookup tables, which makes this implementation
  slow and memory-intensive.
- Randomness for `keygen()` and `encaps()` is specified as a function
  parameter.
- Uses [my SHA-3 implementation][sha3-mine].
- Test suite is built-in to `fips203ipd.c` (see bottom of file).

Use `make` to build a minimal self test application and `make test` to
run the test suite.

See `examples/0-hello-kem/` for a minimal example application which does
a single KEM512 key "exchange".

## Documentation

API documentation is available in `fips203ipd.h`.

A minimal application which does a single KEM512 key "exchange" in
available in the `examples/0-hello-kem/` directory.

## Tests

Use `make test` to build and run the test suite.

The test suite checks each component of this implementation for expected
answers and is built with several sanitizers supported by both [GCC][]
and [Clang][].  The source code for the test suite is embedded at the
bottom of `fips203ipd.c` behind a `TEST_FIPS203IPD` define.

You can also build a quick self test application by typing `make` in the
top-level directory.  The self test application does the following 1000
times for each parameter set:

1. Generate a random encapsulation/decapsulation key pair.
2. Encapsulate a secret using the encapsulation key.
3. Decapsulate the secret using the decapsulation key.
4. Verify that the secrets generated in steps #2 and #3 match.

## Usage

There are safer and faster alternatives, but if you want to use this
library anyway:

1. Copy the following files into your source tree: `fips203ipd.c`,
   `fips203ipd.h`, `sha3.h`, and `sha3.c`.
2. Update your build system to compile `fips203ipd.o` and `sha3.o`.
3. Include `fips203ipd.h` in your application.
4. Use `fips203ipd_*()` functions in your code.

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
[nist]: https://nist.gov/
  "National Institutes of Science and Technology"
[kyber]: https://pq-crystals.org/kyber/
  "Kyber: post-quantum key encapsulation mechanism based on the hardness of the module learning with errors (m-LWE) problem."
[kem]: https://en.wikipedia.org/wiki/Key_encapsulation_mechanism
  "Key encapsulation mechanism."
[gcc]: https://en.wikipedia.org/wiki/GNU_Compiler_Collection
  "GNU Compiler Collection."
[clang]: https://en.wikipedia.org/wiki/Clang
  "LLVM compiler front end."
