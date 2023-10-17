# fips203ipd

[C11][] implementation of the KEM512, KEM768, and KEM1024 parameter sets
from the [FIPS 203 initial public draft (IPD)][fips203ipd].

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

Use `make` to build a minimal self test application, `make doc` to build
the [HTML][]-formatted [API][] documentation, and `make test` to run the
test suite.

## Example

Minimal example of Alice and Bob exchanging a shared secret with KEM512:

```c
//
// hello.c: minimal example of a two parties "alice" and "bob"
// generating a shared secret with KEM512.
//
#include <stdio.h> // fputs()
#include <string.h> // memcmp()
#include "hex.h" // hex_write()
#include "rand-bytes.h" // rand_bytes()
#include "fips203ipd.h" // fips203ipd_*()

int main(void) {
  //
  // alice: generate keypair
  //
  uint8_t ek[FIPS203IPD_KEM512_EK_SIZE] = { 0 }; // encapsulation key
  uint8_t dk[FIPS203IPD_KEM512_DK_SIZE] = { 0 }; // decapsulation key
  {
    // alice: get 64 random bytes for keygen()
    uint8_t keygen_seed[64] = { 0 };
    rand_bytes(keygen_seed, sizeof(keygen_seed));

    fputs("alice: keygen random (64 bytes) = ", stdout);
    hex_write(stdout, keygen_seed, sizeof(keygen_seed));
    fputs("\n", stdout);

    // alice: generate encapsulation/decapsulation key pair
    fips203ipd_kem512_keygen(ek, dk, keygen_seed);
  }
  fputs("alice: generated encapsulation key `ek` and decapsulation key `dk`:\n", stdout);
  printf("alice: ek (%d bytes) = ", FIPS203IPD_KEM512_EK_SIZE);
  hex_write(stdout, ek, sizeof(ek));
  printf("\nalice: dk (%d bytes) = ", FIPS203IPD_KEM512_DK_SIZE);
  hex_write(stdout, dk, sizeof(dk));
  fputs("\n", stdout);

  // alice send `ek` to bob
  fputs("alice: sending encapsulation key `ek` to bob\n\n", stdout);

  //
  // bob: generate shared secret and ciphertext
  //
  uint8_t b_key[32] = { 0 }; // shared secret
  uint8_t ct[FIPS203IPD_KEM512_CT_SIZE] = { 0 }; // ciphertext
  {
    // bob: get 32 random bytes for encaps()
    uint8_t encaps_seed[32] = { 0 };
    rand_bytes(encaps_seed, sizeof(encaps_seed));

    fputs("bob: encaps random (32 bytes) = ", stdout);
    hex_write(stdout, encaps_seed, sizeof(encaps_seed));
    fputs("\n", stdout);

    // bob:
    // 1. get encapsulation key `ek` from alice.
    // 2. generate random shared secret.
    // 3. use `ek` from step #1 to encapsulate the shared secret from step #2.
    // 3. store the shared secret in `b_key`.
    // 4. store the encapsulated shared secret (ciphertext) in `ct`.
    fips203ipd_kem512_encaps(b_key, ct, ek, encaps_seed);
  }

  fputs("bob: generated secret `b_key` and ciphertext `ct`:\nbob: b_key (32 bytes) = ", stdout);
  hex_write(stdout, b_key, sizeof(b_key));
  printf("\nbob: ct (%d bytes) = ", FIPS203IPD_KEM512_CT_SIZE);
  hex_write(stdout, ct, sizeof(ct));
  fputs("\n", stdout);

  // bob sends ciphertext `ct` to alice
  fputs("bob: sending ciphertext `ct` to alice\n\n", stdout);

  //
  // alice: decapsulate shared secret
  //

  // alice:
  // 1. get ciphertext `ct` from bob.
  // 2. use decapsulation key `dk` to decapsulate shared secret from `ct`.
  // 2. store shared secret in `a_key`.
  uint8_t a_key[32] = { 0 };
  fips203ipd_kem512_decaps(a_key, ct, dk);

  fputs("alice: used `dk` to decapsulate secret from `ct` into `a_key`:\nalice: a_key (32 bytes) = ", stdout);
  hex_write(stdout, a_key, sizeof(a_key));
  fputs("\n\n", stdout);

  // check result
  if (!memcmp(a_key, b_key, sizeof(a_key))) {
    // success: alice and bob have the same shared secret
    fputs("SUCCESS! alice secret `a_key` and bob secret `b_key` match.\n", stdout);
    return 0;
  } else {
    // failure: alice and bob do not have the same shared secret
    fputs("FAILURE! alice secret `a_key` and bob secret `b_key` do not match.\n", stdout);
    return -1;
  }
}
```

See `examples/0-hello-kem/` for the full buildable example, including a
`Makefile` and support files.

## Documentation

[API][] documentation is available online [here][api-docs] and also in
`fips203ipd.h`.  If you have [Doxygen][] installed, you can build
[HTML][]-formatted [API][] documentation by typing `make doc`.

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

## License

[MIT No Attribution (MIT-0)][MIT-0]

Copyright 2023 Paul Duncan

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
[doxygen]: https://en.wikipedia.org/wiki/Doxygen
  "API documentation generator."
[api]: https://en.wikipedia.org/wiki/API
  "Application Programming Interface (API)"
[html]: https://en.wikipedia.org/wiki/HTML
  "HyperText Markup Language (HTML)"
[mit-0]: https://opensource.org/license/mit-0/
  "MIT No Attribution license"
[api-docs]: https://pmdn.org/api-docs/fips203ipd/
  "fips203ipd API documentation."
