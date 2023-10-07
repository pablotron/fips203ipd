//
// hello.c: minimal example of a two parties "alice" and "bob"
// generating a shared secret with KEM512.
//
// Build by typing `make` and run by typing `./hello`.
//
// Example:
//
//   > ./hello
//   alice: keygen random (64 bytes) = 30c3e7dfac ... (omitted) ... fecd87f3f
//   alice: generated encapsulation key `ek` and decapsulation key `dk`:
//   alice: ek (800 bytes) = d0f3b03e67 ... (omitted) ... 2da8295829
//   alice: dk (1632 bytes) = 4af498a252 ... (omitted) ... b434abe9e
//   alice: sending encapsulation key `ek` to bob
//
//   bob: encaps random (32 bytes) = b0b41f41da8ed5ee232c9e5683e471cf47fa710db40877d9ade99d8215f5677b
//   bob: generated secret `b_key` and ciphertext `ct`:
//   bob: b_key (32 bytes) = 1c002c91184f5e79fe99276fc22d05fb8b6ccdbfa2b95fe30eee359243a62ed7
//   bob: ct (768 bytes) = f3bcd0755 ... (omitted) ... f22d03a0c
//   bob: sending ciphertext `ct` to alice
//
//   alice: used `dk` to decapsulate secret from `ct` into `a_key`:
//   alice: a_key (32 bytes) = 1c002c91184f5e79fe99276fc22d05fb8b6ccdbfa2b95fe30eee359243a62ed7
//
//   SUCCESS! alice secret `a_key` and bob secret `b_key` match.
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
  // 2. use decapsultion key `dk` to decapsulate shared secret from `ct`.
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
