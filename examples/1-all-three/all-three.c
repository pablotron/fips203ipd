//
// all-three.c: minimal example of a two parties "alice" and "bob"
// generating a shared secret with each of KEM512, KEM768, and KEM1024.
//
// Build by typing `make` and run by typing `./all-three`.
//
// Note: This example is used as a source for examples in the generated
// API documentation.
//
#include <stdio.h> // fputs()
#include <string.h> // memcmp()
#include "hex.h" // hex_write()
#include "rand-bytes.h" // rand_bytes()
#include "fips203ipd.h" // fips203ipd_*()

// print decapsulated key
static void print_decapsulated_key(const char *algo_name, const char *ct_name, const char *key_name, const uint8_t key[static 32]) {
  printf("alice: used %s decapsulation key `dk` to decapsulate secret from %s ciphertext `%s` into `%s`:\nalice: %s (32 bytes) = ", algo_name, algo_name, ct_name, key_name, key_name);
  hex_write(stdout, key, 32);
  fputs("\n\n", stdout);
}

// compare two shared secrets and print success or failure
static void compare_keys(const char *name, const uint8_t a_key[static 32], const uint8_t b_key[static 32]) {
  // compare keys (note: not constant-time!)
  if (!memcmp(a_key, b_key, 32)) {
    printf("%s: SUCCESS! `a_key` == `b_key`\n", name);
  } else {
    printf("%s: FAILURE! `a_key` != `b_key`\n", name);
  }
}

// print generated KEM512 keypair
static void kem512_print_keypair(const uint8_t ek[static FIPS203IPD_KEM512_EK_SIZE], const uint8_t dk[static FIPS203IPD_KEM512_DK_SIZE]) {
  fputs("alice: generated KEM512 encapsulation key `ek` and KEM512 decapsulation key `dk`:\n", stdout);
  printf("alice: ek (%d bytes) = ", FIPS203IPD_KEM512_EK_SIZE);
  hex_write(stdout, ek, FIPS203IPD_KEM512_EK_SIZE);
  printf("\nalice: dk (%d bytes) = ", FIPS203IPD_KEM512_DK_SIZE);
  hex_write(stdout, dk, FIPS203IPD_KEM512_DK_SIZE);
  fputs("\n", stdout);
}

// print generated shared secret and KEM512 ciphertext
static void kem512_print_key_and_ct(const uint8_t key[static 32], const uint8_t ct[static FIPS203IPD_KEM512_CT_SIZE]) {
  fputs("bob: generated secret `b_key` and KEM512 ciphertext `ct`:\nbob: b_key (32 bytes) = ", stdout);
  hex_write(stdout, key, 32);
  printf("\nbob: ct (%d bytes) = ", FIPS203IPD_KEM512_CT_SIZE);
  hex_write(stdout, ct, FIPS203IPD_KEM512_CT_SIZE);
  fputs("\n", stdout);
}

// KEM512 example
static void kem512_example(void) {
  const char *name = "KEM512"; // algorithm name

  //! [kem512-keygen]
  // alice: get 64 random bytes for keygen()
  uint8_t keygen_seed[64] = { 0 };
  rand_bytes(keygen_seed, sizeof(keygen_seed));

  // alice: generate encapsulation/decapsulation key pair from seed
  uint8_t ek[FIPS203IPD_KEM512_EK_SIZE] = { 0 }; // encapsulation key
  uint8_t dk[FIPS203IPD_KEM512_DK_SIZE] = { 0 }; // decapsulation key
  fips203ipd_kem512_keygen(ek, dk, keygen_seed);
  //! [kem512-keygen]
  kem512_print_keypair(ek, dk);

  // alice: send encapsulation key `ek` to bob
  printf("alice: sending %s encapsulation key `ek` to bob\n\n", name);

  //! [kem512-encaps]
  // bob: get 32 random bytes for encaps()
  uint8_t encaps_seed[32] = { 0 };
  rand_bytes(encaps_seed, sizeof(encaps_seed));

  // bob: generate shared secret and ciphertext from encapsulation key and seed
  uint8_t b_key[32] = { 0 }; // shared secret
  uint8_t ct[FIPS203IPD_KEM512_CT_SIZE] = { 0 }; // ciphertext
  fips203ipd_kem512_encaps(b_key, ct, ek, encaps_seed);
  //! [kem512-encaps]
  kem512_print_key_and_ct(b_key, ct);

  // bob: send ciphertext `ct` to alice
  printf("bob: sending %s ciphertext `ct` to alice\n\n", name);

  //! [kem512-decaps]
  // alice: decapsulate shared secret from ciphertext
  uint8_t a_key[32] = { 0 }; // decapsulated key
  fips203ipd_kem512_decaps(a_key, ct, dk);
  //! [kem512-decaps]
  print_decapsulated_key(name, "ct", "a_key", a_key);

  // compare keys (not constant-time)
  compare_keys(name, a_key, b_key);
}

// print generated KEM768 keypair
static void kem768_print_keypair(const uint8_t ek[static FIPS203IPD_KEM768_EK_SIZE], const uint8_t dk[static FIPS203IPD_KEM768_DK_SIZE]) {
  fputs("alice: generated KEM768 encapsulation key `ek` and KEM768 decapsulation key `dk`:\n", stdout);
  printf("alice: ek (%d bytes) = ", FIPS203IPD_KEM768_EK_SIZE);
  hex_write(stdout, ek, FIPS203IPD_KEM768_EK_SIZE);
  printf("\nalice: dk (%d bytes) = ", FIPS203IPD_KEM768_DK_SIZE);
  hex_write(stdout, dk, FIPS203IPD_KEM768_DK_SIZE);
  fputs("\n", stdout);
}

// print generated shared secret and KEM768 ciphertext
static void kem768_print_key_and_ct(const uint8_t key[static 32], const uint8_t ct[static FIPS203IPD_KEM768_CT_SIZE]) {
  fputs("bob: generated secret `b_key` and KEM768 ciphertext `ct`:\nbob: b_key (32 bytes) = ", stdout);
  hex_write(stdout, key, 32);
  printf("\nbob: ct (%d bytes) = ", FIPS203IPD_KEM768_CT_SIZE);
  hex_write(stdout, ct, FIPS203IPD_KEM768_CT_SIZE);
  fputs("\n", stdout);
}

// KEM768 example
static void kem768_example(void) {
  const char *name = "KEM768"; // algorithm name

  //! [kem768-keygen]
  // alice: get 64 random bytes for keygen()
  uint8_t keygen_seed[64] = { 0 };
  rand_bytes(keygen_seed, sizeof(keygen_seed));

  // alice: generate encapsulation/decapsulation key pair from seed
  uint8_t ek[FIPS203IPD_KEM768_EK_SIZE] = { 0 }; // encapsulation key
  uint8_t dk[FIPS203IPD_KEM768_DK_SIZE] = { 0 }; // decapsulation key
  fips203ipd_kem768_keygen(ek, dk, keygen_seed);
  //! [kem768-keygen]
  kem768_print_keypair(ek, dk);

  // alice: send encapsulation key `ek` to bob
  printf("alice: sending %s encapsulation key `ek` to bob\n\n", name);

  //! [kem768-encaps]
  // bob: get 32 random bytes for encaps()
  uint8_t encaps_seed[32] = { 0 };
  rand_bytes(encaps_seed, sizeof(encaps_seed));

  // bob: generate shared secret and ciphertext from encapsulation key and seed
  uint8_t b_key[32] = { 0 }; // shared secret
  uint8_t ct[FIPS203IPD_KEM768_CT_SIZE] = { 0 }; // ciphertext
  fips203ipd_kem768_encaps(b_key, ct, ek, encaps_seed);
  //! [kem768-encaps]
  kem768_print_key_and_ct(b_key, ct);

  // bob: send ciphertext `ct` to alice
  printf("bob: sending %s ciphertext `ct` to alice\n\n", name);

  //! [kem768-decaps]
  // alice: decapsulate shared secret from ciphertext
  uint8_t a_key[32] = { 0 }; // decapsulated key
  fips203ipd_kem768_decaps(a_key, ct, dk);
  //! [kem768-decaps]
  print_decapsulated_key(name, "ct", "a_key", a_key);

  // compare keys (not constant-time)
  compare_keys(name, a_key, b_key);
}

// print generated KEM1024 keypair
static void kem1024_print_keypair(const uint8_t ek[static FIPS203IPD_KEM1024_EK_SIZE], const uint8_t dk[static FIPS203IPD_KEM1024_DK_SIZE]) {
  fputs("alice: generated KEM1024 encapsulation key `ek` and KEM1024 decapsulation key `dk`:\n", stdout);
  printf("alice: ek (%d bytes) = ", FIPS203IPD_KEM1024_EK_SIZE);
  hex_write(stdout, ek, FIPS203IPD_KEM1024_EK_SIZE);
  printf("\nalice: dk (%d bytes) = ", FIPS203IPD_KEM1024_DK_SIZE);
  hex_write(stdout, dk, FIPS203IPD_KEM1024_DK_SIZE);
  fputs("\n", stdout);
}

// print generated shared secret and KEM1024 ciphertext
static void kem1024_print_key_and_ct(const uint8_t key[static 32], const uint8_t ct[static FIPS203IPD_KEM1024_CT_SIZE]) {
  fputs("bob: generated secret `b_key` and KEM1024 ciphertext `ct`:\nbob: b_key (32 bytes) = ", stdout);
  hex_write(stdout, key, 32);
  printf("\nbob: ct (%d bytes) = ", FIPS203IPD_KEM1024_CT_SIZE);
  hex_write(stdout, ct, FIPS203IPD_KEM1024_CT_SIZE);
  fputs("\n", stdout);
}

// KEM1024 example
static void kem1024_example(void) {
  const char *name = "KEM1024"; // algorithm name

  //! [kem1024-keygen]
  // alice: get 64 random bytes for keygen()
  uint8_t keygen_seed[64] = { 0 };
  rand_bytes(keygen_seed, sizeof(keygen_seed));

  // alice: generate encapsulation/decapsulation key pair from seed
  uint8_t ek[FIPS203IPD_KEM1024_EK_SIZE] = { 0 }; // encapsulation key
  uint8_t dk[FIPS203IPD_KEM1024_DK_SIZE] = { 0 }; // decapsulation key
  fips203ipd_kem1024_keygen(ek, dk, keygen_seed);
  //! [kem1024-keygen]
  kem1024_print_keypair(ek, dk);

  // alice: send encapsulation key `ek` to bob
  printf("alice: sending %s encapsulation key `ek` to bob\n\n", name);

  //! [kem1024-encaps]
  // bob: get 32 random bytes for encaps()
  uint8_t encaps_seed[32] = { 0 };
  rand_bytes(encaps_seed, sizeof(encaps_seed));

  // bob: generate shared secret and ciphertext from encapsulation key and seed
  uint8_t b_key[32] = { 0 }; // shared secret
  uint8_t ct[FIPS203IPD_KEM1024_CT_SIZE] = { 0 }; // ciphertext
  fips203ipd_kem1024_encaps(b_key, ct, ek, encaps_seed);
  //! [kem1024-encaps]
  kem1024_print_key_and_ct(b_key, ct);

  // bob: send ciphertext `ct` to alice
  printf("bob: sending %s ciphertext `ct` to alice\n\n", name);

  //! [kem1024-decaps]
  // alice: decapsulate shared secret from ciphertext
  uint8_t a_key[32] = { 0 }; // decapsulated key
  fips203ipd_kem1024_decaps(a_key, ct, dk);
  //! [kem1024-decaps]
  print_decapsulated_key(name, "ct", "a_key", a_key);

  // compare keys (not constant-time)
  compare_keys(name, a_key, b_key);
}

int main(void) {
  kem512_example();
  kem768_example();
  kem1024_example();
}
