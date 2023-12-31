//
// Example application which tests KEM512, KEM768, and KEM1024 by doing
// the following for each parameter set 1000 times:
//
// 1. Generate a random encapsulation key pair.
// 2. Use the encapsulation key to encapsulate a random shared secret.
// 3. Use the decapsulation key to decapsulate the shared secret.
// 4. Verify that the shared secret from steps #2 and #3 match.
//

#include <stdlib.h> // exit()
#include <stdio.h> // printf()
#include <string.h> // memcmp()
#include "fips203ipd.h" // fips203ipd_*()
#include "rand-bytes.h" // rand_bytes()
#include "hex.h" // hex_write()

// number of times to test seach parameter set
#define NUM_ITERATIONS 1000

// Random data used for key generation and encapsulation.
typedef struct {
  uint8_t keygen[64], // random data for keygen()
          encaps[32]; // random data for encaps()
} seeds_t;

// Verify that shared keys `k0` and `k1` are equal.
//
// Prints an error message and exits with an error code if the keys are
// not equal.
static void compare_keys(const char *func, const uint8_t k0[static 32], const uint8_t k1[static 32], const seeds_t * const seeds) {
  // compare keys (note: not constant-time)
  if (memcmp(k0, k1, 32)) {
    fprintf(stderr, "%s: k0 != k1:\nk0 = ", func);
    hex_write(stderr, k0, 32);
    fprintf(stderr, "\nk1 = ");
    hex_write(stderr, k1, 32);
    fprintf(stderr, "\nseeds.keygen = ");
    hex_write(stderr, seeds->keygen, 64);
    fprintf(stderr, "\nseeds.encaps = ");
    hex_write(stderr, seeds->encaps, 32);
    fputs("\n", stderr);
    exit(-1);
  }
}

// Test KEM512 with given seeds.
static void test_kem512(const seeds_t * const seeds) {
  // generate encapsulation and decapsulation keys
  uint8_t ek[FIPS203IPD_KEM512_EK_SIZE] = { 0 };
  uint8_t dk[FIPS203IPD_KEM512_DK_SIZE] = { 0 };
  fips203ipd_kem512_keygen(ek, dk, seeds->keygen);

  // encapsulate, get key and ciphertext
  uint8_t k0[32] = { 0 };
  uint8_t ct[FIPS203IPD_KEM512_CT_SIZE] = { 0 };
  fips203ipd_kem512_encaps(k0, ct, ek, seeds->encaps);

  // decapsulate key from ciphertext
  uint8_t k1[32] = { 0 };
  fips203ipd_kem512_decaps(k1, ct, dk);

  // verify that k0 == k1
  compare_keys(__func__, k0, k1, seeds);
}

// Run KEM768 tests.
static void run_kem512_tests(void) {
  seeds_t seeds = { 0 };

  for (size_t i = 0; i < NUM_ITERATIONS; i++) {
    rand_bytes(&seeds, sizeof(seeds_t)); // read seeds
    test_kem512(&seeds); // run test
  }

  printf("kem512 tests passed\n");
}

// Test KEM768 with given seeds.
static void test_kem768(const seeds_t * const seeds) {
  // generate encapsulation and decapsulation keys
  uint8_t ek[FIPS203IPD_KEM768_EK_SIZE] = { 0 };
  uint8_t dk[FIPS203IPD_KEM768_DK_SIZE] = { 0 };
  fips203ipd_kem768_keygen(ek, dk, seeds->keygen);

  // encapsulate, get shared key and ciphertext
  uint8_t k0[32] = { 0 };
  uint8_t ct[FIPS203IPD_KEM768_CT_SIZE] = { 0 };
  fips203ipd_kem768_encaps(k0, ct, ek, seeds->encaps);

  // decapsulate shared key from ciphertext
  uint8_t k1[32] = { 0 };
  fips203ipd_kem768_decaps(k1, ct, dk);

  // verify that k0 == k1
  compare_keys(__func__, k0, k1, seeds);
}

// Run KEM768 tests.
static void run_kem768_tests(void) {
  seeds_t seeds = { 0 };

  for (size_t i = 0; i < NUM_ITERATIONS; i++) {
    rand_bytes(&seeds, sizeof(seeds_t)); // read seeds
    test_kem768(&seeds); // run test
  }

  printf("kem768 tests passed\n");
}

// Test KEM1024 with given seeds.
static void test_kem1024(const seeds_t * const seeds) {
  // generate encapsulation and decapsulation keys
  uint8_t ek[FIPS203IPD_KEM1024_EK_SIZE] = { 0 };
  uint8_t dk[FIPS203IPD_KEM1024_DK_SIZE] = { 0 };
  fips203ipd_kem1024_keygen(ek, dk, seeds->keygen);

  // encapsulate, get key and ciphertext
  uint8_t k0[32] = { 0 };
  uint8_t ct[FIPS203IPD_KEM1024_CT_SIZE] = { 0 };
  fips203ipd_kem1024_encaps(k0, ct, ek, seeds->encaps);

  // decapsulate key from ciphertext
  uint8_t k1[32] = { 0 };
  fips203ipd_kem1024_decaps(k1, ct, dk);

  // verify that k0 == k1
  compare_keys(__func__, k0, k1, seeds);
}

// Run KEM1024 tests.
static void run_kem1024_tests(void) {
  seeds_t seeds = { 0 };

  for (size_t i = 0; i < NUM_ITERATIONS; i++) {
    rand_bytes(&seeds, sizeof(seeds_t)); // read seeds
    test_kem1024(&seeds); // run test
  }

  printf("kem1024 tests passed\n");
}

int main(void) {
  run_kem512_tests();
  run_kem768_tests();
  run_kem1024_tests();

  printf("all tests passed\n");

  return 0;
}
