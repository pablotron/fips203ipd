//
// main.c: Example application which runs KEM512, KEM768, and KEM1024
// 1000 times each and verifies that the generated shared keys match.
//

#include <stdlib.h> // exit()
#include <stdio.h> // printf()
#include <string.h> // memcmp()
#include <sys/random.h> // getrandom()
#include <err.h> // errx()
#include "fips203.h" // fips203_*()
#include "hex.h" // hex_write()

// number of tests
#define NUM_TESTS 1000

// Fill `buf` with `len` random bytes using `getrandom()`.
//
// Prints an error and exits with an error code if `len` random bytes
// could not be read.
static void rand_bytes(uint8_t * const buf, const size_t len) {
  const ssize_t got = getrandom(buf, len, 0);
  if (got < (ssize_t) len) {
    // print error message, exit with failure
    errx(-1, "read %zu bytes from getrandom() failed", len);
  }
}

// Verify that shared keys `k0` and `k1` are equal.
//
// Prints an error message and exits with an error code if the keys are
// not equal.
static void compare_keys(const char *func, const uint8_t k0[static 32], const uint8_t k1[static 32], const uint8_t keygen_seed[static 64], const uint8_t encaps_seed[static 32]) {
  // compare keys
  if (memcmp(k0, k1, 32)) {
    fprintf(stderr, "%s: k0 != k1:\nk0 = ", func);
    hex_write(stderr, k0, 32);
    fprintf(stderr, "\nk1 = ");
    hex_write(stderr, k1, 32);
    fprintf(stderr, "\nkeygen_seed = ");
    hex_write(stderr, keygen_seed, 64);
    fprintf(stderr, "\nencaps_seed = ");
    hex_write(stderr, encaps_seed, 32);
    fputs("\n", stderr);
    exit(-1);
  }
}

// Test KEM512 with given seeds.
static void test_kem512(const uint8_t keygen_seed[static 64], const uint8_t encaps_seed[static 32]) {
  // generate encapsulation and decapsulation keys
  uint8_t ek[FIPS203_KEM512_EK_SIZE] = { 0 };
  uint8_t dk[FIPS203_KEM512_DK_SIZE] = { 0 };
  fips203_kem512_keygen(ek, dk, keygen_seed);

  // encapsulate, get key and ciphertext
  uint8_t k0[32] = { 0 };
  uint8_t ct[FIPS203_KEM512_CT_SIZE] = { 0 };
  fips203_kem512_encaps(k0, ct, ek, encaps_seed);

  // decapsulate key from ciphertext
  uint8_t k1[32] = { 0 };
  fips203_kem512_decaps(k1, ct, dk);

  // verify that k0 == k1
  compare_keys(__func__, k0, k1, keygen_seed, encaps_seed);
}

// Run KEM768 tests.
static void run_kem512_tests(void) {
  uint8_t buf[96] = { 0 };

  for (size_t i = 0; i < NUM_TESTS; i++) {
    rand_bytes(buf, sizeof(buf)); // read 96 random bytes
    test_kem512(buf, buf + 64); // run test
  }

  printf("kem512 tests passed\n");
}

// Test KEM768 with given seeds.
static void test_kem768(const uint8_t keygen_seed[static 64], const uint8_t encaps_seed[static 32]) {
  // generate encapsulation and decapsulation keys
  uint8_t ek[FIPS203_KEM768_EK_SIZE] = { 0 };
  uint8_t dk[FIPS203_KEM768_DK_SIZE] = { 0 };
  fips203_kem768_keygen(ek, dk, keygen_seed);

  // encapsulate, get shared key and ciphertext
  uint8_t k0[32] = { 0 };
  uint8_t ct[FIPS203_KEM768_CT_SIZE] = { 0 };
  fips203_kem768_encaps(k0, ct, ek, encaps_seed);

  // decapsulate shared key from ciphertext
  uint8_t k1[32] = { 0 };
  fips203_kem768_decaps(k1, ct, dk);

  // verify that k0 == k1
  compare_keys(__func__, k0, k1, keygen_seed, encaps_seed);
}

// Run KEM768 tests.
static void run_kem768_tests(void) {
  uint8_t buf[96] = { 0 };

  for (size_t i = 0; i < NUM_TESTS; i++) {
    rand_bytes(buf, sizeof(buf)); // read 96 random bytes
    test_kem768(buf, buf + 64); // run test
  }

  printf("kem768 tests passed\n");
}

// Test KEM1024 with given seeds.
static void test_kem1024(const uint8_t keygen_seed[static 64], const uint8_t encaps_seed[static 32]) {
  // generate encapsulation and decapsulation keys
  uint8_t ek[FIPS203_KEM1024_EK_SIZE] = { 0 };
  uint8_t dk[FIPS203_KEM1024_DK_SIZE] = { 0 };
  fips203_kem1024_keygen(ek, dk, keygen_seed);

  // encapsulate, get key and ciphertext
  uint8_t k0[32] = { 0 };
  uint8_t ct[FIPS203_KEM1024_CT_SIZE] = { 0 };
  fips203_kem1024_encaps(k0, ct, ek, encaps_seed);

  // decapsulate key from ciphertext
  uint8_t k1[32] = { 0 };
  fips203_kem1024_decaps(k1, ct, dk);

  // verify that k0 == k1
  compare_keys(__func__, k0, k1, keygen_seed, encaps_seed);
}

// Run KEM1024 tests.
static void run_kem1024_tests(void) {
  uint8_t buf[96] = { 0 };

  for (size_t i = 0; i < NUM_TESTS; i++) {
    rand_bytes(buf, sizeof(buf)); // read 96 random bytes
    test_kem1024(buf, buf + 64); // run test
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
