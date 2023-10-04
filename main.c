//
// main.c: Toy application to generate fips203 API.
//

#include <stdlib.h> // exit()
#include <stdio.h> // printf()
#include <string.h> // memcmp()
#include <sys/random.h> // getrandom()
#include <err.h> // errx()
#include "fips203.h"
#include "hex.h"

#define NUM_TESTS 100

// known keygen seed
static const uint8_t KNOWN_KEYGEN_SEED[64] = {
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66
};

// known encaps seed
static const uint8_t KNOWN_ENCAPS_SEED[32] = {
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
};

// Fill `buf` with `len` random bytes.
static void read_rand(uint8_t * const buf, const size_t len) {
  const ssize_t got = getrandom(buf, len, 0);
  if (got < (ssize_t) len) {
    errx(-1, "read %zu bytes from getrandom() failed", len);
  }
}

// Test KEM512 with given seeds.
static void test_fips203_kem512(const uint8_t keygen_seed[static 64], const uint8_t encaps_seed[static 32]) {
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

  // compare keys
  if (memcmp(k0, k1, sizeof(k0))) {
    printf("test_fips203_kem512: k0 != k1:\nk0 = ");
    hex_write(stdout, k0, sizeof(k0));
    printf("\nk1 = ");
    hex_write(stdout, k1, sizeof(k1));
    printf("\n");
    exit(-1);
  }
}

// Test KEM768 with given seeds.
static void test_fips203_kem768(const uint8_t keygen_seed[static 64], const uint8_t encaps_seed[static 32]) {
  // generate encapsulation and decapsulation keys
  uint8_t ek[FIPS203_KEM768_EK_SIZE] = { 0 };
  uint8_t dk[FIPS203_KEM768_DK_SIZE] = { 0 };
  fips203_kem768_keygen(ek, dk, keygen_seed);

  // encapsulate, get key and ciphertext
  uint8_t k0[32] = { 0 };
  uint8_t ct[FIPS203_KEM768_CT_SIZE] = { 0 };
  fips203_kem768_encaps(k0, ct, ek, encaps_seed);

  // decapsulate key from ciphertext
  uint8_t k1[32] = { 0 };
  fips203_kem768_decaps(k1, ct, dk);

  // compare keys
  if (memcmp(k0, k1, sizeof(k0))) {
    printf("test_fips203_kem768: k0 != k1:\nk0 = ");
    hex_write(stdout, k0, sizeof(k0));
    printf("\nk1 = ");
    hex_write(stdout, k1, sizeof(k1));
    printf("\n");
    exit(-1);
  }
}

// run kem tests with given seeds.
static void run_tests(const uint8_t keygen_seed[static 64], const uint8_t encaps_seed[static 32]) {
  test_fips203_kem512(keygen_seed, encaps_seed);
  test_fips203_kem768(keygen_seed, encaps_seed);
}

int main(int argc, char *argv[]) {
  (void) argc;
  (void) argv;

  // run tests with known seeds
  run_tests(KNOWN_KEYGEN_SEED, KNOWN_ENCAPS_SEED);

  for (size_t i = 0; i < NUM_TESTS; i++) {
    // read 96 random bytes
    uint8_t buf[96] = { 0 };
    read_rand(buf, sizeof(buf));

    // run tests with random bytes
    run_tests(buf, buf + 64);
  }

  printf("all tests passed\n");

  // return success
  return 0;
}
