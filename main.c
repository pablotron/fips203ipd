//
// main.c: Toy application to generate fips203 API.
//

#include <stdlib.h> // exit()
#include <stdio.h> // printf()
#include <string.h> // memcmp()
#include "fips203.h"
#include "hex.h"

static const uint8_t KEYGEN_SEED[64] = {
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66
};

static const uint8_t ENCAPS_SEED[32] = {
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
  0x61, 0x73, 0x64, 0x66, 0x61, 0x73, 0x64, 0x66,
};

static void test_fips203_kem512(void) {
  // generate encapsulation and decapsulation keys
  uint8_t ek[FIPS203_KEM512_EK_SIZE] = { 0 };
  uint8_t dk[FIPS203_KEM512_DK_SIZE] = { 0 };
  fips203_kem512_keygen(ek, dk, KEYGEN_SEED);

  // encapsulate, get key and ciphertext
  uint8_t k0[32] = { 0 };
  uint8_t ct[FIPS203_KEM512_CT_SIZE] = { 0 };
  fips203_kem512_encaps(k0, ct, ek, ENCAPS_SEED);

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

  printf("test_fips203_kem512: ok\n");
}

static void test_fips203_kem768(void) {
  // generate encapsulation and decapsulation keys
  uint8_t ek[FIPS203_KEM768_EK_SIZE] = { 0 };
  uint8_t dk[FIPS203_KEM768_DK_SIZE] = { 0 };
  fips203_kem768_keygen(ek, dk, KEYGEN_SEED);

  // encapsulate, get key and ciphertext
  uint8_t k0[32] = { 0 };
  uint8_t ct[FIPS203_KEM768_CT_SIZE] = { 0 };
  fips203_kem768_encaps(k0, ct, ek, ENCAPS_SEED);

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

  printf("test_fips203_kem768: ok\n");
}

int main(int argc, char *argv[]) {
  (void) argc;
  (void) argv;

  // run tests
  test_fips203_kem512();
  test_fips203_kem768();

  return 0;
}
