//
// prf.c: Calculate expected output for prf() when given an all zero
// seed and the given byte as input.
//
// Example:
//
//   > ./prf
//   // expected coefficients, seed = { 0 }, x = 0, y = 0
//   0x0f9, 0x0b0, 0xbc9, 0x054, 0x4a0, ... (omitted)
//

#include <stdio.h> // printf(), fprintf(), fputs()
#include <stdlib.h> // atoi()
#include "sha3.h" // shake128_xof_{init,absorb,squeeze}()

#define OUT_LEN 16 // output length, in bytes

// all zero seed
static const uint8_t SEED[32] = { 0 };

int main(int argc, char *argv[]) {
  (void) argc;
  (void) argv;

  // init xof
  sha3_xof_t xof = { 0 };
  shake128_xof_init(&xof);

  for (size_t i = 0; i < 256; i++) {
    const uint8_t b = i;
    // absorb seed and byte
    shake128_xof_absorb(&xof, SEED, 32);
    shake128_xof_absorb(&xof, &b, 1);

    uint8_t buf[OUT_LEN] = { 0 };
    shake128_xof_squeeze(&xof, buf, sizeof(buf));

    // print results
    printf(".b = %d, .exp = { ", b);
    for (size_t j = 0; j < sizeof(buf); j++) {
      printf("%s%02x", j ? ", " : "", buf[j]);
    }
    fputs(" },\n", stdout);
  }

  // return success
  return 0;
}
