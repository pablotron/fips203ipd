//
// sample-ntt.c: Calculate expected coefficients for poly_sample_ntt()
// for all zero seed and coordinates given as command line parameters.
//
// Additionally, if you define PRINT_SQUEEZED_BYTES you can inspect the
// raw byte stream from the XOF.
//
// Example:
//
//   > ./sample-ntt 0 0
//   // expected coefficients, seed = { 0 }, x = 0, y = 0
//   0x0f9, 0x0b0, 0xbc9, 0x054, 0x4a0, ... (omitted)
//

// print squeezed bytes to stdout?
// (used for manual inspection)
#define PRINT_SQUEEZED_BYTES 1

#include <stdio.h> // printf(), fprintf(), fputs()
#include <stdlib.h> // atoi()
#include "sha3.h" // shake128_xof_{init,absorb,squeeze}()
#ifdef PRINT_SQUEEZED_BYTES
#include "hex.h" // hex_write()
#endif /* PRINT_SQUEEZED_BYTES */

#define Q 3329 // modulus

// all zero seed
static const uint8_t SEED[32] = { 0 };

int main(int argc, char *argv[]) {
  // check command-line argument count
  if (argc < 2) {
    const char * app = (argc > 0) ? argv[0] : "app";
    fprintf(stderr, "Usage: %s <x> <y>\n", app);
    return -1;
  }

  // get coordinates from arguments
  const uint8_t x = atoi(argv[1]),
                y = atoi(argv[2]);
  const uint8_t buf[2] = { x, y };

#ifdef PRINT_SQUEEZED_BYTES
  uint8_t squeezed[4096] = { 0 }; // buffer to store squeezed bytes
  size_t squeezed_ofs = 0; // offset in squeezed byte buffer
#endif /* PRINT_SQUEEZED_BYTES */

  // init xof
  sha3_xof_t xof = { 0 };
  shake128_xof_init(&xof);

  // absorb seed and coordinates
  shake128_xof_absorb(&xof, SEED, 32);
  shake128_xof_absorb(&xof, buf, 2);

  // read coefficients from xof using rejection sampling
  uint16_t cs[256] = { 0 };
  for (size_t i = 0; i < 256;) {
    // squeeze 3 bytes from xof
    uint8_t ds[3] = { 0 };
    shake128_xof_squeeze(&xof, ds, 3);

#ifdef PRINT_SQUEEZED_BYTES
    if (squeezed_ofs < sizeof(squeezed) - 3) {
      // append bytes to squeezed buffer
      squeezed[squeezed_ofs++] = ds[0];
      squeezed[squeezed_ofs++] = ds[1];
      squeezed[squeezed_ofs++] = ds[2];
    }
#endif /* PRINT_SQUEEZED_BYTES */

    // split 3 bytes into two 12-bit samples
    const uint16_t d1 = ((uint16_t) ds[0]) | (((uint16_t) (ds[1] & 0xf)) << 8),
                   d2 = ((uint16_t) ds[1] >> 4) | (((uint16_t) ds[2]) << 4);

    // sample d1
    if (d1 < Q) {
      cs[i++] = d1;
    }

    // sample d2
    if (d2 < Q && i < 256) {
      cs[i++] = d2;
    }
  }

  // print parameters and coefficients to stdout
  printf("// expected coefficients, seed = { 0 }, x = %d, y = %d\n", x, y);
  for (size_t i = 0; i < 256; i++) {
    printf("%s0x%03x", i ? ", " : "", cs[i]);
  }
  fputs("\n", stdout);

#ifdef PRINT_SQUEEZED_BYTES
    // print squeezed bytes to stdout (for manual inspection)
    printf("// squeezed bytes, seed = { 0 }, x = %d, y = %d\n", x, y);
    hex_write(stdout, squeezed, squeezed_ofs);
    fputs("\n", stdout);
#endif /* PRINT_SQUEEZED_BYTES */

  // return success
  return 0;
}
