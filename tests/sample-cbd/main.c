//
// sample-cbd.c: Calculate expected coefficients for poly_sample_cbd$ETA()
// where the first command-line argument is $ETA (and is one of 2 or 3),
// and the second command-line argument is the one byte seed parameter
// used for `prf()`.
//
// (Note: the 32-byte parameter used for `prf()` is fixed as all zero).
//
// Additionally, if you define PRINT_SQUEEZED_BYTES you can inspect the
// raw byte stream from the PRF.
//
// Example:
//
//   > ./sample-cbd 3 0
//   // expected coefficients, eta = 3, seed = { 0 }, byte = 0
//   0x0f9, 0x0b0, 0xbc9, 0x054, 0x4a0, ... (omitted)
//

// print squeezed bytes to stdout?
// (used for manual inspection)
#define PRINT_SQUEEZED_BYTES 1

#include <stdio.h> // printf(), fprintf(), fputs()
#include <stdlib.h> // atoi()
#include <string.h> // memcpy()
#include "sha3.h" // shake128_xof_{init,absorb,squeeze}()
#ifdef PRINT_SQUEEZED_BYTES
#include "hex.h" // hex_write()
#endif /* PRINT_SQUEEZED_BYTES */

#define Q 3329 // modulus

// all zero seed
static const uint8_t SEED[32] = { 0 };

int main(int argc, char *argv[]) {
  // check command-line argument count
  if (argc < 3) {
    const char * app = (argc > 0) ? argv[0] : "app";
    fprintf(stderr, "Usage: %s <eta> <byte>\n", app);
    return -1;
  }

  // get eta and byte from argument
  const uint8_t eta = atoi(argv[1]),
                byte = atoi(argv[2]);

  // check for valid eta
  if (eta != 2 && eta != 3) {
    fprintf(stderr, "invalid eta %d: eta must be 2 or 3\n", eta);
    return -1;
  }

  // populate prf input buffer
  uint8_t prf_src[33] = { 0 };
  memcpy(prf_src, SEED, sizeof(SEED));
  prf_src[32] = byte;

  // allocate PRF output buffer
  const size_t buf_len = 64 * eta;
  uint8_t * const buf = malloc(buf_len);
  if (!buf) {
    fprintf(stderr, "malloc() failed\n");
    return -1;
  }

  // squeeze bytes into buf
  shake256_xof_once(prf_src, sizeof(prf_src), buf, buf_len);

  // read coefficients from xof using rejection sampling
  uint16_t cs[256] = { 0 };
  for (size_t i = 0; i < 256; i++) {
    uint16_t x = 0;
    for (size_t j = 0; j < eta; j++) {
      const size_t ofs = 2 * eta * i + j;
      x += (buf[ofs / 8] >> (ofs % 8)) & 1;
    }

    uint16_t y = 0;
    for (size_t j = 0; j < eta; j++) {
      const size_t ofs = 2 * eta * i + eta + j;
      y += (buf[ofs / 8] >> (ofs % 8)) & 1;
    }

    // sample coefficient
    cs[i] = (x + (Q - y)) % Q; // (x - y) % Q
  }

  // print parameters and coefficients to stdout
  printf("// expected coefficients, eta = %d, seed = { 0 }, byte = %d\n", eta, byte);
  for (size_t i = 0; i < 256; i++) {
    printf("%s%d", i ? ", " : "", cs[i]);
  }
  fputs("\n", stdout);

#ifdef PRINT_SQUEEZED_BYTES
    // print squeezed bytes to stdout (for manual inspection)
    printf("// squeezed bytes, eta = %d, seed = { 0 }, byte = %d\n", eta, byte);
    hex_write(stdout, buf, buf_len);
    fputs("\n", stdout);
#endif /* PRINT_SQUEEZED_BYTES */

  // return success
  return 0;
}
