#ifndef HEX_H
#define HEX_H

#include <stdio.h> // fprintf()
#include <stdint.h> // uint8_t

// print hex-encoded buffer to given file handle.
// (used by top-level main.c)
static void hex_write(FILE *fh, const uint8_t * const buf, const size_t len) {
  for (size_t i = 0; i < len; i++) {
    fprintf(fh, "%02x", buf[i]);
  }
}

#endif /* HEX_H */
