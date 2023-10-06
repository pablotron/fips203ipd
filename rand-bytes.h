#ifndef RAND_BYTES_H
#define RAND_BYTES_H

#include <stddef.h> // size_t
#include <sys/random.h> // getrandom()
#include <err.h> // errx()

// Fill `buf` with `len` random bytes using `getrandom()`.
//
// Prints an error and exits with an error code if `len` random bytes
// could not be read.
static void rand_bytes(void * const buf, const size_t len) {
  const ssize_t got = getrandom(buf, len, 0);
  if (got < (ssize_t) len) {
    // print error message, exit with error
    errx(-1, "getrandom() failed");
  }
}

#endif /* RAND_BYTES_H */
