// mod.c - test behavior of "(x - y) % m" in C.
// build: cc -std=c11 -W -Wall -Wextra -Werror -pedantic -O2 -o mod{,,c}
#include <stdio.h> // printf()
#include <stdlib.h> // atoi()
#include <stdint.h> // uint16_t

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s x y\n", argv[0]);
    return -1;
  }

  // read args (no error checking)
  uint16_t x = atoi(argv[1]),
           y = atoi(argv[2]),
           z = (x - y) % 10,
           w = (x + (10 - y)) % 10;
  printf("x = %d, y = %d, (x - y) %% 10 = %d, (x + (10 - y) %% 10 = %d\n", x, y, z, w);
  return 0;
}
