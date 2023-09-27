#ifndef FIPS203_H
#define FIPS203_H

#include <stdint.h>

void fips203_kem512_keygen(uint8_t ek[static 800], uint8_t dk[static 1632], const uint8_t seed[static 64]);
void fips203_kem512_encaps(uint8_t k[static 32], uint8_t ct[static 768], const uint8_t ek[static 800], const uint8_t seed[static 32]);
void fips203_kem512_decaps(uint8_t k[static 32], const uint8_t ct[static 768], const uint8_t dk_kem[static 1632]);

#endif /* FIPS203_H */
