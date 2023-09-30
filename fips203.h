#ifndef FIPS203_H
#define FIPS203_H

#include <stdint.h>

#define FIPS203_KEM512_EK_SIZE 800 /* 384 * K + 32 */
#define FIPS203_KEM512_DK_SIZE 1632 /* 768 * K + 96 */
#define FIPS203_KEM512_CT_SIZE 768 /* 32 * (DU * K + DV) */

void fips203_kem512_keygen(uint8_t ek[static FIPS203_KEM512_EK_SIZE], uint8_t dk[static FIPS203_KEM512_DK_SIZE], const uint8_t seed[static 64]);
void fips203_kem512_encaps(uint8_t k[static 32], uint8_t ct[static FIPS203_KEM512_CT_SIZE], const uint8_t ek[static FIPS203_KEM512_EK_SIZE], const uint8_t seed[static 32]);
void fips203_kem512_decaps(uint8_t k[static 32], const uint8_t ct[static FIPS203_KEM512_CT_SIZE], const uint8_t dk_kem[static FIPS203_KEM512_DK_SIZE]);

#endif /* FIPS203_H */
