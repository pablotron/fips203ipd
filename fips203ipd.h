#ifndef FIPS203IPD_H
#define FIPS203IPD_H

#include <stdint.h>

#define FIPS203IPD_KEM512_EK_SIZE 800 /* 384 * K + 32 */
#define FIPS203IPD_KEM512_DK_SIZE 1632 /* 768 * K + 96 */
#define FIPS203IPD_KEM512_CT_SIZE 768 /* 32 * (DU * K + DV) */

void fips203ipd_kem512_keygen(uint8_t ek[static FIPS203IPD_KEM512_EK_SIZE], uint8_t dk[static FIPS203IPD_KEM512_DK_SIZE], const uint8_t seed[static 64]);
void fips203ipd_kem512_encaps(uint8_t k[static 32], uint8_t ct[static FIPS203IPD_KEM512_CT_SIZE], const uint8_t ek[static FIPS203IPD_KEM512_EK_SIZE], const uint8_t seed[static 32]);
void fips203ipd_kem512_decaps(uint8_t k[static 32], const uint8_t ct[static FIPS203IPD_KEM512_CT_SIZE], const uint8_t dk_kem[static FIPS203IPD_KEM512_DK_SIZE]);

#define FIPS203IPD_KEM768_EK_SIZE 1184 /* 384 * K + 32 */
#define FIPS203IPD_KEM768_DK_SIZE 2400 /* 768 * K + 96 */
#define FIPS203IPD_KEM768_CT_SIZE 1088 /* 32 * (DU * K + DV) */

void fips203ipd_kem768_keygen(uint8_t ek[static FIPS203IPD_KEM768_EK_SIZE], uint8_t dk[static FIPS203IPD_KEM768_DK_SIZE], const uint8_t seed[static 64]);
void fips203ipd_kem768_encaps(uint8_t k[static 32], uint8_t ct[static FIPS203IPD_KEM768_CT_SIZE], const uint8_t ek[static FIPS203IPD_KEM768_EK_SIZE], const uint8_t seed[static 32]);
void fips203ipd_kem768_decaps(uint8_t k[static 32], const uint8_t ct[static FIPS203IPD_KEM768_CT_SIZE], const uint8_t dk_kem[static FIPS203IPD_KEM768_DK_SIZE]);

#define FIPS203IPD_KEM1024_EK_SIZE 1568 /* 384 * K + 32 */
#define FIPS203IPD_KEM1024_DK_SIZE 3168 /* 768 * K + 96 */
#define FIPS203IPD_KEM1024_CT_SIZE 1568 /* 32 * (DU * K + DV) */

void fips203ipd_kem1024_keygen(uint8_t ek[static FIPS203IPD_KEM1024_EK_SIZE], uint8_t dk[static FIPS203IPD_KEM1024_DK_SIZE], const uint8_t seed[static 64]);
void fips203ipd_kem1024_encaps(uint8_t k[static 32], uint8_t ct[static FIPS203IPD_KEM1024_CT_SIZE], const uint8_t ek[static FIPS203IPD_KEM1024_EK_SIZE], const uint8_t seed[static 32]);
void fips203ipd_kem1024_decaps(uint8_t k[static 32], const uint8_t ct[static FIPS203IPD_KEM1024_CT_SIZE], const uint8_t dk_kem[static FIPS203IPD_KEM1024_DK_SIZE]);

#endif /* FIPS203IPD_H */
