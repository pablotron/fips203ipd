/**
 * @file fips203ipd.h
 * @copyright 2023 Paul Duncan
 *
 * fips203ipd.h: C11 implementation of the KEM512, KEM768, and KEM1024
 * parameter sets from the FIPS 203 initial public draft (IPD).
 *
 * Copyright (c) 2023 Paul Duncan
 * SPDX-License-Identifier: MIT-0
 *
 */

#ifndef FIPS203IPD_H
#define FIPS203IPD_H

#include <stdint.h> // uint8_t

/**
 * @defgroup kem512 KEM512
 * @brief KEM512 constants and functions.
 */

/**
 * @brief Size of KEM512 encapsulation key, in bytes (384 * K + 32).
 * @ingroup kem512
 */
#define FIPS203IPD_KEM512_EK_SIZE 800

/**
 * @brief Size of KEM512 decapsulation key, in bytes (768 * K + 96).
 * @ingroup kem512
 */
#define FIPS203IPD_KEM512_DK_SIZE 1632

/**
 * @brief Size of KEM512 ciphertext, in bytes (32 * (DU * K + DV)).
 * @ingroup kem512
 */
#define FIPS203IPD_KEM512_CT_SIZE 768

/**
 * @brief Generate KEM512 encapsulation key `ek` and decapsulation key
 * `dk` from 64 byte random seed `seed`.
 * @ingroup kem512
 *
 * @warning `seed` **must** be 64 random bytes generated by a
 * [cryptographically secure pseudorandom number generator
 * (CSPRNG)][csprng].   Specifically, section 3.3 of the [FIPS 203
 * initial public draft][fips203ipd] requires an **approved** random bit
 * generator (RBG) with at least 128 bits of strength.
 *
 * @param[out] ek KEM512 encapsulation key (800 bytes).
 * @param[out] dk KEM512 decapsulation key (1632 bytes).
 * @param[in] seed Random seed (64 bytes).
 *
 * Example:
 * @snippet{trimleft} 1-all-three/all-three.c kem512-keygen
 *
 * [csprng]: https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
 *   "Cryptographically Secure Pseudorandom Number Generator (CSPRNG)"
 * [fips203ipd]: https://csrc.nist.gov/pubs/fips/203/ipd
 *   "FIPS 203 (Initial Public Draft): Module-Lattice-Based Key-Encapsulation Mechanism Standard"
 */
void fips203ipd_kem512_keygen(uint8_t ek[static FIPS203IPD_KEM512_EK_SIZE], uint8_t dk[static FIPS203IPD_KEM512_DK_SIZE], const uint8_t seed[static 64]);

/**
 * @brief Generate KEM512 shared key `key` and ciphertext `ct` from given
 * encapsulation key `ek` and randomness `seed`.
 * @ingroup kem512
 *
 * @warning `seed` **must** be 32 random bytes generated by a
 * [cryptographically secure pseudorandom number generator
 * (CSPRNG)][csprng].   Specifically, section 3.3 of the [FIPS 203
 * initial public draft][fips203ipd] requires an **approved** random bit
 * generator (RBG) with at least 128 bits of strength.
 *
 * @param[out] key Shared key (32 bytes).
 * @param[out] ct Ciphertext (768 bytes).
 * @param[in] ek KEM512 encapsulation key (800 bytes).
 * @param[in] seed Random seed (32 bytes).
 *
 * Example:
 * @snippet{trimleft} 1-all-three/all-three.c kem512-encaps
 *
 * [csprng]: https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
 *   "Cryptographically Secure Pseudorandom Number Generator (CSPRNG)"
 * [fips203ipd]: https://csrc.nist.gov/pubs/fips/203/ipd
 *   "FIPS 203 (Initial Public Draft): Module-Lattice-Based Key-Encapsulation Mechanism Standard"
 */
void fips203ipd_kem512_encaps(uint8_t key[static 32], uint8_t ct[static FIPS203IPD_KEM512_CT_SIZE], const uint8_t ek[static FIPS203IPD_KEM512_EK_SIZE], const uint8_t seed[static 32]);

/**
 * @brief Decapsulate shared key `key` from ciphertext `ct` using KEM512
 * decapsulation key `dk` with implicit rejection.
 * @ingroup kem512
 *
 * @param[out] key Shared key (32 bytes).
 * @param[out] ct Ciphertext (768 bytes).
 * @param[in] dk KEM512 decapsulation key (1632 bytes).
 *
 * Example:
 * @snippet{trimleft} 1-all-three/all-three.c kem512-decaps
 */
void fips203ipd_kem512_decaps(uint8_t key[static 32], const uint8_t ct[static FIPS203IPD_KEM512_CT_SIZE], const uint8_t dk[static FIPS203IPD_KEM512_DK_SIZE]);

/**
 * @defgroup kem768 KEM768
 * @brief KEM768 constants and functions.
 */

/**
 * @brief Size of KEM768 encapsulation key, in bytes (384 * K + 32).
 * @ingroup kem768
 */
#define FIPS203IPD_KEM768_EK_SIZE 1184

/**
 * @brief Size of KEM768 decapsulation key, in bytes (768 * K + 96).
 * @ingroup kem768
 */
#define FIPS203IPD_KEM768_DK_SIZE 2400

/**
 * @brief Size of KEM768 ciphertext, in bytes (32 * (DU * K + DV)).
 * @ingroup kem768
 */
#define FIPS203IPD_KEM768_CT_SIZE 1088

/**
 * @brief Generate KEM768 encapsulation key `ek` and decapsulation key
 * `dk` from 64 byte random seed `seed`.
 * @ingroup kem768
 *
 * @warning `seed` **must** be 64 random bytes generated by a
 * [cryptographically secure pseudorandom number generator
 * (CSPRNG)][csprng].   Specifically, section 3.3 of the [FIPS 203
 * initial public draft][fips203ipd] requires an **approved** random bit
 * generator (RBG) with at least 192 bits of strength.
 *
 * @param[out] ek KEM768 encapsulation key (1184 bytes).
 * @param[out] dk KEM768 decapsulation key (2400 bytes).
 * @param[in] seed Random seed (64 bytes).
 *
 * Example:
 * @snippet{trimleft} 1-all-three/all-three.c kem768-keygen
 *
 * [csprng]: https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
 *   "Cryptographically Secure Pseudorandom Number Generator (CSPRNG)"
 * [fips203ipd]: https://csrc.nist.gov/pubs/fips/203/ipd
 *   "FIPS 203 (Initial Public Draft): Module-Lattice-Based Key-Encapsulation Mechanism Standard"
 */
void fips203ipd_kem768_keygen(uint8_t ek[static FIPS203IPD_KEM768_EK_SIZE], uint8_t dk[static FIPS203IPD_KEM768_DK_SIZE], const uint8_t seed[static 64]);

/**
 * @brief Generate KEM768 shared key `key` and ciphertext `ct` from given
 * encapsulation key `ek` and randomness `seed`.
 * @ingroup kem768
 *
 * @warning `seed` **must** be 32 random bytes generated by a
 * [cryptographically secure pseudorandom number generator
 * (CSPRNG)][csprng].   Specifically, section 3.3 of the [FIPS 203
 * initial public draft][fips203ipd] requires an **approved** random bit
 * generator (RBG) with at least 192 bits of strength.
 *
 * @param[out] key Shared key (32 bytes).
 * @param[out] ct Ciphertext (1088 bytes).
 * @param[in] ek KEM768 encapsulation key (1184 bytes).
 * @param[in] seed Random seed (32 bytes).
 *
 * Example:
 * @snippet{trimleft} 1-all-three/all-three.c kem768-encaps
 *
 * [csprng]: https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
 *   "Cryptographically Secure Pseudorandom Number Generator (CSPRNG)"
 * [fips203ipd]: https://csrc.nist.gov/pubs/fips/203/ipd
 *   "FIPS 203 (Initial Public Draft): Module-Lattice-Based Key-Encapsulation Mechanism Standard"
 */
void fips203ipd_kem768_encaps(uint8_t key[static 32], uint8_t ct[static FIPS203IPD_KEM768_CT_SIZE], const uint8_t ek[static FIPS203IPD_KEM768_EK_SIZE], const uint8_t seed[static 32]);

/**
 * @brief Decapsulate shared key `key` from ciphertext `ct` using KEM768
 * decapsulation key `dk` with implicit rejection.
 * @ingroup kem768
 *
 * @param[out] key Shared key (32 bytes).
 * @param[out] ct Ciphertext (1088 bytes).
 * @param[in] dk KEM768 decapsulation key (2400 bytes).
 *
 * Example:
 * @snippet{trimleft} 1-all-three/all-three.c kem768-decaps
 */
void fips203ipd_kem768_decaps(uint8_t key[static 32], const uint8_t ct[static FIPS203IPD_KEM768_CT_SIZE], const uint8_t dk[static FIPS203IPD_KEM768_DK_SIZE]);

/**
 * @defgroup kem1024 KEM1024
 * @brief KEM1024 constants and functions.
 */

/**
 * @brief Size of KEM1024 encapsulation key, in bytes (384 * K + 32).
 * @ingroup kem1024
 */
#define FIPS203IPD_KEM1024_EK_SIZE 1568

/**
 * @brief Size of KEM1024 decapsulation key, in bytes (768 * K + 96).
 * @ingroup kem1024
 */
#define FIPS203IPD_KEM1024_DK_SIZE 3168

/**
 * @brief Size of KEM1024 ciphertext, in bytes (32 * (DU * K + DV)).
 * @ingroup kem1024
 */
#define FIPS203IPD_KEM1024_CT_SIZE 1568

/**
 * @brief Generate KEM1024 encapsulation key `ek` and decapsulation key
 * `dk` from 64 byte random seed `seed`.
 * @ingroup kem1024
 *
 * @warning `seed` **must** be 64 random bytes generated by a
 * [cryptographically secure pseudorandom number generator
 * (CSPRNG)][csprng].   Specifically, section 3.3 of the [FIPS 203
 * initial public draft][fips203ipd] requires an **approved** random bit
 * generator (RBG) with at least 256 bits of strength.
 *
 * @param[out] ek KEM1024 encapsulation key (1568 bytes).
 * @param[out] dk KEM1024 decapsulation key (3168 bytes).
 * @param[in] seed Random seed (64 bytes).
 *
 * Example:
 * @snippet{trimleft} 1-all-three/all-three.c kem1024-keygen
 *
 * [csprng]: https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
 *   "Cryptographically Secure Pseudorandom Number Generator (CSPRNG)"
 * [fips203ipd]: https://csrc.nist.gov/pubs/fips/203/ipd
 *   "FIPS 203 (Initial Public Draft): Module-Lattice-Based Key-Encapsulation Mechanism Standard"
 */
void fips203ipd_kem1024_keygen(uint8_t ek[static FIPS203IPD_KEM1024_EK_SIZE], uint8_t dk[static FIPS203IPD_KEM1024_DK_SIZE], const uint8_t seed[static 64]);

/**
 * @brief Generate KEM1024 shared key `key` and ciphertext `ct` from given
 * encapsulation key `ek` and randomness `seed`.
 * @ingroup kem1024
 *
 * @warning `seed` **must** be 32 random bytes generated by a
 * [cryptographically secure pseudorandom number generator
 * (CSPRNG)][csprng].   Specifically, section 3.3 of the [FIPS 203
 * initial public draft][fips203ipd] requires an **approved** random bit
 * generator (RBG) with at least 256 bits of strength.
 *
 * @param[out] key Shared key (32 bytes).
 * @param[out] ct Ciphertext (1568 bytes).
 * @param[in] ek KEM1024 encapsulation key (1568 bytes).
 * @param[in] seed Random seed (32 bytes).
 *
 * Example:
 * @snippet{trimleft} 1-all-three/all-three.c kem1024-encaps
 *
 * [csprng]: https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
 *   "Cryptographically Secure Pseudorandom Number Generator (CSPRNG)"
 * [fips203ipd]: https://csrc.nist.gov/pubs/fips/203/ipd
 *   "FIPS 203 (Initial Public Draft): Module-Lattice-Based Key-Encapsulation Mechanism Standard"
 */
void fips203ipd_kem1024_encaps(uint8_t key[static 32], uint8_t ct[static FIPS203IPD_KEM1024_CT_SIZE], const uint8_t ek[static FIPS203IPD_KEM1024_EK_SIZE], const uint8_t seed[static 32]);

/**
 * @brief Decapsulate shared key `key` from ciphertext `ct` using KEM1024
 * decapsulation key `dk` with implicit rejection.
 * @ingroup kem1024
 *
 * @param[out] key Shared key (32 bytes).
 * @param[out] ct Ciphertext (1568 bytes).
 * @param[in] dk KEM1024 decapsulation key (3168 bytes).
 *
 * Example:
 * @snippet{trimleft} 1-all-three/all-three.c kem1024-decaps
 */
void fips203ipd_kem1024_decaps(uint8_t key[static 32], const uint8_t ct[static FIPS203IPD_KEM1024_CT_SIZE], const uint8_t dk[static FIPS203IPD_KEM1024_DK_SIZE]);

#endif /* FIPS203IPD_H */
