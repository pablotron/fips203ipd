/**
 * @file sha3.h
 * @author Paul Duncan
 * @copyright MIT No Attribution (MIT-0)
 * @brief C11 implementation of FIPS 202, NIST SP 800-185, and the draft KangarooTwelve and TurboSHAKE specification.
 *
 * sha3
 * https://pablotron.org/sha3
 *
 * Copyright (c) 2023 Paul Duncan
 * SPDX-License-Identifier: MIT-0
 *
 * Embeddable, dependency-free, MIT-0-licensed C11 implementation of the
 * following SHA-3 hash functions, XOFs, and HMACs:
 *
 * - SHA3-224, SHA3-256, SHA3-384, and SHA3-512
 * - HMAC-SHA3-224, HMAC-SHA3-256, HMAC-SHA3-384, and HMAC-SHA3-512
 * - SHAKE128, SHAKE128-XOF, SHAKE256, and SHAKE256-XOF
 * - cSHAKE128, cSHAKE128-XOF, cSHAKE256, and cSHAKE256-XOF
 * - KMAC128, KMAC128-XOF, KMAC256, and KMAC256-XOF
 * - TupleHash128, TupleHash128-XOF, TupleHash256, and TupleHash256-XOF
 * - ParallelHash128, ParallelHash128-XOF, ParallelHash256, and ParallelHash256-XOF
 * - TurboSHAKE128 and TurboSHAKE256
 * - KangarooTwelve
 */
#ifndef SHA3_H
#define SHA3_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stddef.h> // size_t
#include <stdint.h> // uint8_t, uint64_t

/**
 * @defgroup sha3 SHA-3
 *
 * @brief [Cryptographic hash functions][hash] with fixed-length output,
 * as defined in section 6.1 of [FIPS 202][].
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 * [hash]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
 *   "Cryptographic hash function"
 */

/**
 * @defgroup shake SHAKE
 *
 * @brief [eXtendable Output Functions (XOF)][xof] with both
 * fixed-length and arbitrary length output, as defined in section 6.2
 * of [FIPS 202][].
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */

/**
 * @brief Internal [SHA-3][] state (all members are private).
 * @ingroup sha3
 *
 * [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
 *   "Secure Hash Algorithm 3"
 */
typedef union {
  uint8_t u8[200]; /**< 8-bit unsigned integers. */
  uint64_t u64[25]; /**< 64-bit unsigned integers. */
} sha3_state_t;

/**
 * @brief Iterative [SHA-3][] context (all members are private).
 * @ingroup sha3
 *
 * [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
 *   "Secure Hash Algorithm 3"
 */
typedef struct {
  size_t num_bytes; /**< number of bytes absorbed */
  sha3_state_t a; /**< internal state */
  _Bool finalized; /**< mode (absorbing or finalized) */
} sha3_t;

/**
 * @brief Iterative [XOF][] context (all members are private).
 * @ingroup shake
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
typedef struct {
  size_t num_bytes; /**< number of bytes absorbed */
  sha3_state_t a; /**< internal state */
  _Bool squeezing; /**< mode (absorbing or squeezing) */
} sha3_xof_t;

/*!
 * @brief Calculate SHA3-224 hash of input data.
 * @ingroup sha3
 *
 * Hash `len` bytes of input data from source buffer `src` with SHA3-224
 * ([FIPS 202][], section 6.1), then write 28 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.  Must be at least 28 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_224
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void sha3_224(const uint8_t *src, size_t len, uint8_t dst[static 28]);

/**
 * @brief Initialize SHA3-224 hash context.
 * @ingroup sha3
 *
 * @param[out] hash SHA3-224 hash context.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_224_absorb
 */
void sha3_224_init(sha3_t *hash);

/**
 * @brief Initialize SHA3-224 hash context.
 * @ingroup sha3
 *
 * Absorb `len` bytes of input data from source buffer `src` into
 * SHA3-224 hash context `hash`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in,out] hash SHA3-224 hash context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_224_absorb
 */
_Bool sha3_224_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Finalize SHA3-224 hash context and write 28 bytes of output to
 * destination buffer `dst`.
 * @ingroup sha3
 *
 * @param[in,out] hash SHA3-224 hash context.
 * @param[out] dst Destination buffer.  Must be at least 28 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_224_absorb
 */
void sha3_224_final(sha3_t *hash, uint8_t dst[28]);

/**
 * @brief Calculate SHA3-256 hash of input data.
 * @ingroup sha3
 *
 * Hash `len` bytes of input data from source buffer `src` with SHA3-256
 * ([FIPS 202][], section 6.1), then write 32 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.  Must be at least 32 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_256
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void sha3_256(const uint8_t *src, size_t len, uint8_t dst[static 32]);

/**
 * @brief Initialize SHA3-256 hash context.
 * @ingroup sha3
 *
 * @param[out] hash SHA3-256 hash context.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_256_absorb
 */
void sha3_256_init(sha3_t *hash);

/**
 * @brief Absorb input data into SHA3-256 hash context.
 * @ingroup sha3
 *
 * Absorb `len` bytes of input data from source buffer `src` into
 * SHA3-256 hash context `hash`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in,out] hash SHA3-256 hash context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_256_absorb
 */
_Bool sha3_256_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Finalize SHA3-256 hash context and write 32 bytes of output to
 * destination buffer `dst`.
 * @ingroup sha3
 *
 * @param[in,out] hash SHA3-256 hash context.
 * @param[out] dst Destination buffer.  Must be at least 32 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_256_absorb
 */
void sha3_256_final(sha3_t *hash, uint8_t dst[32]);

/**
 * @brief Calculate SHA3-384 hash of input data.
 * @ingroup sha3
 *
 * Hash `len` bytes of input data from source buffer `src` with SHA3-384
 * ([FIPS 202][], section 6.1), then write 48 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.  Must be at least 48 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_384
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void sha3_384(const uint8_t *src, size_t len, uint8_t dst[static 48]);

/**
 * @brief Initialize SHA3-384 hash context.
 * @ingroup sha3
 *
 * @param[out] hash SHA3-384 hash context.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_384_absorb
 */
void sha3_384_init(sha3_t *hash);

/**
 * @brief Absorb input data into SHA3-384 hash context.
 * @ingroup sha3
 *
 * Absorb `len` bytes of input data from source buffer `src` into
 * SHA3-384 hash context `hash`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in,out] hash SHA3-384 hash context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_384_absorb
 */
_Bool sha3_384_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Finalize SHA3-384 hash context and write 48 bytes of output to
 * destination buffer `dst`.
 * @ingroup sha3
 *
 * @param[in,out] hash SHA3-384 hash context.
 * @param[out] dst Destination buffer.  Must be at least 48 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_384_absorb
 */
void sha3_384_final(sha3_t *hash, uint8_t dst[48]);

/**
 * @brief Calculate SHA3-512 hash of input data.
 * @ingroup sha3
 *
 * Hash `len` bytes of input data from source buffer `src` with SHA3-512
 * ([FIPS 202][], section 6.1), then write 64 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.  Must be at least 64 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_512
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void sha3_512(const uint8_t *src, size_t len, uint8_t dst[static 64]);

/**
 * @brief Initialize SHA3-512 hash context.
 * @ingroup sha3
 *
 * @param[out] hash SHA3-512 hash context.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_512_absorb
 */
void sha3_512_init(sha3_t *hash);

/**
 * @brief Absorb input data into SHA3-512 hash context.
 * @ingroup sha3
 *
 * Absorb `len` bytes of input data from source buffer `src` into
 * SHA3-512 hash context `hash`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in,out] hash SHA3-512 hash context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_512_absorb
 */
_Bool sha3_512_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Finalize SHA3-512 hash context and write 64 bytes of output to
 * destination buffer `dst`.
 * @ingroup sha3
 *
 * @param[in,out] hash SHA3-512 hash context.
 * @param[out] dst Destination buffer.  Must be at least 64 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c sha3_512_absorb
 */
void sha3_512_final(sha3_t *hash, uint8_t dst[64]);

/**
 * @defgroup hmac HMAC
 *
 * @brief [HMAC][hmac] instantiated with [SHA-3][] hash functions, as
 * specified in section 7 of [FIPS 202][], [RFC 2104][], and
 * [FIPS 198-1][].
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 * [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
 *   "Secure Hash Algorithm 3"
 * [hmac]: https://en.wikipedia.org/wiki/HMAC
 *   "Keyed Hash Message Authentication Code (HMAC)"
 * [rfc 2104]: https://datatracker.ietf.org/doc/html/rfc2104
 *   "RFC 2104: HMAC: Keyed-Hashing for Message Authentication"
 * [FIPS 198-1]: https://csrc.nist.gov/pubs/fips/198-1/final
 *   "The Keyed-Hash Message Authentication Code (HMAC)"
 */

/**
 * @brief Calculat HMAC-SHA3-224 of given key and data.
 * @ingroup hmac
 *
 * Calculate HMAC-SHA3-224 ([FIPS 202][], Section 7) of key in buffer
 * `key` of length `key_len` and input message in buffer `msg` of length
 * `msg_len` bytes and write 28 byte [message authentication code
 * (MAC)][] to destination buffer `mac`.
 *
 * @param[in] key Key.
 * @param[in] key_len Key length, in bytes.
 * @param[in] msg Input message.
 * @param[in] msg_len Input message length, in bytes.
 * @param[out] mac [MAC][] destination buffer.  Must be at least 28 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_224
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code (MAC)"
 */
void hmac_sha3_224(const uint8_t *key, const size_t key_len, const uint8_t *msg, const size_t msg_len, uint8_t mac[28]);

/**
 * @brief Calculate HMAC-SHA3-256 given key and data.
 * @ingroup hmac
 *
 * Calculate HMAC-SHA3-256 ([FIPS 202][], Section 7) of key in buffer
 * `key` of length `key_len` and input message in buffer `msg` of length
 * `msg_len` bytes and write 32 byte [message authentication code
 * (MAC)][mac] destination buffer `mac`.
 *
 * @param[in] key Key.
 * @param[in] key_len Key length, in bytes.
 * @param[in] msg Input message.
 * @param[in] msg_len Input message length, in bytes.
 * @param[out] mac [MAC][] destination buffer.  Must be at least 32 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_256
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code (MAC)"
 */
void hmac_sha3_256(const uint8_t *key, const size_t key_len, const uint8_t *msg, const size_t msg_len, uint8_t mac[32]);

/**
 * @brief Calculate HMAC-SHA3-384 of given key and data.
 * @ingroup hmac
 *
 * Calculate HMAC-SHA3-384 ([FIPS 202][], Section 7) of key in buffer
 * `key` of length `key_len` and input message in buffer `msg` of length
 * `msg_len` bytes and write 48 byte [message authentication code
 * (MAC)][mac] destination buffer `mac`.
 *
 * @param[in] key Key.
 * @param[in] key_len Key length, in bytes.
 * @param[in] msg Input message.
 * @param[in] msg_len Input message length, in bytes.
 * @param[out] mac [MAC][] destination buffer.  Must be at least 48 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_384
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code (MAC)"
 */
void hmac_sha3_384(const uint8_t *key, const size_t key_len, const uint8_t *msg, const size_t msg_len, uint8_t mac[48]);

/**
 * @brief Calculate HMAC-SHA3-512 of given key and data.
 * @ingroup hmac
 *
 * Calculate HMAC-SHA3-512 ([FIPS 202][], Section 7) of key in buffer
 * `key` of length `key_len` and input message in buffer `msg` of length
 * `msg_len` bytes and write 64 byte [message authentication code
 * (MAC)][mac] destination buffer `mac`.
 *
 * @param[in] key Key.
 * @param[in] key_len Key length, in bytes.
 * @param[in] msg Input message.
 * @param[in] msg_len Input message length, in bytes.
 * @param[out] mac [MAC][] destination buffer.  Must be at least 64 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_512
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code (MAC)"
 */
void hmac_sha3_512(const uint8_t *key, const size_t key_len, const uint8_t *msg, const size_t msg_len, uint8_t mac[64]);

/**
 * @brief HMAC-SHA3 (Hash-based [Message Authentication Code][MAC])
 * context (all members are private).
 * @ingroup hmac
 *
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code (MAC)"
 */
typedef struct {
  sha3_t inner, /**< Inner hash context (private) */
         outer; /**< Outer hash context (private) */
  _Bool finalized; /**< Is this context finalized (private) */
} hmac_sha3_t;

/**
 * @brief Initialize HMAC-SHA3-224 ([FIPS 202][], Section 7) context.
 * @ingroup hmac
 *
 * @param[out] ctx HMAC-SHA3-224 context.
 * @param[in] key Key.
 * @param[in] key_len Key length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_224_absorb
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void hmac_sha3_224_init(hmac_sha3_t *ctx, const uint8_t *key, const size_t key_len);

/**
 * @brief Absorb data into HMAC-SHA3-224 context.
 * @ingroup hmac
 *
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-224
 * context `hmac`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] ctx HMAC-SHA3-224 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_224_absorb
 */
_Bool hmac_sha3_224_absorb(hmac_sha3_t *ctx, const uint8_t *src, const size_t len);

/**
 * @brief Finalize HMAC-SHA3-224 context and write 28 byte [MAC][]
 * to destination buffer.
 * @ingroup hmac
 *
 * @param[in,out] ctx HMAC-SHA3-224 context.
 * @param[out] mac [MAC][] destination buffer.  Must be at least 28 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_224_absorb
 *
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code (MAC)"
 */
void hmac_sha3_224_final(hmac_sha3_t *ctx, uint8_t mac[28]);

/**
 * @brief Initialize HMAC-SHA3-256 ([FIPS 202][], Section 7) context.
 * @ingroup hmac
 *
 * @param[out] ctx HMAC-SHA3-256 context.
 * @param[in] key Key.
 * @param[in] key_len Key length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_256_absorb
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void hmac_sha3_256_init(hmac_sha3_t *ctx, const uint8_t *key, const size_t key_len);

/**
 * @brief Absorb data into HMAC-SHA3-256 context.
 * @ingroup hmac
 *
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-256
 * context `ctx`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] ctx HMAC-SHA3-256 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_256_absorb
 */
_Bool hmac_sha3_256_absorb(hmac_sha3_t *ctx, const uint8_t *src, const size_t len);

/**
 * @brief Finalize HMAC-SHA3-256 context and write 32 byte [MAC][] to
 * destination buffer.
 * @ingroup hmac
 *
 * @param[in,out] ctx HMAC-SHA3-256 context.
 * @param[out] mac [MAC][] destination buffer.  Must be at least 32 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_256_absorb
 *
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code (MAC)"
 */
void hmac_sha3_256_final(hmac_sha3_t *ctx, uint8_t mac[32]);

/**
 * @brief Initialize HMAC-SHA3-384 ([FIPS 202][], Section 7) context.
 * @ingroup hmac
 *
 * @param[out] ctx HMAC-SHA3-384 context.
 * @param[in] key Key.
 * @param[in] key_len Key length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_384_absorb
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void hmac_sha3_384_init(hmac_sha3_t *ctx, const uint8_t *key, const size_t key_len);

/**
 * @brief Absorb data into HMAC-SHA3-384 context.
 * @ingroup hmac
 *
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-384
 * context `ctx`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] ctx HMAC-SHA3-384 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_384_absorb
 */
_Bool hmac_sha3_384_absorb(hmac_sha3_t *ctx, const uint8_t *src, const size_t len);

/**
 * @brief Finalize HMAC-SHA3-384 context and write 48 byte [MAC][] to
 * destination buffer.
 * @ingroup hmac
 *
 * @param[in,out] ctx HMAC-SHA3-384 context.
 * @param[out] mac [MAC][] destination buffer.  Must be at least 48 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_512_absorb
 *
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code (MAC)"
 */
void hmac_sha3_384_final(hmac_sha3_t *ctx, uint8_t mac[48]);

/**
 * @brief Initialize HMAC-SHA3-512 ([FIPS 202][], Section 7) context.
 * @ingroup hmac
 *
 * @param[out] ctx HMAC-SHA3-512 context.
 * @param[in] key Key.
 * @param[in] key_len Key length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_512_absorb
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void hmac_sha3_512_init(hmac_sha3_t *ctx, const uint8_t *key, const size_t key_len);

/**
 * @brief Absorb data into HMAC-SHA3-512 context.
 * @ingroup hmac
 *
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-512
 * context `ctx`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] ctx HMAC-SHA3-512 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_512_absorb
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool hmac_sha3_512_absorb(hmac_sha3_t *ctx, const uint8_t *src, const size_t len);

/**
 * @brief Finalize HMAC-SHA3-512 context and write 64 byte [MAC][]
 * to destination buffer.
 * @ingroup hmac
 *
 * @param[in,out] ctx HMAC-SHA3-512 hash context.
 * @param[out] mac [MAC][] destination buffer.  Must be at least 64 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c hmac_sha3_512_absorb
 *
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code (MAC)"
 */
void hmac_sha3_512_final(hmac_sha3_t *ctx, uint8_t mac[64]);

/**
 * @defgroup shake SHAKE
 *
 * @brief [SHA-3][] [Extendable-output functions (XOFs)][xof] with
 * fixed-length and arbitrary-length output, as defined in section 6.2
 * of [FIPS 202][].
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 * [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
 *   "Secure Hash Algorithm 3"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */

/**
 * @brief Hash data with SHAKE128.
 * @ingroup shake
 *
 * Hash input message in buffer `msg` of length `len` bytes with
 * SHAKE128 ([FIPS 202][], section 6.2) and write 16 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in] msg Input message.
 * @param[in] len Input message length, in bytes.
 * @param[out] dst Destination buffer.  Must be at least 16 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake128
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void shake128(const uint8_t *msg, size_t len, uint8_t dst[static 16]);

/**
 * @brief Hash data with SHAKE256.
 * @ingroup shake
 *
 * Hash input message in buffer `msg` of length `len` bytes with
 * SHAKE256 ([FIPS 202][], section 6.2) and write 32 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in] msg Input message.
 * @param[in] len Input message length, in bytes.
 * @param[out] dst Destination buffer.  Must be at least 32 bytes in length.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake256
 *
 * [FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
 *   "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
 */
void shake256(const uint8_t *msg, size_t len, uint8_t dst[static 32]);

/**
 * @brief Initialize SHAKE128 [extendable-output function (XOF)][xof] context.
 * @ingroup shake
 *
 * @param[out] xof SHAKE128 [XOF][] context.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake128_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void shake128_xof_init(sha3_xof_t * const xof);

/**
 * @brief Absorb data into SHAKE128 [XOF][] context.
 * @ingroup shake
 *
 * Absorb input data in `msg` of length `len` bytes into SHAKE128
 * [XOF][] context `xof`.  Can be called iteratively to absorb input
 * data in chunks.
 *
 * @param[in,out] xof SHAKE128 [XOF][] context.
 * @param[in] msg Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake128_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
_Bool shake128_xof_absorb(sha3_xof_t *xof, const uint8_t *msg, const size_t len);

/**
 * @brief Squeeze bytes from SHAKE128 [XOF][] context.
 * @ingroup shake
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * SHAKE128 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in,out] xof SHAKE128 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake128_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void shake128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into SHAKE128 [XOF][], then squeeze bytes out.
 * @ingroup shake
 *
 * Absorb data in buffer `src` of length `src_len` bytes into SHAKE128
 * [XOF][] context, then squeeze `dst_len` bytes of output into
 * destination buffer `dst`.
 *
 * @note This function will produce different output than shake128(),
 * because shake128() produces fixed-length output and this function
 * produces arbitrary-length output.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake128_xof_once
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void shake128_xof_once(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize SHAKE256 [extendable-output function (XOF)][xof]
 * context.
 * @ingroup shake
 *
 * @param[out] xof SHAKE256 [XOF][] context.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake256_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void shake256_xof_init(sha3_xof_t *xof);

/**
 * @brief Absorb data into SHAKE256 [XOF][] context.
 * @ingroup shake
 *
 * Absorb input data in `msg` of length `len` bytes into SHAKE256
 * [XOF][] context `xof`.  Can be called iteratively to absorb input
 * data in chunks.
 *
 * @param[in,out] xof SHAKE256 [XOF][] context.
 * @param[in] msg Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake256_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
_Bool shake256_xof_absorb(sha3_xof_t *xof, const uint8_t *msg, const size_t len);

/**
 * @brief Squeeze bytes from SHAKE256 [XOF][] context.
 * @ingroup shake
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * SHAKE256 [XOF][] context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in,out] xof SHAKE256 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake256_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void shake256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into SHAKE256 [XOF][], then squeeze bytes out.
 * @ingroup shake
 *
 * Absorb data in buffer `src` of length `src_len` bytes into SHAKE256
 * [XOF][] context, then squeeze `dst_len` bytes of output into
 * destination buffer `dst`.
 *
 * @note This function will produce different output than shake256(),
 * because shake256() produces fixed-length output and this function
 * produces arbitrary-length output.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c shake256_xof_once
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void shake256_xof_once(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @defgroup cshake cSHAKE
 *
 * @brief Customizable SHAKE (cSHAKE) [extendable-output function
 * (XOF)][xof], as defined in section 3 of [SP 800-185][800-185].
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */

/**
 * @brief cSHAKE parameters.
 * @ingroup cshake
 */
typedef struct {
  const uint8_t *name; /**< NIST function name */
  const size_t name_len; /**< NIST function name length, in bytes */
  const uint8_t *custom; /**< Customization string */
  const size_t custom_len; /**< Customization string length, in bytes */
} cshake_params_t;

/**
 * @brief Initialize cSHAKE128, absorb data, then squeeze bytes out.
 * @ingroup cshake
 *
 * Initialize internal cSHAKE128 (customizable SHAKE128, as defined in
 * section 3 of [NIST SP 800-185][800-185]) context with customization
 * parameters `params`, absorb data in buffer `src` of length `src_len`
 * bytes into internal context, then squeeze `dst_len` bytes of output
 * into destination buffer `dst`.
 *
 * @note cSHAKE is used to implement the [extendable output functions
 * (XOFs)][xof] defined in [NIST SP 800-185][800-185] and should
 * generally not be used directly.
 *
 * @param[in] params cSHAKE customization parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c cshake128
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */
void cshake128(const cshake_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize cSHAKE256, absorb data, then squeeze bytes out.
 * @ingroup cshake
 *
 * Initialize internal cSHAKE256 (customizable SHAKE256, as defined in
 * section 3 of [NIST SP 800-185][800-185]) context with customization
 * parameters `params`, absorb data in buffer `src` of length `src_len`
 * bytes into internal context, then squeeze `dst_len` bytes of output
 * into destination buffer `dst`.
 *
 * @note cSHAKE is used to implement the [extendable output functions
 * (XOFs)][xof] defined in [NIST SP 800-185][800-185] and should
 * generally not be used directly.
 *
 * @param[in] params cSHAKE customization parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c cshake256
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */
void cshake256(const cshake_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize cSHAKE128 [XOF][] context.
 * @ingroup cshake
 *
 * Initialize cSHAKE128 (customizable SHAKE128, as defined in section 3 of
 * [NIST SP 800-185][800-185]) [XOF][] context with customization
 * parameters `params`.
 *
 * @note cSHAKE is used to implement the [extendable output functions
 * (XOFs)][xof] defined in [NIST SP 800-185][800-185] and should
 * generally not be used directly.
 *
 * @param[out] xof cSHAKE128 [XOF][] context.
 * @param[in] params cSHAKE128 customization parameters.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c cshake128_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */
void cshake128_xof_init(sha3_xof_t *xof, const cshake_params_t params);

/**
 * @brief Absorb data into cSHAKE128 [XOF][] context.
 * @ingroup cshake
 *
 * Absorb data in buffer `src` of length `len` bytes into cSHAKE128
 * [XOF][] context `xof`.  Can be called iteratively to absorb input
 * data in chunks.
 *
 * @note cSHAKE is used to implement the [extendable output functions
 * (XOFs)][xof] defined in [NIST SP 800-185][800-185] and should
 * generally not be used directly.
 *
 * @param[in,out] xof cSHAKE128 [XOF][] context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c cshake128_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */
_Bool cshake128_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from cSHAKE128 [XOF][] context.
 * @ingroup cshake
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * cSHAKE128 [XOF][] context `xof`.  Can be called iteratively to
 * squeeze output data in chunks.
 *
 * @note cSHAKE is used to implement the [extendable output functions
 * (XOFs)][xof] defined in [NIST SP 800-185][800-185] and should
 * generally not be used directly.
 *
 * @param[in,out] xof cSHAKE128 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c cshake128_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */
void cshake128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Initialize cSHAKE256 [XOF][] context.
 * @ingroup cshake
 *
 * Initialize cSHAKE256 (customizable SHAKE256, as defined in section 3
 * of [NIST SP 800-185][800-185]) [XOF][] context with customization
 * parameters `params`.
 *
 * @note cSHAKE is used to implement the [extendable output functions
 * (XOFs)][xof] defined in [NIST SP 800-185][800-185] and should
 * generally not be used directly.
 *
 * @ingroup cshake
 *
 * @param[out] xof cSHAKE256 [XOF][] context.
 * @param[in] params cSHAKE256 customization parameters.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c cshake256_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */
void cshake256_xof_init(sha3_xof_t *xof, const cshake_params_t params);

/**
 * @brief Absorb data into cSHAKE256 [XOF][] context.
 * @ingroup cshake
 *
 * Absorb data in buffer `src` of length `len` bytes into cSHAKE256
 * [XOF][] context `xof`.  Can be called iteratively to absorb input
 * data in chunks.
 *
 * @note cSHAKE is used to implement the hash and [extendable output
 * functions (XOFs)][xof] defined in [NIST SP 800-185][800-185] and
 * should generally not be used directly.
 *
 * @param[in,out] xof cSHAKE256 [XOF][] context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c cshake256_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */
_Bool cshake256_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from cSHAKE256 [XOF][] context.
 * @ingroup cshake
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * cSHAKE256 [XOF][] context `xof`.  Can be called iteratively to
 * squeeze output data in chunks.
 *
 * @note cSHAKE is used to implement the hash and [extendable output
 * functions (XOFs)][xof] defined in [NIST SP 800-185][800-185] and
 * should generally not be used directly.
 *
 * @param[in,out] xof cSHAKE256 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c cshake256_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */
void cshake256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @defgroup kmac KMAC

 * @brief Keccak [Message Authentication Code (MAC)][mac], as defined in
 * section 4 of [SP 800-185][800-185].
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */

/**
 * @brief KMAC configuration parameters (key and customization string).
 * @ingroup kmac
 */
typedef struct {
  const uint8_t *key; /**< Key string. */
  const size_t key_len; /**< Key string length, in bytes. */
  const uint8_t *custom; /**< Customization string. */
  const size_t custom_len; /**< Customization string length, in bytes. */
} kmac_params_t;

/**
 * @brief Absorb data into KMAC128, then squeeze bytes out.
 * @ingroup kmac
 *
 * Initialize internal KMAC128 (Keccak Message Authentication Code, as
 * defined in section 4 of [NIST SP 800-185][800-185]) context with
 * configuration parameters `params`, absorb data in buffer `src` of
 * length `src_len` bytes into internal context, then squeeze `dst_len`
 * bytes of output into destination buffer `dst`.
 *
 * @param[in] params KMAC configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac128
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
void kmac128(const kmac_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb data into KMAC256, then squeeze bytes out.
 * @ingroup kmac
 *
 * Initialize internal KMAC256 (Keccak Message Authentication Code, as
 * defined in section 4 of [NIST SP 800-185][800-185]) context with
 * configuration parameters `params`, absorb data in buffer `src` of
 * length `src_len` bytes into internal context, then squeeze `dst_len`
 * bytes of output into destination buffer `dst`.
 *
 * @param[in] params KMAC configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac256
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
void kmac256(const kmac_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize KMAC128 [XOF][] context.
 * @ingroup kmac
 *
 * Initialize KMAC128 [XOF][] (Keccak Message Authentication Code eXtendable
 * Output Function, as defined in section 4.3.1 of [NIST SP
 * 800-185][800-185]) context with configuration parameters `params`.
 *
 * @note KMAC128 and KMAC128 [XOF][] produce different output, because
 * KMAC128 encodes the fixed output size as part of the input while
 * KMAC128 [XOF][] does not.  See section 4.3.1 of [NIST SP
 * 800-185][800-185] for details.
 *
 * @param[out] xof KMAC128 [XOF][] context.
 * @param[in] params KMAC configuration parameters.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac128_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
void kmac128_xof_init(sha3_xof_t *xof, const kmac_params_t params);

/**
 * @brief Absorb data into KMAC128 XOF context.
 * @ingroup kmac
 *
 * Absorb data in buffer `src` of length `len` bytes into KMAC128
 * [XOF][] context.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] xof KMAC128 [XOF][] context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac128_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
_Bool kmac128_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze data from KMAC128 [XOF][] context.
 * @ingroup kmac
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * KMAC128 [XOF][] context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @note KMAC128 and KMAC128 [XOF][] produce different output, because
 * KMAC128 encodes the fixed output size as part of the input while
 * KMAC128 [XOF][] does not.  See section 4.3.1 of [NIST SP
 * 800-185][800-185] for details.
 *
 * @param[in,out] xof KMAC128 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac128_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
void kmac128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into KMAC128 [XOF][] context, then squeeze bytes out.
 * @ingroup kmac
 *
 * Initialize internal KMAC128 [XOF][] (Keccak Message Authentication
 * Code eXtendable Output Function, as defined in section 4 of [NIST SP
 * 800-185][800-185]) context with configuration parameters `params`,
 * absorb data in buffer `src` of length `src_len` bytes into internal
 * context, then squeeze `dst_len` bytes of output into destination
 * buffer `dst`.
 *
 * @note KMAC128 and KMAC128 [XOF][] produce different output, because
 * KMAC128 encodes the fixed output size as part of the input while
 * KMAC128 [XOF][] does not.  See section 4.3.1 of [NIST SP
 * 800-185][800-185] for details.
 *
 * @param[in] params KMAC configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac256_xof_once
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
void kmac128_xof_once(const kmac_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize KMAC256 [XOF][] context.
 * @ingroup kmac
 *
 * Initialize KMAC256 [XOF][] (Keccak Message Authentication Code
 * eXtendable Output Function, as defined in section 4.3.1 of [NIST SP
 * 800-185][800-185]) context with configuration parameters `params`.
 *
 * @note KMAC256 and KMAC256 [XOF][] produce different output, because
 * KMAC256 encodes the fixed output size as part of the input while
 * KMAC256 [XOF][] does not.  See section 4.3.1 of [NIST SP
 * 800-185][800-185] for details.
 *
 * @param[out] xof KMAC256 [XOF][] context.
 * @param[in] params KMAC configuration parameters.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac256_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
void kmac256_xof_init(sha3_xof_t *xof, const kmac_params_t params);

/**
 * @brief Absorb data into KMAC256 [XOF][] context.
 * @ingroup kmac
 *
 * Absorb data in buffer `src` of length `len` bytes into KMAC256
 * [XOF][] context.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] xof KMAC256 [XOF][] context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac256_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
_Bool kmac256_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze data from KMAC256 [XOF][] context.
 * @ingroup kmac
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * KMAC256 [XOF][] context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @note KMAC256 and KMAC256 [XOF][] produce different output, because
 * KMAC256 encodes the fixed output size as part of the input while
 * KMAC256 [XOF][] does not.  See section 4.3.1 of [NIST SP
 * 800-185][800-185] for details.
 *
 * @ingroup kmac
 *
 * @param[in,out] xof KMAC256 [XOF] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac256_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
void kmac256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into KMAC256 [XOF][] context, then squeeze bytes out.
 * @ingroup kmac
 *
 * Initialize internal KMAC256 [XOF][] (Keccak Message Authentication
 * Code eXtendable Output Function, as defined in section 4 of [NIST SP
 * 800-185][800-185]) context with configuration parameters `params`,
 * absorb data in buffer `src` of length `src_len` bytes into internal
 * context, then squeeze `dst_len` bytes of output into destination
 * buffer `dst`.
 *
 * @note KMAC256 and KMAC256 [XOF][] produce different output, because
 * KMAC256 encodes the fixed output size as part of the input while
 * KMAC256 [XOF][] does not.  See section 4.3.1 of [NIST SP
 * 800-185][800-185] for details.
 *
 * @param[in] params KMAC configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c kmac256_xof_once
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [mac]: https://en.wikipedia.org/wiki/Message_authentication_code
 *   "Message authentication code"
 */
void kmac256_xof_once(const kmac_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @defgroup tuplehash TupleHash
 * @brief Misuse-resistant cryptographic hash function and [XOF][] for
 * hashing a [tuple][] of byte strings, as defined in section 5 of [SP
 * 800-185][800-185].
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 */

/**
 * @brief Individual element of TupleHash [tuple][].
 * @ingroup tuplehash
 *
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 */
typedef struct {
  const uint8_t *ptr; /**< Pointer to byte string. */
  size_t len; /**< Byte string length, in bytes. */
} tuplehash_str_t;

/**
 * @brief TupleHash configuration parameters.
 * @ingroup tuplehash
 */
typedef struct {
  const tuplehash_str_t *strs; /**< Pointer to tuple elements. */
  const size_t num_strs; /**< Number of elements. */
  const uint8_t *custom; /**< Customization string. */
  const size_t custom_len; /**< Customization string length, in bytes. */
} tuplehash_params_t;

/**
 * @brief Absorb [tuple][] and customization string into TupleHash128,
 * then squeeze bytes out.
 * @ingroup tuplehash
 *
 * Initialize internal TupleHash128 ([NIST SP 800-185][800-185], section
 * 5) context with configuration parameters `params`, then squeeze `len`
 * bytes of output from internal context into destination buffer `dst`.
 *
 * @param[in] params TupleHash128 configuration parameters.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c tuplehash128
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 */
void tuplehash128(const tuplehash_params_t params, uint8_t *dst, const size_t len);

/**
 * @brief Absorb [tuple][] and customization string into TupleHash256,
 * then squeeze bytes out.
 * @ingroup tuplehash
 *
 * Initialize internal TupleHash256 ([NIST SP 800-185][800-185], section
 * 5) context with configuration parameters `params`, then squeeze `len`
 * bytes of output from internal context into destination buffer `dst`.
 *
 * @ingroup tuplehash
 *
 * @param[in] params TupleHash256 configuration parameters.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c tuplehash256
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 */
void tuplehash256(const tuplehash_params_t params, uint8_t *dst, const size_t len);

/**
 * @brief Initialize a TupleHash128 [XOF][] context.
 * @ingroup tuplehash
 *
 * Initialize TupleHash128 [XOF][] (TupleHash eXtendable Output
 * Function, as defined in section 5.3.1 of [NIST SP 800-185][800-185])
 * context with configuration parameters `params`.
 *
 * @note TupleHash128 and TupleHash128 [XOF][] produce different output,
 * because TupleHash128 encodes the fixed output size as part of the
 * input while TupleHash128 [XOF][] does not.  See section 5.3.1 of
 * [NIST SP 800-185][800-185] for details.
 *
 * @param[out] xof TupleHash128 [XOF][] context.
 * @param[in] params TupleHash configuration parameters.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c tuplehash128_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void tuplehash128_xof_init(sha3_xof_t *xof, const tuplehash_params_t params);

/**
 * @brief Squeeze data from TupleHash128 [XOF][] context.
 * @ingroup tuplehash
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * TupleHash128 [XOF][] context `xof`.  Can be called iteratively to
 * squeeze output data in chunks.
 *
 * @note TupleHash128 and TupleHash128 [XOF][] produce different output,
 * because TupleHash128 encodes the fixed output size as part of the
 * input while TupleHash128 [XOF][] does not.  See section 5.3.1 of
 * [NIST SP 800-185][800-185] for details.
 *
 * @param[in,out] xof TupleHash128 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c tuplehash128_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void tuplehash128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into TupleHash128 [XOF][], then squeeze bytes out.
 * @ingroup tuplehash
 *
 * Initialize internal TupleHash128 [XOF][] (TupleHash eXtendable Output
 * Function, as defined in section 5 of [NIST SP 800-185][800-185])
 * context with configuration parameters `params`, then squeeze
 * `len` bytes of output into destination buffer `dst`.
 *
 * @note TupleHash128 and TupleHash128 [XOF][] produce different output,
 * because TupleHash128 encodes the fixed output size as part of the
 * input while TupleHash128 [XOF][] does not.  See section 5.3.1 of
 * [NIST SP 800-185][800-185] for details.
 *
 * @param[in] params TupleHash128 configuration parameters.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c tuplehash128_xof_once
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void tuplehash128_xof_once(const tuplehash_params_t params, uint8_t *dst, const size_t len);

/**
 * @brief Initialize a TupleHash256 [XOF][] context.
 * @ingroup tuplehash
 *
 * Initialize TupleHash256 [XOF][] (TupleHash eXtendable Output
 * Function, as defined in section 5.3.1 of [NIST SP 800-185][800-185])
 * context with configuration parameters `params`.
 *
 * @note TupleHash256 and TupleHash256 [XOF][] produce different output,
 * because TupleHash256 encodes the fixed output size as part of the
 * input while TupleHash256 [XOF][] does not.  See section 5.3.1 of
 * [NIST SP 800-185][800-185] for details.
 *
 * @param[out] xof TupleHash256 [XOF][] context.
 * @param[in] params TupleHash configuration parameters.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c tuplehash256_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void tuplehash256_xof_init(sha3_xof_t *xof, const tuplehash_params_t params);

/**
 * @brief Squeeze bytes from a TupleHash256 [XOF][] context.
 * @ingroup tuplehash
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * TupleHash256 [XOF][] context `xof`.  Can be called iteratively to
 * squeeze output data in chunks.
 *
 * @note TupleHash256 and TupleHash256 [XOF][] produce different output,
 * because TupleHash256 encodes the fixed output size as part of the
 * input while TupleHash256 [XOF][] does not.  See section 5.3.1 of
 * [NIST SP 800-185][800-185] for details.
 *
 * @param[in,out] xof TupleHash256 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c tuplehash256_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void tuplehash256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into TupleHash256 [XOF][], then squeeze bytes out.
 * @ingroup tuplehash
 *
 * Initialize internal TupleHash256 [XOF][] (TupleHash eXtendable Output
 * Function, as defined in section 5 of [NIST SP 800-185][800-185])
 * context with configuration parameters `params`, then squeeze `len`
 * bytes of output into destination buffer `dst`.
 *
 * Note: TupleHash256 and TupleHash256 [XOF][] produce different output,
 * because TupleHash256 encodes the fixed output size as part of the
 * input while TupleHash256 [XOF][] does not.  See section 5.3.1 of
 * [NIST SP 800-185][800-185] for details.
 *
 * @param[in] params TupleHash256 configuration parameters.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c tuplehash256_xof_once
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [tuple]: https://en.wikipedia.org/wiki/Tuple
 *   "Ordered list of elements."
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void tuplehash256_xof_once(const tuplehash_params_t params, uint8_t *dst, const size_t len);

/**
 * @defgroup parallelhash ParallelHash
 * @brief Hash function and [XOF][], as defined in section 6 of [SP
 * 800-185][800-185].
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 */

/**
 * @brief ParallelHash configuration parameters.
 * @ingroup parallelhash
 */
typedef struct {
  const size_t block_len; /**< Block size, in bytes. */
  const uint8_t *custom; /**< Customization string. */
  const size_t custom_len; /**< Customization string length, in bytes. */
} parallelhash_params_t;

/**
 * @brief ParallelHash context (all members are private).
 * @ingroup parallelhash
 */
typedef struct {
  sha3_xof_t root_xof, /**< root xof */
             curr_xof; /**< current block xof (note: shake128, not cshake128) */
  size_t ofs, /**< offset in current block, in bytes */
         block_len, /**< block size, in bytes */
         num_blocks; /**< total number of blocks */
  _Bool squeezing; /**< current state */
} parallelhash_t;

/**
 * @brief Absorb data into ParallelHash128, then squeeze bytes out.
 * @ingroup parallelhash
 *
 * Initialize internal ParallelHash128 ([NIST SP 800-185][800-185],
 * section 6) context with configuration parameters `params`, then
 * squeeze `dst_len` bytes of output from internal context into
 * destination buffer `dst`.
 *
 * @note This ParallelHash implementation is sequential, not parallel.
 *
 * @param[in] params ParallelHash configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash128
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash128(const parallelhash_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb data into ParallelHash256, then squeeze bytes out.
 * @ingroup parallelhash
 *
 * Initialize internal ParallelHash256 ([NIST SP 800-185][800-185],
 * section 6) context with configuration parameters `params`, then
 * squeeze `dst_len` bytes of output from internal context into
 * destination buffer `dst`.
 *
 * @note This ParallelHash implementation is sequential, not parallel.
 *
 * @ingroup parallelhash
 *
 * @param[in] params ParallelHash configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash256
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash256(const parallelhash_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize a ParallelHash128 [XOF][] context.
 * @ingroup parallelhash
 *
 * Initialize ParallelHash128 [XOF][] (ParallelHash eXtendable Output
 * Function, as defined in section 6.3.1 of [NIST SP 800-185][800-185])
 * context with configuration parameters `params`.
 *
 * @note ParallelHash128 and ParallelHash128 [XOF][] produce different
 * output, because ParallelHash128 encodes the fixed output size as part
 * of the input while ParallelHash128 XOF does not.  See section 6.3.1
 * of [NIST SP 800-185][800-185] for details.
 *
 * @note This ParallelHash implementation is sequential, not parallel.
 *
 * @param[out] xof ParallelHash128 [XOF][] context.
 * @param[in] params ParallelHash configuration parameters.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash128_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash128_xof_init(parallelhash_t *xof, const parallelhash_params_t params);

/**
 * @brief Absorb data into a ParallelHash128 [XOF][] context.
 * @ingroup parallelhash
 *
 * Absorb data in buffer `src` of length `len` bytes into
 * ParallelHash128 [XOF][] context.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @note This ParallelHash implementation is sequential, not parallel.
 *
 * @param[in,out] hash ParallelHash128 [XOF][] context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash128_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash128_xof_absorb(parallelhash_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from a ParallelHash128 [XOF][] context.
 * @ingroup parallelhash
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * ParallelHash128 [XOF][] context `xof`.  Can be called iteratively to
 * squeeze output data in chunks.
 *
 * @note ParallelHash128 and ParallelHash128 [XOF][] produce different
 * output, because ParallelHash128 encodes the fixed output size as part
 * of the input while ParallelHash128 [XOF][] does not.  See section
 * 6.3.1 of [NIST SP 800-185][800-185] for details.
 *
 * @note This ParallelHash implementation is sequential, not parallel.
 *
 * @param[in,out] xof ParallelHash128 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash128_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash128_xof_squeeze(parallelhash_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb bytes into ParallelHash128 [XOF][], then squeeze bytes out.
 * @ingroup parallelhash
 *
 * Initialize internal ParallelHash128 [XOF][] (ParallelHash eXtendable
 * Output Function, as defined in section 6.3.1 of [NIST SP
 * 800-185][800-185]) context with configuration parameters `params`,
 * absorb data in buffer `src` of length `src_len` bytes into context,
 * then squeeze `dst_len` bytes of output into destination buffer `dst`.
 *
 * @note ParallelHash128 and ParallelHash128 [XOF][] produce different
 * output, because ParallelHash128 encodes the fixed output size as part
 * of the input while ParallelHash128 [XOF][] does not.  See section 6.3.1
 * of [NIST SP 800-185][800-185] for details.
 *
 * @note This ParallelHash implementation is sequential, not parallel.
 *
 * @param[in] params ParallelHash configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash128_xof_once
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash128_xof_once(const parallelhash_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize a ParallelHash256 [XOF][] context.
 * @ingroup parallelhash
 *
 * Initialize ParallelHash256 [XOF][] (ParallelHash eXtendable Output
 * Function, as defined in section 6.3.1 of [NIST SP 800-185][800-185])
 * context with configuration parameters `params`.
 *
 * @note ParallelHash256 and ParallelHash256 [XOF][] produce different
 * output, because ParallelHash256 encodes the fixed output size as part
 * of the input while ParallelHash256 [XOF][] does not.  See section 6.3.1
 * of [NIST SP 800-185][800-185] for details.
 *
 * Note: This ParallelHash implementation is sequential, not parallel.
 *
 * @param[out] xof ParallelHash256 [XOF][] context.
 * @param[in] params ParallelHash configuration parameters.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash256_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash256_xof_init(parallelhash_t *xof, const parallelhash_params_t params);

/**
 * @brief Absorb data into a ParallelHash256 [XOF][] context.
 * @ingroup parallelhash
 *
 * Absorb data in buffer `src` of length `len` bytes into
 * ParallelHash256 [XOF][] context.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @note This ParallelHash implementation is sequential, not parallel.
 *
 * @param[in,out] xof ParallelHash256 [XOF][] context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash256_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash256_xof_absorb(parallelhash_t *xof, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from a ParallelHash256 [XOF][] context.
 * @ingroup parallelhash
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * ParallelHash256 [XOF][] context `xof`.  Can be called iteratively to
 * squeeze output data in chunks.
 *
 * @note ParallelHash256 and ParallelHash256 [XOF][] produce different
 * output, because ParallelHash256 encodes the fixed output size as part
 * of the input while ParallelHash256 [XOF][] does not.  See section 6.3.1
 * of [NIST SP 800-185][800-185] for details.
 *
 * Note: This ParallelHash implementation is sequential, not parallel.
 *
 * @param[in,out] xof ParallelHash256 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash256_xof
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash256_xof_squeeze(parallelhash_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb bytes into ParallelHash256 [XOF][], then squeeze bytes out.
 * @ingroup parallelhash
 *
 * Initialize internal ParallelHash256 [XOF][] (ParallelHash eXtendable
 * Output Function, as defined in section 6.3.1 of [NIST SP
 * 800-185][800-185]) context with configuration parameters `params`,
 * absorb `src_len` bytes if input from source buffer `src`, then
 * squeeze `dst_len` bytes of output into destination buffer `dst`.
 *
 * @note ParallelHash256 and ParallelHash256 [XOF][] produce different
 * output, because ParallelHash256 encodes the fixed output size as part
 * of the input while ParallelHash256 [XOF][] does not.  See section
 * 6.3.1 of [NIST SP 800-185][800-185] for details.
 *
 * Note: This ParallelHash implementation is sequential, not parallel.
 *
 * @param[in] params ParallelHash configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c parallelhash256_xof_once
 *
 * [800-185]: https://csrc.nist.gov/pubs/sp/800/185/final
 *   "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void parallelhash256_xof_once(const parallelhash_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @defgroup turboshake TurboSHAKE
 * @brief Faster, reduced-round [XOFs][xof], as defined in the [draft
 * KangarooTwelve and TurboSHAKE specification][turboshake-ietf].
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [turboshake-ietf]: https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-10.html
 *   "KangarooTwelve and TurboSHAKE"
 */

/**
 * @brief Absorb bytes into TurboSHAKE128 [XOF][], then squeeze bytes out.
 * @ingroup turboshake
 *
 * Initialize internal TurboSHAKE128 [XOF][] context, absorb `src_len`
 * bytes of input from source buffer `src`, then squeeze `dst_len` bytes
 * of output into destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake128
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void turboshake128(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb bytes into TurboSHAKE128 [XOF][] with custom padding
 * byte, then squeeze bytes out.
 * @ingroup turboshake
 *
 * Initialize internal TurboSHAKE128 [XOF][] context with custom padding
 * byte `pad`, absorb `src_len` bytes of input from source buffer `src`,
 * then squeeze `dst_len` bytes of output into destination buffer `dst`.
 *
 * @note The padding byte value must be in the range [0x01, 0x7F] and
 * can be used for domain separation.
 *
 * @ingroup turboshake
 *
 * @param[in] pad Padding byte.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake128_custom
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void turboshake128_custom(const uint8_t pad, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb bytes into TurboSHAKE256 [XOF][], then squeeze bytes out.
 * @ingroup turboshake
 *
 * Initialize internal TurboSHAKE256 [XOF][] context, absorb `src_len`
 * bytes of input from source buffer `src`, then squeeze `dst_len` bytes
 * of output into destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake256
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void turboshake256(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb bytes into TurboSHAKE256 [XOF][] with custom padding
 * byte, then squeeze bytes out.
 * @ingroup turboshake
 *
 * Initialize internal TurboSHAKE256 [XOF][] context with custom padding
 * byte `pad`, absorb `src_len` bytes of input from source buffer `src`,
 * then squeeze `dst_len` bytes of output into destination buffer `dst`.
 *
 * @note The padding byte value must be in the range [0x01, 0x7F] and
 * can be used for domain separation.
 *
 * @param[in] pad Padding byte.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake256_custom
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void turboshake256_custom(const uint8_t pad, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief TurboShake [XOF][] context (all members are private).
 * @ingroup turboshake
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
typedef struct {
  sha3_xof_t xof; /**< XOF context (private) */
  uint8_t pad; /**< Padding byte (private) */
} turboshake_t;

/**
 * @brief Initialize TurboSHAKE128 [XOF][] context.
 * @ingroup turboshake
 *
 * @param[out] ts TurboSHAKE128 [XOF][] context.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake128_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void turboshake128_init(turboshake_t *ts);

/**
 * @brief Initialize TurboSHAKE128 [XOF][] context with custom padding byte.
 * @ingroup turboshake
 *
 * Initialize TurboSHAKE128 [XOF][] context with custom padding byte.  The
 * custom padding byte can be used as a domain separator and must be in
 * the range [0x01, 0x7f].
 *
 * @param[out] ts TurboSHAKE128 [XOF][] context.
 * @param[in] pad Padding byte (used for domain separation).
 *
 * @return False if the padding byte is out of range and true otherwise.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake128_custom_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
_Bool turboshake128_init_custom(turboshake_t *ts, const uint8_t pad);

/**
 * @brief Absorb data into TurboSHAKE128 [XOF][] context.
 * @ingroup turboshake
 *
 * Absorb `src_len` bytes of input from source buffer `src` into
 * TurboSHAKE128 [XOF][] context `ts`.  Can be called iteratively to
 * absorb input data in chunks.
 *
 * @param[in,out] ts TurboSHAKE128 [XOF][] context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake128_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
_Bool turboshake128_absorb(turboshake_t *ts, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from TurboSHAKE128 [XOF][] context.
 * @ingroup turboshake
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * TurboSHAKE128 [XOF][] context `ts`.  Can be called iteratively to
 * squeeze output data in chunks.
 *
 * @param[in,out] ts TurboSHAKE128 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake128_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void turboshake128_squeeze(turboshake_t *ts, uint8_t *dst, const size_t len);

/**
 * @brief Initialize TurboSHAKE256 [XOF][] context.
 * @ingroup turboshake
 *
 * @param[out] ts TurboSHAKE256 [XOF][] context.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake256_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void turboshake256_init(turboshake_t *ts);

/**
 * @brief Initialize TurboSHAKE256 [XOF] context with custom padding byte.
 * @ingroup turboshake
 *
 * Initialize TurboSHAKE256 [XOF][] context with custom padding byte.
 * The custom padding byte can be used as a domain separator and must be
 * in the range [0x01, 0x7f].
 *
 * @param[out] ts TurboSHAKE256 [XOF][] context.
 * @param[in] pad Padding byte (used for domain separation).
 *
 * @return False if the padding byte is out of range and true otherwise.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake256_custom_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
_Bool turboshake256_init_custom(turboshake_t *ts, const uint8_t pad);

/**
 * @brief Absorb data into TurboSHAKE256 [XOF][] context.
 * @ingroup turboshake
 *
 * Absorb `len` bytes of input from source buffer `src` into
 * TurboSHAKE256 [XOF][] context `ts`.  Can be called iteratively to
 * absorb input data in chunks.
 *
 * @param[in,out] ts TurboSHAKE256 [XOF][] context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake256_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
_Bool turboshake256_absorb(turboshake_t *ts, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from TurboSHAKE256 [XOF][] context.
 * @ingroup turboshake
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * TurboSHAKE256 context `ts`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in,out] ts TurboSHAKE256 [XOF][] context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c turboshake256_xof
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
void turboshake256_squeeze(turboshake_t *ts, uint8_t *dst, const size_t len);

/**
 * @defgroup k12 KangarooTwelve
 * @brief Faster, reduced-round [XOF][] with a customzation string, as
 * defined in the [draft KangarooTwelve and TurboSHAKE
 * specification][turboshake-ietf].
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 * [turboshake-ietf]: https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-10.html
 *   "KangarooTwelve and TurboSHAKE"
 */

/**
 * @brief KangarooTwelve [XOF][] context (all members are private).
 * @ingroup k12
 *
 * [xof]: https://en.wikipedia.org/wiki/Extendable-output_function
 *   "Extendable-Output Function (XOF)"
 */
typedef struct {
  turboshake_t ts; /**< Internal turboshake context (private) */
} k12_t;

/**!
 * @brief Absorb data into KangarooTwelve, then squeeze bytes out.
 * @ingroup k12
 *
 * Initialize internal KangarooTwelve context, absorb `src_len` bytes of
 * input from source buffer `src`, then squeeze `dst_len` bytes of
 * output into destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c k12_once
 */
void k12_once(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb data into KangarooTwelve with customization string, then squeeze bytes out.
 * @ingroup k12
 *
 * Initialize internal KangarooTwelve context with custom string
 * `custom` of length `custom_len`, absorb `src_len` bytes of input from
 * source buffer `src`, then squeeze `dst_len` bytes of output into
 * destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[in] custom Custom string buffer.
 * @param[in] custom_len Custom string length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c k12_custom_once
 */
void k12_custom_once(const uint8_t *src, const size_t src_len, const uint8_t *custom, const size_t custom_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize KangarooTwelve context.
 * @ingroup k12
 *
 * Initialize KangarooTwelve context with message `src` of length
 * `src_len` bytes and custom string `custom` of length `custom_len`
 * bytes.
 *
 * @note This KangarooTwelve implementation is sequential, not parallel.
 *
 * @param[out] k12 KangarooTwelve context.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[in] custom Custom string buffer.
 * @param[in] custom_len Custom string length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c k12_xof
 */
void k12_init(k12_t *k12, const uint8_t *src, const size_t src_len, const uint8_t *custom, const size_t custom_len);

/**
 * @brief Squeeze bytes from KangarooTwelve context.
 * @ingroup k12
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * KangarooTwelve context `k12`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @note This KangarooTwelve implementation is sequential, not parallel.
 *
 * @param[in,out] k12 KangarooTwelve context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 *
 * Example:
 * @snippet{trimleft} 06-all/all-fns.c k12_xof
 */
void k12_squeeze(k12_t *k12, uint8_t *dst, const size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SHA3_H */
