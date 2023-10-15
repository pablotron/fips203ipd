/**
 * @file sha3.h
 * sha3
 * https://pablotron.org/sha3
 *
 * Copyright (c) 2023 Paul Duncan
 * SPDX-License-Identifier: MIT-0
 *
 * C11 implementations of the following SHA-3 algorithms:
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
 * @brief Internal SHA-3 state (all members are private).
 * @ingroup sha3
 */
typedef union {
  uint8_t u8[200]; /**< 8-bit unsigned integers. */
  uint64_t u64[25]; /**< 64-bit unsigned integers. */
} sha3_state_t;

/**
 * @brief Iterative SHA-3 context (all members are private).
 * @ingroup sha3
 */
typedef struct {
  size_t num_bytes; /**< number of bytes absorbed */
  sha3_state_t a; /**< internal state */
  _Bool finalized; /**< mode (absorbing or finalized) */
} sha3_t;

/**
 * @brief Iterative XOF context (all members are private).
 * @ingroup shake
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
 * (FIPS 202, section 6.1), then write 28 bytes of output to destination
 * buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 * @param[out] dst Destination array.  Must be at least 28 bytes in length.
 */
void sha3_224(const uint8_t *src, size_t len, uint8_t dst[static 28]);

/**
 * @brief Initialize SHA3-224 hash context.
 * @ingroup sha3
 *
 * @param[out] hash SHA3-224 hash context.
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
 */
_Bool sha3_224_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Finalize SHA3-224 hash context and write 28 bytes of output to
 * destination buffer `dst`.
 * @ingroup sha3
 *
 * @param[in,out] hash SHA3-224 hash context.
 * @param[out] dst Destination buffer.  Must be at least 28 bytes in length.
 */
void sha3_224_final(sha3_t *hash, uint8_t dst[28]);

/**
 * @brief Calculate SHA3-256 hash of input data.
 * @ingroup sha3
 *
 * Hash `len` bytes of input data from source buffer `src` with SHA3-256
 * (FIPS 202, section 6.1), then write 32 bytes of output to destination
 * buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 * @param[out] dst Destination array.  Must be at least 32 bytes in length.
 */
void sha3_256(const uint8_t *src, size_t len, uint8_t dst[static 32]);

/**
 * @brief Initialize SHA3-256 hash context.
 * @ingroup sha3
 *
 * @param[out] hash SHA3-256 hash context.
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
 */
_Bool sha3_256_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Finalize SHA3-256 hash context and write 32 bytes of output to
 * destination buffer `dst`.
 * @ingroup sha3
 *
 * @param[in,out] hash SHA3-256 hash context.
 * @param[out] dst Destination buffer.  Must be at least 32 bytes in length.
 */
void sha3_256_final(sha3_t *hash, uint8_t dst[32]);

/**
 * @brief Calculate SHA3-384 hash of input data.
 * @ingroup sha3
 *
 * Hash `len` bytes of input data from source buffer `src` with SHA3-384
 * (FIPS 202, section 6.1), then write 48 bytes of output to destination
 * buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 * @param[out] dst Destination array.  Must be at least 48 bytes in length.
 */
void sha3_384(const uint8_t *src, size_t len, uint8_t dst[static 48]);

/**
 * @brief Initialize SHA3-384 hash context.
 * @ingroup sha3
 *
 * @param[out] hash SHA3-384 hash context.
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
 */
_Bool sha3_384_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Finalize SHA3-384 hash context and write 48 bytes of output to
 * destination buffer `dst`.
 * @ingroup sha3
 *
 * @param[in,out] hash SHA3-384 hash context.
 * @param[out] dst Destination buffer.  Must be at least 48 bytes in length.
 */
void sha3_384_final(sha3_t *hash, uint8_t dst[48]);

/**
 * @brief Calculate SHA3-512 hash of input data.
 * @ingroup sha3
 *
 * Hash `len` bytes of input data from source buffer `src` with SHA3-512
 * (FIPS 202, section 6.1), then write 64 bytes of output to destination
 * buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 * @param[out] dst Destination array.  Must be at least 64 bytes in length.
 */
void sha3_512(const uint8_t *src, size_t len, uint8_t dst[static 64]);

/**
 * @brief Initialize SHA3-512 hash context.
 * @ingroup sha3
 *
 * @param[out] hash SHA3-512 hash context.
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
 */
_Bool sha3_512_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Finalize SHA3-512 hash context and write 64 bytes of output to
 * destination buffer `dst`.
 * @ingroup sha3
 *
 * @param[in,out] hash SHA3-512 hash context.
 * @param[out] dst Destination buffer.  Must be at least 64 bytes in length.
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
 * Calculate HMAC-SHA3-224 (FIPS 202, Section 7) of key in buffer `k` of
 * length `k_len` and input message in buffer `m` of length `m_len`
 * bytes and write 28 bytes of output to destination buffer `dst`.
 *
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 * @param[in] m Input message.
 * @param[in] m_len Input message length, in bytes.
 * @param[out] dst Destination array.  Must be at least 28 bytes in length.
 */
void hmac_sha3_224(const uint8_t *k, const size_t k_len, const uint8_t *m, const size_t m_len, uint8_t dst[28]);

/**
 * @brief Calculate HMAC-SHA3-256 given key and data.
 * @ingroup hmac
 *
 * Calculate HMAC-SHA3-256 (FIPS 202, Section 7) of key in buffer `k` of
 * length `k_len` and input message in buffer `m` of length `m_len`
 * bytes and write 32 bytes of output to destination buffer `dst`.
 *
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 * @param[in] m Input message.
 * @param[in] m_len Input message length, in bytes.
 * @param[out] dst Destination array.  Must be at least 32 bytes in length.
 */
void hmac_sha3_256(const uint8_t *k, const size_t k_len, const uint8_t *m, const size_t m_len, uint8_t dst[32]);

/**
 * Calculate HMAC-SHA3-384 of given key and data.
 * @ingroup hmac
 *
 * Calculate HMAC-SHA3-384 (FIPS 202, Section 7) of key in buffer `k` of
 * length `k_len` and input message in buffer `m` of length `m_len`
 * bytes and write 48 bytes of output to destination buffer `dst`.
 *
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 * @param[in] m Input message.
 * @param[in] m_len Input message length, in bytes.
 * @param[out] dst Destination array.  Must be at least 48 bytes in length.
 */
void hmac_sha3_384(const uint8_t *k, const size_t k_len, const uint8_t *m, const size_t m_len, uint8_t dst[48]);

/**
 * @brief Calculate HMAC-SHA3-512 of given key and data.
 * @ingroup hmac
 *
 * Calculate HMAC-SHA3-512 (FIPS 202, Section 7) of key in buffer `k` of
 * length `k_len` and input message in buffer `m` of length `m_len`
 * bytes and write 64 bytes of output to destination buffer `dst`.
 *
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 * @param[in] m Input message.
 * @param[in] m_len Input message length, in bytes.
 * @param[out] dst Destination array.  Must be at least 64 bytes in length.
 */
void hmac_sha3_512(const uint8_t *k, const size_t k_len, const uint8_t *m, const size_t m_len, uint8_t dst[64]);

/**
 * @brief HMAC-SHA3 (Hash-based Message Authentication Code) context.
 * @ingroup hmac
 */
typedef struct {
  sha3_t inner, /**< Inner hash context (private) */
         outer; /**< Outer hash context (private) */
  _Bool finalized; /**< Is this context finalized (private) */
} hmac_sha3_t;

/**
 * @brief Initialize HMAC-SHA3-224 (FIPS 202, Section 7) context.
 * @ingroup hmac
 *
 * @param[out] hmac HMAC-SHA3-224 context.
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 */
void hmac_sha3_224_init(hmac_sha3_t *hmac, const uint8_t *k, const size_t k_len);

/**
 * @brief Absorb data into HMAC-SHA3-224 context.
 * @ingroup hmac
 *
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-224
 * context `hmac`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] hmac HMAC-SHA3-224 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool hmac_sha3_224_absorb(hmac_sha3_t *hmac, const uint8_t *src, const size_t len);

/**
 * @brief Finalize HMAC-SHA3-224 hash context and write 28 bytes of
 * output to destination buffer `dst`.
 * @ingroup hmac
 *
 * @param[in,out] hmac HMAC-SHA3-224 hash context.
 * @param[out] dst Destination buffer.  Must be at least 28 bytes in length.
 */
void hmac_sha3_224_final(hmac_sha3_t *hmac, uint8_t dst[28]);

/**
 * @brief Initialize HMAC-SHA3-256 (FIPS 202, Section 7) context.
 * @ingroup hmac
 *
 * @param[out] hmac HMAC-SHA3-256 context.
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 */
void hmac_sha3_256_init(hmac_sha3_t *hmac, const uint8_t *k, const size_t k_len);

/**
 * @brief Absorb data into HMAC-SHA3-256 context.
 * @ingroup hmac
 *
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-256
 * context `hmac`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] hmac HMAC-SHA3-256 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool hmac_sha3_256_absorb(hmac_sha3_t *hmac, const uint8_t *src, const size_t len);

/**
 * @brief Finalize HMAC-SHA3-256 hash context and write 32 bytes of
 * output to destination buffer `dst`.
 * @ingroup hmac
 *
 * @param[in,out] hmac HMAC-SHA3-256 hash context.
 * @param[out] dst Destination buffer.  Must be at least 32 bytes in length.
 */
void hmac_sha3_256_final(hmac_sha3_t *hmac, uint8_t dst[32]);

/**
 * @brief Initialize HMAC-SHA3-384 (FIPS 202, Section 7) context.
 * @ingroup hmac
 *
 * @param[out] hmac HMAC-SHA3-384 context.
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 */
void hmac_sha3_384_init(hmac_sha3_t *hmac, const uint8_t *k, const size_t k_len);

/**
 * @brief Absorb data into HMAC-SHA3-384 context.
 * @ingroup hmac
 *
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-384
 * context `hmac`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] hmac HMAC-SHA3-384 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool hmac_sha3_384_absorb(hmac_sha3_t *hmac, const uint8_t *src, const size_t len);

/**
 * @brief Finalize HMAC-SHA3-384 hash context and write 48 bytes of
 * output to destination buffer `dst`.
 * @ingroup hmac
 *
 * @param[in,out] hmac HMAC-SHA3-384 hash context.
 * @param[out] dst Destination buffer.  Must be at least 48 bytes in length.
 */
void hmac_sha3_384_final(hmac_sha3_t *hmac, uint8_t dst[48]);

/**
 * @brief Initialize HMAC-SHA3-512 (FIPS 202, Section 7) context.
 * @ingroup hmac
 *
 * @param[out] hmac HMAC-SHA3-512 context.
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 */
void hmac_sha3_512_init(hmac_sha3_t *hmac, const uint8_t *k, const size_t k_len);

/**
 * @brief Absorb data into HMAC-SHA3-512 context.
 * @ingroup hmac
 *
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-512
 * context `hmac`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] hmac HMAC-SHA3-512 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool hmac_sha3_512_absorb(hmac_sha3_t *hmac, const uint8_t *src, const size_t len);

/**
 * @brief Finalize HMAC-SHA3-512 hash context and write 64 bytes of
 * output to destination buffer `dst`.
 * @ingroup hmac
 *
 * @param[in,out] hmac HMAC-SHA3-512 hash context.
 * @param[out] dst Destination buffer.  Must be at least 64 bytes in length.
 */
void hmac_sha3_512_final(hmac_sha3_t *hmac, uint8_t dst[64]);

/**
 * @defgroup shake SHAKE
 *
 * @brief [SHA-3][] [XOFs][xof] with both fixed-length output and
 * arbitrary-length output, as defined in section 6.2 of [FIPS 202][].
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
 * Hash input message in buffer `m` of length `m_len` bytes with
 * SHAKE128 (FIPS 202, section 6.2) and write 16 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in] m Input message.
 * @param[in] m_len Input message length, in bytes.
 * @param[out] dst Destination array.  Must be at least 16 bytes in length.
 */
void shake128(const uint8_t *m, size_t m_len, uint8_t dst[static 16]);

/**
 * @brief Hash data with SHAKE256.
 * @ingroup shake
 *
 * Hash input message in buffer `m` of length `m_len` bytes with
 * SHAKE256 (FIPS 202, section 6.2) and write the result to output
 * buffer `dst`.
 *
 * @param[in] m Input message.
 * @param[in] m_len Input message length, in bytes.
 * @param[out] dst Destination array.  Must be at least 16 bytes in length.
 */
void shake256(const uint8_t *m, size_t m_len, uint8_t dst[static 32]);

/**
 * @brief Initialize SHAKE128 extendable-output function (XOF) context.
 * @ingroup shake
 *
 * @param[out] xof SHAKE128 XOF context.
 */
void shake128_xof_init(sha3_xof_t * const xof);

/**
 * @brief Absorb data into SHAKE128 XOF context.
 * @ingroup shake
 *
 * Absorb input data in `m` of length `len` bytes into SHAKE128 XOF
 * context `xof`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] xof SHAKE128 XOF context.
 * @param[in] m Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool shake128_xof_absorb(sha3_xof_t *xof, const uint8_t *m, const size_t len);

/**
 * @brief Squeeze bytes from SHAKE128 XOF context.
 * @ingroup shake
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * SHAKE128 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in,out] xof SHAKE128 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void shake128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb data into SHAKE128 XOF, then squeeze bytes out.
 * @ingroup shake
 *
 * Absorb data in buffer `src` of length `src_len` bytes into SHAKE128
 * XOF context, then squeeze `dst_len` bytes of output into destination
 * buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void shake128_xof_once(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize SHAKE256 extendable-output function (XOF) context.
 * @ingroup shake
 *
 * @param[out] xof SHAKE256 XOF context.
 */
void shake256_xof_init(sha3_xof_t *xof);

/**
 * @brief Absorb data into SHAKE256 XOF context.
 * @ingroup shake
 *
 * Absorb input data in `m` of length `len` bytes into SHAKE256 XOF
 * context `xof`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in,out] xof SHAKE256 XOF context.
 * @param[in] m Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool shake256_xof_absorb(sha3_xof_t *xof, const uint8_t *m, const size_t len);

/**
 * @brief Squeeze bytes from SHAKE256 XOF context.
 * @ingroup shake
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * SHAKE256 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in,out] xof SHAKE256 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void shake256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb data into SHAKE256 XOF, then squeeze bytes out.
 * @ingroup shake
 *
 * Absorb data in buffer `src` of length `src_len` bytes into SHAKE256
 * XOF context, then squeeze `dst_len` bytes of output into destination
 * buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void shake256_xof_once(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @defgroup cshake cSHAKE
 *
 * @brief Fixed-length and [XOF][] variants of the customizable-SHAKE
 * primitive, as defined in section 3 of [SP 800-185][800-185].
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
 * section 3 of NIST SP 800-185) context with customization parameters
 * `params`, absorb data in buffer `src` of length `src_len` bytes into
 * internal context, then squeeze `dst_len` bytes of output into
 * destination buffer `dst`.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in] params cSHAKE customization parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void cshake128(const cshake_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize cSHAKE256, absorb data, then squeeze bytes out.
 * @ingroup cshake
 *
 * Initialize internal cSHAKE256 (customizable SHAKE256, as defined in
 * section 3 of NIST SP 800-185) context with customization parameters
 * `params`, absorb data in buffer `src` of length `src_len` bytes into
 * internal context, then squeeze `dst_len` bytes of output into
 * destination buffer `dst`.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in] params cSHAKE customization parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void cshake256(const cshake_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize cSHAKE128 XOF context.
 * @ingroup cshake
 *
 * Initialize cSHAKE128 (customizable SHAKE128, as defined in section 3 of
 * NIST SP 800-185) XOF context with customization parameters `params`.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[out] xof cSHAKE128 context.
 * @param[in] params cSHAKE128 customization parameters.
 */
void cshake128_xof_init(sha3_xof_t *xof, const cshake_params_t params);

/**
 * @brief Absorb data into cSHAKE128 XOF context.
 * @ingroup cshake
 *
 * Absorb data in buffer `src` of length `len` bytes into cSHAKE128 XOF
 * context `xof`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in,out] xof cSHAKE128 context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool cshake128_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from cSHAKE128 XOF context.
 * @ingroup cshake
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * cSHAKE128 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in,out] xof cSHAKE128 context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void cshake128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Initialize cSHAKE256 XOF context.
 * @ingroup cshake
 *
 * Initialize cSHAKE256 (customizable SHAKE256, as defined in section 3 of
 * NIST SP 800-185) XOF context with customization parameters `params`.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @ingroup cshake
 *
 * @param[out] xof cSHAKE256 context.
 * @param[in] params cSHAKE256 customization parameters.
 */
void cshake256_xof_init(sha3_xof_t *xof, const cshake_params_t params);

/**
 * @brief Absorb data into cSHAKE256 XOF context.
 * @ingroup cshake
 *
 * Absorb data in buffer `src` of length `len` bytes into cSHAKE256 XOF
 * context `xof`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in,out] xof cSHAKE256 context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool cshake256_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from cSHAKE256 XOF context.
 * @ingroup cshake
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * cSHAKE256 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in,out] xof cSHAKE256 context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
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
 * defined in section 4 of NIST SP 800-185) context with configuration
 * parameters `params`, absorb data in buffer `src` of length `src_len`
 * bytes into internal context, then squeeze `dst_len` bytes of output
 * into destination buffer `dst`.
 *
 * @param[in] params KMAC configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void kmac128(const kmac_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb data into KMAC256, then squeeze bytes out.
 * @ingroup kmac
 *
 * Initialize internal KMAC256 (Keccak Message Authentication Code, as
 * defined in section 4 of NIST SP 800-185) XOF context with
 * configuration parameters `params`, absorb data in buffer `src` of
 * length `src_len` bytes into internal context, then squeeze `dst_len`
 * bytes of output into destination buffer `dst`.
 *
 * @param[in] params KMAC configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void kmac256(const kmac_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize KMAC128 XOF context.
 * @ingroup kmac
 *
 * Initialize KMAC128 XOF (Keccak Message Authentication Code eXtendable
 * Output Function, as defined in section 4.3.1 of NIST SP 800-185)
 * context with configuration parameters `params`.
 *
 * Note: KMAC128 and KMAC128 XOF produce different output, because
 * KMAC128 encodes the fixed output size as part of the input while
 * KMAC128 XOF does not.  See section 4.3.1 of NIST SP 800-185 for
 * details.
 *
 * @param[out] xof KMAC128 XOF context.
 * @param[in] params KMAC configuration parameters.
 */
void kmac128_xof_init(sha3_xof_t *xof, const kmac_params_t params);

/**
 * @brief Absorb data into KMAC128 XOF context.
 * @ingroup kmac
 *
 * Absorb data in buffer `src` of length `len` bytes into KMAC128 XOF
 * context.  Can be called iteratively to absorb input data in chunks.
 *
 * @param[in,out] xof KMAC128 XOF context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool kmac128_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze data from KMAC128 XOF context.
 * @ingroup kmac
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * KMAC128 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: KMAC128 and KMAC128 XOF produce different output, because
 * KMAC128 encodes the fixed output size as part of the input while
 * KMAC128 XOF does not.  See section 4.3.1 of NIST SP 800-185 for
 * details.
 *
 * @param[in,out] xof KMAC128 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void kmac128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into KMAC128 XOF context, then squeeze bytes out.
 * @ingroup kmac
 *
 * Initialize internal KMAC128 XOF (Keccak Message Authentication Code
 * eXtendable Output Function, as defined in section 4 of NIST SP
 * 800-185) context with configuration parameters `params`, absorb data
 * in buffer `src` of length `src_len` bytes into internal context, then
 * squeeze `dst_len` bytes of output into destination buffer `dst`.
 *
 * Note: KMAC128 and KMAC128 XOF produce different output, because
 * KMAC128 encodes the fixed output size as part of the input while
 * KMAC128 XOF does not.  See section 4.3.1 of NIST SP 800-185 for
 * details.
 *
 * @param[in] params KMAC configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void kmac128_xof_once(const kmac_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize KMAC256 XOF context.
 * @ingroup kmac
 *
 * Initialize KMAC256 XOF (Keccak Message Authentication Code eXtendable
 * Output Function, as defined in section 4.3.1 of NIST SP 800-185)
 * context with configuration parameters `params`.
 *
 * Note: KMAC256 and KMAC256 XOF produce different output, because
 * KMAC256 encodes the fixed output size as part of the input while
 * KMAC256 XOF does not.  See section 4.3.1 of NIST SP 800-185 for
 * details.
 *
 * @param[out] xof KMAC256 XOF context.
 * @param[in] params KMAC configuration parameters.
 */
void kmac256_xof_init(sha3_xof_t *xof, const kmac_params_t params);

/**
 * @brief Absorb data into KMAC256 XOF context.
 * @ingroup kmac
 *
 * Absorb data in buffer `src` of length `len` bytes into KMAC256 XOF
 * context.  Can be called iteratively to absorb input data in chunks.
 *
 * @param[in,out] xof KMAC256 XOF context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool kmac256_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze data from KMAC256 XOF context.
 * @ingroup kmac
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * KMAC256 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: KMAC256 and KMAC256 XOF produce different output, because
 * KMAC256 encodes the fixed output size as part of the input while
 * KMAC256 XOF does not.  See section 4.3.1 of NIST SP 800-185 for
 * details.
 *
 * @ingroup kmac
 *
 * @param[in,out] xof KMAC256 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void kmac256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into KMAC256 XOF context, then squeeze bytes out.
 * @ingroup kmac
 *
 * Initialize internal KMAC256 XOF (Keccak Message Authentication Code
 * eXtendable Output Function, as defined in section 4 of NIST SP
 * 800-185) context with configuration parameters `params`, absorb data
 * in buffer `src` of length `src_len` bytes into internal context, then
 * squeeze `dst_len` bytes of output into destination buffer `dst`.
 *
 * Note: KMAC256 and KMAC256 XOF produce different output, because
 * KMAC256 encodes the fixed output size as part of the input while
 * KMAC256 XOF does not.  See section 4.3.1 of NIST SP 800-185 for
 * details.
 *
 * @param[in] params KMAC configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
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
 * @brief TupleHash tuple element.
 * @ingroup tuplehash
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
 * @brief Absorb data into TupleHash128, then squeeze bytes out.
 * @ingroup tuplehash
 *
 * Initialize internal TupleHash128 (NIST SP 800-185, section 5) context
 * with configuration parameters `params`, then squeeze `dst_len` bytes
 * of output from internal context into destination buffer `dst`.
 *
 * @param[in] params TupleHash128 configuration parameters.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void tuplehash128(const tuplehash_params_t params, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb data into TupleHash256, then squeeze bytes out.
 * @ingroup tuplehash
 *
 * Initialize internal TupleHash256 (NIST SP 800-185, section 5) context
 * with configuration parameters `params`, then squeeze `dst_len` bytes
 * of output from internal context into destination buffer `dst`.
 *
 * @ingroup tuplehash
 *
 * @param[in] params TupleHash256 configuration parameters.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void tuplehash256(const tuplehash_params_t params, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize a TupleHash128 XOF context.
 * @ingroup tuplehash
 *
 * Initialize TupleHash128 XOF (TupleHash eXtendable Output Function, as
 * defined in section 5.3.1 of NIST SP 800-185) context with
 * configuration parameters `params`.
 *
 * Note: TupleHash128 and TupleHash128 XOF produce different output,
 * because TupleHash128 encodes the fixed output size as part of the
 * input while TupleHash128 XOF does not.  See section 5.3.1 of NIST SP
 * 800-185 for details.
 *
 * @param[out] xof TupleHash128 XOF context.
 * @param[in] params TupleHash configuration parameters.
 */
void tuplehash128_xof_init(sha3_xof_t *xof, const tuplehash_params_t params);

/**
 * @brief Squeeze data from TupleHash128 XOF context.
 * @ingroup tuplehash
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * TupleHash128 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: TupleHash128 and TupleHash128 XOF produce different output,
 * because TupleHash128 encodes the fixed output size as part of the
 * input while TupleHash128 XOF does not.  See section 5.3.1 of NIST SP
 * 800-185 for details.
 *
 * @param[in,out] xof TupleHash128 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void tuplehash128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into TupleHash128 XOF, then squeeze bytes out.
 * @ingroup tuplehash
 *
 * Initialize internal TupleHash128 XOF (TupleHash eXtendable Output
 * Function, as defined in section 5 of NIST SP 800-185) context with
 * configuration parameters `params`, then squeeze `dst_len` bytes of
 * output into destination buffer `dst`.
 *
 * Note: TupleHash128 and TupleHash128 XOF produce different output,
 * because TupleHash128 encodes the fixed output size as part of the
 * input while TupleHash128 XOF does not.  See section 5.3.1 of NIST SP
 * 800-185 for details.
 *
 * @param[in] params TupleHash128 configuration parameters.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void tuplehash128_xof_once(const tuplehash_params_t params, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize a TupleHash256 XOF context.
 * @ingroup tuplehash
 *
 * Initialize TupleHash256 XOF (TupleHash eXtendable Output Function, as
 * defined in section 5.3.1 of NIST SP 800-185) context with
 * configuration parameters `params`.
 *
 * Note: TupleHash256 and TupleHash256 XOF produce different output,
 * because TupleHash256 encodes the fixed output size as part of the
 * input while TupleHash256 XOF does not.  See section 5.3.1 of NIST SP
 * 800-185 for details.
 *
 * @param[out] xof TupleHash256 XOF context.
 * @param[in] params TupleHash configuration parameters.
 */
void tuplehash256_xof_init(sha3_xof_t *xof, const tuplehash_params_t params);

/**
 * @brief Squeeze bytes from a TupleHash256 XOF context.
 * @ingroup tuplehash
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * TupleHash256 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: TupleHash256 and TupleHash256 XOF produce different output,
 * because TupleHash256 encodes the fixed output size as part of the
 * input while TupleHash256 XOF does not.  See section 5.3.1 of NIST SP
 * 800-185 for details.
 *
 * @param[in,out] xof TupleHash256 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void tuplehash256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb data into TupleHash256 XOF, then squeeze bytes out.
 * @ingroup tuplehash
 *
 * Initialize internal TupleHash256 XOF (TupleHash eXtendable Output
 * Function, as defined in section 5 of NIST SP 800-185) context with
 * configuration parameters `params`, then squeeze `dst_len` bytes of
 * output into destination buffer `dst`.
 *
 * Note: TupleHash256 and TupleHash256 XOF produce different output,
 * because TupleHash256 encodes the fixed output size as part of the
 * input while TupleHash256 XOF does not.  See section 5.3.1 of NIST SP
 * 800-185 for details.
 *
 * @param[in] params TupleHash256 configuration parameters.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
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
 * Initialize internal ParallelHash128 (NIST SP 800-185, section 6)
 * context with configuration parameters `params`, then squeeze
 * `dst_len` bytes of output from internal context into destination
 * buffer `dst`.
 *
 * Note: This implementation of ParallelHash128 is sequential, not
 * parallel.
 *
 * Note: This implementation of ParallelHash128 is sequential, not
 * @param[in] params ParallelHash128 configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void parallelhash128(const parallelhash_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb data into ParallelHash256, then squeeze bytes out.
 * @ingroup parallelhash
 *
 * Initialize internal ParallelHash256 (NIST SP 800-185, section 6)
 * context with configuration parameters `params`, then squeeze
 * `dst_len` bytes of output from internal context into destination
 * buffer `dst`.
 *
 * Note: This implementation of ParallelHash256 is sequential, not
 * parallel.
 *
 * @ingroup parallelhash
 *
 * @param[in] params ParallelHash256 configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void parallelhash256(const parallelhash_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize a ParallelHash128 XOF context.
 * @ingroup parallelhash
 *
 * Initialize ParallelHash128 XOF (ParallelHash eXtendable Output
 * Function, as defined in section 6.3.1 of NIST SP 800-185) context
 * with configuration parameters `params`.
 *
 * Note: ParallelHash128 and ParallelHash128 XOF produce different
 * output, because ParallelHash128 encodes the fixed output size as part
 * of the input while ParallelHash128 XOF does not.  See section 6.3.1
 * of NIST SP 800-185 for details.
 *
 * Note: This implementation of ParallelHash128 is sequential, not
 * parallel.
 *
 * @param[out] xof ParallelHash128 XOF context.
 * @param[in] params ParallelHash configuration parameters.
 */
void parallelhash128_xof_init(parallelhash_t *xof, const parallelhash_params_t params);

/**
 * @brief Absorb data into a ParallelHash128 XOF context.
 * @ingroup parallelhash
 *
 * Absorb data in buffer `src` of length `len` bytes into
 * ParallelHash128 XOF context.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * Note: This implementation of ParallelHash128 is sequential, not
 * parallel.
 *
 * @param[in,out] hash ParallelHash128 XOF context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 */
void parallelhash128_xof_absorb(parallelhash_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from a ParallelHash128 XOF context.
 * @ingroup parallelhash
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * ParallelHash128 XOF context `xof`.  Can be called iteratively to
 * squeeze output data in chunks.
 *
 * Note: ParallelHash128 and ParallelHash128 XOF produce different
 * output, because ParallelHash128 encodes the fixed output size as part
 * of the input while ParallelHash128 XOF does not.  See section 6.3.1
 * of NIST SP 800-185 for details.
 *
 * Note: This implementation of ParallelHash128 is sequential, not
 * parallel.
 *
 * @param[in,out] xof ParallelHash128 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void parallelhash128_xof_squeeze(parallelhash_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb bytes into ParallelHash128 XOF, then squeeze bytes out.
 * @ingroup parallelhash
 *
 * Initialize internal ParallelHash128 XOF (ParallelHash eXtendable
 * Output Function, as defined in section 6.3.1 of NIST SP 800-185)
 * context with configuration parameters `params`, absorb data in buffer
 * `src` of length `src_len` bytes into context, then squeeze `dst_len`
 * bytes of output into destination buffer `dst`.
 *
 * Note: ParallelHash128 and ParallelHash128 XOF produce different
 * output, because ParallelHash128 encodes the fixed output size as part
 * of the input while ParallelHash128 XOF does not.  See section 6.3.1
 * of NIST SP 800-185 for details.
 *
 * Note: This implementation of ParallelHash128 is sequential, not
 * parallel.
 *
 * @param[in] params ParallelHash configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void parallelhash128_xof_once(const parallelhash_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Initialize a ParallelHash256 XOF context.
 * @ingroup parallelhash
 *
 * Initialize ParallelHash256 XOF (ParallelHash eXtendable Output
 * Function, as defined in section 6.3.1 of NIST SP 800-185) context
 * with configuration parameters `params`.
 *
 * Note: ParallelHash256 and ParallelHash256 XOF produce different
 * output, because ParallelHash256 encodes the fixed output size as part
 * of the input while ParallelHash256 XOF does not.  See section 6.3.1
 * of NIST SP 800-185 for details.
 *
 * Note: This implementation of ParallelHash256 is sequential, not
 * parallel.
 *
 * @param[out] xof ParallelHash256 XOF context.
 * @param[in] params ParallelHash configuration parameters.
 */
void parallelhash256_xof_init(parallelhash_t *xof, const parallelhash_params_t params);

/**
 * @brief Absorb data into a ParallelHash256 XOF context.
 * @ingroup parallelhash
 *
 * Absorb data in buffer `src` of length `len` bytes into
 * ParallelHash256 XOF context.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * Note: This implementation of ParallelHash256 is sequential, not
 * parallel.
 *
 * @param[in,out] hash ParallelHash256 XOF context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 */
void parallelhash256_xof_absorb(parallelhash_t *hash, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from a ParallelHash256 XOF context.
 * @ingroup parallelhash
 *
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * ParallelHash256 XOF context `xof`.  Can be called iteratively to
 * squeeze output data in chunks.
 *
 * Note: ParallelHash256 and ParallelHash256 XOF produce different
 * output, because ParallelHash256 encodes the fixed output size as part
 * of the input while ParallelHash256 XOF does not.  See section 6.3.1
 * of NIST SP 800-185 for details.
 *
 * Note: This implementation of ParallelHash256 is sequential, not
 * parallel.
 *
 * @param[in,out] xof ParallelHash256 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void parallelhash256_xof_squeeze(parallelhash_t *xof, uint8_t *dst, const size_t len);

/**
 * @brief Absorb bytes into ParallelHash256 XOF, then squeeze bytes out.
 * @ingroup parallelhash
 *
 * Initialize internal ParallelHash256 XOF (ParallelHash eXtendable
 * Output Function, as defined in section 6.3.1 of NIST SP 800-185)
 * context with configuration parameters `params`, absorb `src_len`
 * bytes if input from source buffer `src`, then squeeze `dst_len`
 * bytes of output into destination buffer `dst`.
 *
 * Note: ParallelHash256 and ParallelHash256 XOF produce different
 * output, because ParallelHash256 encodes the fixed output size as part
 * of the input while ParallelHash256 XOF does not.  See section 6.3.1
 * of NIST SP 800-185 for details.
 *
 * Note: This implementation of ParallelHash256 is sequential, not
 * parallel.
 *
 * @param[in] params ParallelHash configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
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
 * @brief Absorb bytes into TurboSHAKE128, then squeeze bytes out.
 * @ingroup turboshake
 *
 * Initialize internal TurboSHAKE128 context, absorb `src_len` bytes of
 * input from source buffer `src`, then squeeze `dst_len` bytes of
 * output into destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void turboshake128(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb bytes into TurboSHAKE128 with custom padding byte, then squeeze bytes out.
 * @ingroup turboshake
 *
 * Initialize internal TurboSHAKE128 context with custom padding byte
 * `pad`, absorb `src_len` bytes of input from source buffer `src`, then
 * squeeze `dst_len` bytes of output into destination buffer `dst`.
 *
 * Note: The padding byte value must be in the range [0x01, 0x7F] and
 * can be used for domain separation.
 *
 * @ingroup turboshake
 *
 * @param[in] pad Padding byte.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void turboshake128_custom(const uint8_t pad, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb bytes into TurboSHAKE256, then squeeze bytes out.
 * @ingroup turboshake
 *
 * Initialize internal TurboSHAKE256 context, absorb `src_len` bytes of
 * input from source buffer `src`, then squeeze `dst_len` bytes of
 * output into destination buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void turboshake256(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief Absorb bytes into TurboSHAKE256 with custom padding byte, then squeeze bytes out.
 * @ingroup turboshake
 *
 * Initialize internal TurboSHAKE256 context with custom padding byte
 * `pad`, absorb `src_len` bytes of input from source buffer `src`, then
 * squeeze `dst_len` bytes of output into destination buffer `dst`.
 *
 * Note: The padding byte value must be in the range [0x01, 0x7F] and
 * can be used for domain separation.
 *
 * @param[in] pad Padding byte.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void turboshake256_custom(const uint8_t pad, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * @brief TurboShake XOF context.
 * @ingroup turboshake
 */
typedef struct {
  sha3_xof_t xof; /**< XOF context (private) */
  uint8_t pad; /**< Padding byte (private) */
} turboshake_t;

/**
 * @brief Initialize TurboSHAKE128 context.
 * @ingroup turboshake
 *
 * @param[out] ts TurboSHAKE128 context.
 */
void turboshake128_init(turboshake_t *ts);

/**
 * @brief Initialize TurboSHAKE128 context with custom padding byte.
 * @ingroup turboshake
 *
 * Initialize TurboSHAKE128 context with custom padding byte.  The
 * custom padding byte can be used as a domain separator and must be in
 * the range [0x01, 0x7f].
 *
 * @param[out] ts TurboSHAKE128 context.
 * @param[in] pad Padding byte (used for domain separation).
 *
 * @return False if the padding byte is out of range and true otherwise.
 */
_Bool turboshake128_init_custom(turboshake_t *ts, const uint8_t pad);

/**
 * @brief Absorb data into TurboSHAKE128 context.
 * @ingroup turboshake
 *
 * Absorb `src_len` bytes of input from source buffer `src` into
 * TurboSHAKE128 context `ts`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in,out] ts TurboSHAKE128 context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool turboshake128_absorb(turboshake_t *ts, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from TurboSHAKE128 context.
 * @ingroup turboshake
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * TurboSHAKE128 context `ts`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in,out] ts TurboSHAKE128 context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void turboshake128_squeeze(turboshake_t *ts, uint8_t *dst, const size_t len);

/**
 * @brief Initialize TurboSHAKE256 context.
 * @ingroup turboshake
 *
 * @param[out] ts TurboSHAKE256 context.
 */
void turboshake256_init(turboshake_t *ts);

/**
 * @brief Initialize TurboSHAKE256 context with custom padding byte.
 * @ingroup turboshake
 *
 * Initialize TurboSHAKE256 context with custom padding byte.  The
 * custom padding byte can be used as a domain separator and must be in
 * the range [0x01, 0x7f].
 *
 * @param[out] ts TurboSHAKE256 context.
 * @param[in] pad Padding byte (used for domain separation).
 *
 * @return False if the padding byte is out of range and true otherwise.
 */
_Bool turboshake256_init_custom(turboshake_t *ts, const uint8_t pad);

/**
 * @brief Absorb data into TurboSHAKE256 context.
 * @ingroup turboshake
 *
 * Absorb `src_len` bytes of input from source buffer `src` into
 * TurboSHAKE256 context `ts`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in,out] ts TurboSHAKE256 context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool turboshake256_absorb(turboshake_t *ts, const uint8_t *src, const size_t len);

/**
 * @brief Squeeze bytes from TurboSHAKE256 context.
 * @ingroup turboshake
 *
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * TurboSHAKE256 context `ts`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in,out] ts TurboSHAKE256 context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
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
 * @brief KangarooTwelve context.
 * @ingroup k12
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
 * Note: This implementation of KangarooTwelve is sequential, not
 * parallel.
 *
 * @param[out] k12 KangarooTwelve context.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[in] custom Custom string buffer.
 * @param[in] custom_len Custom string length, in bytes.
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
 * Note: This implementation of KangarooTwelve is sequential, not
 * parallel.
 *
 * @param[in,out] k12 KangarooTwelve context.
 * @param[out] dst Destination buffer.
 * @param[in] dst_len Destination buffer length, in bytes.
 */
void k12_squeeze(k12_t *k12, uint8_t *dst, const size_t dst_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SHA3_H */
