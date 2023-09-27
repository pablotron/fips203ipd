/**
 * sha3
 * https://pablotron.org/sha3
 *
 * Copyright (c) 2023 Paul Duncan
 * SPDX-License-Identifier: MIT-0
 *
 * C11 implementations of the following SHA-3 algorithms:
 *
 * - SHA3-224
 * - SHA3-256
 * - SHA3-384
 * - SHA3-512
 * - HMAC-SHA3-224
 * - HMAC-SHA3-256
 * - HMAC-SHA3-384
 * - HMAC-SHA3-512
 * - SHAKE128 and SHAKE128-XOF
 * - SHAKE256 and SHAKE256-XOF
 * - cSHAKE128 and cSHAKE128-XOF
 * - cSHAKE256 and cSHAKE256-XOF
 * - KMAC128 and KMAC128-XOF
 * - KMAC256 and KMAC256-XOF
 * - TupleHash128 and TupleHash128-XOF
 * - TupleHash256 and TupleHash256-XOF
 * - ParallelHash128 and ParallelHash128-XOF
 * - ParallelHash256 and ParallelHash256-XOF
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

// Internal SHA-3 state.
typedef union {
  uint8_t u8[200];
  uint64_t u64[25];
} sha3_state_t;

// Iterative SHA-3 context (all members are private).
typedef struct {
  size_t num_bytes; // number of bytes absorbed
  sha3_state_t a; // internal state
  _Bool finalized; // mode (absorbing or finalized)
} sha3_t;

// Iterative XOF context (all members are private).
typedef struct {
  size_t num_bytes; // number of bytes absorbed
  sha3_state_t a; // internal state
  _Bool squeezing; // mode (absorbing or squeezing)
} sha3_xof_t;

/**
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
 * Initialize SHA3-224 hash context.
 *
 * @param[out] hash SHA3-224 hash context.
 */
void sha3_224_init(sha3_t *hash);

/**
 * Absorb `len` bytes of input data from source buffer `src` into
 * SHA3-224 hash context `hash`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in/out] hash SHA3-224 hash context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool sha3_224_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * Finalize SHA3-224 hash context and write 28 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in/out] hash SHA3-224 hash context.
 * @param[out] dst Destination buffer.  Must be at least 28 bytes in length.
 */
void sha3_224_final(sha3_t *hash, uint8_t dst[28]);

/**
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
 * Initialize SHA3-256 hash context.
 *
 * @param[out] hash SHA3-256 hash context.
 */
void sha3_256_init(sha3_t *hash);

/**
 * Absorb `len` bytes of input data from source buffer `src` into
 * SHA3-256 hash context `hash`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in/out] hash SHA3-256 hash context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool sha3_256_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * Finalize SHA3-256 hash context and write 32 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in/out] hash SHA3-256 hash context.
 * @param[out] dst Destination buffer.  Must be at least 32 bytes in length.
 */
void sha3_256_final(sha3_t *hash, uint8_t dst[32]);

/**
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
 * Initialize SHA3-384 hash context.
 *
 * @param[out] hash SHA3-384 hash context.
 */
void sha3_384_init(sha3_t *hash);

/**
 * Absorb `len` bytes of input data from source buffer `src` into
 * SHA3-384 hash context `hash`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in/out] hash SHA3-384 hash context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool sha3_384_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * Finalize SHA3-384 hash context and write 48 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in/out] hash SHA3-384 hash context.
 * @param[out] dst Destination buffer.  Must be at least 48 bytes in length.
 */
void sha3_384_final(sha3_t *hash, uint8_t dst[48]);

/**
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
 * Initialize SHA3-512 hash context.
 *
 * @param[out] hash SHA3-512 hash context.
 */
void sha3_512_init(sha3_t *hash);

/**
 * Absorb `len` bytes of input data from source buffer `src` into
 * SHA3-512 hash context `hash`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in/out] hash SHA3-512 hash context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool sha3_512_absorb(sha3_t *hash, const uint8_t *src, const size_t len);

/**
 * Finalize SHA3-512 hash context and write 64 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in/out] hash SHA3-512 hash context.
 * @param[out] dst Destination buffer.  Must be at least 64 bytes in length.
 */
void sha3_512_final(sha3_t *hash, uint8_t dst[64]);

/**
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

// HMAC-SHA3 (Hash-based Message Authentication Code) context.
typedef struct {
  sha3_t inner, outer;
  _Bool finalized;
} hmac_sha3_t;

/**
 * Initialize HMAC-SHA3-224 (FIPS 202, Section 7) context.
 *
 * @param[out] hmac HMAC-SHA3-224 context.
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 */
void hmac_sha3_224_init(hmac_sha3_t *hmac, const uint8_t *k, const size_t k_len);

/**
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-224
 * context `hmac`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in/out] hmac HMAC-SHA3-224 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool hmac_sha3_224_absorb(hmac_sha3_t *hmac, const uint8_t *src, const size_t len);

/**
 * Finalize HMAC-SHA3-224 hash context and write 28 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in/out] hmac HMAC-SHA3-224 hash context.
 * @param[out] dst Destination buffer.  Must be at least 28 bytes in length.
 */
void hmac_sha3_224_final(hmac_sha3_t *hmac, uint8_t dst[28]);

/**
 * Initialize HMAC-SHA3-256 (FIPS 202, Section 7) context.
 *
 * @param[out] hmac HMAC-SHA3-256 context.
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 */
void hmac_sha3_256_init(hmac_sha3_t *hmac, const uint8_t *k, const size_t k_len);

/**
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-256
 * context `hmac`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in/out] hmac HMAC-SHA3-256 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool hmac_sha3_256_absorb(hmac_sha3_t *hmac, const uint8_t *src, const size_t len);

/**
 * Finalize HMAC-SHA3-256 hash context and write 32 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in/out] hmac HMAC-SHA3-256 hash context.
 * @param[out] dst Destination buffer.  Must be at least 32 bytes in length.
 */
void hmac_sha3_256_final(hmac_sha3_t *hmac, uint8_t dst[32]);

/**
 * Initialize HMAC-SHA3-384 (FIPS 202, Section 7) context.
 *
 * @param[out] hmac HMAC-SHA3-384 context.
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 */
void hmac_sha3_384_init(hmac_sha3_t *hmac, const uint8_t *k, const size_t k_len);

/**
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-384
 * context `hmac`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in/out] hmac HMAC-SHA3-384 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool hmac_sha3_384_absorb(hmac_sha3_t *hmac, const uint8_t *src, const size_t len);

/**
 * Finalize HMAC-SHA3-384 hash context and write 48 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in/out] hmac HMAC-SHA3-384 hash context.
 * @param[out] dst Destination buffer.  Must be at least 48 bytes in length.
 */
void hmac_sha3_384_final(hmac_sha3_t *hmac, uint8_t dst[48]);

/**
 * Initialize HMAC-SHA3-512 (FIPS 202, Section 7) context.
 *
 * @param[out] hmac HMAC-SHA3-512 context.
 * @param[in] k Key.
 * @param[in] k_len Key length, in bytes.
 */
void hmac_sha3_512_init(hmac_sha3_t *hmac, const uint8_t *k, const size_t k_len);

/**
 * Absorb input data in `src` of length `len` bytes into HMAC-SHA3-512
 * context `hmac`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in/out] hmac HMAC-SHA3-512 context.
 * @param[in] src Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool hmac_sha3_512_absorb(hmac_sha3_t *hmac, const uint8_t *src, const size_t len);

/**
 * Finalize HMAC-SHA3-512 hash context and write 64 bytes of output to
 * destination buffer `dst`.
 *
 * @param[in/out] hmac HMAC-SHA3-512 hash context.
 * @param[out] dst Destination buffer.  Must be at least 64 bytes in length.
 */
void hmac_sha3_512_final(hmac_sha3_t *hmac, uint8_t dst[64]);

/**
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
 * Initialize SHAKE128 extendable-output function (XOF) context.
 *
 * @param[out] xof SHAKE128 XOF context.
 */
void shake128_xof_init(sha3_xof_t * const xof);

/**
 * Absorb input data in `m` of length `len` bytes into SHAKE128 XOF
 * context `xof`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in/out] xof SHAKE128 XOF context.
 * @param[in] m Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool shake128_xof_absorb(sha3_xof_t *xof, const uint8_t *m, const size_t len);

/**
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * SHAKE128 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in/out] xof SHAKE128 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void shake128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t dst_len);

/**
 * Absorb data in buffer `src` of length `src_len` bytes into SHAKE128
 * XOF context, then squeeze `dst_len` bytes of output into destination
 * buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void shake128_xof_once(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * Initialize SHAKE256 extendable-output function (XOF) context.
 *
 * @param[out] xof SHAKE256 XOF context.
 */
void shake256_xof_init(sha3_xof_t *xof);

/**
 * Absorb input data in `m` of length `len` bytes into SHAKE256 XOF
 * context `xof`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * @param[in/out] xof SHAKE256 XOF context.
 * @param[in] m Input data.
 * @param[in] len Input data length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool shake256_xof_absorb(sha3_xof_t *xof, const uint8_t *m, const size_t len);

/**
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * SHAKE256 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in/out] xof SHAKE256 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void shake256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t dst_len);

/**
 * Absorb data in buffer `src` of length `src_len` bytes into SHAKE256
 * XOF context, then squeeze `dst_len` bytes of output into destination
 * buffer `dst`.
 *
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void shake256_xof_once(const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

// cSHAKE parameters.
typedef struct {
  const uint8_t *name; // NIST function name
  const size_t name_len; // length of NIST function name, in bytes
  const uint8_t *custom; // customization string
  const size_t custom_len; // length of customization string, in bytes
} cshake_params_t;

/**
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
 * @param[in] len Destination buffer length, in bytes.
 */
void cshake128(const cshake_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
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
 * @param[in] len Destination buffer length, in bytes.
 */
void cshake256(const cshake_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
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
 * Absorb data in buffer `src` of length `len` bytes into cSHAKE128 XOF
 * context `xof`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in/out] xof cSHAKE128 context.
 * @param[in] msg Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool cshake128_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * cSHAKE128 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in/out] xof cSHAKE128 context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void cshake128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
 * Initialize cSHAKE256 (customizable SHAKE256, as defined in section 3 of
 * NIST SP 800-185) XOF context with customization parameters `params`.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[out] xof cSHAKE256 context.
 * @param[in] params cSHAKE256 customization parameters.
 */
void cshake256_xof_init(sha3_xof_t *xof, const cshake_params_t params);

/**
 * Absorb data in buffer `src` of length `len` bytes into cSHAKE256 XOF
 * context `xof`.  Can be called iteratively to absorb input data in
 * chunks.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in/out] xof cSHAKE256 context.
 * @param[in] msg Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool cshake256_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * cSHAKE256 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: cSHAKE is used to implement the hash and extendable output
 * functions (XOF) defined in NIST SP 800-185 and should generally not
 * be used directly.
 *
 * @param[in/out] xof cSHAKE256 context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void cshake256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

// KMAC configuration parameters (key and customization string).
typedef struct {
  const uint8_t *key; // key string
  const size_t key_len; // length of key string, in bytes
  const uint8_t *custom; // customization string
  const size_t custom_len; // length of customization string, in bytes
} kmac_params_t;

/**
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
 * @param[in] len Destination buffer length, in bytes.
 */
void kmac128(const kmac_params_t params, const uint8_t *msg, const size_t msg_len, uint8_t *dst, const size_t dst_len);

/**
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
 * @param[in] len Destination buffer length, in bytes.
 */
void kmac256(const kmac_params_t params, const uint8_t *msg, const size_t msg_len, uint8_t *dst, const size_t dst_len);

/**
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
 * Absorb data in buffer `src` of length `len` bytes into KMAC128 XOF
 * context.  Can be called iteratively to absorb input data in chunks.
 *
 * @param[in/out] xof KMAC128 XOF context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool kmac128_xof_absorb(sha3_xof_t *xof, const uint8_t *src, const size_t len);

/**
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * KMAC128 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: KMAC128 and KMAC128 XOF produce different output, because
 * KMAC128 encodes the fixed output size as part of the input while
 * KMAC128 XOF does not.  See section 4.3.1 of NIST SP 800-185 for
 * details.
 *
 * @param[in/out] xof KMAC128 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void kmac128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
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
 * @param[in] len Destination buffer length, in bytes.
 */
void kmac128_xof_once(const kmac_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
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
 * Absorb data in buffer `src` of length `len` bytes into KMAC256 XOF
 * context.  Can be called iteratively to absorb input data in chunks.
 *
 * @param[in/out] xof KMAC256 XOF context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been squeezed).
 */
_Bool kmac256_xof_absorb(sha3_xof_t *xof, const uint8_t *msg, const size_t len);

/**
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * KMAC256 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: KMAC256 and KMAC256 XOF produce different output, because
 * KMAC256 encodes the fixed output size as part of the input while
 * KMAC256 XOF does not.  See section 4.3.1 of NIST SP 800-185 for
 * details.
 *
 * @param[in/out] xof KMAC256 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void kmac256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
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
 * @param[in] len Destination buffer length, in bytes.
 */
void kmac256_xof_once(const kmac_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

// TupleHash tuple element.
typedef struct {
  const uint8_t *ptr; // pointer to byte string
  size_t len; // byte string length, in bytes.
} tuplehash_str_t;

// TupleHash configuration parameters.
typedef struct {
  const tuplehash_str_t *strs; // strings
  const size_t num_strs; // number of strings
  const uint8_t *custom; // customization string
  const size_t custom_len; // length of customization string, in bytes
} tuplehash_params_t;

/**
 * Initialize internal TupleHash128 (NIST SP 800-185, section 5) context
 * with configuration parameters `params`, then squeeze `dst_len` bytes
 * of output from internal context into destination buffer `dst`.
 *
 * @param[in] params TupleHash128 configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void tuplehash128(const tuplehash_params_t params, uint8_t *dst, const size_t dst_len);

/**
 * Initialize internal TupleHash256 (NIST SP 800-185, section 5) context
 * with configuration parameters `params`, then squeeze `dst_len` bytes
 * of output from internal context into destination buffer `dst`.
 *
 * @param[in] params TupleHash256 configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void tuplehash256(const tuplehash_params_t params, uint8_t *dst, const size_t dst_len);

/**
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
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * TupleHash128 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: TupleHash128 and TupleHash128 XOF produce different output,
 * because TupleHash128 encodes the fixed output size as part of the
 * input while TupleHash128 XOF does not.  See section 5.3.1 of NIST SP
 * 800-185 for details.
 *
 * @param[in/out] xof TupleHash128 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void tuplehash128_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
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
 * @param[in] len Destination buffer length, in bytes.
 */
void tuplehash128_xof_once(const tuplehash_params_t params, uint8_t *dst, const size_t dst_len);

/**
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
 * Squeeze `len` bytes of output into destination buffer `dst` from
 * TupleHash256 XOF context `xof`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: TupleHash256 and TupleHash256 XOF produce different output,
 * because TupleHash256 encodes the fixed output size as part of the
 * input while TupleHash256 XOF does not.  See section 5.3.1 of NIST SP
 * 800-185 for details.
 *
 * @param[in/out] xof TupleHash256 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void tuplehash256_xof_squeeze(sha3_xof_t *xof, uint8_t *dst, const size_t len);

/**
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

// ParallelHash configuration parameters.
typedef struct {
  const size_t block_len; // block size, in bytes
  const uint8_t *custom; // customization string
  const size_t custom_len; // length of customization string, in bytes
} parallelhash_params_t;

// ParallelHash context.
typedef struct {
  sha3_xof_t root_xof, // root xof
             curr_xof; // xof for current block (note: shake128, not cshake128)
  size_t ofs, // offset in current block, in bytes
         block_len, // block size, in bytes
         num_blocks; // total number of blocks
  _Bool squeezing; // current state
} parallelhash_t;

/**
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
 * @param[in] len Destination buffer length, in bytes.
 */
void parallelhash128(const parallelhash_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
 * Initialize internal ParallelHash256 (NIST SP 800-185, section 6)
 * context with configuration parameters `params`, then squeeze
 * `dst_len` bytes of output from internal context into destination
 * buffer `dst`.
 *
 * Note: This implementation of ParallelHash256 is sequential, not
 * parallel.
 *
 * @param[in] params ParallelHash256 configuration parameters.
 * @param[in] src Source buffer.
 * @param[in] src_len Source buffer length, in bytes.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void parallelhash256(const parallelhash_params_t params, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
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
void parallelhash128_xof_init(parallelhash_t *hash, const parallelhash_params_t params);

/**
 * Absorb data in buffer `src` of length `len` bytes into
 * ParallelHash128 XOF context.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * Note: This implementation of ParallelHash128 is sequential, not
 * parallel.
 *
 * @param[in/out] hash ParallelHash128 XOF context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 */
void parallelhash128_xof_absorb(parallelhash_t *hash, const uint8_t *src, const size_t len);

/**
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
 * @param[in/out] xof ParallelHash128 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void parallelhash128_xof_squeeze(parallelhash_t *hash, uint8_t *dst, const size_t len);

/**
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
void parallelhash256_xof_init(parallelhash_t *hash, const parallelhash_params_t params);

/**
 * Absorb data in buffer `src` of length `len` bytes into
 * ParallelHash256 XOF context.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * Note: This implementation of ParallelHash256 is sequential, not
 * parallel.
 *
 * @param[in/out] hash ParallelHash256 XOF context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 */
void parallelhash256_xof_absorb(parallelhash_t *hash, const uint8_t *src, const size_t len);

/**
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
 * @param[in/out] xof ParallelHash256 XOF context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void parallelhash256_xof_squeeze(parallelhash_t *hash, uint8_t *dst, const size_t len);

/**
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
 * Initialize internal TurboSHAKE128 context with custom padding byte
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
void turboshake128_custom(const uint8_t pad, const uint8_t *src, const size_t src_len, uint8_t *dst, const size_t dst_len);

/**
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

// TurboShake XOF context.
typedef struct {
  sha3_xof_t xof;
  uint8_t pad;
} turboshake_t;

/**
 * Initialize TurboSHAKE128 context.
 *
 * @param[out] ts TurboSHAKE128 context.
 */
void turboshake128_init(turboshake_t *ts);

/**
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
 * Absorb `src_len` bytes of input from source buffer `src` into
 * TurboSHAKE128 context `ts`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in/out] ts TurboSHAKE128 context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool turboshake128_absorb(turboshake_t *ts, const uint8_t *src, const size_t len);

/**
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * TurboSHAKE128 context `ts`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in/out] ts TurboSHAKE128 context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void turboshake128_squeeze(turboshake_t *ts, uint8_t *dst, const size_t len);

/**
 * Initialize TurboSHAKE256 context.
 *
 * @param[out] ts TurboSHAKE256 context.
 */
void turboshake256_init(turboshake_t *ts);

/**
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
 * Absorb `src_len` bytes of input from source buffer `src` into
 * TurboSHAKE256 context `ts`.  Can be called iteratively to absorb
 * input data in chunks.
 *
 * @param[in/out] ts TurboSHAKE256 context.
 * @param[in] src Source buffer.
 * @param[in] len Source buffer length, in bytes.
 *
 * @return True if data was absorbed, and false otherwise (e.g., if context has already been finalized).
 */
_Bool turboshake256_absorb(turboshake_t *ts, const uint8_t *src, const size_t len);

/**
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * TurboSHAKE128 context `ts`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * @param[in/out] ts TurboSHAKE128 context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void turboshake256_squeeze(turboshake_t *ts, uint8_t *dst, const size_t len);

// KangarooTwelve context
typedef struct {
  turboshake_t ts;
} k12_t;

/**
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
 * Squeeze `dst_len` bytes of output into destination buffer `dst` from
 * KangarooTwelve context `k12`.  Can be called iteratively to squeeze
 * output data in chunks.
 *
 * Note: This implementation of KangarooTwelve is sequential, not
 * parallel.
 *
 * @param[in/out] k12 KangarooTwelve context.
 * @param[out] dst Destination buffer.
 * @param[in] len Destination buffer length, in bytes.
 */
void k12_squeeze(k12_t *k12, uint8_t *dst, const size_t dst_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SHA3_H */
