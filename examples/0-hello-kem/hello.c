//
// hello.c: minimal example of a client and server generating a shared
// secret with KEM512.
//
// Build by typing `make`.
//
// Example:
//
//   > ./hello
//   client: keygen random (64 bytes) = 30c3e7dfac ... (omitted) ... fecd87f3f
//   client: generated encapsulation key `ek` and decapsulation key `dk`:
//   client: ek (800 bytes) = d0f3b03e67 ... (omitted) ... 2da8295829
//   client: dk (1632 bytes) = 4af498a252 ... (omitted) ... b434abe9e
//   client: sending encapsulation key `ek` to server
//
//   server: encaps random (32 bytes) = b0b41f41da8ed5ee232c9e5683e471cf47fa710db40877d9ade99d8215f5677b
//   server: generated secret `s_key` and ciphertext `ct`:
//   server: s_key (32 bytes) = 1c002c91184f5e79fe99276fc22d05fb8b6ccdbfa2b95fe30eee359243a62ed7
//   server: ct (768 bytes) = f3bcd0755 ... (omitted) ... f22d03a0c
//   server: sending ciphertext `ct` to client
//
//   client: used `dk` to decapsulate secret from `ct` into `c_key`:
//   client: c_key (32 bytes) = 1c002c91184f5e79fe99276fc22d05fb8b6ccdbfa2b95fe30eee359243a62ed7
//
//   SUCCESS! client secret `c_key` and server secret `s_key` match.
//

#include <stdio.h> // fputs()
#include <string.h> // memcmp()
#include "hex.h" // hex_write()
#include "rand-bytes.h" // rand_bytes()
#include "fips203ipd.h" // fips203ipd_*()

int main(void) {
  //
  // client: generate keypair
  //
  uint8_t ek[FIPS203IPD_KEM512_EK_SIZE] = { 0 }; // encapsulation key
  uint8_t dk[FIPS203IPD_KEM512_DK_SIZE] = { 0 }; // decapsulation key
  {
    // client: get 64 random bytes for keygen()
    uint8_t keygen_seed[64] = { 0 };
    rand_bytes(keygen_seed, sizeof(keygen_seed));

    fputs("client: keygen random (64 bytes) = ", stdout);
    hex_write(stdout, keygen_seed, sizeof(keygen_seed));
    fputs("\n", stdout);

    // client: generate encapsulation/decapsulation key pair
    fips203ipd_kem512_keygen(ek, dk, keygen_seed);
  }
  fputs("client: generated encapsulation key `ek` and decapsulation key `dk`:\n", stdout);
  printf("client: ek (%d bytes) = ", FIPS203IPD_KEM512_EK_SIZE);
  hex_write(stdout, ek, sizeof(ek));
  printf("\nclient: dk (%d bytes) = ", FIPS203IPD_KEM512_DK_SIZE);
  hex_write(stdout, dk, sizeof(dk));
  fputs("\n", stdout);

  // client send `ek` to server
  fputs("client: sending encapsulation key `ek` to server\n\n", stdout);

  //
  // server: generate shared secret and ciphertext
  //
  uint8_t s_key[32] = { 0 }; // shared secret
  uint8_t ct[FIPS203IPD_KEM512_CT_SIZE] = { 0 }; // ciphertext
  {
    // server: get 32 random bytes for encaps()
    uint8_t encaps_seed[32] = { 0 };
    rand_bytes(encaps_seed, sizeof(encaps_seed));

    fputs("server: encaps random (32 bytes) = ", stdout);
    hex_write(stdout, encaps_seed, sizeof(encaps_seed));
    fputs("\n", stdout);

    // server:
    // 1. get encapsulation key `ek` from client.
    // 2. generate random shared secret.
    // 3. use `ek` from step #1 to encapsulate the shared secret from step #2.
    // 3. store the shared secret in `s_key`.
    // 4. store the encapsulated shared secret (ciphertext) in `ct`.
    fips203ipd_kem512_encaps(s_key, ct, ek, encaps_seed);
  }

  fputs("server: generated secret `s_key` and ciphertext `ct`:\nserver: s_key (32 bytes) = ", stdout);
  hex_write(stdout, s_key, sizeof(s_key));
  printf("\nserver: ct (%d bytes) = ", FIPS203IPD_KEM512_CT_SIZE);
  hex_write(stdout, ct, sizeof(ct));
  fputs("\n", stdout);

  // server sends ciphertext `ct` to client
  fputs("server: sending ciphertext `ct` to client\n\n", stdout);

  //
  // client: decapsulate shared secret
  //

  // client:
  // 1. get ciphertext `ct` from server.
  // 2. use decapsultion key `dk` to decapsulate shared secret from `ct`.
  // 2. store shared secret in `c_key`.
  uint8_t c_key[32] = { 0 };
  fips203ipd_kem512_decaps(c_key, ct, dk);

  fputs("client: used `dk` to decapsulate secret from `ct` into `c_key`:\nclient: c_key (32 bytes) = ", stdout);
  hex_write(stdout, c_key, sizeof(c_key));
  fputs("\n\n", stdout);

  // check result
  if (!memcmp(c_key, s_key, sizeof(c_key))) {
    // success: client and server have the same shared secret
    fputs("SUCCESS! client secret `c_key` and server secret `s_key` match.\n", stdout);
    return 0;
  } else {
    // failure: client and server do not have the same shared secret
    fputs("FAILURE! client secret `c_key` and server secret `s_key` do not match.\n", stdout);
    return -1;
  }
}
