

# `libsodium` internals




## `crypto_secretbox_*` internals (XSalsa20 + Poly1305)

* https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox
* XSalsa20 -- https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xsalsa20
* Poly1305 -- https://libsodium.gitbook.io/doc/advanced/poly1305

* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_secretbox/crypto_secretbox.c#L48
````
crypto_secretbox(unsigned char *c, const unsigned char *m,
                 unsigned long long mlen, const unsigned char *n,
                 const unsigned char *k)
{
    crypto_secretbox_xsalsa20poly1305(c, m, mlen, n, k);
}
````

* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_secretbox/crypto_secretbox.c#L56
````
crypto_secretbox_open(unsigned char *m, const unsigned char *c,
                      unsigned long long clen, const unsigned char *n,
                      const unsigned char *k)
{
    crypto_secretbox_xsalsa20poly1305_open(m, c, clen, n, k);
}
````



## `crypto_sign_*` internals (Ed25519)

* https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures
* Ed25519 -- https://libsodium.gitbook.io/doc/advanced/point-arithmetic

* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_sign/crypto_sign.c#L54
````
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    crypto_sign_ed25519_keypair(pk, sk);
}
````

* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_sign/crypto_sign.c#L76
````
crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                     const unsigned char *m, unsigned long long mlen,
                     const unsigned char *sk)
{
    crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk);
}
````

* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_sign/crypto_sign.c#L84
````
crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *pk)
{
    crypto_sign_ed25519_verify_detached(sig, m, mlen, pk);
}
````



## `crypto_kx_*` (Curve25519)

* https://libsodium.gitbook.io/doc/advanced/scalar_multiplication
* Curve25519 -- https://libsodium.gitbook.io/doc/advanced/scalar_multiplication

* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_kx/crypto_kx.c#L23
````
crypto_kx_keypair(unsigned char pk[crypto_kx_PUBLICKEYBYTES],
                  unsigned char sk[crypto_kx_SECRETKEYBYTES])
{
    randombytes_buf(sk, crypto_kx_SECRETKEYBYTES);
    crypto_scalarmult_base(pk, sk);
}
````

* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_scalarmult/crypto_scalarmult.c#L11
````
crypto_scalarmult_base(unsigned char *q, const unsigned char *n)
{
    crypto_scalarmult_curve25519_base(q, n);
}
````

* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_kx/crypto_kx.c#L34
* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_kx/crypto_kx.c#L75
````
crypto_kx_client_session_keys(unsigned char rx[crypto_kx_SESSIONKEYBYTES],
                              unsigned char tx[crypto_kx_SESSIONKEYBYTES],
                              const unsigned char client_pk[crypto_kx_PUBLICKEYBYTES],
                              const unsigned char client_sk[crypto_kx_SECRETKEYBYTES],
                              const unsigned char server_pk[crypto_kx_PUBLICKEYBYTES])
{
    crypto_generichash_state h;
    unsigned char            q[crypto_scalarmult_BYTES];
    unsigned char            keys[2 * crypto_kx_SESSIONKEYBYTES];

    crypto_scalarmult(q, client_sk, server_pk);

    crypto_generichash_init(&h, NULL, 0U, sizeof keys);
    crypto_generichash_update(&h, q, crypto_scalarmult_BYTES);
    crypto_generichash_update(&h, client_pk, crypto_kx_PUBLICKEYBYTES);
    crypto_generichash_update(&h, server_pk, crypto_kx_PUBLICKEYBYTES);
    crypto_generichash_final(&h, keys, sizeof keys);

    for (i = 0; i < crypto_kx_SESSIONKEYBYTES; i++) {
        rx[i] = keys[i]; /* rx cannot be NULL */
        tx[i] = keys[i + crypto_kx_SESSIONKEYBYTES]; /* tx cannot be NULL */
    }
}
````

* https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_scalarmult/crypto_scalarmult.c#L17
````
crypto_scalarmult(unsigned char *q, const unsigned char *n,
                  const unsigned char *p)
{
    crypto_scalarmult_curve25519(q, n, p);
}
````

