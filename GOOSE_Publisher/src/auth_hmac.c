#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

void hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t *prk, size_t prk_len)
{
    unsigned int L=0;
    const uint8_t zeros[32]={0};
    const uint8_t *s = (salt && salt_len) ? salt : zeros;
    size_t s_len = (salt && salt_len) ? salt_len : sizeof(zeros);
    HMAC(EVP_sha256(), s, (int)s_len, ikm, ikm_len, prk, &L);
    (void)prk_len;
}

void hkdf_sha256_expand(const uint8_t *prk, size_t prk_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len)
{
    (void)prk_len;
    uint8_t T[32]; size_t Tlen=0;
    uint8_t ctr=1;
    size_t out = 0;
    while (out < okm_len) {
        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, prk, 32, EVP_sha256(), NULL);
        if (Tlen) HMAC_Update(ctx, T, Tlen);
        if (info && info_len) HMAC_Update(ctx, info, info_len);
        HMAC_Update(ctx, &ctr, 1);
        unsigned int L=0; HMAC_Final(ctx, T, &L); HMAC_CTX_free(ctx);
        size_t copy = (okm_len - out > L) ? L : okm_len - out;
        memcpy(okm+out, T, copy); out += copy; Tlen = L; ctr++;
    }
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out32)
{
    unsigned int L=0;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out32, &L);
}
