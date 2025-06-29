#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/kem.h>
#include <oqs/sig.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <arpa/inet.h>

#define MSG_MAX 4096

size_t load(const char *fname, uint8_t *buf, size_t maxlen) {
    FILE *f = fopen(fname, "rb");
    if (!f) exit(1);
    size_t n = fread(buf, 1, maxlen, f); fclose(f);
    return n;
}
void write_uint16(FILE *f, uint16_t n) { uint16_t be = htons(n); fwrite(&be, 1, 2, f);}
void write_uint32(FILE *f, uint32_t n) { uint32_t be = htonl(n); fwrite(&be, 1, 4, f);}
void hkdf(const uint8_t *input, size_t in_len, uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, input, in_len);
    EVP_PKEY_CTX_add1_hkdf_info(pctx, (uint8_t*)"pq", 2);
    size_t olen = out_len;
    EVP_PKEY_derive(pctx, out, &olen);
    EVP_PKEY_CTX_free(pctx);
}
int aes256gcm_encrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *plaintext, int plaintext_len, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext + ciphertext_len);
    ciphertext_len += 16;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int main() {
    char msg[MSG_MAX], filename[256];
    printf("Masukkan pesan > "); fgets(msg, sizeof(msg), stdin);
    size_t msg_len = strlen(msg);
    if (msg_len > 0 && msg[msg_len-1]=='\n') msg_len--;
    printf("Masukkan nama file (boleh dengan/tanpa .enc) > ");
    fgets(filename, sizeof(filename), stdin); filename[strcspn(filename, "\n")]=0;
    if (!strstr(filename, ".enc")) strcat(filename, ".enc");

    uint8_t kem_pk[OQS_KEM_kyber_1024_length_public_key];
    uint8_t sig_sk[OQS_SIG_dilithium_5_length_secret_key];
    load("keys/kyber_pub.key", kem_pk, sizeof(kem_pk));
    load("keys/dilithium_sec.key", sig_sk, sizeof(sig_sk));

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    uint8_t kem_ct[OQS_KEM_kyber_1024_length_ciphertext];
    uint8_t shared_secret[OQS_KEM_kyber_1024_length_shared_secret];
    OQS_KEM_encaps(kem, kem_ct, shared_secret, kem_pk);

    uint8_t aes_key[32];
    hkdf(shared_secret, sizeof(shared_secret), aes_key, 32);

    uint8_t iv[12]; RAND_bytes(iv, 12);
    uint8_t aes_ct[MSG_MAX+32];
    int ct_len = aes256gcm_encrypt(aes_key, iv, (uint8_t*)msg, msg_len, aes_ct);

    size_t payload_len = 12 + ct_len + sizeof(kem_ct);
    uint8_t *payload = malloc(payload_len);
    memcpy(payload, iv, 12);
    memcpy(payload+12, aes_ct, ct_len);
    memcpy(payload+12+ct_len, kem_ct, sizeof(kem_ct));

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    uint8_t signature[OQS_SIG_dilithium_5_length_signature]; size_t sig_len=0;
    OQS_SIG_sign(sig, signature, &sig_len, payload, payload_len, sig_sk);

    FILE *f = fopen(filename, "wb");
    write_uint16(f, 12); fwrite(iv,1,12,f);
    write_uint16(f, sizeof(kem_ct)); fwrite(kem_ct,1,sizeof(kem_ct),f);
    write_uint32(f, ct_len); fwrite(aes_ct,1,ct_len,f);
    write_uint16(f, sig_len); fwrite(signature,1,sig_len,f);
    fclose(f);

    free(payload);
    OQS_SIG_free(sig);
    OQS_KEM_free(kem);
    printf("Pesan terenkripsi & ditandatangani tersimpan di %s\n", filename);
    return 0;
}
