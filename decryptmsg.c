#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/kem.h>
#include <oqs/sig.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <arpa/inet.h>

#define MSG_MAX 4096

size_t load(const char *fname, uint8_t *buf, size_t maxlen) {
    FILE *f = fopen(fname, "rb");
    if (!f) exit(1);
    size_t n = fread(buf, 1, maxlen, f); fclose(f); return n;
}
uint16_t read_uint16(FILE *f) { uint16_t n; if (fread(&n,1,2,f)!=2) exit(1); return ntohs(n);}
uint32_t read_uint32(FILE *f) { uint32_t n; if (fread(&n,1,4,f)!=4) exit(1); return ntohl(n);}
void hkdf(const uint8_t *input, size_t in_len, uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx); EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, input, in_len);
    EVP_PKEY_CTX_add1_hkdf_info(pctx, (uint8_t*)"pq", 2); size_t olen = out_len;
    EVP_PKEY_derive(pctx, out, &olen); EVP_PKEY_CTX_free(pctx);
}
int aes256gcm_decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *ciphertext, int ciphertext_len, uint8_t *plaintext) {
    if (ciphertext_len < 16) return -1;
    int ct_real_len = ciphertext_len-16, len=0, pt_len=0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_real_len); pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(ciphertext+ct_real_len));
    int ret = EVP_DecryptFinal_ex(ctx, plaintext+len, &len);
    pt_len = (ret > 0) ? (pt_len+len) : -1;
    EVP_CIPHER_CTX_free(ctx); return pt_len;
}

int main() {
    char filename[256];
    printf("Masukkan nama file (boleh dengan/tanpa .enc) > ");
    fgets(filename,sizeof(filename),stdin); filename[strcspn(filename,"\n")]=0;
    if (!strstr(filename, ".enc")) strcat(filename, ".enc");
    FILE *f = fopen(filename, "rb"); if (!f) return 1;

    uint16_t len_iv = read_uint16(f); uint8_t iv[32]; fread(iv,1,len_iv,f);
    uint16_t len_kem = read_uint16(f); uint8_t kem_ct[2048]; fread(kem_ct,1,len_kem,f);
    uint32_t len_aes = read_uint32(f); uint8_t aes_ct[MSG_MAX+64]; fread(aes_ct,1,len_aes,f);
    uint16_t len_sig = read_uint16(f); uint8_t signature[8192]; fread(signature,1,len_sig,f); fclose(f);

    size_t payload_len = len_iv + len_aes + len_kem;
    uint8_t *payload = malloc(payload_len);
    memcpy(payload, iv, len_iv); memcpy(payload+len_iv, aes_ct, len_aes); memcpy(payload+len_iv+len_aes, kem_ct, len_kem);

    uint8_t kem_sk[OQS_KEM_kyber_1024_length_secret_key];
    uint8_t sig_pk[OQS_SIG_dilithium_5_length_public_key];
    load("keys/kyber_sec.key", kem_sk, sizeof(kem_sk));
    load("keys/dilithium_pub.key", sig_pk, sizeof(sig_pk));

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    int verified = OQS_SIG_verify(sig, payload, payload_len, signature, len_sig, sig_pk);
    if (verified != 0) {
        printf("Signature verification failed!\n");
        free(payload); OQS_SIG_free(sig); return 1;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    uint8_t shared_secret[OQS_KEM_kyber_1024_length_shared_secret];
    OQS_KEM_decaps(kem, shared_secret, kem_ct, kem_sk);

    uint8_t aes_key[32]; hkdf(shared_secret, sizeof(shared_secret), aes_key, 32);
    uint8_t plaintext[MSG_MAX+1] = {0};
    int pt_len = aes256gcm_decrypt(aes_key, iv, aes_ct, len_aes, plaintext);
    if (pt_len < 0) printf("AES-GCM decryption failed!\n");
    else { plaintext[pt_len]=0; printf("Pesan terbuka: %s\n", plaintext); }

    free(payload); OQS_SIG_free(sig); OQS_KEM_free(kem);
    return 0;
}
