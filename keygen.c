#include <stdio.h>
#include <stdlib.h>
#include <oqs/kem.h>
#include <oqs/sig.h>
#include <sys/stat.h>

void ensure_dir(const char *dir) {
    struct stat st = {0};
    if (stat(dir, &st) == -1) mkdir(dir, 0700);
}

int main() {
    ensure_dir("keys");

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    uint8_t kem_pk[OQS_KEM_kyber_1024_length_public_key];
    uint8_t kem_sk[OQS_KEM_kyber_1024_length_secret_key];
    OQS_KEM_keypair(kem, kem_pk, kem_sk);

    FILE *f = fopen("keys/kyber_pub.key", "wb");
    fwrite(kem_pk, 1, sizeof(kem_pk), f); fclose(f);
    f = fopen("keys/kyber_sec.key", "wb");
    fwrite(kem_sk, 1, sizeof(kem_sk), f); fclose(f);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    uint8_t sig_pk[OQS_SIG_dilithium_5_length_public_key];
    uint8_t sig_sk[OQS_SIG_dilithium_5_length_secret_key];
    OQS_SIG_keypair(sig, sig_pk, sig_sk);

    f = fopen("keys/dilithium_pub.key", "wb");
    fwrite(sig_pk, 1, sizeof(sig_pk), f); fclose(f);
    f = fopen("keys/dilithium_sec.key", "wb");
    fwrite(sig_sk, 1, sizeof(sig_sk), f); fclose(f);

    OQS_KEM_free(kem);
    OQS_SIG_free(sig);
    printf("Kunci tersimpan (format biner):\n- keys/kyber_pub.key\n- keys/kyber_sec.key\n- keys/dilithium_pub.key\n- keys/dilithium_sec.key\n");
    return 0;
}
