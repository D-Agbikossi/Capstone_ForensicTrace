/* integrity.c — SHA-256 sidecar for output JSON (GNU sha256sum format). */
#include "forensictrace.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

int ft_integrity_write(FTContext *c)
{
    FILE *in;
    unsigned char buf[8192];
    size_t n;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *mdctx;
    char sidecar[1200];
    char hex[65];
    int i;
    FILE *out;

    if (!c || !c->output_path[0]) {
        return -1;
    }

    in = fopen(c->output_path, "rb");
    if (!in) {
        fprintf(stderr, "[integrity] cannot open %s\n", c->output_path);
        return -1;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(in);
        fprintf(stderr, "[integrity] EVP_MD_CTX_new failed\n");
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(in);
        return -1;
    }

    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (EVP_DigestUpdate(mdctx, buf, n) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(in);
            return -1;
        }
    }
    fclose(in);

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    for (i = 0; i < (int)hash_len; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }
    hex[hash_len * 2] = '\0';

    snprintf(sidecar, sizeof(sidecar), "%s.sha256", c->output_path);
    out = fopen(sidecar, "w");
    if (!out) {
        fprintf(stderr, "[integrity] cannot write %s\n", sidecar);
        return -1;
    }
    fprintf(out, "%s  %s\n", hex, c->output_path);
    fclose(out);

    printf("[integrity] SHA-256: %s\n", hex);
    printf("[integrity] written to %s\n", sidecar);
    return 0;
}
