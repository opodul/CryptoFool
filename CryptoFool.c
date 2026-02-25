// compile with:   gcc -Wall -O2 CryptoFool.c -o CryptoFool -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

// --- Base64 helpers using OpenSSL ---

char *base64_encode(const unsigned char *in, int len) {
    int out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;
    int actual = EVP_EncodeBlock((unsigned char *)out, in, len);
    if (actual < 0) { free(out); return NULL; }
    out[actual] = '\0';
    return out;
}

unsigned char *base64_decode(const char *in, int *out_len) {
    int len = strlen(in);
    unsigned char *out = malloc(len); // base64 shrinks
    if (!out) return NULL;
    int actual = EVP_DecodeBlock(out, (const unsigned char *)in, len);
    if (actual < 0) { free(out); return NULL; }

    // Remove possible padding artifacts
    while (actual > 0 && in[len - 1] == '=') {
        actual--;
        len--;
    }
    *out_len = actual;
    return out;
}

// --- Key derivation: PBKDF2-HMAC-SHA256, 32 bytes ---

int derive_key(const char *password, const char *salt, int iterations,
               unsigned char key[32]) {
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                           (const unsigned char *)salt, strlen(salt),
                           iterations, EVP_sha256(), 32, key)) {
        return 0;
    }
    return 1;
}

// --- AES-GCM encrypt: IV(12) + CIPHERTEXT + TAG(16) ---

int aes_gcm_encrypt(const unsigned char *key,
                    const unsigned char *plaintext, int plaintext_len,
                    unsigned char **out, int *out_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, ciphertext_len;
    unsigned char iv[12];
    unsigned char tag[16];

    if (RAND_bytes(iv, sizeof(iv)) != 1) return 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto err;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto err;

    unsigned char *ciphertext = malloc(plaintext_len + 16);
    if (!ciphertext) goto err;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        free(ciphertext);
        goto err;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        free(ciphertext);
        goto err;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        free(ciphertext);
        goto err;
    }

    *out_len = 12 + ciphertext_len + 16;
    *out = malloc(*out_len);
    if (!*out) {
        free(ciphertext);
        goto err;
    }

    memcpy(*out, iv, 12);
    memcpy(*out + 12, ciphertext, ciphertext_len);
    memcpy(*out + 12 + ciphertext_len, tag, 16);

    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// --- AES-GCM decrypt: expects IV(12) + CIPHERTEXT + TAG(16) ---

int aes_gcm_decrypt(const unsigned char *key,
                    const unsigned char *in, int in_len,
                    unsigned char **plaintext, int *plaintext_len) {
    if (in_len < 12 + 16) return 0;

    const unsigned char *iv = in;
    const unsigned char *ciphertext = in + 12;
    int ciphertext_len = in_len - 12 - 16;
    const unsigned char *tag = in + 12 + ciphertext_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto err;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto err;

    *plaintext = malloc(ciphertext_len);
    if (!*plaintext) goto err;

    int len, p_len;
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1)
        goto err2;
    p_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1)
        goto err2;

    if (EVP_DecryptFinal_ex(ctx, *plaintext + p_len, &len) != 1)
        goto err2;
    p_len += len;

    *plaintext_len = p_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;

err2:
    free(*plaintext);
err:
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// --- Format helpers: Hint$Salt!Iter#Base64(...) ---

char *encrypt_string(const char *hint, const char *salt, int iterations,
                     const char *plaintext, const char *password) {
    unsigned char key[32];
    if (!derive_key(password, salt, iterations, key)) {
        fprintf(stderr, "Key derivation failed\n");
        return NULL;
    }

    unsigned char *combined = NULL;
    int combined_len = 0;
    if (!aes_gcm_encrypt(key, (const unsigned char *)plaintext,
                         (int)strlen(plaintext), &combined, &combined_len)) {
        fprintf(stderr, "Encryption failed\n");
        return NULL;
    }

    char *b64 = base64_encode(combined, combined_len);
    free(combined);
    if (!b64) {
        fprintf(stderr, "Base64 encode failed\n");
        return NULL;
    }

    // Build final string
    size_t out_len = strlen(hint) + 1 + strlen(salt) + 1 + 10 + 1 + strlen(b64) + 1;
    char *out = malloc(out_len);
    if (!out) { free(b64); return NULL; }

    snprintf(out, out_len, "%s$%s!%d#%s", hint, salt, iterations, b64);
    free(b64);
    return out;
}

char *decrypt_string(const char *full_string, const char *password) {
    char *copy = strdup(full_string); // duplicate the string
    if (!copy) return NULL;

    char *hint = strtok(copy, "$");
    char *salt_and_iter = strtok(NULL, "$");
    if (!hint || !salt_and_iter) { free(copy); return NULL; }

    char *salt = strtok(salt_and_iter, "!");
    char *iter_and_data = strtok(NULL, "!");
    if (!salt || !iter_and_data) { free(copy); return NULL; }

    char *iter_str = strtok(iter_and_data, "#");
    char *data_part = strtok(NULL, "#");
    if (!iter_str || !data_part) { free(copy); return NULL; }

    int iterations = atoi(iter_str);

    unsigned char key[32];
    if (!derive_key(password, salt, iterations, key)) {
        free(copy);
        return NULL;
    }

    int iv_data_len = 0;
    unsigned char *iv_data = base64_decode(data_part, &iv_data_len);
    if (!iv_data) { free(copy); return NULL; }

    unsigned char *dataout = NULL;
    int dataout_len = 0;
    if (!aes_gcm_decrypt(key, iv_data, iv_data_len, &dataout, &dataout_len)) {
        free(iv_data);
        free(copy);
        return NULL;
    }

    free(iv_data);
    free(copy);

    char *out = malloc(dataout_len + 1);
    if (!out) { free(dataout); return NULL; }
    memcpy(out, dataout, dataout_len);
    out[dataout_len] = '\0';
    free(dataout);
    return out;
}

void strip_newline(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    if (n && (s[n-1] == '\n' || s[n-1] == '\r')) s[n-1] = '\0';
}

int main(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("========================================\n");
    printf("          C-Code CRYPTOFOOL        \n");
    printf("========================================\n");
    printf("\n[E] Encrypt a message\n[D] Decrypt a string\nChoice: ");

    char choice[4];
    if (!fgets(choice, sizeof(choice), stdin)) return 1;
    strip_newline(choice);

    if (choice[0] == 'e' || choice[0] == 'E') {
        char hint[256], salt[256], it_str[32], msg[2048], pwd[256];

        printf("Password Hint: ");
        fgets(hint, sizeof(hint), stdin); strip_newline(hint);

        printf("Salt: ");
        fgets(salt, sizeof(salt), stdin); strip_newline(salt);

        printf("Iterations (ex. 600000): ");
        fgets(it_str, sizeof(it_str), stdin); strip_newline(it_str);
        int iterations = atoi(it_str);

        printf("Data: ");
        fgets(msg, sizeof(msg), stdin); strip_newline(msg);

        printf("Password: ");
        fgets(pwd, sizeof(pwd), stdin); strip_newline(pwd);

        char *enc = encrypt_string(hint, salt, iterations, msg, pwd);
        if (!enc) {
            fprintf(stderr, "Encryption failed.\n");
            return 1;
        }
        printf("\n--------- GENERATED METADATA ---------\n");
        printf("%s\n", enc);
        printf("--------------------------------------\n");
        free(enc);

    } else if (choice[0] == 'd' || choice[0] == 'D') {
        char full[4096], pwd[256];

        printf("\nPaste full string (Hint$Salt!Iter#Data):\n> ");
        if (!fgets(full, sizeof(full), stdin)) return 1;
        strip_newline(full);

        printf("Master Password: ");
        fgets(pwd, sizeof(pwd), stdin); strip_newline(pwd);

        char *dec = decrypt_string(full, pwd);
        if (!dec) {
            printf("\n[!] Decryption Error: Incorrect password or invalid format.\n");
            return 1;
        }
        printf("\n--------- DECRYPTED MESSAGE ---------\n");
        printf("%s\n", dec);
        printf("-------------------------------------\n");
        free(dec);
    } else {
        printf("Invalid choice.\n");
    }

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}

