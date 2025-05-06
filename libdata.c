// libdata.c
#include "libdata.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/data_daemon.sock"

static ssize_t read_all(int fd, void *buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, (char *)buf + total, count - total);
        if (n <= 0)
            return n;
        total += n;
    }
    return total;
}

static ssize_t write_all(int fd, const void *buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t n = write(fd, (const char *)buf + total, count - total);
        if (n <= 0)
            return n;
        total += n;
    }
    return total;
}

void hash_challenge(char *challenge, char *response) {
    // Compute SHA-256 hash of the challenge
    SHA256((unsigned char*)challenge, 32, (unsigned char*)response);
}

static int encrypt_data(uint8_t *input, uint8_t *output, uint8_t *key, uint8_t *iv, int input_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating EVP context\n");
        return -1;
    }
    int len, cipher_len;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptUpdate(ctx, output, &len, input, input_len)) {
        fprintf(stderr, "Error encrypting data\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len = len;
    if (!EVP_EncryptFinal_ex(ctx, output + len, &len)) {
        fprintf(stderr, "Error finalizing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return cipher_len;
}

static int decrypt_data(uint8_t *input, uint8_t *output, uint8_t *key, uint8_t *iv, int input_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating EVP context\n");
        return -1;
    }
    int len, plain_len;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptUpdate(ctx, output, &len, input, input_len)) {
        fprintf(stderr, "Error decrypting data\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plain_len = len;
    if (!EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        fprintf(stderr, "Error finalizing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plain_len += len;
    output[plain_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return plain_len;
}

static int connect_to_daemon() {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1)
        return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path)-1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(sock);
        return -1;
    }
    char challenge[32], response[32];
    if (read_all(sock, challenge, 32) != 32) {
        close(sock);
        return -1;
    }
    hash_challenge(challenge, response);
    if (write_all(sock, response, 32) != 32) {
        close(sock);
        return -1;
    }
    char auth_result[8];
    if (read_all(sock, auth_result, 7) != 7 || memcmp(auth_result, "AUTH_OK", 7) != 0) {
        close(sock);
        return -1;
    }
    return sock;
}

uint8_t sendNewBlock(char *ID, uint8_t *secret, uint32_t data_length, void *data) {
    int sock = connect_to_daemon();
    if (sock == -1)
        return 0;
    uint8_t iv[16], encrypted_data[DATA_MAX_SIZE];
    RAND_bytes(iv, 16);
    int encrypted_len = encrypt_data(data, encrypted_data, secret, iv, data_length);
    if (encrypted_len == -1) {
        close(sock);
        return 0;
    }
    char command[16] = {0};
    strncpy(command, "STORE", sizeof(command)-1);
    if (write_all(sock, command, 16) != 16 ||
        write_all(sock, ID, 64) != 64 ||
        write_all(sock, secret, SECRET_SIZE) != SECRET_SIZE ||
        write_all(sock, iv, 16) != 16 ||
        write_all(sock, &encrypted_len, 4) != 4 ||
        write_all(sock, encrypted_data, encrypted_len) != encrypted_len) {
        close(sock);
        return 0;
    }
    char reply[16];
    if (read_all(sock, reply, 2) != 2 || memcmp(reply, "OK", 2) != 0) {
        close(sock);
        return 0;
    }
    close(sock);
    return 1;
}

/* Updated updateBlock: sends "UPDATE" command with version check */
uint8_t updateBlock(char *ID, uint8_t *secret, uint32_t data_length, void *data, time_t last_update_client) {
    int sock = connect_to_daemon();
    if (sock == -1)
        return 0;
    uint8_t iv[16], encrypted_data[DATA_MAX_SIZE];
    RAND_bytes(iv, 16);
    int encrypted_len = encrypt_data(data, encrypted_data, secret, iv, data_length);
    if (encrypted_len == -1) {
        close(sock);
        return 0;
    }
    char command[16] = {0};
    strncpy(command, "UPDATE", sizeof(command)-1);
    if (write_all(sock, command, 16) != 16 ||
        write_all(sock, ID, 64) != 64 ||
        write_all(sock, secret, SECRET_SIZE) != SECRET_SIZE ||
        write_all(sock, &last_update_client, sizeof(time_t)) != sizeof(time_t) ||
        write_all(sock, iv, 16) != 16 ||
        write_all(sock, &encrypted_len, 4) != 4 ||
        write_all(sock, encrypted_data, encrypted_len) != encrypted_len) {
        close(sock);
        return 0;
    }
    char reply[16];
    if (read_all(sock, reply, 2) != 2 || memcmp(reply, "OK", 2) != 0) {
        close(sock);
        return 0;
    }
    close(sock);
    return 1;
}

uint8_t getBlock(char *ID, uint8_t *secret, uint32_t buffer_size, void *buffer) {
    int sock = connect_to_daemon();
    if (sock == -1)
        return 0;
    char command[16] = {0};
    strncpy(command, "RETRIEVE", sizeof(command)-1);
    if (write_all(sock, command, 16) != 16 ||
        write_all(sock, ID, 64) != 64 ||
        write_all(sock, secret, SECRET_SIZE) != SECRET_SIZE) {
        close(sock);
        return 0;
    }
    uint8_t iv[16];
    uint32_t encrypted_len;
    if (read_all(sock, iv, 16) != 16 || read_all(sock, &encrypted_len, 4) != 4) {
        close(sock);
        return 0;
    }
    if (encrypted_len > DATA_MAX_SIZE) {
        close(sock);
        return 0;
    }
    uint8_t encrypted_data[DATA_MAX_SIZE];
    if (read_all(sock, encrypted_data, encrypted_len) != encrypted_len) {
        close(sock);
        return 0;
    }
    int decrypted_len = decrypt_data(encrypted_data, buffer, secret, iv, encrypted_len);
    if (decrypted_len == -1) {
        close(sock);
        return 0;
    }
    close(sock);
    return 1;
}

uint8_t getLastUpdateTime(char *ID, uint8_t *secret, time_t *last_update) {
    int sock = connect_to_daemon();
    if (sock == -1)
        return 0;
    char command[16] = {0};
    strncpy(command, "LAST_UPDATE", sizeof(command)-1);
    if (write_all(sock, command, 16) != 16 ||
        write_all(sock, ID, 64) != 64 ||
        write_all(sock, secret, SECRET_SIZE) != SECRET_SIZE) {
        close(sock);
        return 0;
    }
    if (read_all(sock, last_update, sizeof(time_t)) != sizeof(time_t)) {
        close(sock);
        return 0;
    }
    close(sock);
    return 1;
}

/* New function: Associate alternative secret */
uint8_t associateAltSecret(char *ID, uint8_t *auth_secret, uint8_t *alt_secret, uint8_t permissions) {
    int sock = connect_to_daemon();
    if (sock == -1)
        return 0;
    char command[16] = {0};
    strncpy(command, "ASSOC", sizeof(command)-1);
    if (write_all(sock, command, 16) != 16 ||
        write_all(sock, ID, 64) != 64 ||
        write_all(sock, auth_secret, SECRET_SIZE) != SECRET_SIZE ||
        write_all(sock, alt_secret, ALT_SECRET_SIZE) != ALT_SECRET_SIZE ||
        write_all(sock, &permissions, 1) != 1) {
         close(sock);
         return 0;
    }
    char reply[16];
    if (read_all(sock, reply, 2) != 2 || memcmp(reply, "OK", 2) != 0) {
         close(sock);
         return 0;
    }
    close(sock);
    return 1;
}

/* New function: Remove alternative secret */
uint8_t removeAltSecret(char *ID, uint8_t *auth_secret, uint8_t *alt_secret) {
    int sock = connect_to_daemon();
    if (sock == -1)
        return 0;
    char command[16] = {0};
    strncpy(command, "RMSECRET", sizeof(command)-1);
    if (write_all(sock, command, 16) != 16 ||
        write_all(sock, ID, 64) != 64 ||
        write_all(sock, auth_secret, SECRET_SIZE) != SECRET_SIZE ||
        write_all(sock, alt_secret, ALT_SECRET_SIZE) != ALT_SECRET_SIZE) {
         close(sock);
         return 0;
    }
    char reply[16];
    if (read_all(sock, reply, 2) != 2 || memcmp(reply, "OK", 2) != 0) {
         close(sock);
         return 0;
    }
    close(sock);
    return 1;
}

/* New function: Partial read */
uint8_t readPartialBlock(char *ID, uint8_t *secret, uint32_t offset, uint32_t length, void *buffer) {
    int sock = connect_to_daemon();
    if (sock == -1)
        return 0;
    char command[16] = {0};
    strncpy(command, "READ_PART", sizeof(command)-1);
    if (write_all(sock, command, 16) != 16 ||
        write_all(sock, ID, 64) != 64 ||
        write_all(sock, secret, SECRET_SIZE) != SECRET_SIZE ||
        write_all(sock, &offset, 4) != 4 ||
        write_all(sock, &length, 4) != 4) {
         close(sock);
         return 0;
    }
    if (read_all(sock, buffer, length) != length) {
         close(sock);
         return 0;
    }
    close(sock);
    return 1;
}

/* New function: Partial write/update */
uint8_t writePartialBlock(char *ID, uint8_t *secret, uint32_t offset, uint32_t length, void *data) {
    int sock = connect_to_daemon();
    if (sock == -1)
        return 0;
    char command[16] = {0};
    strncpy(command, "WRITE_PART", sizeof(command)-1);
    if (write_all(sock, command, 16) != 16 ||
        write_all(sock, ID, 64) != 64 ||
        write_all(sock, secret, SECRET_SIZE) != SECRET_SIZE ||
        write_all(sock, &offset, 4) != 4 ||
        write_all(sock, &length, 4) != 4 ||
        write_all(sock, data, length) != length) {
         close(sock);
         return 0;
    }
    char reply[16];
    if (read_all(sock, reply, 2) != 2 || memcmp(reply, "OK", 2) != 0) {
         close(sock);
         return 0;
    }
    close(sock);
    return 1;
}
