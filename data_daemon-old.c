#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <syslog.h>

#define SOCKET_PATH "/tmp/data_daemon.sock"
#define DATA_FILE "data_blocks.db"
#define MAX_BLOCKS 100
#define SECRET_SIZE 16
#define DATA_MAX_SIZE 1024

typedef struct {
    char id[64];
    uint8_t master_secret[SECRET_SIZE];
    uint8_t encrypted_data[DATA_MAX_SIZE];
    uint32_t data_length;
    time_t last_updated;
} DataBlock;

DataBlock storage[MAX_BLOCKS];
int block_count = 0;

// Generate Secure Challenge
void generate_secure_challenge(char *challenge) {
    RAND_bytes((unsigned char *)challenge, 32);
}

// Hash Challenge Response (Simple XOR)
void hash_challenge(char *challenge, char *response) {
    for (int i = 0; i < 32; i++) {
        response[i] = challenge[i] ^ 0xAA;
    }
}

// Encrypt Data using OpenSSL EVP API (AES-256-CBC)
void encrypt_data(uint8_t *input, uint8_t *output, uint8_t *key, uint8_t *iv, int input_len, int *output_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, output, &len, input, input_len);
    *output_len = len;

    EVP_EncryptFinal_ex(ctx, output + len, &len);
    *output_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

// Decrypt Data using OpenSSL EVP API (AES-256-CBC)
void decrypt_data(uint8_t *input, uint8_t *output, uint8_t *key, uint8_t *iv, int input_len, int *output_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    EVP_DecryptUpdate(ctx, output, &len, input, input_len);
    *output_len = len;

    EVP_DecryptFinal_ex(ctx, output + len, &len);
    *output_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

// Handle Client Requests
void handle_client(int client_socket) {
    char challenge[32], response[32];
    generate_secure_challenge(challenge);
    write(client_socket, challenge, 32);
    
    read(client_socket, response, 32);
    char expected_response[32];
    hash_challenge(challenge, expected_response);
    
    if (memcmp(response, expected_response, 32) != 0) {
        write(client_socket, "ERR_AUTH", 8);
        syslog(LOG_ERR, "Authentication failed for client");
        close(client_socket);
        return;
    }
    write(client_socket, "AUTH_OK", 7);
    
    char command[16], id[64];
    uint8_t secret[SECRET_SIZE], encrypted_data[DATA_MAX_SIZE];
    uint32_t data_length;
    
    read(client_socket, command, 16);
    read(client_socket, id, 64);
    read(client_socket, secret, SECRET_SIZE);

    if (strcmp(command, "STORE") == 0) {
        read(client_socket, encrypted_data, DATA_MAX_SIZE);
        if (block_count >= MAX_BLOCKS) {
            write(client_socket, "ERR_FULL", 8);
            syslog(LOG_ERR, "Data storage is full, unable to store data block");
        } else {
            strcpy(storage[block_count].id, id);
            memcpy(storage[block_count].master_secret, secret, SECRET_SIZE);
            memcpy(storage[block_count].encrypted_data, encrypted_data, DATA_MAX_SIZE);
            storage[block_count].data_length = data_length;
            storage[block_count].last_updated = time(NULL);
            block_count++;
            write(client_socket, "OK", 2);
            syslog(LOG_INFO, "Stored data block with ID: %s", id);
        }
    } else if (strcmp(command, "RETRIEVE") == 0) {
        for (int i = 0; i < block_count; i++) {
            if (strcmp(storage[i].id, id) == 0 && 
                memcmp(storage[i].master_secret, secret, SECRET_SIZE) == 0) {
                write(client_socket, storage[i].encrypted_data, DATA_MAX_SIZE);
                syslog(LOG_INFO, "Retrieved data block with ID: %s", id);
                close(client_socket);
                return;
            }
        }
        write(client_socket, "ERR_ACCESS", 10);
        syslog(LOG_WARNING, "Access denied for client to data block ID: %s", id);
    }

    close(client_socket);
}

int main() {
    // Open syslog
    openlog("data_daemon", LOG_PID | LOG_CONS, LOG_USER);

    int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {AF_UNIX, SOCKET_PATH};
    unlink(SOCKET_PATH);
    
    bind(server_socket, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_socket, 5);

    syslog(LOG_INFO, "Daemon started securely...");

    while (1) {
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket >= 0) {
            pid_t pid = fork();
            if (pid == 0) {
                // In child process
                close(server_socket);
                handle_client(client_socket);
                exit(0); // Terminate child process after handling the client
            } else {
                // In parent process
                close(client_socket); // Parent doesn't need the client socket
            }
        }
    }
    close(server_socket);
    
    // Close syslog
    closelog();

    return 0;
}
