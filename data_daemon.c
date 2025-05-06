// data_daemon.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

// Function prototypes for encryption and decryption
static int daemon_encrypt_data(uint8_t *input, uint8_t *output, uint8_t *key, uint8_t *iv, int input_len);
static int daemon_decrypt_data(uint8_t *input, uint8_t *output, uint8_t *key, uint8_t *iv, int input_len);


#define SOCKET_PATH "/tmp/data_daemon.sock"
#define DATA_FILE "data_blocks.db"
#define MAX_BLOCKS 100
#define SECRET_SIZE 64
#define DATA_MAX_SIZE 1024

// New definitions for alternative secrets and expiry
#define MAX_ALT_SECRETS 5
#define ALT_SECRET_SIZE 16
#define EXPIRY_TIME 3600  // Blocks older than 1 hour will be removed

// DataBlock now stores the IV along with the encrypted data, plus alternative secrets.
typedef struct {
    char id[64];
    uint8_t master_secret[SECRET_SIZE];
    uint8_t iv[16]; // Initialization Vector for AES
    uint8_t encrypted_data[DATA_MAX_SIZE];
    uint32_t data_length;
    time_t last_updated;
    int alt_count; // Number of alternative secrets
    struct {
        uint8_t secret[ALT_SECRET_SIZE]; // Alternative secret (16 bytes)
        uint8_t permissions;             // 1: read only, 2: update only, 3: read & update
    } alt_secrets[MAX_ALT_SECRETS];
} DataBlock;

typedef struct {
    int block_count;
    DataBlock blocks[MAX_BLOCKS];
} SharedData;

SharedData *shared_data = NULL;
sem_t *shm_sem = NULL;

/* Function to daemonize the process */
void daemonize() {
    pid_t pid, sid;

    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "Fork failed during daemonization");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    sid = setsid();
    if (sid < 0) {
        syslog(LOG_ERR, "Failed to create new session for daemon");
        exit(EXIT_FAILURE);
    }

    if (chdir("/") < 0) {
        syslog(LOG_ERR, "Failed to change directory to root");
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    syslog(LOG_INFO, "Daemonization complete. Running in background.");
}

/* Save persistent storage to file with secure permissions */
void save_storage() {
    const char *master_key = getenv("DATA_DAEMON_MASTER_KEY");
    FILE *file = fopen(DATA_FILE, "wb");
    if (!file) {
        syslog(LOG_ERR, "Failed to open storage file for writing");
        return;
    }
    if (master_key) {
        // Derive a 256-bit key from the master key string using SHA-256
        unsigned char key[32];
        SHA256((unsigned char*)master_key, strlen(master_key), key);

        // Use the shared_data struct as plaintext (size of SharedData)
        size_t plain_size = sizeof(SharedData);
        unsigned char iv[16];
        if (RAND_bytes(iv, 16) != 1) {
            syslog(LOG_ERR, "Failed to generate IV for storage encryption");
            fclose(file);
            return;
        }
        // Allocate buffer for ciphertext (allow extra space for padding)
        unsigned char ciphertext[sizeof(SharedData) + AES_BLOCK_SIZE];
        int ciphertext_len = daemon_encrypt_data((uint8_t*)shared_data, ciphertext, key, iv, plain_size);


        if (ciphertext_len < 0) {
            syslog(LOG_ERR, "Encryption failed in save_storage");
            fclose(file);
            return;
        }
        // Write IV (16 bytes), ciphertext length (int), then ciphertext.
        fwrite(iv, 1, 16, file);
        fwrite(&ciphertext_len, sizeof(int), 1, file);
        fwrite(ciphertext, 1, ciphertext_len, file);
    } else {
        // No master key provided; store plaintext.
        fwrite(&(shared_data->block_count), sizeof(int), 1, file);
        fwrite(shared_data->blocks, sizeof(DataBlock), shared_data->block_count, file);
    }
    fclose(file);
    chmod(DATA_FILE, 0600);  // restrict file permissions
    syslog(LOG_INFO, "Storage saved. Count: %d", shared_data->block_count);
}
/* Load persistent storage from file */
void load_storage() {
    const char *master_key = getenv("DATA_DAEMON_MASTER_KEY");
    FILE *file = fopen(DATA_FILE, "rb");
    if (file) {
        if (master_key) {
            unsigned char iv[16];
            int ciphertext_len = 0;
            fread(iv, 1, 16, file);
            fread(&ciphertext_len, sizeof(int), 1, file);
            unsigned char ciphertext[sizeof(SharedData) + AES_BLOCK_SIZE];
            if (fread(ciphertext, 1, ciphertext_len, file) != (size_t)ciphertext_len) {
                syslog(LOG_ERR, "Failed to read complete ciphertext");
                fclose(file);
                return;
            }
            unsigned char key[32];
            SHA256((unsigned char*)master_key, strlen(master_key), key);
//            int plain_len = decrypt_data(ciphertext, (uint8_t*)shared_data, key, iv, ciphertext_len);
            int plain_len = daemon_decrypt_data(ciphertext, (uint8_t*)shared_data, key, iv, ciphertext_len);

            if (plain_len < 0) {
                syslog(LOG_ERR, "Decryption failed in load_storage");
                fclose(file);
                return;
            }
        } else {
            fread(&(shared_data->block_count), sizeof(int), 1, file);
            if (shared_data->block_count > MAX_BLOCKS || shared_data->block_count < 0) {
                syslog(LOG_ERR, "Corrupted data: invalid block_count");
                shared_data->block_count = 0;
            } else {
                fread(shared_data->blocks, sizeof(DataBlock), shared_data->block_count, file);
            }
        }
        fclose(file);
        syslog(LOG_INFO, "Storage loaded. Count: %d", shared_data->block_count);
    } else {
        syslog(LOG_INFO, "No storage file found, starting fresh");
        shared_data->block_count = 0;
    }
}

/* Cleanup storage: remove blocks older than EXPIRY_TIME seconds */
void cleanup_storage() {
    time_t now = time(NULL);
    sem_wait(shm_sem);
    int i = 0;
    while(i < shared_data->block_count) {
        if(now - shared_data->blocks[i].last_updated > EXPIRY_TIME) {
            syslog(LOG_INFO, "Removing expired block with ID: %s", shared_data->blocks[i].id);
            for (int j = i; j < shared_data->block_count - 1; j++) {
                shared_data->blocks[j] = shared_data->blocks[j+1];
            }
            shared_data->block_count--;
        } else {
            i++;
        }
    }
    sem_post(shm_sem);
}

/* Encryption function for daemon */
static int daemon_encrypt_data(uint8_t *input, uint8_t *output, uint8_t *key, uint8_t *iv, int input_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        syslog(LOG_ERR, "Error creating EVP context");
        return -1;
    }
    int len, cipher_len;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        syslog(LOG_ERR, "Error initializing encryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptUpdate(ctx, output, &len, input, input_len)) {
        syslog(LOG_ERR, "Error encrypting data");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len = len;
    if (!EVP_EncryptFinal_ex(ctx, output + len, &len)) {
        syslog(LOG_ERR, "Error finalizing encryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return cipher_len;
}

/* Decryption function for daemon */
static int daemon_decrypt_data(uint8_t *input, uint8_t *output, uint8_t *key, uint8_t *iv, int input_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        syslog(LOG_ERR, "Error creating EVP context");
        return -1;
    }
    int len, plain_len;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        syslog(LOG_ERR, "Error initializing decryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptUpdate(ctx, output, &len, input, input_len)) {
        syslog(LOG_ERR, "Error decrypting data");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plain_len = len;
    if (!EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        syslog(LOG_ERR, "Error finalizing decryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plain_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plain_len;
}

/* Compute SHA-256 hash of challenge */
void hash_challenge(char *challenge, char *response) {
    SHA256((unsigned char*)challenge, 32, (unsigned char*)response);
}
/* Generate a secure random challenge */
void generate_secure_challenge(char *challenge) {
    if (RAND_bytes((unsigned char *)challenge, 32) != 1) {
        syslog(LOG_ERR, "Failed to generate secure challenge");
        memset(challenge, 0, 32);
    }
}


/* Handle an individual client connection */
void handle_client(int client_socket) {
    syslog(LOG_INFO, "Handling client request...");
    char challenge[32], response[32];

    /* Handshake: generate, send challenge and verify response */
    generate_secure_challenge(challenge);
    if (write(client_socket, challenge, 32) != 32) {
        syslog(LOG_ERR, "Failed to send challenge");
        close(client_socket);
        return;
    }
    if (read(client_socket, response, 32) != 32) {
        syslog(LOG_ERR, "Failed to read challenge response");
        close(client_socket);
        return;
    }
    char expected_response[32];
    hash_challenge(challenge, expected_response);
    if (memcmp(response, expected_response, 32) != 0) {
        syslog(LOG_ERR, "Authentication failed for client");
        write(client_socket, "ERR_AUTH", 8);
        sleep(2);  // simple rate limiting on failed auth
        close(client_socket);
        return;
    }
    if (write(client_socket, "AUTH_OK", 7) != 7) {
        syslog(LOG_ERR, "Failed to send AUTH_OK");
        close(client_socket);
        return;
    }

    /* Read the command (16 bytes) */
    char command[16];
    memset(command, 0, sizeof(command));
    if (read(client_socket, command, 16) != 16) {
        syslog(LOG_ERR, "Failed to read command");
        close(client_socket);
        return;
    }

    if (strcmp(command, "STORE") == 0) {
        char id[64];
        uint8_t secret[SECRET_SIZE];
        uint8_t iv[16];
        uint32_t data_length;
        uint8_t encrypted_data[DATA_MAX_SIZE];

        if (read(client_socket, id, 64) != 64 ||
            read(client_socket, secret, SECRET_SIZE) != SECRET_SIZE ||
            read(client_socket, iv, 16) != 16 ||
            read(client_socket, &data_length, 4) != 4) {
            syslog(LOG_ERR, "Failed to read STORE parameters");
            close(client_socket);
            return;
        }
        if (data_length > DATA_MAX_SIZE) {
            syslog(LOG_ERR, "Data length exceeds maximum");
            close(client_socket);
            return;
        }
        if (read(client_socket, encrypted_data, data_length) != data_length) {
            syslog(LOG_ERR, "Failed to read encrypted data");
            close(client_socket);
            return;
        }
        syslog(LOG_INFO, "Received STORE request for ID: %s", id);
        sem_wait(shm_sem);
        // Check for duplicate ID
        for (int i = 0; i < shared_data->block_count; i++) {
            if (strcmp(shared_data->blocks[i].id, id) == 0) {
                sem_post(shm_sem);
                write(client_socket, "ERR_EXISTS", 10);
                syslog(LOG_WARNING, "Block with ID %s already exists", id);
                close(client_socket);
                return;
            }
        }
        if (shared_data->block_count >= MAX_BLOCKS) {
            sem_post(shm_sem);
            write(client_socket, "ERR_FULL", 8);
            syslog(LOG_ERR, "Data storage is full");
            close(client_socket);
            return;
        }
        int index = shared_data->block_count;
        strncpy(shared_data->blocks[index].id, id, sizeof(shared_data->blocks[index].id)-1);
        memcpy(shared_data->blocks[index].master_secret, secret, SECRET_SIZE);
        memcpy(shared_data->blocks[index].iv, iv, 16);
        memcpy(shared_data->blocks[index].encrypted_data, encrypted_data, data_length);
        shared_data->blocks[index].data_length = data_length;
        shared_data->blocks[index].last_updated = time(NULL);
        shared_data->blocks[index].alt_count = 0;
        shared_data->block_count++;
        sem_post(shm_sem);

        save_storage();
        if (write(client_socket, "OK", 2) != 2) {
            syslog(LOG_ERR, "Failed to send OK to client");
        }
    }
    else if (strcmp(command, "RETRIEVE") == 0) {
        char id[64];
        uint8_t secret[SECRET_SIZE];
        if (read(client_socket, id, 64) != 64 ||
            read(client_socket, secret, SECRET_SIZE) != SECRET_SIZE) {
            syslog(LOG_ERR, "Failed to read RETRIEVE parameters");
            close(client_socket);
            return;
        }
        int found = 0;
        sem_wait(shm_sem);
        for (int i = 0; i < shared_data->block_count; i++) {
            if ((strcmp(shared_data->blocks[i].id, id) == 0) &&
                (memcmp(shared_data->blocks[i].master_secret, secret, SECRET_SIZE) == 0)) {
                if (write(client_socket, shared_data->blocks[i].iv, 16) != 16 ||
                    write(client_socket, &shared_data->blocks[i].data_length, 4) != 4 ||
                    write(client_socket, shared_data->blocks[i].encrypted_data,
                          shared_data->blocks[i].data_length) != shared_data->blocks[i].data_length) {
                    syslog(LOG_ERR, "Failed to send data for block ID: %s", id);
                } else {
                    syslog(LOG_INFO, "Data block retrieved successfully with ID: %s", id);
                }
                found = 1;
                break;
            }
        }
        sem_post(shm_sem);
        if (!found) {
            syslog(LOG_WARNING, "Access denied for client to block ID: %s", id);
            write(client_socket, "ERR_ACCESS", 10);
        }
    }
    else if (strcmp(command, "LAST_UPDATE") == 0) {
        char id[64];
        uint8_t secret[SECRET_SIZE];
        if (read(client_socket, id, 64) != 64 ||
            read(client_socket, secret, SECRET_SIZE) != SECRET_SIZE) {
            syslog(LOG_ERR, "Failed to read LAST_UPDATE parameters");
            close(client_socket);
            return;
        }
        int found = 0;
        sem_wait(shm_sem);
        for (int i = 0; i < shared_data->block_count; i++) {
            if ((strcmp(shared_data->blocks[i].id, id) == 0) &&
                (memcmp(shared_data->blocks[i].master_secret, secret, SECRET_SIZE) == 0)) {
                if (write(client_socket, &shared_data->blocks[i].last_updated, sizeof(time_t)) != sizeof(time_t)) {
                    syslog(LOG_ERR, "Failed to send last update for block ID: %s", id);
                }
                found = 1;
                break;
            }
        }
        sem_post(shm_sem);
        if (!found) {
            write(client_socket, "ERR_ACCESS", 10);
        }
    }
    /* New command: UPDATE (with version check) */
    else if (strcmp(command, "UPDATE") == 0) {
        char id[64];
        uint8_t secret[SECRET_SIZE];
        time_t client_version;
        uint8_t iv[16];
        uint32_t data_length;
        uint8_t encrypted_data[DATA_MAX_SIZE];

        if (read(client_socket, id, 64) != 64 ||
            read(client_socket, secret, SECRET_SIZE) != SECRET_SIZE ||
            read(client_socket, &client_version, sizeof(time_t)) != sizeof(time_t) ||
            read(client_socket, iv, 16) != 16 ||
            read(client_socket, &data_length, 4) != 4) {
            syslog(LOG_ERR, "Failed to read UPDATE parameters");
            close(client_socket);
            return;
        }
        if (data_length > DATA_MAX_SIZE) {
            syslog(LOG_ERR, "Data length exceeds maximum");
            close(client_socket);
            return;
        }
        if (read(client_socket, encrypted_data, data_length) != data_length) {
            syslog(LOG_ERR, "Failed to read encrypted data for UPDATE");
            close(client_socket);
            return;
        }
        syslog(LOG_INFO, "Received UPDATE request for ID: %s", id);
        sem_wait(shm_sem);
        int found = 0;
        for (int i = 0; i < shared_data->block_count; i++) {
            if ((strcmp(shared_data->blocks[i].id, id) == 0) &&
                (memcmp(shared_data->blocks[i].master_secret, secret, SECRET_SIZE) == 0)) {
                // Check version: client must have the latest block version
                if (shared_data->blocks[i].last_updated != client_version) {
                    sem_post(shm_sem);
                    write(client_socket, "ERR_OUTDATED", 12);
                    syslog(LOG_WARNING, "UPDATE rejected for ID %s: outdated version", id);
                    close(client_socket);
                    return;
                }
                // Proceed with update
                memcpy(shared_data->blocks[i].iv, iv, 16);
                memcpy(shared_data->blocks[i].encrypted_data, encrypted_data, data_length);
                shared_data->blocks[i].data_length = data_length;
                shared_data->blocks[i].last_updated = time(NULL);
                found = 1;
                break;
            }
        }
        sem_post(shm_sem);
        if (found) {
            save_storage();
            write(client_socket, "OK", 2);
            syslog(LOG_INFO, "Block with ID %s updated successfully", id);
        } else {
            write(client_socket, "ERR_ACCESS", 10);
            syslog(LOG_WARNING, "UPDATE failed: block with ID %s not found or secret mismatch", id);
        }
    }
    /* New command: Associate alternative secret */
    else if (strcmp(command, "ASSOC") == 0) {
        char id[64];
        uint8_t auth_secret[SECRET_SIZE];
        uint8_t alt_secret[ALT_SECRET_SIZE];
        uint8_t permissions;
        if (read(client_socket, id, 64) != 64 ||
            read(client_socket, auth_secret, SECRET_SIZE) != SECRET_SIZE ||
            read(client_socket, alt_secret, ALT_SECRET_SIZE) != ALT_SECRET_SIZE ||
            read(client_socket, &permissions, 1) != 1) {
            syslog(LOG_ERR, "Failed to read ASSOC parameters");
            close(client_socket);
            return;
        }
        int found = 0;
        sem_wait(shm_sem);
        for (int i = 0; i < shared_data->block_count; i++) {
            if (strcmp(shared_data->blocks[i].id, id) == 0 &&
                memcmp(shared_data->blocks[i].master_secret, auth_secret, SECRET_SIZE) == 0) {
                if (shared_data->blocks[i].alt_count < MAX_ALT_SECRETS) {
                    memcpy(shared_data->blocks[i].alt_secrets[shared_data->blocks[i].alt_count].secret, alt_secret, ALT_SECRET_SIZE);
                    shared_data->blocks[i].alt_secrets[shared_data->blocks[i].alt_count].permissions = permissions;
                    shared_data->blocks[i].alt_count++;
                    found = 1;
                }
                break;
            }
        }
        sem_post(shm_sem);
        if (found)
            write(client_socket, "OK", 2);
        else
            write(client_socket, "ERR_ASSOC", 9);
    }
    /* New command: Remove alternative secret */
    else if (strcmp(command, "RMSECRET") == 0) {
       char id[64];
        uint8_t auth_secret[SECRET_SIZE];
        uint8_t alt_secret[ALT_SECRET_SIZE];
        if (read(client_socket, id, 64) != 64 ||
            read(client_socket, auth_secret, SECRET_SIZE) != SECRET_SIZE ||
            read(client_socket, alt_secret, ALT_SECRET_SIZE) != ALT_SECRET_SIZE) {
            syslog(LOG_ERR, "Failed to read RMSECRET parameters");
            close(client_socket);
            return;
        }
        int removed = 0;
        sem_wait(shm_sem);
        for (int i = 0; i < shared_data->block_count; i++) {
            if (strcmp(shared_data->blocks[i].id, id) == 0 &&
                memcmp(shared_data->blocks[i].master_secret, auth_secret, SECRET_SIZE) == 0) {
                for (int j = 0; j < shared_data->blocks[i].alt_count; j++) {
                    if (memcmp(shared_data->blocks[i].alt_secrets[j].secret, alt_secret, ALT_SECRET_SIZE) == 0) {
                        // Shift subsequent alternative secrets left
                        for (int k = j; k < shared_data->blocks[i].alt_count - 1; k++) {
                            shared_data->blocks[i].alt_secrets[k] = shared_data->blocks[i].alt_secrets[k+1];
                        }
                        shared_data->blocks[i].alt_count--;
                        memset(shared_data->blocks[i].alt_secrets[shared_data->blocks[i].alt_count].secret, 0, ALT_SECRET_SIZE);
                        removed = 1;
                        break;
                    }
                }
                break;
            }
        }
        sem_post(shm_sem);
        if (removed)
            write(client_socket, "OK", 2);
        else
            write(client_socket, "ERR_RMSECRET", 12);
    }
    /* New command: Partial read */
    else if (strcmp(command, "READ_PART") == 0) {
        char id[64];
        uint8_t provided_secret[SECRET_SIZE];
        uint32_t offset, part_length;
        if (read(client_socket, id, 64) != 64 ||
            read(client_socket, provided_secret, SECRET_SIZE) != SECRET_SIZE ||
            read(client_socket, &offset, 4) != 4 ||
            read(client_socket, &part_length, 4) != 4) {
            syslog(LOG_ERR, "Failed to read READ_PART parameters");
            close(client_socket);
            return;
        }
        int authorized = 0;
        int index_found = -1;
        sem_wait(shm_sem);
        for (int i = 0; i < shared_data->block_count; i++) {
            if (strcmp(shared_data->blocks[i].id, id) == 0) {
                if (memcmp(shared_data->blocks[i].master_secret, provided_secret, SECRET_SIZE) == 0) {
                    authorized = 1;
                    index_found = i;
                    break;
                }
                for (int j = 0; j < shared_data->blocks[i].alt_count; j++) {
                    uint8_t perm = shared_data->blocks[i].alt_secrets[j].permissions;
                    if ((perm == 1 || perm == 3) &&
                        memcmp(shared_data->blocks[i].alt_secrets[j].secret, provided_secret, ALT_SECRET_SIZE) == 0) {
                        authorized = 1;
                        index_found = i;
                        break;
                    }
                }
                if (authorized) break;
            }
        }
        if (!authorized || index_found < 0) {
            sem_post(shm_sem);
            write(client_socket, "ERR_ACCESS", 10);
            close(client_socket);
            return;
        }
        DataBlock *block = &shared_data->blocks[index_found];
        uint8_t key[SECRET_SIZE];
        memcpy(key, block->master_secret, SECRET_SIZE);
        uint8_t plain[DATA_MAX_SIZE];
        int decrypted_len = daemon_decrypt_data(block->encrypted_data, plain, key, block->iv, block->data_length);
        sem_post(shm_sem);
        if (decrypted_len < 0 || offset + part_length > (uint32_t)decrypted_len) {
            write(client_socket, "ERR_RANGE", 9);
            close(client_socket);
            return;
        }
        if (write(client_socket, plain + offset, part_length) != part_length) {
            syslog(LOG_ERR, "Failed to send partial data");
        }
    }
    /* New command: Partial write/update */
    else if (strcmp(command, "WRITE_PART") == 0) {
        char id[64];
        uint8_t provided_secret[SECRET_SIZE];
        uint32_t offset, new_part_length;
        if (read(client_socket, id, 64) != 64 ||
            read(client_socket, provided_secret, SECRET_SIZE) != SECRET_SIZE ||
            read(client_socket, &offset, 4) != 4 ||
            read(client_socket, &new_part_length, 4) != 4) {
            syslog(LOG_ERR, "Failed to read WRITE_PART parameters");
            close(client_socket);
            return;
        }
        uint8_t new_data[new_part_length];
        if (read(client_socket, new_data, new_part_length) != new_part_length) {
            syslog(LOG_ERR, "Failed to read new partial data");
            close(client_socket);
            return;
        }
        int authorized = 0;
        int index_found = -1;
        sem_wait(shm_sem);
        for (int i = 0; i < shared_data->block_count; i++) {
            if (strcmp(shared_data->blocks[i].id, id) == 0) {
                if (memcmp(shared_data->blocks[i].master_secret, provided_secret, SECRET_SIZE) == 0) {
                    authorized = 1;
                    index_found = i;
                    break;
                }
                for (int j = 0; j < shared_data->blocks[i].alt_count; j++) {
                    uint8_t perm = shared_data->blocks[i].alt_secrets[j].permissions;
                    if ((perm == 2 || perm == 3) &&
                        memcmp(shared_data->blocks[i].alt_secrets[j].secret, provided_secret, ALT_SECRET_SIZE) == 0) {
                        authorized = 1;
                        index_found = i;
                        break;
                    }
                }
                if (authorized) break;
            }
        }
        if (!authorized || index_found < 0) {
            sem_post(shm_sem);
            write(client_socket, "ERR_ACCESS", 10);
            close(client_socket);
            return;
        }
        DataBlock *block = &shared_data->blocks[index_found];
        uint8_t key[SECRET_SIZE];
        memcpy(key, block->master_secret, SECRET_SIZE);
        uint8_t plain[DATA_MAX_SIZE];
        int decrypted_len = daemon_decrypt_data(block->encrypted_data, plain, key, block->iv, block->data_length);
        if (decrypted_len < 0 || offset + new_part_length > (uint32_t)decrypted_len) {
            sem_post(shm_sem);
            write(client_socket, "ERR_RANGE", 9);
            close(client_socket);
            return;
        }
        memcpy(plain + offset, new_data, new_part_length);
        uint8_t new_iv[16];
        RAND_bytes(new_iv, 16);
        uint8_t new_encrypted[DATA_MAX_SIZE];
        int new_encrypted_len = daemon_encrypt_data(plain, new_encrypted, key, new_iv, decrypted_len);
        if (new_encrypted_len < 0) {
            sem_post(shm_sem);
            write(client_socket, "ERR_ENCRYPT", 11);
            close(client_socket);
            return;
        }
        memcpy(block->iv, new_iv, 16);
        memcpy(block->encrypted_data, new_encrypted, new_encrypted_len);
        block->data_length = new_encrypted_len;
        block->last_updated = time(NULL);
        sem_post(shm_sem);
        save_storage();
        write(client_socket, "OK", 2);
    }
    else {
        write(client_socket, "ERR_CMD", 7);
        syslog(LOG_ERR, "Unknown command: %s", command);
    }
    close(client_socket);
}

int main() {
    openlog("data_daemon", LOG_PID | LOG_CONS, LOG_USER);

    /* Daemonize the process so it runs in background */
    daemonize();

    syslog(LOG_INFO, "Starting data daemon initialization");

    /* Create and map shared memory */
//    int shm_fd = shm_open("/data_daemon_shm", O_CREAT | O_RDWR, 0666);
    int shm_fd = shm_open("/data_daemon_shm", O_CREAT | O_RDWR, 0600);

    if (shm_fd == -1) {
        syslog(LOG_ERR, "Failed to create shared memory");
        exit(EXIT_FAILURE);
    }
    if (ftruncate(shm_fd, sizeof(SharedData)) == -1) {
        syslog(LOG_ERR, "Failed to set shared memory size");
        exit(EXIT_FAILURE);
    }
    shared_data = mmap(NULL, sizeof(SharedData), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared_data == MAP_FAILED) {
        syslog(LOG_ERR, "Failed to map shared memory");
        exit(EXIT_FAILURE);
    }
    if (shared_data->block_count < 0 || shared_data->block_count > MAX_BLOCKS)
        memset(shared_data, 0, sizeof(SharedData));

    /* Open a named semaphore */
//    shm_sem = sem_open("/data_daemon_sem", O_CREAT, 0666, 1);
    shm_sem = sem_open("/data_daemon_sem", O_CREAT, 0600, 1);

    if (shm_sem == SEM_FAILED) {
        syslog(LOG_ERR, "Failed to open semaphore");
        exit(EXIT_FAILURE);
    }

    load_storage();

    int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_socket < 0) {
        syslog(LOG_ERR, "Failed to create socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    unlink(SOCKET_PATH);
    if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "Failed to bind socket");
        exit(EXIT_FAILURE);
    }
    chmod(SOCKET_PATH, 0700);  // restrict socket access
    if (listen(server_socket, 5) < 0) {
        syslog(LOG_ERR, "Failed to listen on socket");
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "Daemon started securely and listening on %s", SOCKET_PATH);

    while (1) {
        cleanup_storage();
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket >= 0) {
            pid_t pid = fork();
            if (pid == 0) {
                close(server_socket);
                handle_client(client_socket);
                exit(0);
            } else if (pid > 0) {
                close(client_socket);
            } else {
                syslog(LOG_ERR, "Fork failed");
            }
        }
    }

    close(server_socket);
    munmap(shared_data, sizeof(SharedData));
    sem_close(shm_sem);
    sem_unlink("/data_daemon_sem");
    shm_unlink("/data_daemon_shm");
    closelog();

    return 0;
}
