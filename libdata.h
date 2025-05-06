// libdata.h
#ifndef LIBDATA_H
#define LIBDATA_H

#include <stdint.h>
#include <time.h>

#define SECRET_SIZE 64
#define DATA_MAX_SIZE 1024
#define ALT_SECRET_SIZE 16

// Existing functions
uint8_t sendNewBlock(char *ID, uint8_t *secret, uint32_t data_length, void *data);
uint8_t getBlock(char *ID, uint8_t *secret, uint32_t buffer_size, void *buffer);
// Updated updateBlock now requires the last known version.
uint8_t updateBlock(char *ID, uint8_t *secret, uint32_t data_length, void *data, time_t last_update_client);
uint8_t getLastUpdateTime(char *ID, uint8_t *secret, time_t *last_update);

// New functions for alternative secret management
uint8_t associateAltSecret(char *ID, uint8_t *auth_secret, uint8_t *alt_secret, uint8_t permissions);
uint8_t removeAltSecret(char *ID, uint8_t *auth_secret, uint8_t *alt_secret);

// New functions for partial block operations
uint8_t readPartialBlock(char *ID, uint8_t *secret, uint32_t offset, uint32_t length, void *buffer);
uint8_t writePartialBlock(char *ID, uint8_t *secret, uint32_t offset, uint32_t length, void *data);

#endif
