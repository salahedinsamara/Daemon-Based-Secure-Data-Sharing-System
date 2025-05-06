// client_lastupdate.c
#include "libdata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SECRET_SIZE 64

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ID> <secret>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *id = argv[1];
    char *secret_str = argv[2];
    uint8_t secret[SECRET_SIZE];

    // Initialize the secret array (zero it) and copy the provided string.
    memset(secret, 0, SECRET_SIZE);
    strncpy((char*)secret, secret_str, SECRET_SIZE);

    time_t last_update;
    if (getLastUpdateTime(id, secret, &last_update)) {
        printf("Last update time for '%s': %s", id, ctime(&last_update));
    } else {
        fprintf(stderr, "Failed to retrieve last update time for '%s'.\n", id);
    }

    return EXIT_SUCCESS;
}
