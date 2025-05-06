// client_prompt.c
#include "libdata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BUFFER_SIZE 1024
#define SECRET_SIZE 64
#define ALT_SECRET_SIZE 16

/* Helper function to clear leftover input */
void clear_stdin() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int main() {
    int choice;
    char id[64];
    char secret_str[128];
    uint8_t secret[SECRET_SIZE];
    char data[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    time_t last_update;

    while (1) {
        printf("\nSelect an operation:\n");
        printf("1. Store Data Block\n");
        printf("2. Retrieve Data Block\n");
        printf("3. Update Data Block (full update)\n");
        printf("4. Get Last Update Time\n");
        printf("5. Associate Alternative Secret\n");
        printf("6. Remove Alternative Secret\n");
        printf("7. Partial Read of Data Block\n");
        printf("8. Partial Write/Update of Data Block\n");
        printf("9. Exit\n");
        printf("Choice: ");
        if(scanf("%d", &choice) != 1) {
            printf("Invalid input.\n");
            clear_stdin();
            continue;
        }
        clear_stdin();  // Remove extra characters

        if (choice == 9) {
            break;
        }

        printf("Enter ID: ");
        fgets(id, sizeof(id), stdin);
        id[strcspn(id, "\n")] = '\0'; // Remove newline

        printf("Enter secret: ");
        fgets(secret_str, sizeof(secret_str), stdin);
        secret_str[strcspn(secret_str, "\n")] = '\0';
        /* Zero out secret and copy user input (up to SECRET_SIZE bytes) */
        memset(secret, 0, SECRET_SIZE);
        strncpy((char*)secret, secret_str, SECRET_SIZE);

        if (choice == 1) {
            printf("Enter data to store: ");
            fgets(data, sizeof(data), stdin);
            data[strcspn(data, "\n")] = '\0';
            if (sendNewBlock(id, secret, strlen(data), data)) {
                printf("Data block stored successfully!\n");
            } else {
                printf("Failed to store data block.\n");
            }
        } else if (choice == 2) {
            if (getBlock(id, secret, BUFFER_SIZE, buffer)) {
                printf("Retrieved data: %s\n", buffer);
            } else {
                printf("Failed to retrieve data block.\n");
            }
        } else if (choice == 3) {
            /* For update, first get the current last update time */
            if (!getLastUpdateTime(id, secret, &last_update)) {
                printf("Failed to retrieve last update time. Cannot update block.\n");
            } else {
                printf("Enter new data to update: ");
                fgets(data, sizeof(data), stdin);
                data[strcspn(data, "\n")] = '\0';
                if (updateBlock(id, secret, strlen(data), data, last_update))
                    printf("Data block updated successfully!\n");
                else
                    printf("Failed to update data block. It might be outdated.\n");
            }
        } else if (choice == 4) {
            if (getLastUpdateTime(id, secret, &last_update))
                printf("Last update time: %s", ctime(&last_update));
            else
                printf("Failed to get last update time.\n");
        } else if (choice == 5) {
            char alt_secret_str[32];
            uint8_t alt_secret[ALT_SECRET_SIZE];
            unsigned int perm;
            printf("Enter alternative secret (max 16 chars): ");
            fgets(alt_secret_str, sizeof(alt_secret_str), stdin);
            alt_secret_str[strcspn(alt_secret_str, "\n")] = '\0';
            memset(alt_secret, 0, ALT_SECRET_SIZE);
            strncpy((char*)alt_secret, alt_secret_str, ALT_SECRET_SIZE);
            printf("Enter permission (1: read only, 2: update only, 3: read & update): ");
            scanf("%u", &perm);
            clear_stdin();
            if (associateAltSecret(id, secret, alt_secret, (uint8_t)perm))
                printf("Alternative secret associated successfully!\n");
            else
                printf("Failed to associate alternative secret.\n");
        } else if (choice == 6) {
            char alt_secret_str[32];
            uint8_t alt_secret[ALT_SECRET_SIZE];
            printf("Enter alternative secret to remove: ");
            fgets(alt_secret_str, sizeof(alt_secret_str), stdin);
            alt_secret_str[strcspn(alt_secret_str, "\n")] = '\0';
            memset(alt_secret, 0, ALT_SECRET_SIZE);
            strncpy((char*)alt_secret, alt_secret_str, ALT_SECRET_SIZE);
            if (removeAltSecret(id, secret, alt_secret))
                printf("Alternative secret removed successfully!\n");
            else
                printf("Failed to remove alternative secret.\n");
        } else if (choice == 7) {
            uint32_t offset, length;
            printf("Enter offset: ");
            scanf("%u", &offset);
            printf("Enter length: ");
            scanf("%u", &length);
            clear_stdin();
            if (readPartialBlock(id, secret, offset, length, buffer)) {
                buffer[length] = '\0';
                printf("Partial data: %s\n", buffer);
            } else {
                printf("Failed to perform partial read.\n");
            }
        } else if (choice == 8) {
            uint32_t offset, length;
            printf("Enter offset: ");
            scanf("%u", &offset);
            printf("Enter length of new data: ");
            scanf("%u", &length);
            clear_stdin();
            printf("Enter new partial data: ");
            fgets(data, length+1, stdin);  // read exactly 'length' characters (plus null terminator)
            data[strcspn(data, "\n")] = '\0';
            if (writePartialBlock(id, secret, offset, length, data))
                printf("Partial data updated successfully!\n");
            else
                printf("Failed to update partial data.\n");
        } else {
            printf("Invalid choice.\n");
        }
    }

    return 0;
}
