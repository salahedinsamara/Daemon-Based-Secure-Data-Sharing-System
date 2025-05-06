// test.c
#include "libdata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BUFFER_SIZE 1024
#define SECRET_SIZE 64
#define ALT_SECRET_SIZE 16

// Helper function to print a test result line.
void print_result(FILE *fp, const char *test_desc, int passed) {
    fprintf(fp, "%s: %s\n", test_desc, passed ? "PASS" : "FAIL");
}

int main() {
    FILE *fp = fopen("test_results.txt", "w");
    if (!fp) {
        fprintf(stderr, "Failed to open output file.\n");
        return 1;
    }
    fprintf(fp, "Test Results for Data Daemon Application\n");
    fprintf(fp, "-----------------------------------------\n\n");

    int res;
    char retrieved[BUFFER_SIZE];
    char partial[BUFFER_SIZE];
    time_t last_update;

    // Prepare a master secret and test block ID/data.
    const char *id = "TestBlock";
    const char *secret_str = "TestSecret";
    uint8_t secret[SECRET_SIZE];
    memset(secret, 0, SECRET_SIZE);
    strncpy((char*)secret, secret_str, SECRET_SIZE);

    // Test 1: Normal Store and Retrieve.
    const char *data1 = "Hello, World!";
    res = sendNewBlock((char*)id, secret, strlen(data1), (void*)data1);
    print_result(fp, "Test 1a - Store block", res == 1);

    memset(retrieved, 0, BUFFER_SIZE);
    res = getBlock((char*)id, secret, BUFFER_SIZE, retrieved);
    print_result(fp, "Test 1b - Retrieve block", res == 1 && strcmp(retrieved, data1) == 0);
    fprintf(fp, "    Retrieved: \"%s\"\n", retrieved);

    // Test 2: Duplicate store should fail.
    res = sendNewBlock((char*)id, secret, strlen("New Data"), (void*)"New Data");
    print_result(fp, "Test 2 - Duplicate store check", res == 0);

    // Test 3: Successful Update.
    if (getLastUpdateTime((char*)id, secret, &last_update)) {
        const char *data2 = "Updated Data";
        res = updateBlock((char*)id, secret, strlen(data2), (void*)data2, last_update);
        print_result(fp, "Test 3a - Update with current version", res == 1);

        memset(retrieved, 0, BUFFER_SIZE);
        res = getBlock((char*)id, secret, BUFFER_SIZE, retrieved);
        print_result(fp, "Test 3b - Retrieve after update", res == 1 && strcmp(retrieved, data2) == 0);
        fprintf(fp, "    Retrieved: \"%s\"\n", retrieved);
    } else {
        fprintf(fp, "Test 3 - Failed to get last update time for update test\n");
    }

    // Test 4: Update with outdated version should fail.
    if (getLastUpdateTime((char*)id, secret, &last_update)) {
        time_t outdated = last_update - 10;  // simulate an outdated version
        const char *data_fail = "Should Not Update";
        res = updateBlock((char*)id, secret, strlen(data_fail), (void*)data_fail, outdated);
        print_result(fp, "Test 4 - Update with outdated version", res == 0);
    } else {
        fprintf(fp, "Test 4 - Failed to get last update time for outdated update test\n");
    }

    // Test 5: Partial Read.
    memset(partial, 0, BUFFER_SIZE);
    res = readPartialBlock((char*)id, secret, 0, 5, partial);
    // Expecting first 5 characters of "Updated Data" ("Updat")
    print_result(fp, "Test 5 - Partial read", res == 1 && strncmp(partial, "Updat", 5) == 0);
    fprintf(fp, "    Partial read: \"%s\"\n", partial);

    // Test 6: Partial Write.
    // Change first 5 characters to "Hello"
    res = writePartialBlock((char*)id, secret, 0, 5, "Hello");
    if (res == 1) {
        memset(retrieved, 0, BUFFER_SIZE);
        if (getBlock((char*)id, secret, BUFFER_SIZE, retrieved)) {
            // "Updated Data" becomes "Helloed Data" after replacing first 5 characters.
            print_result(fp, "Test 6 - Partial write", strcmp(retrieved, "Helloed Data") == 0);
            fprintf(fp, "    New block content: \"%s\"\n", retrieved);
        } else {
            fprintf(fp, "Test 6 - Failed to retrieve block after partial write\n");
        }
    } else {
        print_result(fp, "Test 6 - Partial write", 0);
    }

    // Test 7: Alternative Secret Management.
    // Associate alternative secret "AltSecret1234567" (16 bytes) with permission 3 (read & update)
    const char *alt_str = "AltSecret1234567"; // exactly 16 characters
    uint8_t alt_secret[ALT_SECRET_SIZE];
    memset(alt_secret, 0, ALT_SECRET_SIZE);
    strncpy((char*)alt_secret, alt_str, ALT_SECRET_SIZE);
    res = associateAltSecret((char*)id, secret, alt_secret, 3);
    print_result(fp, "Test 7a - Associate alternative secret", res == 1);

    // Use alternative secret to perform a partial read.
    memset(partial, 0, BUFFER_SIZE);
    res = readPartialBlock((char*)id, alt_secret, 0, 5, partial);
    print_result(fp, "Test 7b - Partial read with alternative secret", res == 1 && strncmp(partial, "Hello", 5) == 0);
    fprintf(fp, "    Partial read with alt secret: \"%s\"\n", partial);

    // Remove alternative secret.
    res = removeAltSecret((char*)id, secret, alt_secret);
    print_result(fp, "Test 7c - Remove alternative secret", res == 1);

    // Attempt to use removed alternative secret should fail.
    res = readPartialBlock((char*)id, alt_secret, 0, 5, partial);
    print_result(fp, "Test 7d - Access with removed alternative secret", res == 0);

    // Test 8: Retrieval with wrong secret should fail.
    uint8_t wrong_secret[SECRET_SIZE];
    memset(wrong_secret, 0, SECRET_SIZE);
    strncpy((char*)wrong_secret, "WrongSecret", SECRET_SIZE);
    memset(retrieved, 0, BUFFER_SIZE);
    res = getBlock((char*)id, wrong_secret, BUFFER_SIZE, retrieved);
    print_result(fp, "Test 8 - Retrieval with wrong secret", res == 0);

    // Test 9: Retrieval of non-existing block.
    memset(retrieved, 0, BUFFER_SIZE);
    res = getBlock("NonExistent", secret, BUFFER_SIZE, retrieved);
    print_result(fp, "Test 9 - Retrieval of non-existing block", res == 0);

    // Test 10: Partial read with out-of-range parameters.
    memset(partial, 0, BUFFER_SIZE);
    if (getBlock((char*)id, secret, BUFFER_SIZE, retrieved)) {
        int len = strlen(retrieved);
        res = readPartialBlock((char*)id, secret, len+5, 10, partial);
        print_result(fp, "Test 10 - Partial read out-of-range", res == 0);
    } else {
        fprintf(fp, "Test 10 - Failed to retrieve block for out-of-range test\n");
    }

    fclose(fp);
    printf("Testing complete. Results saved to test_results.txt\n");
    return 0;
}
