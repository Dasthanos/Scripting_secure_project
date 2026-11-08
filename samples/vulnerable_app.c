/* Intentionally vulnerable classroom examples. Do not use in production. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_name(const char *user_input) {
    char name[16];
    strcpy(name, user_input); /* CWE-120 candidate */
    printf(name);             /* CWE-134 candidate */
}

void run_user_command(const char *command) {
    system(command);          /* CWE-78 candidate */
}

void read_name(void) {
    char name[16];
    scanf("%s", name);       /* CWE-120 candidate: no field width */
}

void copy_bytes(const char *input, size_t user_length) {
    char destination[16];
    memcpy(destination, input, user_length); /* CWE-787 candidate */
}
