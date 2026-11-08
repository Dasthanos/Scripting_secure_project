/* Safer counterparts for discussion; these do not prove whole-program safety. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void copy_name(const char *user_input) {
    char name[16];
    snprintf(name, sizeof(name), "%s", user_input);
    printf("%s", name);
}

void run_tool(const char *validated_argument) {
    /* Prefer an argument-vector API over building a shell command string. */
    execl("/usr/bin/example-tool", "example-tool", validated_argument, (char *)0);
}

void read_name(void) {
    char name[16];
    if (scanf("%15s", name) != 1) {
        return;
    }
}
