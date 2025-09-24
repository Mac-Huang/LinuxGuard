
#include <stdio.h>
#include <string.h>

void vulnerable_buffer() {
    char buffer[10];
    char *input = "This is a very long string that will overflow";
    strcpy(buffer, input);  // Buffer overflow
}

void safe_buffer() {
    char buffer[10];
    char *input = "short";
    strncpy(buffer, input, sizeof(buffer)-1);
    buffer[sizeof(buffer)-1] = '\0';
}
