
# Test file for pattern detection
void vulnerable_function() {
    char buffer[100];
    strcpy(buffer, user_input);  // Buffer overflow

    char *ptr = malloc(100);
    free(ptr);
    *ptr = 'A';  // Use after free
}
