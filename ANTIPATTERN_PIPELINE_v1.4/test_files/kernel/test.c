
void test_buffer_overflow() {
    char buffer[10];
    strcpy(buffer, user_input);  // Buffer overflow
}

void test_use_after_free() {
    char *ptr = malloc(100);
    free(ptr);
    *ptr = 'A';  // Use after free
}
