
#include <stdlib.h>

void use_after_free_bug() {
    int *ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    *ptr = 10;  // Use after free
}

void null_deref_bug() {
    int *p = NULL;
    *p = 5;  // Null pointer dereference
}
