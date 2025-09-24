
#include <stdlib.h>

void memory_leak() {
    int *leak = (int*)malloc(100 * sizeof(int));
    // Missing free(leak)
    return;  // Memory leak
}

int divide_by_zero(int x) {
    return x / 0;  // Division by zero
}
