#include <stdio.h>

// init_arrays

__attribute__((constructor)) void INIT() { printf("In .init_array\n"); }

int main() { printf("Wow hello\n"); }
