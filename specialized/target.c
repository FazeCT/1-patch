#include <stdio.h>

int GLOBAL_VAR = 1000;
int GLOBAL_VAR_2 = 2000;

int main() {
    printf("Global variable 1: %d\n", GLOBAL_VAR);
    printf("Global variable 2: %d\n", GLOBAL_VAR_2);

    return 0;
}