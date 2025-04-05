#include <stdio.h>
int GLOBAL_VAR = 1000;
int GLOBAL_VAR_2 = 2000;

int main() {
    printf("Global 1: %d\n", GLOBAL_VAR);
    printf("Global 2: %d\n", GLOBAL_VAR_2);
}