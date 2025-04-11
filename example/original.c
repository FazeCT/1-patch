#include <stdio.h>

int GLOBAL_VAR = 1000;
int GLOBAL_VAR_2 = 2000;

volatile void lmao() {
    printf("%s\n", "lmao");
}

int add(int a, int b) {
    return a + b;
}

int main() {
    printf("%d\n", add(GLOBAL_VAR, GLOBAL_VAR_2));
}