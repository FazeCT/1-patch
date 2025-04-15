#include <stdio.h>

int GLOBAL_VAR = 1000;
int GLOBAL_VAR_2 = 2000;

void hello_world() {
    printf("%s\n", "hello_world");
}

int add(int a, int b) {
    hello_world();
    return a + b;
}

int main() {
    printf("%d\n", add(GLOBAL_VAR, GLOBAL_VAR_2));
    printf("%d\n", GLOBAL_VAR);
}