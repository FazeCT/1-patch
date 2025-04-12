#include <stdio.h>

volatile int add_GLOBAL_VAR = 3969;

volatile int add_lmao() {
    return add_GLOBAL_VAR;
}
volatile int fix_0x4808E0() {
    int a, b;

    asm volatile (
        "movl %%eax, %0\n\t" 
        "movl %%ebx, %1\n\t" 
        : "=r" (a), "=r" (b) 
        :                    
        : "eax", "ebx"       
    );
    return add_lmao() + a - b;
}

int main() {}