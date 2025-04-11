#include <stdio.h>

volatile int add_lmao() {
    return 6969696;
}
volatile int fix_0x4808E0() {
    int a, b;

    asm volatile (
        "movl %%eax, %0\n\t" // Move the value in rax (eax for 32-bit) to variable a
        "movl %%ebx, %1\n\t" // Move the value in rbx (ebx for 32-bit) to variable b
        : "=r" (a), "=r" (b) // Output operands
        :                    // No input operands
        : "eax", "ebx"       // Clobbered registers
    );
    return add_lmao() + a + b;
}

int main() {}