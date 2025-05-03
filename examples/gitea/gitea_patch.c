#include <stdio.h>
#include <stdarg.h>

void fix_0x2BECFA0_showWebStartupMessage() {
    char* msg;
    int size;

    __asm__ __volatile__ (
        "mov %%rax, %0\n\t" 
        "movl %%ebx, %1\n\t"
        : "=r" (msg), "=r" (size)
        :
        : "rax", "ebx"
    );

    char* msg_cut = malloc(size + 1);
    if (msg_cut == NULL) {
        return;
    }
    memcpy(msg_cut, msg, size);
    msg_cut[size] = '\0';

    puts("showWebStartupMessage was called with:");
    puts(msg_cut);
    puts("--------------------------------------");

    free(msg_cut);
}