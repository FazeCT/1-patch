#include <stdio.h>

volatile int ref_0x4014;
volatile int fix_0x4010 = 3000;

volatile int fix_0x1149() {
    return ref_0x4014;
}

int main() {}