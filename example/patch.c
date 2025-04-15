#include <stdio.h>

int add_array[][3] = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

volatile int fix_cocay = 1;

volatile int add_0x4010 = 6969;

volatile int fix_0x1183(int a, int b) {
    return add_array[0][2] * add_0x4010;
}