#include <stdio.h>

FILE* ref_0x4010_stdout;
char* ref_0x4030_buffer;

int ref_0x1100_printf(const char *format, ...) {};
int ref_0x1140_fflush(FILE *stream) {};
int ref_0x1160_scanf(const char *format, ...) {};

void fix_0x1404_writebuf() {
    ref_0x1100_printf("Data for buffer: ");
    ref_0x1140_fflush(ref_0x4010_stdout);

    // Read maximum 4 bytes + 1 for null terminator
    return ref_0x1160_scanf("%4s", ref_0x4030_buffer);
}