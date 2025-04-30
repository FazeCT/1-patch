#include <stdio.h>

int ref_0x404060_sus;
FILE* ref_0x404068_stdout;

int ref_0x4010B0_puts(const char *s) {};
int ref_0x4010C0_printf(const char *format, ...) {};
char* ref_0x4010D0_fgets(char *s, int n, FILE *stream) {};
int ref_0x4010E0_fflush(FILE *stream) {};
FILE* ref_0x4010F0_fopen(const char *filename, const char *modes) {};
int ref_0x401100_scanf(const char *, ...) {};

int fix_0x4011F6_main() {
    char buf[1024];
    char flag[64];

    ref_0x4010C0_printf("You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n");
    ref_0x4010E0_fflush(ref_0x404068_stdout);
    ref_0x401100_scanf("%1024s", buf);
    ref_0x4010C0_printf("Here's your input: ");
    ref_0x4010B0_puts(buf);
    ref_0x4010E0_fflush(ref_0x404068_stdout);

    if (ref_0x404060_sus == 0x67616c66) {
        ref_0x4010C0_printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");

        FILE *fd = ref_0x4010F0_fopen("flag.txt", "r");
        ref_0x4010D0_fgets(flag, 64, fd);

        ref_0x4010C0_printf("%s", flag);
        ref_0x4010E0_fflush(ref_0x404068_stdout);
    }
    else {
        ref_0x4010C0_printf("sus = 0x%x\n", ref_0x404060_sus);
        ref_0x4010C0_printf("You can do better!\n");
        ref_0x4010E0_fflush(ref_0x404068_stdout);
    }

    return 0;
}