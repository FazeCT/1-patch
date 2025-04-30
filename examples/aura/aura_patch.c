#include <stdio.h>
#include <stddef.h>

const char ref_0x2004_format[];
const char ref_0x201A_modes[];
const char ref_0x201C_devnull[];
const char ref_0x2026_flagtxt[];
const char ref_0x202F_aS[];
const char ref_0x2034_output[];

FILE* ref_0x4060_stdout;
FILE* ref_0x4070_stdin;
FILE* ref_0x4080_stderr;

int ref_0x408C_aura;

int fix_0x1199_main() {
    FILE *stream;
    char v6[32];
    char input_buf[256];

    setbuf(ref_0x4070_stdin, 0);
    setbuf(ref_0x4060_stdout, 0);
    setbuf(ref_0x4080_stderr, 0);

    printf(ref_0x2004_format, &ref_0x408C_aura);

    // Read from stdin straight to buffer
    if (fgets(input_buf, sizeof(input_buf), ref_0x4070_stdin) == NULL) {
        perror("fgets");
        exit(1);
    }

    if (ref_0x408C_aura) {
        stream = fopen(ref_0x2026_flagtxt, ref_0x201A_modes);
        fread(v6, 1, 17, stream);
        printf(ref_0x202F_aS, v6);
    } else {
        puts(ref_0x2034_output);
    }
    return 0;
}