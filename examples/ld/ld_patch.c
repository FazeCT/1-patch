#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

FILE* ref_0x537520_stdout;
FILE* ref_0x537580_stderr;

void ref_0x5B5F0_vfinfo(FILE *fp, const char *fmt, va_list ap, bool is_warning) {};

void fix_0x5CE94_einfo(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    bool is_fatal = false;
    if (fmt[0] == '%' && fmt[1] == 'F') {
        is_fatal = true;
    }

    fflush(ref_0x537520_stdout);
    ref_0x5B5F0_vfinfo(ref_0x537580_stderr, fmt, args, true);
    fflush(ref_0x537580_stderr);

    va_end(args);

    if (is_fatal) {
        exit(1);
    }
}