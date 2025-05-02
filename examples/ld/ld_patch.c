#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

FILE* ref_0x537520_stdout;
FILE* ref_0x537580_stderr;

void ref_0x5B5F0_vfinfo(FILE *fp, const char *fmt, va_list ap, bool is_warning) {};
void ref_0x1B011F_xexit(int code) {};

void fix_0x5CE94_einfo(const char *fmt, ...) {
    va_list args;

    fflush(ref_0x537520_stdout);

    va_start(args, fmt);

    const char *p = fmt;
    bool is_fatal = false;

    char *new_fmt = malloc(strlen(fmt) + 1);
    if (!new_fmt) {
        return NULL;
    }

    char *q = new_fmt; 

    while (*p) {
        if (*p == '%') {
            p++;
            if (*p == 'F') {
                is_fatal = true;
                p++;
                continue; 
            }
            *q++ = '%';
        }
        *q++ = *p++;
    }
    *q = '\0';

    ref_0x5B5F0_vfinfo(ref_0x537580_stderr, new_fmt, args, true);
    va_end(args);

    free(new_fmt);
    fflush(ref_0x537580_stderr);

    if (is_fatal) {
        ref_0x1B011F_xexit(1);
    }
}