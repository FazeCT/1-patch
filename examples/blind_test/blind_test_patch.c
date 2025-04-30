#include <stdint.h>

const char ref_0x2004_scmpinit[];
const char ref_0x2011_scmpload[];

int64_t ref_0x1030_scmpinit() {};
int64_t ref_0x1040_scmpadd() {};
int64_t ref_0x1050_scmpload() {};
int64_t ref_0x1070_scmprelease() {};
void ref_0x1090_perror() {};
void ref_0x10A0_exit() {};

void fix_0x11A9() {
    int64_t ctx;

    // Initialize seccomp context (ALLOW)
    ctx = ref_0x1030_scmpinit(0x7fff0000); 
    if (!ctx) {
        ref_0x1090_perror(ref_0x2004_scmpinit);
        ref_0x10A0_exit(1);
    }

    // KILL following syscalls
    ref_0x1040_scmpadd(ctx, 0x00000000, 1, 0);    // SYS_write
    ref_0x1040_scmpadd(ctx, 0x00000000, 41, 0);   // SYS_socket
    ref_0x1040_scmpadd(ctx, 0x00000000, 20, 0);   // SYS_writev
    ref_0x1040_scmpadd(ctx, 0x00000000, 18, 0);   // SYS_pwrite64

    if ((int)ref_0x1050_scmpload(ctx) < 0) {
        ref_0x1090_perror(ref_0x2011_scmpload);
        ref_0x1070_scmprelease(ctx);
        ref_0x10A0_exit(1);
    }
    ref_0x1070_scmprelease(ctx);
}