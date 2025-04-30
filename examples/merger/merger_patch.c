#include <stdint.h>
#include <stddef.h>

uint64_t ref_0x4040_arr[32];
const char ref_0x204D_merged[];
const char ref_0x200E_invalid[];
const char ref_0x2041_dst_prompt[];
const char ref_0x2047_src_prompt[];

void ref_0x1120_free(void* ptr) {};
int ref_0x1130_puts(const char *s) {};
size_t ref_0x1140_strlen(const char *s) {};
char* ref_0x1180_strncat(char *dest, const char *src, size_t n) {};
int ref_0x1170_printf(const char *format, ...) {};
void* ref_0x11D0_realloc(void *ptr, size_t size) {};

int ref_0x1362_get_index() {}

void fix_0x1547_merge() {
    int dst = ref_0x1362_get_index(ref_0x2041_dst_prompt);
    int src = ref_0x1362_get_index(ref_0x2047_src_prompt);
    size_t v1, v2, v3;
    char* dst_str;
    char* src_str;
    char* sa;

    // If dst == src, skip the merge (avoid double free)
    if (ref_0x4040_arr[dst] && ref_0x4040_arr[src] && dst != src) {
        dst_str = ref_0x4040_arr[dst];
        src_str = ref_0x4040_arr[src];

        v1 = ref_0x1140_strlen(dst_str);
        v2 = ref_0x1140_strlen(src_str);

        sa = ref_0x11D0_realloc(dst, v1 + v2 + 1);
        v3 = ref_0x1140_strlen(src);

        ref_0x1180_strncat(sa, src, v3);
        ref_0x1170_printf(ref_0x204D_merged, sa);
        ref_0x1120_free(src);

        ref_0x4040_arr[dst] = sa;
        ref_0x4040_arr[src] = 0;
    }

    else {
        ref_0x1130_puts(ref_0x200E_invalid);
    }
}