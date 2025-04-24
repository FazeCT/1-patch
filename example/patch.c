#include <stdio.h>

long long ref_0x4010_itsjoever;
const char ref_0x2010[];
const char ref_0x2048[];
const char ref_0x2078[];
const char ref_0x20B0[];
int ref_0x11A9(short count) {};

volatile int fix_0x11C6() {
    short count;
    unsigned int total_cost;
    
    printf(ref_0x2010, 1337);
    printf("%s", ref_0x2048);
    scanf("%hd", &count);
    
    total_cost = ref_0x11A9(count);

    if (count < 0) {
        printf("You can't buy a negative amount of items!\n");
    } else if (total_cost > ref_0x4010_itsjoever) {
        printf("%s",ref_0x2078);
    } else {
        ref_0x4010_itsjoever -= total_cost;
        printf(ref_0x20B0, count, ref_0x4010_itsjoever);
    }
    return 0;
}
int main() {};