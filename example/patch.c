#include <stdio.h>

volatile long long ref_0x4010;
volatile int ref_0x11A9(short count) {};

volatile int fix_0x11C6() {
    short count;
    unsigned int total_cost;
    
    printf("Welcome to the shop! We sell items for $%d each.\n", 1337);
    printf("How many items would you like to buy? ");
    scanf("%hd", &count);
    
    total_cost = ref_0x11A9(count);

    if (count < 0) {
        printf("You can't buy a negative amount of items!\n");
    } else if (total_cost > ref_0x4010) {
        printf("You don't have enough money to buy that many items!\n");
    } else {
        ref_0x4010 -= total_cost;
        printf("You bought %d items. Your new balance is $%lld.\n", count, ref_0x4010);
    }
    return 0;
}
int main() {};
