#include <stdio.h>

const short PRICE = 1337;
long long BALANCE = 1000;

int handle_buying(short count) {
    return count * PRICE;
}

int main() {
    short count;
    int total_cost;

    printf("Welcome to the shop! We sell items for $%d each.\n", PRICE);
    printf("How many items would you like to buy? ");
    scanf("%hd", &count);
    
    total_cost = handle_buying(count);

    if (total_cost > BALANCE) {
        printf("You don't have enough money to buy that many items!\n");
    } else {
        BALANCE -= total_cost;
        printf("You bought %d items. Your new balance is $%lld.\n", count, BALANCE);
    }
}