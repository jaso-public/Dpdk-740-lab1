#include <stdio.h>

void print_mac(uint8_t* mac) {
    printf("%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "", mac[0], mac[1], mac[2], mac[3], mac[4] ,mac[5]);
}
