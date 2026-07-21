#include <stdio.h>

int main(void)
{
    unsigned char packet[] = {
        // Destination MAC
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

        // Source MAC
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,

        // EtherType
        0x08, 0x00
    };

    printf("Destination MAC: FF:FF:FF:FF:FF:FF\n");

    printf("Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[6], packet[7], packet[8],
           packet[9], packet[10], packet[11]);

    unsigned short etherType = (packet[12] << 8) | packet[13];

    printf("EtherType:       0x%04X\n", etherType);

    if (etherType == 0x0800)
    {
        printf("Protocol:        IPv4\n");
    }
    else if (etherType == 0x0806)
    {
        printf("Protocol:        ARP\n");
    }
    else
    {
        printf("Protocol:        Unknown\n");
    }

    return 0;
}