#include "checksum.h"

unsigned short calculateIPv4Checksum(unsigned char header[], int length)
{
    unsigned int sum = 0;

    for (int i = 0; i < length; i += 2)
    {
        unsigned short word = (header[i] << 8) | header[i + 1];

        sum += word;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (unsigned short)(~sum);
}