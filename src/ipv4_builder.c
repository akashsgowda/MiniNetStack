#include "ipv4_builder.h"
#include "checksum.h"

#define IPV4_HEADER_SIZE 20
#define IPV4_IDENTIFICATION 0x1234
#define IPV4_FLAGS_AND_OFFSET 0x0000
#define IPV4_TTL 64
#define IPV4_PROTOCOL 6

#define SOURCE_IP_1 192
#define SOURCE_IP_2 168
#define SOURCE_IP_3 1
#define SOURCE_IP_4 100

#define DESTINATION_IP_1 8
#define DESTINATION_IP_2 8
#define DESTINATION_IP_3 8
#define DESTINATION_IP_4 8

void buildIPv4Header(unsigned char packet[], int payloadLength)
{
    packet[0] = 0x45;

    packet[1] = 0x00;

    packet[2] = (IPV4_HEADER_SIZE + payloadLength) >> 8;
    packet[3] = (IPV4_HEADER_SIZE + payloadLength) & 0xFF;
    packet[4] = IPV4_IDENTIFICATION >> 8;
    packet[5] = IPV4_IDENTIFICATION & 0xFF;
    packet[6] = IPV4_FLAGS_AND_OFFSET >> 8;
    packet[7] = IPV4_FLAGS_AND_OFFSET & 0xFF;
    packet[8] = IPV4_TTL;
    packet[9] = IPV4_PROTOCOL;
    packet[10] = 0x00;
    packet[11] = 0x00;

    packet[12] = SOURCE_IP_1;
    packet[13] = SOURCE_IP_2;
    packet[14] = SOURCE_IP_3;
    packet[15] = SOURCE_IP_4;

    packet[16] = DESTINATION_IP_1;
    packet[17] = DESTINATION_IP_2;
    packet[18] = DESTINATION_IP_3;
    packet[19] = DESTINATION_IP_4;

    unsigned short checksum = calculateIPv4Checksum(packet, IPV4_HEADER_SIZE);

    packet[10] = checksum >> 8;
    packet[11] = checksum & 0xFF;
}