# MiniNetStack

MiniNetStack is a user-space TCP/IP stack written in C.

The project explores how network communication works at a low level by implementing protocol handling directly from raw packet data. It focuses on understanding packet structures, header parsing, and how different layers of the network stack interact.

## Overview

Applications usually communicate over networks through high-level APIs such as sockets. MiniNetStack works below that layer by processing packets directly and implementing the logic required to interpret network protocols.

The project is built incrementally, starting from Ethernet frames and progressing towards higher-level protocols.

## Protocols

The stack is designed to support:

- Ethernet
- ARP
- IPv4
- ICMP
- UDP
- TCP

## Project Structure

```text
MiniNetStack/
├── build/
├── docs/
├── include/
├── src/
├── tests/
└── README.md
```

## Build

```bash
gcc src/main.c -o build/mininetstack
```

Run:

```bash
./build/mininetstack
```

## License

MIT License