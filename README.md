## Project IPK - Varianta Zeta: Sniffer paketu

Small program for sniffing on the network.

### Usage:

`sudo ./ipk-sniffer -i interface [-p port] [--tcp|-t] [--udp|-u] [-n num]`

The program need root access to the interface to be capable of reading the packets.
- interface says what interface should the program use for sniffing. If the argument -i
is omitted, then the program prints out the available interfaces.
