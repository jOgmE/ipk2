## Project IPK - Varianta Zeta: Sniffer paketu

Small program for sniffing on the network.

### Usage:

`sudo ./ipk-sniffer -i interface [-p port] [--tcp|-t] [--udp|-u] [-n num]`

The program need root access to the interface to be capable of reading the packets.
- *interface* says what interface should the program use for sniffing. If the argument `-i`
is omitted, then the program prints out the available interfaces.
- *port* filters the packets depending on the given port number. Port number range is 0..65535
- *num* states how many packets we wish to be printed out. This number can be less if timeout happens.
- if `--tcp` or `-t` is set only TCP packets will be showed
- if `--udp` or `-u` is set only UDP packets will be showed

### Extensions
- interface any

### Files

The solution consists of these files:
- sniffer.c
- makefile
- manual.pdf
- this README.md
