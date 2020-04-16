FLAGS=-std=gnu99 -Wall -Werror -I/usr/include/pcap -g

ipk-sniffer: sniffer.c
	gcc $(FLAGS) $^ -o ipk_sniffer -lpcap

clean:
	rm -f ipk_sniffer
