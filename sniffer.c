/* Project for IPK - "sniffer"
 * 
 * @Author: Norbert Pocs (xpocsn00)
 * @date: 15.04.2020
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#include <pcap.h>
#include <pcap/pcap.h>
#include <sll.h> //for cooked header
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

//global variables :peepocry
static int tcp_flag = 0;
static int udp_flag = 0;
int num = 1;
pcap_t *handler;

void print_data(const u_char *data, int data_size, int *offset){
    for(int i=0; i<data_size;i++){
        //print 16 char represented data
        if(i!= 0 && i%16==0){
            for(int j=i-16; j<i;j++){
                if(j%8 == 0) printf(" ");
                if(data[j] >= 32 && data[j] <= 126){ //printable char
                    printf("%c", (unsigned char)data[j]);
                }
                else printf("."); //non printable char
            }
            printf("\n");
        }
        //printing hex line head
        if(i==0 || i%16 == 0){
            printf("%04X: ", *offset);
            *offset += 16;
        }
        //printing hex data
        printf("%02X ",(unsigned int)data[i]);

        //print non full line of char represented data
        if(i == data_size-1){
            for(int j=0; j<(15-i%16); j++){
                //ws padding between hex and data
                printf("   ");
            }
            for(int j=i-i%16;j<=i;j++){
                if(j%8 == 0) printf(" ");
                if(data[j] >= 32 && data[j] <= 126){ //printable char
                    printf("%c", (unsigned char)data[j]);
                }
                else printf("."); //non printable char
            }
            printf("\n");
        }
    }
}

void print_proto(const u_char *buffer, int size, struct tm *time, suseconds_t usec, int proto, \
        uint16_t ipv){
    char srcIP[INET6_ADDRSTRLEN];
    char destIP[INET6_ADDRSTRLEN];
    char srcHost[NI_MAXHOST] = {0};
    char destHost[NI_MAXHOST]= {0};
    char srcPortChar[6];
    char destPortChar[6];
    u_int srcPort, destPort;
    struct addrinfo *sinfo, *dinfo;
    unsigned short ipheadlen;
    struct iphdr *iphead;
    struct ipv6hdr *ip6head;

    if(ipv == ETH_P_IP){
        iphead = (struct iphdr*)buffer;
        ipheadlen = iphead->ihl*4;
        //src dest IP
        inet_ntop(AF_INET, &(iphead->saddr), srcIP, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iphead->daddr), destIP, INET6_ADDRSTRLEN);
    }else if(ipv == ETH_P_IPV6){
        ip6head = (struct ipv6hdr*)buffer;
        ipheadlen = sizeof(struct ipv6hdr);
        inet_ntop(AF_INET6, &(ip6head->saddr), srcIP, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6head->daddr), destIP, INET6_ADDRSTRLEN);
    }

    const u_char *protohead = buffer + ipheadlen;

    if(proto == 17){
        //src dest PORT
        srcPort = ntohs(((struct udphdr*)protohead)->source);
        destPort = ntohs(((struct udphdr*)protohead)->dest);
    }else{
        //src dest PORT
        srcPort = ntohs(((struct tcphdr*)protohead)->source);
        destPort = ntohs(((struct tcphdr*)protohead)->dest);
    }
    sprintf(srcPortChar, "%u", srcPort);
    sprintf(destPortChar, "%u", destPort);

    //      --GET_HOST_NAME--
    getaddrinfo(srcIP, srcPortChar, NULL, &sinfo);
    getnameinfo(sinfo->ai_addr, sinfo->ai_addrlen, srcHost, NI_MAXHOST, NULL, 0, 0);

    getaddrinfo(destIP, destPortChar, NULL, &dinfo);
    getnameinfo(dinfo->ai_addr, dinfo->ai_addrlen, destHost, NI_MAXHOST, NULL, 0, 0);

    //cleaning
    freeaddrinfo(sinfo);
    freeaddrinfo(dinfo);

    printf("%02d:%02d:%02d.%ld ",time->tm_hour, time->tm_min, time->tm_sec, usec);
    if(srcHost[0] == 0){
        printf("%s : %d > ",srcIP, srcPort);
    }else{
        printf("%s : %d > ",srcHost, srcPort);
    }
    if(destHost[0] == 0){
        printf("%s : %d\n\n", destIP, destPort);
    }else{
        printf("%s : %d\n\n", destHost, destPort);
    }
    const u_char *data;
    int data_size;

    if(ipv == ETH_P_IP){
        if(proto == 6){
            data = buffer + sizeof(struct iphdr) + sizeof(struct udphdr);
            data_size = size - sizeof(struct iphdr) - sizeof(struct udphdr);
        }else if(proto == 17){
            data = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
            data_size = size - sizeof(struct iphdr) - sizeof(struct tcphdr);
        }
    }else if(ipv == ETH_P_IPV6){
        if(proto == 6){
            data = buffer + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
            data_size = size - sizeof(struct ipv6hdr) - sizeof(struct udphdr);
        }else if(proto == 17){
            data = buffer + sizeof(struct ipv6hdr) + sizeof(struct tcphdr);
            data_size = size - sizeof(struct ipv6hdr) - sizeof(struct tcphdr);
        }
    }

    //printing header
    int offset = 0;
    if(proto == 6){
        if(ipv == ETH_P_IP){
            print_data(buffer, sizeof(struct udphdr) + sizeof(struct iphdr), &offset);
        }else if(ipv == ETH_P_IPV6){
            print_data(buffer, sizeof(struct udphdr) + sizeof(struct ipv6hdr), &offset);
        }
    }else{
        if(ipv == ETH_P_IP){
            print_data(buffer, sizeof(struct tcphdr) + sizeof(struct iphdr), &offset);
        }else if(ipv == ETH_P_IPV6){
            print_data(buffer, sizeof(struct tcphdr) + sizeof(struct ipv6hdr), &offset);
        }
    }
    //printing packet data
    if(data_size > 0){
        printf("\n");
        print_data(data, data_size, &offset);
    }
}

void read_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
    //counter for packages
    int pkg_counter = 0;
    int size = h->len;
    struct tm *time = localtime(&(h->ts.tv_sec));
    const u_char *iphead;
    uint16_t ipv;
    int proto;

    //1 for ethhdr
    //113 for linux cooked
    int link_frame_type = pcap_datalink(handler);
    
    if(link_frame_type == 113){
        //struct sll_header* cookedhdr = (struct sll_header*) bytes;
        iphead = bytes + sizeof(struct sll_header);
    }else if(link_frame_type == 1){
        iphead = bytes + sizeof(struct ethhdr);
        ipv = ntohs(((struct ethhdr*)bytes)->h_proto); //ip version 4|6
        if(ipv == ETH_P_IP){
            proto = ((struct iphdr*)iphead)->protocol; //protocol TCP|UDP
        }else if(ipv == ETH_P_IPV6){
            proto = ((struct ipv6hdr*)iphead)->nexthdr;
        }
    }

    print_proto(iphead, size - sizeof(struct ethhdr), time, h->ts.tv_usec, \
            proto, ipv);
    ++pkg_counter;

    if(pkg_counter && num != pkg_counter) printf("\n");
}

void print_available_devices(void){
    pcap_if_t *list = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int r;

    //looking for available devices
    r = pcap_findalldevs(&list, errbuf);
    if(r == PCAP_ERROR){
        fprintf(stderr, "%s\n", errbuf);
        exit(r);
    }

    //printing devices
    pcap_if_t *print_out = list;
    while(print_out != NULL){
        printf("%s\n", print_out->name);
        print_out = print_out->next;
    }
    
    pcap_freealldevs(list);
}

int main(int argc, char **argv){
    //variables
    int c;
    //program flags
    const char *interface = NULL;
    char filter_str[256] = {0};
    const char *port = NULL;
    struct bpf_program bp; //filter program
    //long options
    static struct option long_opts[] = {
        {"tcp", no_argument, &tcp_flag, 1},
        {"udp", no_argument, &udp_flag, 1},
        {0,0,0,0}
    };

    int option_index = 0;

    while((c = getopt_long(argc, argv, "i:p:tun:", long_opts, &option_index)) != -1){
        switch(c){
            case 0:
                //for longopts
                continue;
            case 'i':
                interface = optarg;
                break;
            case 'p':
                port = optarg;
                break;
            case 't':
                tcp_flag = 1;
                break;
            case 'u':
                udp_flag = 1;
                break;
            case 'n':
                if(sscanf(optarg, "%d", &num) == EOF){
                    fprintf(stderr, "error matching argument num\n");
                    exit(-1);
                }
                break;
            default:
                fprintf(stderr, "Wrong argument given.\n");
                exit(-1);
        }
    }
    //checking mandatory option
    if(interface == NULL){
        //missing -i
        print_available_devices();
        exit(0);
    }

    //variables for sniffing
    char errbuf[PCAP_ERRBUF_SIZE];

    //setting filter string
    if(port){
        if(udp_flag){
            sprintf(filter_str, "port %s && udp", port);
        }else if(tcp_flag){
            sprintf(filter_str, "port %s && tcp", port);
        }else{
            sprintf(filter_str, "port %s && tcp || udp", port);
        }
    }else{
        if(udp_flag){
            sprintf(filter_str, "udp");
        }else if(tcp_flag){
            sprintf(filter_str, "tcp");
        }else{
            sprintf(filter_str, "tcp || udp");
        }
    }

    //opening sniffer
    handler = pcap_open_live(interface, 65536, 0, 5000, errbuf);
    if(handler == NULL){
        fprintf(stderr, "%s\n", errbuf);
        exit(-1);
    }
    //setting filter
    if(pcap_compile(handler, &bp, filter_str, 0, 0) == -1){
        fprintf(stderr, "Couldn't compile the filter\n");
        exit(-1);
    }
    if(pcap_setfilter(handler, &bp) == -1){
        fprintf(stderr, "Couldn't set the filter\n");
        exit(-1);
    }
    //infinite loop
    pcap_dispatch(handler, num, read_packet, NULL);
    //TODO make timeout ^
    
    pcap_close(handler);
    pcap_freecode(&bp);

    return 0;
}
