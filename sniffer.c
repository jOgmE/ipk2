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
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

//global variables :peepocry
static int tcp_flag = 0;
static int udp_flag = 0;
int port = -1;

void print_data(const u_char *data, int data_size, int *offset){
    for(int i=0; i<data_size;i++){
        //print 16 char represented data
        if(i!= 0 && i%16==0){
            for(int j=i-16; j<i;j++){
                if(j%8 == 0) printf(" ");
                if(data[j] >= 32 && data[j] <= 128){ //printable char
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
                if(data[j] >= 32 && data[j] <= 128){ //printable char
                    printf("%c", (unsigned char)data[j]);
                }
                else printf("."); //non printable char
            }
            printf("\n");
        }
    }
}

void print_tcp(const u_char *buffer, int size, struct tm *time, suseconds_t usec){
    //      --VARIABLES--
    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    char srcHost[NI_MAXHOST] = {0};
    char destHost[NI_MAXHOST] = {0};
    char srcPortChar[6];
    char destPortChar[6];
    u_int srcPort, destPort;
    struct addrinfo *sinfo;//, *dinfo;

    //      --IP_HEADER--
    struct iphdr *iphead = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short ipheadlen = iphead->ihl*4;
    //src dest IP
    inet_ntop(AF_INET, &(iphead->saddr), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iphead->daddr), destIP, INET_ADDRSTRLEN);

    //      --TCP_HEADER--
    struct tcphdr *tcphead = (struct tcphdr*)(buffer + ipheadlen + sizeof(struct ethhdr));
    int tcpheadlen = sizeof(struct ethhdr) + ipheadlen + tcphead->doff*4;
    //src dest PORT
    srcPort = ntohs(tcphead->source);
    destPort = ntohs(tcphead->dest);
    sprintf(srcPortChar, "%u", srcPort);
    sprintf(destPortChar, "%u", destPort);

    //      --GET_HOST_NAME--
    getaddrinfo(srcIP, srcPortChar, NULL, &sinfo);
    getnameinfo(sinfo->ai_addr, sinfo->ai_addrlen, srcHost, NI_MAXHOST, NULL, 0, 0);

    getaddrinfo(destIP, destPortChar, NULL, &sinfo);
    getnameinfo(sinfo->ai_addr, sinfo->ai_addrlen, destHost, NI_MAXHOST, NULL, 0, 0);

    //cleaning
    freeaddrinfo(sinfo);

    //      --PRINTING--
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

    const u_char *data = buffer + tcpheadlen;
    int data_size = size - tcpheadlen;

    //printing header
    int offset = 0;
    print_data((const u_char *)tcphead, tcpheadlen, &offset);
    printf("\n");
    //printing packet data
    print_data(data, data_size, &offset);
}

void print_udp(const u_char *buffer, int size, struct tm *time, suseconds_t usec){
    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    char srcHost[NI_MAXHOST] = {0};
    char destHost[NI_MAXHOST]= {0};
    char srcPortChar[6];
    char destPortChar[6];
    u_int srcPort, destPort;
    struct addrinfo *sinfo;//, *dinfo;

    struct iphdr *iphead = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short ipheadlen = iphead->ihl*4;

    struct udphdr *udphead = (struct udphdr*)(buffer + ipheadlen + sizeof(struct ethhdr));
    int udpheadlen = sizeof(struct ethhdr) + ipheadlen + udphead->len;

    srcPort = ntohs(udphead->source);
    destPort = ntohs(udphead->dest);
    sprintf(srcPortChar, "%u", srcPort);
    sprintf(destPortChar, "%u", destPort);

    //      --GET_HOST_NAME--
    getaddrinfo(srcIP, srcPortChar, NULL, &sinfo);
    getnameinfo(sinfo->ai_addr, sinfo->ai_addrlen, srcHost, NI_MAXHOST, NULL, 0, 0);

    getaddrinfo(destIP, destPortChar, NULL, &sinfo);
    getnameinfo(sinfo->ai_addr, sinfo->ai_addrlen, destHost, NI_MAXHOST, NULL, 0, 0);

    //cleaning
    freeaddrinfo(sinfo);

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
    const u_char *data = buffer + udpheadlen;
    int data_size = size - udpheadlen;

    //printing header
    int offset = 0;
    print_data((const u_char *)udphead, udpheadlen, &offset);
    printf("\n");
    //printing packet data
    print_data(data, data_size, &offset);
}

void read_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
    //counter for packages
    int pkg_counter = 0;
    int size = h->len;
    struct tm *time;

    struct iphdr *iphead = (struct iphdr*)(bytes + sizeof(struct ethhdr));
    if(iphead->protocol == 6 && tcp_flag){ //TCP
        time = localtime(&(h->ts.tv_sec));
        print_tcp(bytes, size, time, h->ts.tv_usec);
        ++pkg_counter;
    }else if(iphead->protocol == 17 && udp_flag){ //UDP
        time = localtime(&(h->ts.tv_sec));
        print_udp(bytes, size, time, h->ts.tv_usec);
        ++pkg_counter;
    }

    if(pkg_counter) printf("\n");
    else pkg_counter++;
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
    int num = 1;
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
                if(sscanf(optarg, "%d", &port) == EOF){
                    fprintf(stderr, "error matching argument port\n");
                    exit(-1);
                }
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
    //both unset, printing both
    if(!tcp_flag && !udp_flag){
        tcp_flag = 1;
        udp_flag = 1;
    }

    //variables for sniffing
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handler;

    //doing sniff
    handler = pcap_open_live(interface, 65536, 1, 0, errbuf);
    if(handler == NULL){
        fprintf(stderr, "%s\n", errbuf);
        exit(-1);
    }
    pcap_loop(handler, num, read_packet, NULL);

    return 0;
}
