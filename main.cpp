/*
 * 1. Ethernet Header's src mac & dst mac
 * 2. IP Header's src ip & dst ip
 * 3. TCP Header's src port & dst port
 * 4. Payload(data)'s hexadecimal value(max 16byte)
 */
#include <pcap.h> //pcap library
#include <stdio.h>
//#include <libnet/libnet-headers.h> // for libnet structure
#include <stdlib.h> //for exit
#include <arpa/inet.h> // for inet_ntoa
#include <libnet.h>
#include <netinet/in.h> //in_addr


struct ethernet_str {
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t type;
};

struct ipv4_str {
    uint8_t ip_ver:4, ip_hdrlen:4; // version 4, headerlength
    uint16_t ip_total_len;
    uint16_t ip_id;
    uint16_t ip_flag;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_checksum;
    //struct in_addr ip_src, ip_dst;
    uint8_t ip_src[4];
    uint8_t ip_dst[4];
};

struct tcp_str {
    uint16_t port_src;
    uint16_t port_dst;
};

void show_mac(struct ethernet_str *eth_h) {
    printf("Destination MAC : ");
    for (int i=0; i<6; i++) {
        printf("%02X", eth_h->ether_dhost[i]);
        if(i<5) printf(":");
    }
    printf("\n");
    printf("Source MAC : ");
    for (int i=0; i<6; i++) {
        printf("%02X", eth_h->ether_shost[i]);
        if(i<5) printf(":");
    }
    printf("\n");
}

void show_ip(struct ipv4_str *ip4_h) {
    printf("Source IP : ");
    for (int i=0; i<4; i++) {
        printf("%u", ip4_h->ip_src[i]);
        if(i<3) printf(".");
    }
    printf("\n");
    printf("Destination IP : ");
    for (int i=0; i<4; i++){
        printf("%u", ip4_h->ip_dst[i]);
        if(i<3) printf(".");
    }
    printf("\n");
}

void usage() {
    printf("syntax : pcap-test <interface>\n");
    printf("sample : pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if(argc != 2){
        usage();
        exit(1);
    }

    char* dev = argv[1]; // name of device : ex) eth0, wlan0, my device
    char errbuf[PCAP_ERRBUF_SIZE];

    //pcap_t* pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //65536
    if (handle == nullptr) { //professor .c NULL .cpp nullptr
        fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
        exit(1);
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int result = pcap_next_ex(handle, &header, &packet);
        // pcap_next_ex -> get packet, raw data addr -> &packet, time&len -> &header
        if (result == 0) continue;
        if (result == -1 || result == -2) {
            printf("pcap_next_ex return %d(%s)\n", result, pcap_geterr(handle));
            break;
        }

        // requirement libnet-headers.h
        struct ethernet_str *eth_h = (struct ethernet_str*)packet;
        
        if (htons(eth_h->type) == 0x0800) {
            struct ipv4_str *ip4_h = (struct ipv4_str*)(packet+14);
            // condition(?) ip header -> tcp header? 0x06 protocol. only tcp packet.
            if ((ip4_h->ip_p) == 0x06) {
                struct tcp_str *tcp_h =(struct tcp_str*)(packet+((ip4_h->ip_hdrlen)*4));
                // src mac, dst mac / eth_h->ether_shost, eth_h->ether_dhost
                printf("\n------------------------------------------------------\n");
                /*
                printf("destination mac : %02X:%02X:%02X:%02X:%02X:%02X\n", eth_h->ether_dhost[0], eth_h->ether_dhost[1], eth_h->ether_dhost[2],
                        eth_h->ether_dhost[3], eth_h->ether_dhost[4], eth_h->ether_dhost[5]);
                printf("source mac      : %02X:%02X:%02X:%02X:%02X:%02X\n", eth_h->ether_shost[0], eth_h->ether_shost[1], eth_h->ether_shost[2],
                        eth_h->ether_shost[3], eth_h->ether_shost[4], eth_h->ether_shost[5]);
                //printf("%04X\n", ntohs(eth_h->type));
                */
                show_mac(eth_h);
    
                // src ip, dst ip / ip4_h->ip_src, ip4_h->ip_dst
                //printf("\n------------------------------------------------------\n");
                //printf("Source IP      : %s\n", inet_ntoa(ip4_h->ip_src));
                //printf("Destination IP : %s\n", inet_ntoa(ip4_h->ip_dst));
                //printf("Source IP      : %u.%u.%u.%u\n", ip4_h->ip_src[0], ip4_h->ip_src[1], ip4_h->ip_src[2], ip4_h->ip_src[3]);
                //printf("Destination IP : %u.%u.%u.%u\n", ip4_h->ip_dst[0], ip4_h->ip_dst[1], ip4_h->ip_dst[2], ip4_h->ip_dst[3]);
                show_ip(ip4_h);

                // src port_n, dst port_n / posrt_src, tcp_h->port_dst
                //printf("\n------------------------------------------------------\n");
                printf("%0004X\n", tcp_h->port_src);
                printf("Source Port Number      : %u\n", tcp_h->port_src);
                printf("Destination Port Number : %u\n", tcp_h->port_dst);
    
                //for (int i=0; i<16; i++) { printf("%02X "); }

            }
        }
    }

    pcap_close(handle);
    return 0;
}

