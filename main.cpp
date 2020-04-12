/*
 * 1. Ethernet Header's src mac & dst mac
 * 2. IP Header's src ip & dst ip
 * 3. TCP Header's src port & dst port
 * 4. Payload(data)'s hexadecimal value(max 16byte)
 */
#include <pcap.h> //pcap library
#include <stdio.h>
#include <stdlib.h> //for exit
#include <arpa/inet.h> // for inet_ntoa
#include <libnet.h>
#include <netinet/in.h> //in_addr

#define ETHERTYPE_IP    0x0800

struct ethernet_str {
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t type;
};

struct ipv4_str {
    uint8_t ip_ver_hdlen; // version 4, headerlength
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
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t tcp_offR;
    uint8_t tcp_flags;
    uint16_t tcp_win;
    uint16_t tcp_sum;
    uint16_t tcp_up;
};

void print_mac(uint8_t const ether_mac[6]) {
    for (int i=0; i<6; i++) {
        printf("%02X", ether_mac[i]);
        if(i<5) printf(":");
    }
    printf("\n");
}

void print_ip(uint8_t const ip4[4]) {
    for (int i=0; i<4; i++) {
        printf("%u", ip4[i]);
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

        struct ethernet_str *eth_h = (struct ethernet_str*)packet;
        if (htons(eth_h->type) == ETHERTYPE_IP) {
            struct ipv4_str *ip4_h = (struct ipv4_str*)(packet+sizeof(ethernet_str));
            int ip_hlen = (ip4_h->ip_ver_hdlen & 0x0F)*4;
            // condition(?) ip header -> tcp header? 0x06 protocol. only tcp packet.
            if ((ip4_h->ip_p) == 0x06) {
                struct tcp_str *tcp_h =(struct tcp_str*)(packet+ip_hlen+sizeof(ethernet_str));
                int tcp_hlen = ((tcp_h->tcp_offR & 0xF0)>>4)*4;

                printf("\n------------------------------------------------------\n");
                printf("Destination MAC : ");
                print_mac(eth_h->ether_dhost);
                printf("Source MAC : ");
                print_mac(eth_h->ether_shost);

                printf("Source IP : ");
                print_ip(ip4_h->ip_src);
                printf("Destination IP : ");
                print_ip(ip4_h->ip_dst);

                printf("Source Port Number      : %d\n", ntohs(tcp_h->port_src));
                printf("Destination Port Number : %d\n", ntohs(tcp_h->port_dst));

                const u_char *data_payload = packet + sizeof(ethernet_str) + ip_hlen + tcp_hlen;
                int data_len = ntohs(ip4_h->ip_total_len) - tcp_hlen - ip_hlen;
                if (data_len > 0) {
                    printf(" Data \n -> ");
                    if (data_len < 16) {
                        for (int i=0; i<data_len; i++) {
                            printf("%02X ", *data_payload);
                            data_payload++;
                        }
                    } else if (data_len > 16) {
                        for (int i=0; i<16; i++) {
                            printf("%02X ", *data_payload);
                            data_payload++;
                        }
                    }
                }

            }
        }
    }

    pcap_close(handle);
    return 0;
}

