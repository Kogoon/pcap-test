/*
 * 1. Ethernet Header's src mac & dst mac
 * 2. IP Header's src ip & dst ip
 * 3. TCP Header's src port & dst port
 * 4. Payload(data)'s hexadecimal value(max 16byte)
 */
#include <pcap.h> //pcap library
#include <stdio.h>
//#include <./libnet/libnet-headers.h> // for libnet structure
#include <stdlib.h> //for exit
#include <arpa/inet.h> // for inet_ntoa
//#include <netinet/ip.h> //for ip , iphdr, ip_addr
#include <libnet.h>

//#define IPv4 0x0800
//#define ARP 0x0806

void usage() {
    printf("syntax : pcap-test <interface>\n");
    printf("sample : pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if(argc != 2){
        usage();
        return -1;
    }

    char* dev = argv[1]; // name of device : ex) eth0, wlan0, my device
    char errbuf[PCAP_ERRBUF_SIZE];

    //pcap_t* pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //65536
    if (handle == nullptr) { //professor .c NULL .cpp nullptr
        fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
        //how to use fprintf?
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
            // pcap_next_ex : pcap receive, how?
            break;
        }

        // requirement libnet-headers.h
        struct libnet_ethernet_hdr *eth_h; // use libnet_ethernet_hdr struct in libnet
        struct libnet_ipv4_hdr *ip4_h; // use libnet_ipv4_hdr struct
        struct libnet_tcp_hdr *tcp_h; // use libnet_tcp_hdr struct

        eth_h = (struct libnet_ethernet_hdr*)packet;
        ip4_h = (struct libnet_ipv4_hdr*)packet;
        tcp_h = (struct libnet_tcp_hdr*)packet;

        // condition(?) ip header -> tcp header? 0x06 protocol. only tcp packet.
        if ((ip4_h->ip_p) == 0x06) {

            // src mac, dst mac / eth_h->ether_shost, eth_h->ether_dhost
            printf("\n-------------------------------------------------------n");
            printf("destination mac : %02X:%02X:%02X:%02X:%02X:%02X\n", eth_h->ether_dhost[0], eth_h->ether_dhost[1], eth_h->ether_dhost[2],
                    eth_h->ether_dhost[3], eth_h->ether_dhost[4], eth_h->ether_dhost[5]);
            printf("source mac      : %02X:%02X:%02X:%02X:%02X:%02X\n", eth_h->ether_shost[0], eth_h->ether_shost[1], eth_h->ether_shost[2],
                    eth_h->ether_shost[3], eth_h->ether_shost[4], eth_h->ether_shost[5]);

            // src ip, dst ip / ip4_h->ip_src, ip4_h->ip_dst
            printf("\n-------------------------------------------------------n");
            printf("Source IP      : %s\n", inet_ntoa(ip4_h->ip_src));
            printf("Destination IP : %s\n", inet_ntoa(ip4_h->ip_dst));

            // src port_n, dst port_n / tcp_h->th_sport, tcp_h->th_dport
            printf("\n-------------------------------------------------------n");
            printf("Source Port Number      : \n");
            printf("Destination Port Number : \n");

        }
    }

    pcap_close(handle);
    return 0;
}

