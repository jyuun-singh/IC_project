#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <time.h>

void print_header(FILE *f) {
    fprintf(f, "Protocol | Source IP       | SrcPort | Destination IP | DstPort | Info\n");
    fprintf(f, "-------------------------------------------------------------------------------\n");
}

int main(){
    
    unsigned char buffer[65536];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock<0){ perror("Socket"); return 1;}

    // Timestamp log file
    char fname[64];
    time_t now = time(NULL);
    strftime(fname, sizeof(fname), "capture_%Y%m%d_%H%M%S.txt", localtime(&now));
    FILE *f = fopen(fname, "w");
    if (!f) { perror("fopen"); return 1; }

    print_header(f);

    for(int i = 0; i<60 ; i++) {

        int len = recvfrom(sock, buffer, sizeof(buffer), 0,
                            &saddr, (socklen_t *)&saddr_len);
        if (len < 0) { perror("recvfrom"); break;}

        struct ethhdr *eth = (struct ethhdr *)buffer;

        /* ARP  */
        if(ntohs(eth->h_proto) == ETH_P_ARP) {
            struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ethhdr));

            fprintf(f, "ARP     | %-15s |   -   | %-15s |   -   | ARP Who-has/Reply\n",
                    inet_ntoa(*(struct in_addr *)arp->arp_spa),
                    inet_ntoa(*(struct in_addr *)arp->arp_tpa));
            continue;
        }


        Switch (iph->protocol) {
            
        }
    }

    fclose(f);
    close(sock);
    return 0;
}
