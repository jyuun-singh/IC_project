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
  
  return 0;
}
