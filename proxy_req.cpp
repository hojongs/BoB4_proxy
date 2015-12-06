#include <stdlib.h>
#include <string.h>

#include <unistd.h> //sleep
#include <pthread.h>
#include <stdint.h> //uintxx_t
#include <pcap.h>
#include <sys/socket.h> //ethhdr -> ifru_addr
#include <linux/if_ether.h> //ethhdr
#include <netinet/ether.h> //ether_ntoa
#include <netinet/ip.h> //iphdr
#include <netinet/tcp.h> //iphdr
#include <netinet/udp.h> //iphdr

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define ICMPHDR_LEN 8
#define DST_IP "8.8.8.8"


