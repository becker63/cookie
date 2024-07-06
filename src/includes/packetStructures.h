#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default packet length (maximum bytes per packet to capture) */
#define PACKET_LENGTH 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define ETHERNET_HEADER_SIZE 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct ethernet_header {
        uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        uint16_t ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
        uint8_t  ip_version;                 /* version << 4 | header length >> 2 */
        uint8_t  ip_typeOfService;                 /* type of service */
        uint16_t ip_length;                 /* total length */
        uint16_t ip_id;                  /* identification */
        uint16_t ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        uint8_t  ip_ttl;                 /* time to live */
        uint8_t  ip_protocol;                   /* protocol */
        uint16_t ip_checkSum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)  (((ip)->ip_version) & 0x0f)
#define IP_V(ip)   (((ip)->ip_version) >> 4)

/* TCP header */
typedef int tcp_seq;

struct tcp_header {
        uint16_t th_sport;               /* source port */
        uint16_t th_dport;               /* destination port */
        tcp_seq th_sequenceNumber;       /* sequence number */
        tcp_seq th_ack;                  /* acknowledgement number */
        uint8_t  th_dataOffset;          /* data offset, rsvd */
#define TH_OFF(th)   (((th)->th_dataOffset & 0xf0) >> 4)
        uint8_t  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        uint16_t th_window;                 /* window */
        uint16_t th_checksum;               /* checksum */
        uint16_t th_urgentPointer;          /* urgent pointer */
};

#define MAX_TCP_STREAMS 100
#define MAX_TCP_STREAM_PKTS 100

extern int tcp_streams_index;
