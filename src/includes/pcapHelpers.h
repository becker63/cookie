#include <pcap.h>
#include "map.h"

char* findDefaultDevice();
pcap_t* handleOpen(char* name);

typedef struct {
    bpf_u_int32 mask;
    bpf_u_int32 ip;
} maskIp;
maskIp getDeviceInfo(char* name);

int compileAndSetFilter(pcap_t *handle, char* filter, bpf_u_int32 ip);

#define FAKE_SIGNAL 99
void cleanUp(int sig, pcap_t* handle);

void err_handle_packet(
    thread_mapt ** tcp_streams,
	const struct pcap_pkthdr *header,
	const uint8_t *packet
    );

void print_payload(const uint8_t *payload, int len);

struct tcp_stream {
        // combine dest and src port together to make an id for the stream
        uint16_t port_id;
        tcp_seq current_seq;
        int tcp_header_index;
};

struct ip_addr
{
    unsigned char one;
    unsigned char two;
    unsigned char three;
};

char* formatIP(bpf_u_int32 ip);

void construct_seq(
	const struct tcp_header *tcp,
	thread_mapt *tm);
