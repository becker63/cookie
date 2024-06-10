#include <pcap.h>

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
    uint8_t *tcp_streams, 
	const struct pcap_pkthdr *header, 
	const uint8_t *packet
    );

void print_payload(const uint8_t *payload, int len);
