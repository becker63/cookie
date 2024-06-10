#include <pcap.h>
#include <stdlib.h>
#include "includes/pcapHelpers.h"
#include "includes/packetStructures.h"
#include "includes/helpers.h"
#include <string.h>
#include <signal.h>
#include <stdbool.h>

char errbuf[PCAP_ERRBUF_SIZE] = {0};

struct bpf_program fp;

/*
returns the default interface
the pcap helper that is supposed to do this is depricated (pcap_lookupdev) so I rewrote it
*/
char *findDefaultDevice()
{

	pcap_if_t *ift = NULL;

	if (pcap_findalldevs(&ift, errbuf) == 0)
	{
		char *int_name = strdup(ift->name);
		printf("reading from default interface: %s\n", int_name);
		pcap_freealldevs(ift);
		return (int_name);
	}
	else
	{
		printf("error: %x\n", errbuf);
		exit(-1);
	}
}

maskIp getDeviceInfo(char *name)
{

	maskIp ret;
	if (pcap_lookupnet(name, &ret.ip, &ret.mask, errbuf) == -1)
	{
		printf("Couldn't get netmask or ip for device %s: %s\n", name, errbuf);
	}
	return ret;
};

pcap_t *handleOpen(char *name)
{

	pcap_t *handle;

	handle = pcap_open_live(name, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s, %s\n", name, errbuf);
		exit(2);
	}
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", name);
		exit(2);
	}
	return handle;
}

int compileAndSetFilter(pcap_t *handle, char *filter, bpf_u_int32 ip)
{
	if (pcap_compile(handle, &fp, filter, 0, ip) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		return (2);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		return (2);
	}
	return 1;
}

void cleanUp(int sig, pcap_t *ptr)
{
	static pcap_t *handle = NULL;
	if (handle == NULL)
	{
		handle = ptr;
	}

	if (sig == SIGINT)
	{
		signal(sig, SIG_IGN);
		printf("\n\ncleaning up...\n");
		pcap_breakloop(handle);
		pcap_close(handle);
		exit(0);
	}
}

void print_hex_ascii_line(const uint8_t *payload, int len, int offset)
{

	int i;
	int gap;
	const uint8_t *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++)
	{
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16)
	{
		gap = 16 - len;
		for (i = 0; i < gap; i++)
		{
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++)
	{
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const uint8_t *payload, int len)
{

	int len_rem = len;
	int line_width = 16; /* number of bytes per line */
	int line_len;
	int offset = 0; /* zero-based offset counter */
	const uint8_t *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width)
	{
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;;)
	{
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width)
		{
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void print_flags(uint8_t th_flag)
{
	if (th_flag & TH_FIN)
	{
		printf("TH_FIN ");
	};
	if (th_flag & TH_SYN)
	{
		printf("TH_SYN ");
	};
	if (th_flag & TH_RST)
	{
		printf("TH_RST ");
	};
	if (th_flag & TH_PUSH)
	{
		printf("TH_PUSH ");
	};
	if (th_flag & TH_ACK)
	{
		printf("TH_ACK ");
	};
	if (th_flag & TH_URG)
	{
		printf("TH_URG ");
	};
	if (th_flag & TH_ECE)
	{
		printf("TH_ECE ");
	};
	if (th_flag & TH_CWR)
	{
		printf("TH_CWR ");
	};
}

void print_packet(const struct tcp_header *tcp, const struct ip_header *ip, const char *payload, int size_payload)
{
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* print extra info*/
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	printf("   syn: %lu\n", ntohl(tcp->th_sequenceNumber));
	printf("   ack: %lu\n", ntohl(tcp->th_ack));

	/* print flags*/
	printf("   flag: %x ", tcp->th_flags);
	print_flags(tcp->th_flags);
	puts("\n");

	if (size_payload > 0)
	{
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
}

bool stream_in_arr(struct tcp_streams **tcp_streams, uint16_t id)
{
	if(tcp_streams == NULL){
		return false;
	}
	for (int i; i < MAX_TCP_STREAMS; i++)
	{
		if (tcp_streams[i]->port_id == id)
		{
			return true;
		}
	}
	return false;
}

void print_streams(struct tcp_streams **tcp_streams, uint16_t id){

		for(int i2; i2 < MAX_TCP_STREAM_PKTS; i2++) {
			printf("src: %d", tcp_streams[id]->stream[i2]->th_sport);
			printf("dst: %d", tcp_streams[id]->stream[i2]->th_dport);
		}

}

void construct_seq(
	const struct tcp_header *tcp,
	struct tcp_streams **tcp_streams)
{
	uint16_t id = tcp->th_sport + tcp->th_dport;
	struct tcp_streams *tcp_stream;
	tcp_stream = malloc(sizeof(struct tcp_streams));

	if (stream_in_arr(tcp_streams, id)){
		printf("stream already exists, adding new packets to stream");
		tcp_stream = tcp_streams[id];
	}
	else {
		printf("making new stream");
		tcp_stream->port_id = id;
		tcp_stream->stream = malloc(sizeof(struct tcp_header *) * MAX_TCP_STREAM_PKTS);
		tcp_stream->cur_index = 0;
		// this index is out of range, need to figure out how to turn this into actual hashmap
		tcp_streams[id] = tcp_stream;
	}

	tcp_stream->stream[tcp_stream->cur_index] = tcp;
	tcp_stream->cur_index += 1;
	
	print_streams(tcp_streams, id);
}

void err_handle_packet(
    uint8_t *tcp_streams, 
	const struct pcap_pkthdr *header, 
	const uint8_t *packet
    )
{

	static int count = 1; /* packet counter */

	/* declare pointers to packet headers */
	const struct ethernet_header *ethernet; /* The ethernet header [1] */
	const struct ip_header *ip;				/* The IP header */
	const struct tcp_header *tcp;			/* The TCP header */
	char *payload;							/* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct ethernet_header *)(packet);

	/* define/compute ip header offset */
	ip = (struct ip_header *)(packet + ETHERNET_HEADER_SIZE);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20)
	{
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	if (ip->ip_protocol != IPPROTO_TCP)
	{
		return;
	}

	/* define/compute tcp header offset */
	tcp = (struct tcp_header *)(packet + ETHERNET_HEADER_SIZE + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20)
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	/* define/compute tcp payload (segment) offset */
	payload = (uint8_t *)(packet + ETHERNET_HEADER_SIZE + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_length) - (size_ip + size_tcp);

	// print_packet(tcp, ip, payload, size_payload);

	construct_seq(tcp, (struct tcp_streams**)tcp_streams);

	return;
}
