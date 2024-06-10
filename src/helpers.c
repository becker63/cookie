#include <pcap.h>
#include <stdio.h>

struct ip_addr
{
    unsigned char one;
    unsigned char two;
    unsigned char three;
};

char* formatIP(bpf_u_int32 ip)
{
    static char ipstr[11];
    struct ip_addr *ptr = (struct ip_addr *)&ip;
    snprintf(ipstr, 11, "%d.%d.%d", ptr->one, ptr->two, ptr->three);
    return ipstr;
}