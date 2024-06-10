#include <stdio.h>
#include <pcap.h>
#include "includes/pcapHelpers.h"
#include "includes/helpers.h"
#include "includes/packetStructures.h"
#include <sys/types.h>
#include <stdbool.h>
#include  <signal.h>

// https://www.tcpdump.org/pcap.html

int main(int, char **)
{
    /* init */
    // char *name = findDefaultDevice();
    char *name = "lo";
    maskIp maskIp = getDeviceInfo(name);
    pcap_t *handle = handleOpen(name);


    /* filter */
    compileAndSetFilter(handle, "port 3005", maskIp.ip); 

    /* Now do work */

    // note.. this signal is UB https://stackoverflow.com/a/43400143. but useful!
    signal(SIGINT, (void (*)(int))cleanUp);
    cleanUp(FAKE_SIGNAL, handle);

    // arr of pointers to tcp streams (to be turned into a circular buffer later)
    struct tcp_streams **tcp_streams = malloc(sizeof(struct tcp_streams *) * MAX_TCP_STREAMS);

    pcap_loop(handle, -1, (pcap_handler)err_handle_packet, (uint8_t*)tcp_streams);
    return 0;
}