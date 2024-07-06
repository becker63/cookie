#include "includes/map.h"

/**
 * Constructs a sequence of TCP packets based on the given TCP header and thread map.
 *
 * @param tcp Pointer to the TCP header.
 * @param tm Pointer to the thread map.
 *
 * @return void
 *
 * @throws None
 */
void construct_seq(const struct tcp_header *tcp, thread_mapt *tm) {
    int key = tcp->th_sport+tcp->th_dport;
    linknode_t *head = map_get(tm, key);
    printf("checking if packet %d already exits: \n", key);
    if(head == NULL){
        printf("not in map: adding\n");
        head = create_new_node(tcp);
        map_set(tm, key, head);
    } else {
        printf("in map: appending to stream\n");
        append(&head, tcp);
        map_set(tm, key, head);
    }

    linknode_t *cur = head;
    while(cur != NULL) {
        printf("ack: %d seq: %d\n", cur->value->th_ack, cur->value->th_sequenceNumber);
        cur = cur->next;
    }
};
