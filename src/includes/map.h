#include <stdbool.h>
#include "packetStructures.h"
// the primary struct with actual data


// linked list part of data structure
struct linknode {
    struct tcp_header *value;
    struct linknode* next;
};
typedef struct linknode linknode_t;

linknode_t* create_new_node(struct tcp_header *value);

linknode_t* insert_at_head(linknode_t *head, linknode_t *node_to_insert);

void append(linknode_t** head, struct tcp_header *value);



// the map stuff
typedef struct node {
   int key;
   linknode_t *val;
   struct node *next;
} nodet;

typedef struct thread_map {
   int len;
   int cap;
   struct node **list;
} thread_mapt;

static int hash(thread_mapt *m, int key);

linknode_t* map_get(thread_mapt *m, int key);

bool map_set(thread_mapt *m, int in_key, linknode_t *val);

thread_mapt* map_new(const unsigned int size);

int map_len(thread_mapt *m);

bool map_del(thread_mapt *m, int key);

void map_free(thread_mapt *m);

void list_free(nodet *n);
