#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "includes/map.h"

// map part
static int hash(thread_mapt *m, int key){
    return key % m->cap;
}

/**
 * Retrieves the value associated with the given key in the map.
 *
 * @param m A pointer to the map.
 * @param key The key to retrieve the value for.
 *
 * @return The value associated with the given key, or NULL if the key is not found.
 */
linknode_t* map_get(thread_mapt *m, int key){
    int pos = hash(m, key);
    nodet *list = m->list[pos];
    nodet *temp = list;
    while(temp){
        if(temp->key == key){
            return temp->val;
        }
        temp = temp->next;
    }
    return 0;
}

/**
 * Resizes the given thread map to a new capacity.
 *
 * @param m A pointer to the thread map to be resized.
 * @param new_cap The new capacity for the thread map.
 *
 * @return True if the resize operation is successful, false otherwise.
 *
 * @throws None
 */
bool map_resize(thread_mapt *m, int new_cap)
{
    thread_mapt *nm = map_new(new_cap);
    if (!nm) {
        return -1;
    }

    for (int i = 0; i < m->len; i++) {
        struct node *list = m->list[i];
        struct node *temp = list;
        while (temp) {
            int st = map_set(nm, temp->key, temp->val);
            if (st != 0) {
                return false;
            }
            temp = temp->next;
        }
    }

    list_free(*m->list);
    *m = *nm;
    return true;
}
/**
 * Inserts a packet in the threadmap.
 *
 * @param m A pointer to the thread map to be resized.
 * @param in_key key for map.
 * @param val the tcp packet to insert.
 * 
 * @return True if the resize operation is successful, false otherwise.
 *
 * @throws None
 */
bool map_set(thread_mapt *m, int in_key, linknode_t *val){
    // check if map needs to resized, fail if needed
    if (m->len == m->cap) {
        if (map_resize(m, m->cap*2) == false) {
            return false;
        }
    }

    // check if node already exists to set
    int pos = hash(m, in_key);
    nodet *list = m->list[pos];
    nodet *temp = list;
    while(temp){
        if(temp->key == in_key){
            temp->val = val;
        }
        temp = temp->next;
    }

    // make a new node
    struct node *new = malloc(sizeof(struct node));
    if (!new) {
        return false;
    }
    memset(new, 0, sizeof(struct node));
    new->key = in_key;
    new->val = val;
    new->next = list;
    m->list[pos] = new;
    m->len++;
    return true;
}

bool map_del(thread_mapt *m, int key) {
    int pos = hash(m, key);
    struct node **n = &m->list[pos];
    while (*n) {
        struct node *temp = *n;
        if (temp->key == key) {
            *n = temp->next;
            break;
        } else {
            temp = (*n)->next;
        }
    }
    m->len--;
    return true;
}

int map_len(thread_mapt *m) {
    int items = 0;
    for (int i = 0; i < m->cap; i++) {
        if (!m->list[i]) {
            items++;
        }
    }
    return items;
}

thread_mapt* map_new(const unsigned int size){
    thread_mapt *m = malloc(sizeof(thread_mapt));
    if (!m) {
        return NULL;
    }
    memset(m, 0, sizeof(thread_mapt));
    m->cap = size;

    m->len = 0;
    m->list = calloc(sizeof(struct node*), m->cap);
    for (int i = 0; i < m->cap; i++) {
        m->list[i] = NULL;
    }
    return m;
}

void list_free(nodet *n){
    if(!n){
        return;
    }
    nodet *tmp;
    while(n != NULL){
        tmp = n;
        free(tmp->val);
        free(tmp);
        n = n->next;
    }
    free(n);
}

void map_free(thread_mapt *m){
    if (!m) {
        return;
    }
    if (m->list) {
        list_free(*m->list);
    }
    free(m);
}



// linked list part
linknode_t* create_new_node(struct tcp_header *value){
    linknode_t *result = malloc(sizeof(linknode_t));
    result->value = value;
    result->next = NULL;
    return result;
}

linknode_t* insert_at_head(linknode_t *head, linknode_t *linknode_to_insert){
    linknode_to_insert->next = head;
    return linknode_to_insert;
}

/**
 * Inserts a packet in the threadmap.
 *
 * @param head a double pointer to the head of the list.
 * @param value the tcp packet to insert.
 *
 * @throws None
 */
void append(linknode_t** head, struct tcp_header *value){
    // https://stackoverflow.com/questions/58064683/how-to-change-a-pointer-value-between-functions
    linknode_t* tmp = create_new_node(value);
    *head = insert_at_head(*head, tmp);
}
