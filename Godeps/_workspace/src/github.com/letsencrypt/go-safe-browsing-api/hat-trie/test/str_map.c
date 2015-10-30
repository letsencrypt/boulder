
/*
 * This file is part of fastq-tools.
 *
 * Copyright (c) 2011 by Daniel C. Jones <dcjones@cs.washington.edu>
 *
 */


#include "str_map.h"
#include "misc.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


static const size_t INITIAL_TABLE_SIZE = 16;
static const double MAX_LOAD = 0.77;


/*
 * Paul Hsieh's SuperFastHash
 * http://www.azillionmonkeys.com/qed/hash.html
 */


#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
    || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
        +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

static uint32_t hash(const char * data, size_t len) {
    uint32_t hash = len, tmp;
    int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= data[sizeof (uint16_t)] << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += *data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}



static void rehash(str_map* T, size_t new_n);
static void clear(str_map*);



str_map* str_map_create()
{
    str_map* T = malloc_or_die(sizeof(str_map));
    T->A = malloc_or_die(INITIAL_TABLE_SIZE * sizeof(str_map_pair*));
    memset(T->A, 0, INITIAL_TABLE_SIZE * sizeof(str_map_pair*));
    T->n = INITIAL_TABLE_SIZE;
    T->m = 0;
    T->max_m = T->n * MAX_LOAD;

    return T;
}


void str_map_destroy(str_map* T)
{
    if (T != NULL) {
        clear(T);
        free(T->A);
        free(T);
    }
}



void clear(str_map* T)
{
    str_map_pair* u;
    size_t i;
    for (i = 0; i < T->n; i++) {
        while (T->A[i]) {
            u = T->A[i]->next;
            free(T->A[i]->key);
            free(T->A[i]);
            T->A[i] = u;
        }
    }

    T->m = 0;
}


static void insert_without_copy(str_map* T, str_map_pair* V)
{
    uint32_t h = hash(V->key, V->keylen) % T->n;
    V->next = T->A[h];
    T->A[h] = V;
    T->m++;
}



static void rehash(str_map* T, size_t new_n)
{
    str_map U;
    U.n = new_n;
    U.m = 0;
    U.max_m = U.n * MAX_LOAD;
    U.A = malloc_or_die(U.n * sizeof(str_map_pair*));
    memset(U.A, 0, U.n * sizeof(str_map_pair*));

    str_map_pair *j, *k;
    size_t i;
    for (i = 0; i < T->n; i++) {
        j = T->A[i];
        while (j) {
            k = j->next;
            insert_without_copy(&U, j);
            j = k;
        }
        T->A[i] = NULL;
    }

    free(T->A);
    T->A = U.A;
    T->n = U.n;
    T->max_m = U.max_m;
}


void str_map_set(str_map* T, const char* key, size_t keylen, value_t value)
{
    if (T->m >= T->max_m) rehash(T, T->n * 2);

    uint32_t h = hash(key, keylen) % T->n;

    str_map_pair* u = T->A[h];

    while (u) {
        if (u->keylen == keylen && memcmp(u->key, key, keylen) == 0) {
            u->value = value;
            return;
        }

        u = u->next;
    }

    u = malloc_or_die(sizeof(str_map_pair));
    u->key = malloc_or_die(keylen);
    memcpy(u->key, key, keylen);
    u->keylen = keylen;
    u->value  = value;

    u->next = T->A[h];
    T->A[h] = u;

    T->m++;
}


value_t str_map_get(const str_map* T, const char* key, size_t keylen)
{
    uint32_t h = hash(key, keylen) % T->n;

    str_map_pair* u = T->A[h];

    while (u) {
        if (u->keylen == keylen && memcmp(u->key, key, keylen) == 0) {
            return u->value;
        }

        u = u->next;
    }

    return 0;
}

void str_map_del(str_map* T, const char* key, size_t keylen)
{
    uint32_t h = hash(key, keylen) % T->n;

    str_map_pair* u = T->A[h];
    str_map_pair* p = NULL;
    while (u) {
        
        if (u->keylen == keylen && memcmp(u->key, key, keylen) == 0) {
            if (p) {
                p->next = u->next;
            } else {
                T->A[h] = u->next;
            }
            free(u->key);
            free(u);
            --T->m;
            return;
        }

        p = u;
        u = u->next;
    }

}

