/*
 * Copyright (c) 2011 by Daniel C. Jones <dcjones@cs.washington.edu>
 *
 * hash :
 * A quick and simple hash table mapping strings to things.
 *
 */


#ifndef ISOLATOR_STR_MAP_H
#define ISOLATOR_STR_MAP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#include "common.h"


typedef struct str_map_pair_
{
    char*         key;
    size_t        keylen;
    value_t       value;

    struct str_map_pair_* next;
} str_map_pair;


typedef struct
{
    str_map_pair** A; /* table proper */
    size_t n;         /* table size */
    size_t m;         /* hashed items */
    size_t max_m;     /* max hashed items before rehash */
} str_map;



str_map* str_map_create(void);
void     str_map_destroy(str_map*);
void     str_map_set(str_map*, const char* key, size_t keylen, value_t value);
value_t  str_map_get(const str_map*, const char* key, size_t keylen);
void     str_map_del(str_map* T, const char* key, size_t keylen);

#if defined(__cplusplus)
}
#endif

#endif

