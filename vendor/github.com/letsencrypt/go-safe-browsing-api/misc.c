/*
 * This file is part of hat-trie.
 *
 * Copyright (c) 2011 by Daniel C. Jones <dcjones@cs.washington.edu>
 *
 */

#include "misc.h"
#include <stdlib.h>


void* malloc_or_die(size_t n)
{
    void* p = malloc(n);
    if (p == NULL && n != 0) {
        fprintf(stderr, "Cannot allocate %zu bytes.\n", n);
        exit(EXIT_FAILURE);
    }
    return p;
}


void* realloc_or_die(void* ptr, size_t n)
{
    void* p = realloc(ptr, n);
    if (p == NULL && n != 0) {
        fprintf(stderr, "Cannot allocate %zu bytes.\n", n);
        exit(EXIT_FAILURE);
    }
    return p;
}


FILE* fopen_or_die(const char* path, const char* mode)
{
    FILE* f = fopen(path, mode);
    if (f == NULL) {
        fprintf(stderr, "Cannot open file %s with mode %s.\n", path, mode);
        exit(EXIT_FAILURE);
    }
    return f;
}




