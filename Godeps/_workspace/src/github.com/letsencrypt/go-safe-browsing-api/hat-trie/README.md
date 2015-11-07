
Hat-Trie
========

[![Build Status](https://travis-ci.org/dcjones/hat-trie.svg)](https://travis-ci.org/dcjones/hat-trie)

This a ANSI C99 implementation of the HAT-trie data structure of Askitis and
Sinha, an extremely efficient (space and time) modern variant of tries.

The version implemented here maps arrays of bytes to words (i.e., unsigned
longs), which can be used to store counts, pointers, etc, or not used at all if
you simply want to maintain a set of unique strings.

For details see,

  1. Askitis, N., & Sinha, R. (2007). HAT-trie: a cache-conscious trie-based data
     structure for strings. Proceedings of the thirtieth Australasian conference on
     Computer science-Volume 62 (pp. 97–105). Australian Computer Society, Inc.

  2. Askitis, N., & Zobel, J. (2005). Cache-conscious collision resolution in
     string hash tables. String Processing and Information Retrieval (pp.
     91–102). Springer.


Installation
------------

    git clone git@github.com:dcjones/hat-trie.git
    cd hat-trie
    autoreconf -i
    ./configure
    make install

To use the library, include `hat-trie.h` and link using `-lhat-trie`.


Tests
-----

Build and run the tests:

    make check

Other Language Bindings
-----------------------
 * Ruby - https://github.com/luikore/triez
 * Python - https://github.com/kmike/hat-trie
