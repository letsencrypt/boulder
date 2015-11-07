
TESTS = check_ahtable check_hattrie
check_PROGRAMS = check_ahtable check_hattrie bench_sorted_iter

check_ahtable_SOURCES  = check_ahtable.c str_map.c
check_ahtable_LDADD    = $(top_builddir)/src/libhat-trie.la
check_ahtable_CPPFLAGS = -I$(top_builddir)/src

check_hattrie_SOURCES  = check_hattrie.c str_map.c
check_hattrie_LDADD    = $(top_builddir)/src/libhat-trie.la
check_hattrie_CPPFLAGS = -I$(top_builddir)/src

bench_sorted_iter_SOURCES  = bench_sorted_iter.c
bench_sorted_iter_LDADD    = $(top_builddir)/src/libhat-trie.la
bench_sorted_iter_CPPFLAGS = -I$(top_builddir)/src
