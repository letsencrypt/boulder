/*
 * This file is part of hat-trie.
 *
 * Copyright (c) 2011 by Daniel C. Jones <dcjones@cs.washington.edu>
 *
 */

#include "hat-trie.h"
#include "ahtable.h"
#include "misc.h"
#include "pstdint.h"
#include <assert.h>
#include <string.h>

#define HT_UNUSED(x) x=x

/* maximum number of keys that may be stored in a bucket before it is burst */
static const size_t MAX_BUCKET_SIZE = 16384;
#define NODE_MAXCHAR 0xff // 0x7f for 7-bit ASCII
#define NODE_CHILDS (NODE_MAXCHAR+1)

static const uint8_t NODE_TYPE_TRIE          = 0x1;
static const uint8_t NODE_TYPE_PURE_BUCKET   = 0x2;
static const uint8_t NODE_TYPE_HYBRID_BUCKET = 0x4;
static const uint8_t NODE_HAS_VAL            = 0x8;


struct trie_node_t_;

/* Node's may be trie nodes or buckets. This union allows us to keep
 * non-specific pointer. */
typedef union node_ptr_
{
    ahtable_t*           b;
    struct trie_node_t_* t;
    uint8_t*             flag;
} node_ptr;


typedef struct trie_node_t_
{
    uint8_t flag;

    /* the value for the key that is consumed on a trie node */
    value_t val;

    /* Map a character to either a trie_node_t or a ahtable_t. The first byte
     * must be examined to determine which. */
    node_ptr xs[NODE_CHILDS];

} trie_node_t;

struct hattrie_t_
{
    node_ptr root; // root node
    size_t m;      // number of stored keys
};

/* Create a new trie node with all pointers pointing to the given child (which
 * can be NULL). */
static trie_node_t* alloc_trie_node(hattrie_t* T, node_ptr child)
{
    trie_node_t* node = malloc_or_die(sizeof(trie_node_t));
    node->flag = NODE_TYPE_TRIE;
    node->val  = 0;

    /* pass T to allow custom allocator for trie. */
    HT_UNUSED(T); /* unused now */

    size_t i;
    for (i = 0; i < NODE_CHILDS; ++i) node->xs[i] = child;
    return node;
}

/* iterate trie nodes until string is consumed or bucket is found */
static node_ptr hattrie_consume(node_ptr *p, const char **k, size_t *l, unsigned brk)
{
    node_ptr node = p->t->xs[(unsigned char) **k];
    while (*node.flag & NODE_TYPE_TRIE && *l > brk) {
        ++*k;
        --*l;
        *p   = node;
        node = node.t->xs[(unsigned char) **k];
    }

    /* copy and writeback variables if it's faster */

    assert(*p->flag & NODE_TYPE_TRIE);
    return node;
}

/* use node value and return pointer to it */
static inline value_t* hattrie_useval(hattrie_t *T, node_ptr n)
{
    if (!(n.t->flag & NODE_HAS_VAL)) {
        n.t->flag |= NODE_HAS_VAL;
        ++T->m;
    }
    return &n.t->val;
}

/* clear node value if exists */
static inline int hattrie_clrval(hattrie_t *T, node_ptr n)
{
    if (n.t->flag & NODE_HAS_VAL) {
        n.t->flag &= ~NODE_HAS_VAL;
        n.t->val = 0;
        --T->m;
        return 0;
    }
    return -1;
}

/* find node in trie */
static node_ptr hattrie_find(hattrie_t* T, const char **key, size_t *len)
{
    node_ptr parent = T->root;
    assert(*parent.flag & NODE_TYPE_TRIE);

    if (*len == 0) return parent;

    node_ptr node = hattrie_consume(&parent, key, len, 1);

    /* if the trie node consumes value, use it */
    if (*node.flag & NODE_TYPE_TRIE) {
        if (!(node.t->flag & NODE_HAS_VAL)) {
            node.flag = NULL;
        }
        return node;
    }

    /* pure bucket holds only key suffixes, skip current char */
    if (*node.flag & NODE_TYPE_PURE_BUCKET) {
        *key += 1;
        *len -= 1;
    }

    /* do not scan bucket, it's not needed for this operation */
    return node;
}

hattrie_t* hattrie_create()
{
    hattrie_t* T = malloc_or_die(sizeof(hattrie_t));
    T->m = 0;

    node_ptr node;
    node.b = ahtable_create();
    node.b->flag = NODE_TYPE_HYBRID_BUCKET;
    node.b->c0 = 0x00;
    node.b->c1 = NODE_MAXCHAR;
    T->root.t = alloc_trie_node(T, node);

    return T;
}


static void hattrie_free_node(node_ptr node)
{
    if (*node.flag & NODE_TYPE_TRIE) {
        size_t i;
        for (i = 0; i < NODE_CHILDS; ++i) {
            if (i > 0 && node.t->xs[i].t == node.t->xs[i - 1].t) continue;

            /* XXX: recursion might not be the best choice here. It is possible
             * to build a very deep trie. */
            if (node.t->xs[i].t) hattrie_free_node(node.t->xs[i]);
        }
        free(node.t);
    }
    else {
        ahtable_free(node.b);
    }
}


void hattrie_free(hattrie_t* T)
{
    hattrie_free_node(T->root);
    free(T);
}

/* Perform one split operation on the given node with the given parent.
 */
static void hattrie_split(hattrie_t* T, node_ptr parent, node_ptr node)
{
    /* only buckets may be split */
    assert(*node.flag & NODE_TYPE_PURE_BUCKET ||
           *node.flag & NODE_TYPE_HYBRID_BUCKET);

    assert(*parent.flag & NODE_TYPE_TRIE);

    if (*node.flag & NODE_TYPE_PURE_BUCKET) {
        /* turn the pure bucket into a hybrid bucket */
        parent.t->xs[node.b->c0].t = alloc_trie_node(T, node);

        /* if the bucket had an empty key, move it to the new trie node */
        value_t* val = ahtable_tryget(node.b, NULL, 0);
        if (val) {
            parent.t->xs[node.b->c0].t->val     = *val;
            parent.t->xs[node.b->c0].t->flag |= NODE_HAS_VAL;
            *val = 0;
            ahtable_del(node.b, NULL, 0);
        }

        node.b->c0   = 0x00;
        node.b->c1   = NODE_MAXCHAR;
        node.b->flag = NODE_TYPE_HYBRID_BUCKET;

        return;
    }

    /* This is a hybrid bucket. Perform a proper split. */

    /* count the number of occourances of every leading character */
    unsigned int cs[NODE_CHILDS]; // occurance count for leading chars
    memset(cs, 0, NODE_CHILDS * sizeof(unsigned int));
    size_t len;
    const char* key;

    ahtable_iter_t* i = ahtable_iter_begin(node.b, false);
    while (!ahtable_iter_finished(i)) {
        key = ahtable_iter_key(i, &len);
        assert(len > 0);
        cs[(unsigned char) key[0]] += 1;
        ahtable_iter_next(i);
    }
    ahtable_iter_free(i);

    /* choose a split point */
    unsigned int left_m, right_m, all_m;
    unsigned char j = node.b->c0;
    all_m   = ahtable_size(node.b);
    left_m  = cs[j];
    right_m = all_m - left_m;
    int d;

    while (j + 1 < node.b->c1) {
        d = abs((int) (left_m + cs[j + 1]) - (int) (right_m - cs[j + 1]));
        if (d <= abs((int) (left_m - right_m)) && left_m + cs[j + 1] < all_m) {
            j += 1;
            left_m  += cs[j];
            right_m -= cs[j];
        }
        else break;
    }

    /* now split into two node cooresponding to ranges [0, j] and
     * [j + 1, NODE_MAXCHAR], respectively. */


    /* create new left and right nodes */

    /* TODO: Add a special case if either node is a hybrid bucket containing all
     * the keys. In such a case, do not build a new table, just use the old one.
     * */
    size_t num_slots;


    for (num_slots = ahtable_initial_size;
            (double) left_m > ahtable_max_load_factor * (double) num_slots;
            num_slots *= 2);

    node_ptr left, right;
    left.b  = ahtable_create_n(num_slots);
    left.b->c0   = node.b->c0;
    left.b->c1   = j;
    left.b->flag = left.b->c0 == left.b->c1 ?
                      NODE_TYPE_PURE_BUCKET : NODE_TYPE_HYBRID_BUCKET;


    for (num_slots = ahtable_initial_size;
            (double) right_m > ahtable_max_load_factor * (double) num_slots;
            num_slots *= 2);

    right.b = ahtable_create_n(num_slots);
    right.b->c0   = j + 1;
    right.b->c1   = node.b->c1;
    right.b->flag = right.b->c0 == right.b->c1 ?
                      NODE_TYPE_PURE_BUCKET : NODE_TYPE_HYBRID_BUCKET;


    /* update the parent's pointer */

    unsigned int c;
    for (c = node.b->c0; c <= j; ++c) parent.t->xs[c] = left;
    for (; c <= node.b->c1; ++c)      parent.t->xs[c] = right;



    /* distribute keys to the new left or right node */
    value_t* u;
    value_t* v;
    i = ahtable_iter_begin(node.b, false);
    while (!ahtable_iter_finished(i)) {
        key = ahtable_iter_key(i, &len);
        u   = ahtable_iter_val(i);
        assert(len > 0);

        /* left */
        if ((unsigned char) key[0] <= j) {
            if (*left.flag & NODE_TYPE_PURE_BUCKET) {
                v = ahtable_get(left.b, key + 1, len - 1);
            }
            else {
                v = ahtable_get(left.b, key, len);
            }
            *v = *u;
        }

        /* right */
        else {
            if (*right.flag & NODE_TYPE_PURE_BUCKET) {
                v = ahtable_get(right.b, key + 1, len - 1);
            }
            else {
                v = ahtable_get(right.b, key, len);
            }
            *v = *u;
        }

        ahtable_iter_next(i);
    }

    ahtable_iter_free(i);
    ahtable_free(node.b);
}

value_t* hattrie_get(hattrie_t* T, const char* key, size_t len)
{
    node_ptr parent = T->root;
    assert(*parent.flag & NODE_TYPE_TRIE);

    if (len == 0) return &parent.t->val;

    /* consume all trie nodes, now parent must be trie and child anything */
    node_ptr node = hattrie_consume(&parent, &key, &len, 0);
    assert(*parent.flag & NODE_TYPE_TRIE);

    /* if the key has been consumed on a trie node, use its value */
    if (len == 0) {
        if (*node.flag & NODE_TYPE_TRIE) {
            return hattrie_useval(T, node);
        }
        else if (*node.flag & NODE_TYPE_HYBRID_BUCKET) {
            return hattrie_useval(T, parent);
        }
    }


    /* preemptively split the bucket if it is full */
    while (ahtable_size(node.b) >= MAX_BUCKET_SIZE) {
        hattrie_split(T, parent, node);

        /* after the split, the node pointer is invalidated, so we search from
         * the parent again. */
        node = hattrie_consume(&parent, &key, &len, 0);

        /* if the key has been consumed on a trie node, use its value */
        if (len == 0) {
            if (*node.flag & NODE_TYPE_TRIE) {
                return hattrie_useval(T, node);
            }
            else if (*node.flag & NODE_TYPE_HYBRID_BUCKET) {
                return hattrie_useval(T, parent);
            }
        }
    }

    assert(*node.flag & NODE_TYPE_PURE_BUCKET || *node.flag & NODE_TYPE_HYBRID_BUCKET);

    assert(len > 0);
    size_t m_old = node.b->m;
    value_t* val;
    if (*node.flag & NODE_TYPE_PURE_BUCKET) {
        val = ahtable_get(node.b, key + 1, len - 1);
    }
    else {
        val = ahtable_get(node.b, key, len);
    }
    T->m += (node.b->m - m_old);

    return val;
}


value_t* hattrie_tryget(hattrie_t* T, const char* key, size_t len)
{
    /* find node for given key */
    node_ptr node = hattrie_find(T, &key, &len);
    if (node.flag == NULL) {
        return NULL;
    }

    /* if the trie node consumes value, use it */
    if (*node.flag & NODE_TYPE_TRIE) {
        return &node.t->val;
    }

    return ahtable_tryget(node.b, key, len);
}


int hattrie_del(hattrie_t* T, const char* key, size_t len)
{
    node_ptr parent = T->root;
    assert(*parent.flag & NODE_TYPE_TRIE);

    /* find node for deletion */
    node_ptr node = hattrie_find(T, &key, &len);
    if (node.flag == NULL) {
        return -1;
    }

    /* if consumed on a trie node, clear the value */
    if (*node.flag & NODE_TYPE_TRIE) {
        return hattrie_clrval(T, node);
    }

    /* remove from bucket */
    size_t m_old = ahtable_size(node.b);
    int ret =  ahtable_del(node.b, key, len);
    T->m -= (m_old - ahtable_size(node.b));

    /* merge empty buckets */
    /*! \todo */

    return ret;
}


/* plan for iteration:
 * This is tricky, as we have no parent pointers currently, and I would like to
 * avoid adding them. That means maintaining a stack
 *
 */

typedef struct hattrie_node_stack_t_
{
    unsigned char   c;
    size_t level;

    node_ptr node;
    struct hattrie_node_stack_t_* next;

} hattrie_node_stack_t;


struct hattrie_iter_t_
{
    char* key;
    size_t keysize; // space reserved for the key
    size_t level;

    /* keep track of keys stored in trie nodes */
    bool    has_nil_key;
    value_t nil_val;

    const hattrie_t* T;
    bool sorted;
    ahtable_iter_t* i;
    hattrie_node_stack_t* stack;
};


static void hattrie_iter_pushchar(hattrie_iter_t* i, size_t level, char c)
{
    if (i->keysize < level) {
        i->keysize *= 2;
        i->key = realloc_or_die(i->key, i->keysize * sizeof(char));
    }

    if (level > 0) {
        i->key[level - 1] = c;
    }

    i->level = level;
}


static void hattrie_iter_nextnode(hattrie_iter_t* i)
{
    if (i->stack == NULL) return;

    /* pop the stack */
    node_ptr node;
    hattrie_node_stack_t* next;
    unsigned char   c;
    size_t level;

    node  = i->stack->node;
    next  = i->stack->next;
    c     = i->stack->c;
    level = i->stack->level;

    free(i->stack);
    i->stack = next;

    if (*node.flag & NODE_TYPE_TRIE) {
        hattrie_iter_pushchar(i, level, c);

        if(node.t->flag & NODE_HAS_VAL) {
            i->has_nil_key = true;
            i->nil_val = node.t->val;
        }

        /* push all child nodes from right to left */
        int j;
        for (j = NODE_MAXCHAR; j >= 0; --j) {

            /* skip repeated pointers to hybrid bucket */
            if (j < NODE_MAXCHAR && node.t->xs[j].t == node.t->xs[j + 1].t) continue;

            // push stack
            next = i->stack;
            i->stack = malloc_or_die(sizeof(hattrie_node_stack_t));
            i->stack->node  = node.t->xs[j];
            i->stack->next  = next;
            i->stack->level = level + 1;
            i->stack->c     = (unsigned char) j;
        }
    }
    else {
        if (*node.flag & NODE_TYPE_PURE_BUCKET) {
            hattrie_iter_pushchar(i, level, c);
        }
        else {
            i->level = level - 1;
        }

        i->i = ahtable_iter_begin(node.b, i->sorted);
    }
}


hattrie_iter_t* hattrie_iter_begin(const hattrie_t* T, bool sorted)
{
    hattrie_iter_t* i = malloc_or_die(sizeof(hattrie_iter_t));
    i->T = T;
    i->sorted = sorted;
    i->i = NULL;
    i->keysize = 16;
    i->key = malloc_or_die(i->keysize * sizeof(char));
    i->level   = 0;
    i->has_nil_key = false;
    i->nil_val     = 0;

    i->stack = malloc_or_die(sizeof(hattrie_node_stack_t));
    i->stack->next   = NULL;
    i->stack->node   = T->root;
    i->stack->c      = '\0';
    i->stack->level  = 0;


    while (((i->i == NULL || ahtable_iter_finished(i->i)) && !i->has_nil_key) &&
           i->stack != NULL ) {

        ahtable_iter_free(i->i);
        i->i = NULL;
        hattrie_iter_nextnode(i);
    }

    if (i->i != NULL && ahtable_iter_finished(i->i)) {
        ahtable_iter_free(i->i);
        i->i = NULL;
    }

    return i;
}


void hattrie_iter_next(hattrie_iter_t* i)
{
    if (hattrie_iter_finished(i)) return;

    if (i->i != NULL && !ahtable_iter_finished(i->i)) {
        ahtable_iter_next(i->i);
    }
    else if (i->has_nil_key) {
        i->has_nil_key = false;
        i->nil_val = 0;
        hattrie_iter_nextnode(i);
    }

    while (((i->i == NULL || ahtable_iter_finished(i->i)) && !i->has_nil_key) &&
           i->stack != NULL ) {

        ahtable_iter_free(i->i);
        i->i = NULL;
        hattrie_iter_nextnode(i);
    }

    if (i->i != NULL && ahtable_iter_finished(i->i)) {
        ahtable_iter_free(i->i);
        i->i = NULL;
    }
}


bool hattrie_iter_finished(hattrie_iter_t* i)
{
    return i->stack == NULL && i->i == NULL && !i->has_nil_key;
}


void hattrie_iter_free(hattrie_iter_t* i)
{
    if (i == NULL) return;
    if (i->i) ahtable_iter_free(i->i);

    hattrie_node_stack_t* next;
    while (i->stack) {
        next = i->stack->next;
        free(i->stack);
        i->stack = next;
    }

    free(i->key);
    free(i);
}


const char* hattrie_iter_key(hattrie_iter_t* i, size_t* len)
{
    if (hattrie_iter_finished(i)) return NULL;

    size_t sublen;
    const char* subkey;

    if (i->has_nil_key) {
        subkey = NULL;
        sublen = 0;
    }
    else subkey = ahtable_iter_key(i->i, &sublen);

    if (i->keysize < i->level + sublen + 1) {
        while (i->keysize < i->level + sublen + 1) i->keysize *= 2;
        i->key = realloc_or_die(i->key, i->keysize * sizeof(char));
    }

    memcpy(i->key + i->level, subkey, sublen);
    i->key[i->level + sublen] = '\0';

    *len = i->level + sublen;
    return i->key;
}


value_t* hattrie_iter_val(hattrie_iter_t* i)
{
    if (i->has_nil_key) return &i->nil_val;

    if (hattrie_iter_finished(i)) return NULL;

    return ahtable_iter_val(i->i);
}
