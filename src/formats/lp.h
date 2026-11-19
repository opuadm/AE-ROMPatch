#ifndef AEP_LP_H
#define AEP_LP_H

#include <stddef.h>
#include <stdint.h>

#include "core/rsrc.h"

typedef struct {
    uint64_t off;
    uint64_t len;
    int zero;
} lp_extent;

typedef struct {
    char name[40];
    lp_extent *ext;
    size_t n;
    uint64_t size;
} lp_part;

typedef struct {
    lp_part *parts;
    size_t n;
} lp_table;

int lp_probe(rsrc *src);
int lp_read(rsrc *src, lp_table *t, char *err, size_t errlen);
void lp_free(lp_table *t);
rsrc *lp_open_partition(rsrc *src, const lp_part *p);

#endif
