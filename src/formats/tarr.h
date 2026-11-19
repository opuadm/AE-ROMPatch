#ifndef AEP_TARR_H
#define AEP_TARR_H

#include <stddef.h>
#include <stdint.h>

#include "core/rsrc.h"
#include "core/stream.h"

typedef int (*tar_member_fn)(void *ctx, const char *name, uint64_t size, rsrc *base, uint64_t off, sreader *data);

int tar_probe(const unsigned char *h, size_t n);
int tar_scan_rsrc(rsrc *src, tar_member_fn cb, void *ctx, char *err, size_t errlen);
int tar_scan_stream(sreader *in, tar_member_fn cb, void *ctx, char *err, size_t errlen);

typedef struct gzseq gzseq;
gzseq *gzseq_open(seq_read_fn rd, void *ctx);
long gzseq_read(void *g, void *buf, size_t len);
void gzseq_close(gzseq *g);

long rsrc_seq_read(void *ctx, void *buf, size_t len);
typedef struct {
    rsrc *src;
    uint64_t off, end;
} rsrc_seq;

#endif
