#ifndef AEP_STREAM_H
#define AEP_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "formats/ota.h"
#include "core/rsrc.h"

typedef struct {
    seq_read_fn rd;
    void *ctx;
    unsigned char *peek;
    size_t npeek, ppos;
    uint64_t consumed;
    uint64_t limit;
} sreader;

void sreader_init(sreader *r, seq_read_fn rd, void *ctx, uint64_t limit);
long sreader_read(void *r, void *buf, size_t len);
int sreader_peek(sreader *r, unsigned char *buf, size_t len);
int sreader_skip(sreader *r, uint64_t n);
void sreader_free(sreader *r);

rsrc *stream_decompress_to_temp(sreader *in, const char *label, char *err, size_t errlen);

#endif
