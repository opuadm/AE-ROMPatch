#ifndef AEP_CODEC_H
#define AEP_CODEC_H

#include <stddef.h>

#include "core/util.h"

typedef enum {
    CODEC_NONE,
    CODEC_GZIP,
    CODEC_LZ4_LEGACY,
    CODEC_LZ4_FRAME,
    CODEC_XZ,
    CODEC_LZMA,
    CODEC_BZIP2,
    CODEC_ZSTD,
    CODEC_UNKNOWN
} codec_t;

codec_t codec_detect(const unsigned char *d, size_t len);
const char *codec_name(codec_t c);
int codec_decompress(const unsigned char *d, size_t len, buf_t *out, size_t limit, char *err, size_t errlen);
int lz4_block_window(const unsigned char *src, size_t slen, buf_t *out, size_t limit, size_t window_start);
int gzip_compress(const unsigned char *d, size_t len, int level, buf_t *out);

#endif
