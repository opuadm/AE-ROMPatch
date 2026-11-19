#include "core/codec.h"

#include <string.h>
#include <zlib.h>

codec_t codec_detect(const unsigned char *d, size_t len)
{
    if (len >= 2 && d[0] == 0x1f && d[1] == 0x8b)
        return CODEC_GZIP;
    if (len >= 4 && le32(d) == 0x184C2102U)
        return CODEC_LZ4_LEGACY;
    if (len >= 4 && le32(d) == 0x184D2204U)
        return CODEC_LZ4_FRAME;
    if (len >= 6 && !memcmp(d, "\xfd" "7zXZ\0", 6))
        return CODEC_XZ;
    if (len >= 3 && d[0] == 0x5d && d[1] == 0x00 && d[2] == 0x00)
        return CODEC_LZMA;
    if (len >= 3 && !memcmp(d, "BZh", 3))
        return CODEC_BZIP2;
    if (len >= 4 && le32(d) == 0xFD2FB528U)
        return CODEC_ZSTD;
    if (len >= 6 && (!memcmp(d, "070701", 6) || !memcmp(d, "070702", 6)))
        return CODEC_NONE;
    return CODEC_UNKNOWN;
}

const char *codec_name(codec_t c)
{
    switch (c) {
    case CODEC_NONE: return "uncompressed";
    case CODEC_GZIP: return "gzip";
    case CODEC_LZ4_LEGACY: return "lz4 (legacy)";
    case CODEC_LZ4_FRAME: return "lz4 (frame)";
    case CODEC_XZ: return "xz";
    case CODEC_LZMA: return "lzma";
    case CODEC_BZIP2: return "bzip2";
    case CODEC_ZSTD: return "zstd";
    default: return "unknown";
    }
}

static int gunzip(const unsigned char *d, size_t len, buf_t *out, size_t limit, char *err, size_t errlen)
{
    z_stream z;
    memset(&z, 0, sizeof z);
    if (inflateInit2(&z, 15 + 32) != Z_OK) {
        snprintf(err, errlen, "zlib init failed");
        return -1;
    }
    z.next_in = (unsigned char *)d;
    z.avail_in = (uInt)len;
    unsigned char tmp[65536];
    int r;
    do {
        z.next_out = tmp;
        z.avail_out = sizeof tmp;
        r = inflate(&z, Z_NO_FLUSH);
        if (r != Z_OK && r != Z_STREAM_END) {
            if (out->len)
                break;
            inflateEnd(&z);
            snprintf(err, errlen, "corrupt gzip data");
            return -1;
        }
        size_t got = sizeof tmp - z.avail_out;
        if (limit && out->len + got > limit) {
            inflateEnd(&z);
            snprintf(err, errlen, "decompressed data exceeds %zu MiB", limit >> 20);
            return -1;
        }
        buf_put(out, tmp, got);
    } while (r != Z_STREAM_END && (z.avail_in || z.avail_out == 0));
    inflateEnd(&z);
    return 0;
}

int lz4_block_window(const unsigned char *src, size_t slen, buf_t *out, size_t limit, size_t window_start)
{
    size_t ip = 0;
    while (ip < slen) {
        unsigned token = src[ip++];
        size_t lit = token >> 4;
        if (lit == 15) {
            unsigned char b;
            do {
                if (ip >= slen)
                    return -1;
                b = src[ip++];
                lit += b;
            } while (b == 255);
        }
        if (ip + lit > slen || (limit && out->len + lit > limit))
            return -1;
        buf_put(out, src + ip, lit);
        ip += lit;
        if (ip >= slen)
            break;
        if (ip + 2 > slen)
            return -1;
        size_t offset = src[ip] | (src[ip + 1] << 8);
        ip += 2;
        size_t mlen = token & 15;
        if (mlen == 15) {
            unsigned char b;
            do {
                if (ip >= slen)
                    return -1;
                b = src[ip++];
                mlen += b;
            } while (b == 255);
        }
        mlen += 4;
        if (offset == 0 || offset > out->len - window_start || (limit && out->len + mlen > limit))
            return -1;
        buf_reserve(out, mlen);
        unsigned char *o = out->data + out->len;
        const unsigned char *m = o - offset;
        for (size_t i = 0; i < mlen; i++)
            o[i] = m[i];
        out->len += mlen;
        out->data[out->len] = 0;
    }
    return 0;
}

static int lz4_legacy(const unsigned char *d, size_t len, buf_t *out, size_t limit, char *err, size_t errlen)
{
    size_t p = 4;
    while (p + 4 <= len) {
        uint32_t clen = le32(d + p);
        if (clen == 0x184C2102U) {
            p += 4;
            continue;
        }
        if (clen == 0 || p + 4 + clen > len)
            break;
        p += 4;
        if (lz4_block_window(d + p, clen, out, limit, out->len) < 0) {
            snprintf(err, errlen, "corrupt lz4 legacy data");
            return -1;
        }
        p += clen;
    }
    if (!out->len) {
        snprintf(err, errlen, "empty lz4 stream");
        return -1;
    }
    return 0;
}

static int lz4_frame(const unsigned char *d, size_t len, buf_t *out, size_t limit, char *err, size_t errlen)
{
    size_t p = 0;
    while (p + 7 <= len && le32(d + p) == 0x184D2204U) {
        unsigned flg = d[p + 4];
        if ((flg >> 6) != 1) {
            snprintf(err, errlen, "unsupported lz4 frame version");
            return -1;
        }
        int independent = (flg >> 5) & 1;
        int block_ck = (flg >> 4) & 1;
        int content_size = (flg >> 3) & 1;
        int content_ck = (flg >> 2) & 1;
        int dict = flg & 1;
        p += 6 + (content_size ? 8 : 0) + (dict ? 4 : 0) + 1;
        size_t frame_start = out->len;
        for (;;) {
            if (p + 4 > len) {
                snprintf(err, errlen, "truncated lz4 frame");
                return -1;
            }
            uint32_t bsize = le32(d + p);
            p += 4;
            if (bsize == 0)
                break;
            int raw = (bsize >> 31) & 1;
            bsize &= 0x7fffffffU;
            if (p + bsize > len) {
                snprintf(err, errlen, "truncated lz4 block");
                return -1;
            }
            if (raw) {
                if (limit && out->len + bsize > limit) {
                    snprintf(err, errlen, "decompressed data too large");
                    return -1;
                }
                buf_put(out, d + p, bsize);
            } else if (lz4_block_window(d + p, bsize, out, limit, independent ? out->len : frame_start) < 0) {
                snprintf(err, errlen, "corrupt lz4 frame data");
                return -1;
            }
            p += bsize + (block_ck ? 4 : 0);
        }
        if (content_ck)
            p += 4;
        while (p + 8 <= len && (le32(d + p) & 0xFFFFFFF0U) == 0x184D2A50U)
            p += 8 + le32(d + p + 4);
    }
    if (!out->len) {
        snprintf(err, errlen, "empty lz4 frame");
        return -1;
    }
    return 0;
}

int codec_decompress(const unsigned char *d, size_t len, buf_t *out, size_t limit, char *err, size_t errlen)
{
    codec_t c = codec_detect(d, len);
    switch (c) {
    case CODEC_NONE:
        buf_put(out, d, len);
        return 0;
    case CODEC_GZIP:
        return gunzip(d, len, out, limit, err, errlen);
    case CODEC_LZ4_LEGACY:
        return lz4_legacy(d, len, out, limit, err, errlen);
    case CODEC_LZ4_FRAME:
        return lz4_frame(d, len, out, limit, err, errlen);
    case CODEC_UNKNOWN:
        snprintf(err, errlen, "unrecognised compression");
        return -1;
    default:
        snprintf(err, errlen, "%s compression is not supported; decompress it first (e.g. with the matching command-line tool)",
                 codec_name(c));
        return -1;
    }
}

int gzip_compress(const unsigned char *d, size_t len, int level, buf_t *out)
{
    z_stream z;
    memset(&z, 0, sizeof z);
    if (deflateInit2(&z, level, Z_DEFLATED, 15 + 16, 9, Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;
    z.next_in = (unsigned char *)d;
    z.avail_in = (uInt)len;
    unsigned char tmp[65536];
    int r;
    do {
        z.next_out = tmp;
        z.avail_out = sizeof tmp;
        r = deflate(&z, Z_FINISH);
        if (r == Z_STREAM_ERROR) {
            deflateEnd(&z);
            return -1;
        }
        buf_put(out, tmp, sizeof tmp - z.avail_out);
    } while (r != Z_STREAM_END);
    deflateEnd(&z);
    return 0;
}
