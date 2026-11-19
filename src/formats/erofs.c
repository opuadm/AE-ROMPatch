#include "formats/erofs.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "core/util.h"

#ifdef HAVE_LZMA
#include <lzma.h>
#endif
#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#define EROFS_MAGIC 0xE0F5E1E2U
#define EROFS_SB_OFF 1024

#define FEAT_ZERO_PADDING 0x1
#define FEAT_COMPR_CFGS 0x2
#define FEAT_CHUNKED 0x4
#define FEAT_DEVICE_TABLE 0x8
#define FEAT_ZTAILPACKING 0x10
#define FEAT_FRAGMENTS 0x20
#define FEAT_XATTR_PREFIXES 0x40
#define FEAT_KNOWN 0x7f

#define L_FLAT_PLAIN 0
#define L_COMPRESSED_FULL 1
#define L_FLAT_INLINE 2
#define L_COMPRESSED_COMPACT 3
#define L_CHUNK_BASED 4

#define ADV_COMPACTED_2B 0x1
#define ADV_BIG_PCLUSTER_1 0x2
#define ADV_BIG_PCLUSTER_2 0x4
#define ADV_INLINE_PCLUSTER 0x8
#define ADV_INTERLACED 0x10
#define ADV_FRAGMENT 0x20

#define T_PLAIN 0
#define T_HEAD1 1
#define T_NONHEAD 2
#define T_HEAD2 3
#define D0_CBLKCNT (1u << 11)
#define LI_PARTIAL_REF (1u << 15)

#define ALG_LZ4 0
#define ALG_LZMA 1
#define ALG_DEFLATE 2
#define ALG_ZSTD 3
#define ALG_SHIFTED 4
#define ALG_INTERLACED 5

#define MAX_EXTENT (64u << 20)

struct erofs {
    rsrc *src;
    uint32_t blkbits, blksz;
    uint64_t meta_off;
    uint64_t root;
    uint32_t incompat;
    uint64_t packed_nid;
    efile *packed;
    char err[256];
};

struct efile {
    erofs *fs;
    erofs_stat_t st;
    uint64_t iloc;
    uint32_t isize, xsize;
    int layout;
    uint64_t raw_blkaddr;
    uint16_t chunkfmt;

    uint16_t advise;
    uint8_t algo[2];
    uint32_t lbits;
    uint64_t ebase;
    int ztail, fragment, whole_fragment;
    uint64_t idata_size, idataoff;
    uint64_t fragmentoff;
    uint64_t tail_headlcn;

    unsigned char *cbuf;
    uint64_t cla, clen;
};

typedef struct {
    int type;
    uint32_t clusterofs;
    uint64_t pblk;
    uint32_t delta[2];
    uint32_t compressedblks;
    int partialref;
    uint64_t nextpackoff;
    uint64_t lcn;
} lcl;

static int fail(erofs *fs, const char *msg)
{
    snprintf(fs->err, sizeof fs->err, "%s", msg);
    return -1;
}

const char *erofs_error(erofs *fs)
{
    return fs->err;
}

int erofs_probe(rsrc *src)
{
    unsigned char m[4];
    if (src->size < EROFS_SB_OFF + 128 || rsrc_read(src, m, 4, EROFS_SB_OFF) < 0)
        return 0;
    return le32(m) == EROFS_MAGIC;
}

erofs *erofs_open(rsrc *src, char *err, size_t errlen)
{
    unsigned char sb[128];
    if (rsrc_read(src, sb, sizeof sb, EROFS_SB_OFF) < 0 || le32(sb) != EROFS_MAGIC) {
        snprintf(err, errlen, "not an EROFS image");
        return NULL;
    }
    erofs *fs = xcalloc(1, sizeof *fs);
    fs->src = src;
    fs->blkbits = sb[12];
    if (fs->blkbits < 9 || fs->blkbits > 16) {
        snprintf(err, errlen, "unsupported EROFS block size");
        free(fs);
        return NULL;
    }
    fs->blksz = 1u << fs->blkbits;
    fs->root = le16(sb + 14);
    fs->meta_off = (uint64_t)le32(sb + 40) << fs->blkbits;
    fs->incompat = le32(sb + 80);
    fs->packed_nid = le64(sb + 96);
    if (fs->incompat & ~FEAT_KNOWN) {
        snprintf(err, errlen, "EROFS image uses features this tool does not know (0x%x)", fs->incompat & ~FEAT_KNOWN);
        free(fs);
        return NULL;
    }
    if ((fs->incompat & FEAT_DEVICE_TABLE) && le16(sb + 86)) {
        snprintf(err, errlen, "multi-device EROFS images are not supported");
        free(fs);
        return NULL;
    }
    return fs;
}

void erofs_close(erofs *fs)
{
    if (!fs)
        return;
    efile_close(fs->packed);
    rsrc_close(fs->src);
    free(fs);
}

uint64_t erofs_root(erofs *fs)
{
    return fs->root;
}

static int read_inode(erofs *fs, uint64_t nid, efile *f)
{
    unsigned char b[64];
    uint64_t iloc = fs->meta_off + nid * 32;
    if (iloc + 32 > fs->src->size || rsrc_read(fs->src, b, 32, iloc) < 0)
        return fail(fs, "inode out of range");
    uint16_t fmt = le16(b);
    int ext = fmt & 1;
    f->layout = (fmt >> 1) & 7;
    f->iloc = iloc;
    f->isize = ext ? 64 : 32;
    if (ext && rsrc_read(fs->src, b, 64, iloc) < 0)
        return fail(fs, "inode out of range");
    uint16_t xcount = le16(b + 2);
    f->xsize = xcount ? 12 + (xcount - 1) * 4u : 0;
    f->st.nid = nid;
    f->st.mode = le16(b + 4);
    f->st.layout = f->layout;
    f->raw_blkaddr = le32(b + 16);
    f->chunkfmt = le16(b + 16);
    if (ext) {
        f->st.size = le64(b + 8);
        f->st.uid = le32(b + 24);
        f->st.gid = le32(b + 28);
        f->st.mtime = (int64_t)le64(b + 32);
    } else {
        f->st.size = le32(b + 8);
        f->st.uid = le16(b + 24);
        f->st.gid = le16(b + 26);
        f->st.mtime = (int32_t)le32(b + 12);
    }
    if (f->layout > L_CHUNK_BASED)
        return fail(fs, "unknown EROFS data layout");
    return 0;
}

int erofs_stat(erofs *fs, uint64_t nid, erofs_stat_t *st)
{
    efile f;
    memset(&f, 0, sizeof f);
    if (read_inode(fs, nid, &f) < 0)
        return -1;
    *st = f.st;
    return 0;
}

static uint64_t align8(uint64_t v)
{
    return (v + 7) & ~(uint64_t)7;
}

static unsigned decode_bits(unsigned lobits, const unsigned char *in, unsigned pos, int *type)
{
    uint32_t v = le32(in + pos / 8) >> (pos & 7);
    *type = (int)((v >> lobits) & 3);
    return v & ((1u << lobits) - 1);
}

static unsigned la_distance(unsigned lobits, unsigned encodebits, unsigned vcnt, const unsigned char *in, int i)
{
    unsigned lo = 0, d1 = 0;
    int type;
    do {
        lo = decode_bits(lobits, in, encodebits * (unsigned)i, &type);
        if (type != T_NONHEAD)
            return d1;
        ++d1;
    } while (++i < (int)vcnt);
    if (!(lo & D0_CBLKCNT))
        d1 += lo - 1;
    return d1;
}

static int unpack_compact(efile *f, unsigned ashift, uint64_t pos, int lookahead, lcl *m)
{
    erofs *fs = f->fs;
    unsigned lbits = f->lbits;
    unsigned vcnt;
    if ((1u << ashift) == 4 && lbits <= 14)
        vcnt = 2;
    else if ((1u << ashift) == 2 && lbits <= 12)
        vcnt = 16;
    else
        return fail(fs, "unsupported compact index layout");
    unsigned lobits = lbits > 12 ? lbits : 12;
    unsigned packsz = vcnt << ashift;
    unsigned encodebits = (packsz - 4) * 8 / vcnt;
    uint64_t eofs = pos & (packsz - 1);
    uint64_t base = pos - eofs;
    unsigned char in[40];
    memset(in, 0, sizeof in);
    if (rsrc_read(fs->src, in, packsz, base) < 0)
        return fail(fs, "cannot read compact index");
    m->nextpackoff = base + packsz;
    int big = (f->advise & ADV_BIG_PCLUSTER_1) != 0;
    int i = (int)(eofs >> ashift);
    int type;
    unsigned lo = decode_bits(lobits, in, encodebits * (unsigned)i, &type);
    m->type = type;
    if (type == T_NONHEAD) {
        m->clusterofs = 1u << lbits;
        if (lookahead)
            m->delta[1] = la_distance(lobits, encodebits, vcnt, in, i);
        if (lo & D0_CBLKCNT) {
            if (!big)
                return fail(fs, "corrupt compact index (CBLKCNT without big pclusters)");
            m->compressedblks = lo & ~D0_CBLKCNT;
            m->delta[0] = 1;
            return 0;
        } else if (i + 1 != (int)vcnt) {
            m->delta[0] = lo;
            return 0;
        }
        lo = decode_bits(lobits, in, encodebits * (unsigned)(i - 1), &type);
        if (type != T_NONHEAD)
            lo = 0;
        else if (lo & D0_CBLKCNT)
            lo = 1;
        m->delta[0] = lo + 1;
        return 0;
    }
    m->clusterofs = lo;
    m->delta[0] = 0;
    long nblk;
    if (!big) {
        nblk = 1;
        while (i > 0) {
            --i;
            lo = decode_bits(lobits, in, encodebits * (unsigned)i, &type);
            if (type == T_NONHEAD)
                i -= (int)lo;
            if (i >= 0)
                ++nblk;
        }
    } else {
        nblk = 0;
        while (i > 0) {
            --i;
            lo = decode_bits(lobits, in, encodebits * (unsigned)i, &type);
            if (type == T_NONHEAD) {
                if (lo & D0_CBLKCNT) {
                    --i;
                    nblk += lo & ~D0_CBLKCNT;
                    continue;
                }
                if (lo <= 1)
                    return fail(fs, "corrupt compact index");
                i -= (int)lo - 2;
                continue;
            }
            ++nblk;
        }
    }
    m->pblk = le32(in + packsz - 4) + (uint64_t)nblk;
    return 0;
}

static int load_lcluster(efile *f, uint64_t lcn, int lookahead, lcl *m)
{
    erofs *fs = f->fs;
    m->lcn = lcn;
    m->compressedblks = 0;
    m->partialref = 0;
    m->delta[0] = m->delta[1] = 0;
    if (f->layout == L_COMPRESSED_FULL) {
        uint64_t pos = f->ebase + lcn * 8;
        unsigned char d[8];
        if (rsrc_read(fs->src, d, 8, pos) < 0)
            return fail(fs, "cannot read compression index");
        m->nextpackoff = pos + 8;
        uint16_t adv = le16(d);
        m->type = adv & 3;
        if (m->type == T_NONHEAD) {
            m->clusterofs = 1u << f->lbits;
            m->delta[0] = le16(d + 4);
            if (m->delta[0] & D0_CBLKCNT) {
                if (!(f->advise & (ADV_BIG_PCLUSTER_1 | ADV_BIG_PCLUSTER_2)))
                    return fail(fs, "corrupt index (CBLKCNT without big pclusters)");
                m->compressedblks = m->delta[0] & ~D0_CBLKCNT;
                m->delta[0] = 1;
            }
            m->delta[1] = le16(d + 6);
        } else {
            m->partialref = (adv & LI_PARTIAL_REF) != 0;
            m->clusterofs = le16(d + 2);
            if (m->clusterofs >= (1u << f->lbits))
                return fail(fs, "corrupt index (cluster offset)");
            m->pblk = le32(d + 4);
        }
        return 0;
    }
    uint64_t lsz = 1ull << f->lbits;
    uint64_t totalidx = (f->st.size + lsz - 1) / lsz;
    if (lcn >= totalidx)
        return fail(fs, "index past the end of the file");
    uint64_t ebase = f->ebase;
    uint64_t c4init = ((32 - ebase % 32) / 4) & 7;
    uint64_t c2b = 0;
    if ((f->advise & ADV_COMPACTED_2B) && c4init < totalidx)
        c2b = (totalidx - c4init) / 16 * 16;
    uint64_t pos = ebase;
    unsigned ashift;
    if (lcn < c4init) {
        ashift = 2;
    } else {
        pos += c4init * 4;
        lcn -= c4init;
        if (lcn < c2b) {
            ashift = 1;
        } else {
            pos += c2b * 2;
            lcn -= c2b;
            ashift = 2;
        }
    }
    pos += lcn << ashift;
    return unpack_compact(f, ashift, pos, lookahead, m);
}

static int lookback(efile *f, lcl *m, uint32_t dist, uint64_t *la, int *headtype)
{
    while (m->lcn >= dist) {
        uint64_t lcn = m->lcn - dist;
        if (load_lcluster(f, lcn, 0, m) < 0)
            return -1;
        if (m->type == T_NONHEAD) {
            dist = m->delta[0];
            if (!dist)
                return fail(f->fs, "corrupt index (zero lookback)");
            continue;
        }
        *headtype = m->type;
        *la = (lcn << f->lbits) | m->clusterofs;
        return 0;
    }
    return fail(f->fs, "corrupt index (no head lcluster)");
}

typedef struct {
    uint64_t la, llen;
    uint64_t pa, plen;
    int headtype;
    int alg;
    int meta;
    int fragment;
    uint64_t headlcn;
} zmap;

static int compressed_len(efile *f, lcl *m, uint64_t initial_lcn, int headtype)
{
    uint64_t lcn = m->lcn;
    if (m->compressedblks)
        return 0;
    int big1 = (f->advise & ADV_BIG_PCLUSTER_1) != 0, big2 = (f->advise & ADV_BIG_PCLUSTER_2) != 0;
    if ((headtype == T_HEAD1 && !big1) || ((headtype == T_PLAIN || headtype == T_HEAD2) && !big2) ||
        (lcn << f->lbits) >= f->st.size) {
        m->compressedblks = 1;
        return 0;
    }
    if (load_lcluster(f, lcn + 1, 0, m) < 0)
        return -1;
    (void)initial_lcn;
    switch (m->type) {
    case T_PLAIN:
    case T_HEAD1:
    case T_HEAD2:
        m->compressedblks = 1;
        return 0;
    case T_NONHEAD:
        if (m->delta[0] != 1 || !m->compressedblks)
            return fail(f->fs, "corrupt index (pcluster size)");
        return 0;
    }
    return fail(f->fs, "corrupt index");
}

static int decompressed_len(efile *f, uint64_t headlcn, uint64_t la, uint64_t *llen)
{
    lcl m;
    uint64_t lcn = headlcn;
    for (int guard = 0; guard < 1 << 20; guard++) {
        if ((lcn << f->lbits) >= f->st.size) {
            *llen = f->st.size - la;
            return 0;
        }
        if (load_lcluster(f, lcn, 1, &m) < 0)
            return -1;
        if (m.type == T_NONHEAD) {
            if (!m.delta[1])
                m.delta[1] = 1;
        } else {
            if (lcn != headlcn) {
                *llen = (lcn << f->lbits) + m.clusterofs - la;
                return 0;
            }
            m.delta[1] = 1;
        }
        lcn += m.delta[1];
    }
    return fail(f->fs, "corrupt index (extent too long)");
}

static int map_blocks(efile *f, uint64_t ofs, int findtail, zmap *z)
{
    lcl m;
    memset(&m, 0, sizeof m);
    memset(z, 0, sizeof *z);
    uint64_t initial = ofs >> f->lbits;
    uint64_t endoff = ofs & ((1ull << f->lbits) - 1);
    if (load_lcluster(f, initial, 0, &m) < 0)
        return -1;
    if (findtail && f->ztail)
        f->idataoff = m.nextpackoff;
    int headtype = m.type;
    switch (m.type) {
    case T_PLAIN:
    case T_HEAD1:
    case T_HEAD2:
        if (endoff >= m.clusterofs) {
            z->la = (m.lcn << f->lbits) | m.clusterofs;
            break;
        }
        if (!m.lcn)
            return fail(f->fs, "corrupt index (first lcluster)");
        if (lookback(f, &m, 1, &z->la, &headtype) < 0)
            return -1;
        break;
    case T_NONHEAD:
        if (lookback(f, &m, m.delta[0], &z->la, &headtype) < 0)
            return -1;
        break;
    default:
        return fail(f->fs, "corrupt index type");
    }
    z->headtype = headtype;
    z->headlcn = m.lcn;
    if (findtail) {
        f->tail_headlcn = m.lcn;
        if (f->fragment && f->layout == L_COMPRESSED_FULL)
            f->fragmentoff |= (uint64_t)m.pblk << 32;
        return 0;
    }
    if (decompressed_len(f, z->headlcn, z->la, &z->llen) < 0)
        return -1;
    if (f->ztail && z->headlcn == f->tail_headlcn) {
        z->meta = 1;
        z->pa = f->idataoff;
        z->plen = f->idata_size;
    } else if (f->fragment && z->headlcn == f->tail_headlcn) {
        z->fragment = 1;
    } else {
        uint64_t pblk = m.pblk;
        if (compressed_len(f, &m, initial, headtype) < 0)
            return -1;
        z->pa = pblk << f->fs->blkbits;
        z->plen = (uint64_t)m.compressedblks << f->fs->blkbits;
    }
    if (headtype == T_PLAIN)
        z->alg = (f->advise & ADV_INTERLACED) ? ALG_INTERLACED : ALG_SHIFTED;
    else
        z->alg = f->algo[headtype == T_HEAD2 ? 1 : 0];
    return 0;
}

static size_t skip_padding(erofs *fs, const unsigned char *in, size_t len)
{
    if (!(fs->incompat & FEAT_ZERO_PADDING))
        return 0;
    size_t i = 0;
    while (i < len && i < fs->blksz && !in[i])
        i++;
    return i;
}

static int lz4_partial(const unsigned char *src, size_t slen, unsigned char *out, size_t olen)
{
    size_t ip = 0, op = 0;
    while (ip < slen && op < olen) {
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
        if (ip + lit > slen)
            return -1;
        size_t take = lit > olen - op ? olen - op : lit;
        memcpy(out + op, src + ip, take);
        op += take;
        ip += lit;
        if (op >= olen || ip >= slen)
            break;
        if (ip + 2 > slen)
            return -1;
        size_t off = src[ip] | (src[ip + 1] << 8);
        ip += 2;
        size_t ml = token & 15;
        if (ml == 15) {
            unsigned char b;
            do {
                if (ip >= slen)
                    return -1;
                b = src[ip++];
                ml += b;
            } while (b == 255);
        }
        ml += 4;
        if (!off || off > op)
            return -1;
        for (size_t k = 0; k < ml && op < olen; k++, op++)
            out[op] = out[op - off];
    }
    if (op < olen)
        memset(out + op, 0, olen - op);
    return op == olen ? 0 : (op ? 0 : -1);
}

static int decompress(efile *f, int alg, const unsigned char *in, size_t ilen, unsigned char *out, size_t olen,
                      uint64_t la)
{
    erofs *fs = f->fs;
    size_t margin;
    switch (alg) {
    case ALG_SHIFTED:
        if (ilen < olen) {
            memcpy(out, in, ilen);
            memset(out + ilen, 0, olen - ilen);
        } else {
            memcpy(out, in, olen);
        }
        return 0;
    case ALG_INTERLACED: {
        if (!ilen)
            return fail(fs, "empty interlaced pcluster");
        size_t ofs = (size_t)(la & (fs->blksz - 1));
        for (size_t i = 0; i < olen; i++)
            out[i] = in[(ofs + i) % ilen];
        return 0;
    }
    case ALG_LZ4:
        margin = skip_padding(fs, in, ilen);
        if (lz4_partial(in + margin, ilen - margin, out, olen) < 0)
            return fail(fs, "corrupt LZ4 data");
        return 0;
    case ALG_DEFLATE: {
        margin = skip_padding(fs, in, ilen);
        z_stream zs;
        memset(&zs, 0, sizeof zs);
        if (inflateInit2(&zs, -15) != Z_OK)
            return fail(fs, "zlib init failed");
        zs.next_in = (unsigned char *)in + margin;
        zs.avail_in = (uInt)(ilen - margin);
        zs.next_out = out;
        zs.avail_out = (uInt)olen;
        int r = inflate(&zs, Z_FINISH);
        size_t got = olen - zs.avail_out;
        inflateEnd(&zs);
        if (r != Z_STREAM_END && got != olen && !(r == Z_BUF_ERROR && got))
            return fail(fs, "corrupt DEFLATE data");
        if (got < olen)
            memset(out + got, 0, olen - got);
        return 0;
    }
#ifdef HAVE_LZMA
    case ALG_LZMA: {
        margin = skip_padding(fs, in, ilen);
        lzma_stream s = LZMA_STREAM_INIT;
        if (lzma_microlzma_decoder(&s, ilen - margin, olen, 0, 1u << 23) != LZMA_OK)
            return fail(fs, "lzma init failed");
        s.next_in = in + margin;
        s.avail_in = ilen - margin;
        s.next_out = out;
        s.avail_out = olen;
        lzma_ret r = lzma_code(&s, LZMA_FINISH);
        size_t got = olen - s.avail_out;
        lzma_end(&s);
        if (r != LZMA_STREAM_END && r != LZMA_OK && got != olen)
            return fail(fs, "corrupt LZMA data");
        if (got < olen)
            memset(out + got, 0, olen - got);
        return 0;
    }
#endif
#ifdef HAVE_ZSTD
    case ALG_ZSTD: {
        margin = skip_padding(fs, in, ilen);
        ZSTD_DStream *ds = ZSTD_createDStream();
        ZSTD_initDStream(ds);
        ZSTD_inBuffer ib = {in + margin, ilen - margin, 0};
        ZSTD_outBuffer ob = {out, olen, 0};
        while (ob.pos < olen && ib.pos < ib.size) {
            size_t r = ZSTD_decompressStream(ds, &ob, &ib);
            if (ZSTD_isError(r)) {
                ZSTD_freeDStream(ds);
                return fail(fs, "corrupt Zstandard data");
            }
            if (r == 0)
                break;
        }
        ZSTD_freeDStream(ds);
        if (ob.pos < olen)
            memset(out + ob.pos, 0, olen - ob.pos);
        return 0;
    }
#endif
    default:
        return fail(fs, alg == ALG_LZMA || alg == ALG_ZSTD ? "this build lacks the decompressor for this EROFS image"
                                                            : "unknown EROFS compression algorithm");
    }
}

static int init_compressed(efile *f)
{
    erofs *fs = f->fs;
    uint64_t pos = align8(f->iloc + f->isize + f->xsize);
    unsigned char h[8];
    if (rsrc_read(fs->src, h, 8, pos) < 0)
        return fail(fs, "cannot read compression header");
    if (h[7] & 0x80) {
        f->whole_fragment = 1;
        f->fragmentoff = le32(h);
        return 0;
    }
    f->advise = le16(h + 4);
    f->algo[0] = h[6] & 15;
    f->algo[1] = h[6] >> 4;
    f->lbits = fs->blkbits + (h[7] & 7);
    f->ebase = pos + 8 + (f->layout == L_COMPRESSED_FULL ? 8 : 0);
    if (f->layout == L_COMPRESSED_COMPACT && f->lbits > 14 && f->st.size)
        return fail(fs, "unsupported compact lcluster size");
    if (f->st.size == 0)
        return 0;
    if (f->advise & ADV_INLINE_PCLUSTER) {
        f->ztail = 1;
        f->idata_size = le16(h + 2);
    }
    if (f->advise & ADV_FRAGMENT) {
        f->fragment = 1;
        f->fragmentoff = le32(h);
    }
    if (f->ztail || f->fragment) {
        zmap z;
        if (map_blocks(f, f->st.size - 1, 1, &z) < 0)
            return -1;
    }
    return 0;
}

efile *efile_open(erofs *fs, uint64_t nid)
{
    efile *f = xcalloc(1, sizeof *f);
    f->fs = fs;
    if (read_inode(fs, nid, f) < 0 ||
        ((f->layout == L_COMPRESSED_FULL || f->layout == L_COMPRESSED_COMPACT) && init_compressed(f) < 0)) {
        free(f);
        return NULL;
    }
    return f;
}

void efile_close(efile *f)
{
    if (!f)
        return;
    free(f->cbuf);
    free(f);
}

static int packed_read(erofs *fs, uint64_t off, void *buf, size_t len)
{
    if (!fs->packed_nid)
        return fail(fs, "fragment without a packed inode");
    if (!fs->packed) {
        fs->packed = efile_open(fs, fs->packed_nid);
        if (!fs->packed)
            return -1;
    }
    return efile_read(fs->packed, off, buf, len);
}

static int read_flat(efile *f, uint64_t off, unsigned char *b, size_t len)
{
    erofs *fs = f->fs;
    uint64_t bs = fs->blksz;
    if (f->layout == L_FLAT_PLAIN)
        return rsrc_read(fs->src, b, len, (f->raw_blkaddr << fs->blkbits) + off) < 0 ? fail(fs, "read error") : 0;
    if (f->layout == L_FLAT_INLINE) {
        uint64_t nblocks = (f->st.size + bs - 1) / bs;
        uint64_t lastblk = nblocks ? nblocks - 1 : 0;
        while (len) {
            uint64_t blk = off / bs;
            size_t take;
            uint64_t phys;
            if (blk < lastblk) {
                take = (size_t)((lastblk * bs - off) < len ? (lastblk * bs - off) : len);
                phys = (f->raw_blkaddr << fs->blkbits) + off;
            } else {
                take = len;
                phys = f->iloc + f->isize + f->xsize + (off & (bs - 1));
            }
            if (rsrc_read(fs->src, b, take, phys) < 0)
                return fail(fs, "read error");
            b += take;
            off += take;
            len -= take;
        }
        return 0;
    }
    unsigned chunkbits = fs->blkbits + (f->chunkfmt & 31);
    int indexes = (f->chunkfmt & 0x20) != 0;
    unsigned unit = indexes ? 8 : 4;
    uint64_t base = f->iloc + f->isize + f->xsize;
    base = (base + unit - 1) / unit * unit;
    while (len) {
        uint64_t chunk = off >> chunkbits;
        uint64_t within = off & ((1ull << chunkbits) - 1);
        size_t take = (size_t)(((1ull << chunkbits) - within) < len ? ((1ull << chunkbits) - within) : len);
        unsigned char e[8];
        if (rsrc_read(fs->src, e, unit, base + chunk * unit) < 0)
            return fail(fs, "cannot read chunk index");
        uint32_t blk = indexes ? le32(e + 4) : le32(e);
        if (indexes && le16(e + 2))
            return fail(fs, "multi-device chunk");
        if (blk == 0xFFFFFFFFU)
            memset(b, 0, take);
        else if (rsrc_read(fs->src, b, take, ((uint64_t)blk << fs->blkbits) + within) < 0)
            return fail(fs, "read error");
        b += take;
        off += take;
        len -= take;
    }
    return 0;
}

int efile_read(efile *f, uint64_t off, void *buf, size_t len)
{
    erofs *fs = f->fs;
    unsigned char *b = buf;
    if (!len)
        return 0;
    if (off > f->st.size || len > f->st.size - off)
        return fail(fs, "read past the end of the file");
    if (f->layout == L_FLAT_PLAIN || f->layout == L_FLAT_INLINE || f->layout == L_CHUNK_BASED)
        return read_flat(f, off, b, len);
    if (f->whole_fragment)
        return packed_read(fs, f->fragmentoff + off, b, len);
    while (len) {
        if (f->cbuf && off >= f->cla && off < f->cla + f->clen) {
            size_t take = (size_t)(f->cla + f->clen - off < len ? f->cla + f->clen - off : len);
            memcpy(b, f->cbuf + (off - f->cla), take);
            b += take;
            off += take;
            len -= take;
            continue;
        }
        zmap z;
        if (map_blocks(f, off, 0, &z) < 0)
            return -1;
        if (z.la > off || z.la + z.llen <= off || z.llen > MAX_EXTENT)
            return fail(fs, "corrupt extent map");
        free(f->cbuf);
        f->cbuf = xmalloc((size_t)z.llen + 1);
        f->cla = z.la;
        f->clen = z.llen;
        if (z.fragment) {
            if (packed_read(fs, f->fragmentoff, f->cbuf, (size_t)z.llen) < 0) {
                f->clen = 0;
                return -1;
            }
            continue;
        }
        if (z.plen > MAX_EXTENT) {
            f->clen = 0;
            return fail(fs, "corrupt pcluster size");
        }
        unsigned char *in = xmalloc((size_t)z.plen + 1);
        if (rsrc_read(fs->src, in, (size_t)z.plen, z.pa) < 0) {
            free(in);
            f->clen = 0;
            return fail(fs, "read error");
        }
        int r = decompress(f, z.alg, in, (size_t)z.plen, f->cbuf, (size_t)z.llen, z.la);
        free(in);
        if (r < 0) {
            f->clen = 0;
            return -1;
        }
    }
    return 0;
}

int erofs_readdir(erofs *fs, uint64_t nid, erofs_dir_cb cb, void *ctx)
{
    efile *f = efile_open(fs, nid);
    if (!f)
        return -1;
    if ((f->st.mode & 0xF000) != 0x4000 || f->st.size > (256u << 20)) {
        efile_close(f);
        return fail(fs, "not a directory");
    }
    size_t size = (size_t)f->st.size;
    unsigned char *d = xmalloc(size + 1);
    if (efile_read(f, 0, d, size) < 0) {
        free(d);
        efile_close(f);
        return -1;
    }
    efile_close(f);
    int r = 0;
    for (size_t blk = 0; blk < size && !r; blk += fs->blksz) {
        size_t max = size - blk < fs->blksz ? size - blk : fs->blksz;
        const unsigned char *p = d + blk;
        if (max < 12)
            break;
        unsigned first = le16(p + 8);
        if (first < 12 || first > max || first % 12) {
            r = fail(fs, "corrupt directory block");
            break;
        }
        unsigned n = first / 12;
        for (unsigned i = 0; i < n && !r; i++) {
            uint64_t cnid = le64(p + i * 12);
            unsigned no = le16(p + i * 12 + 8);
            uint8_t ft = p[i * 12 + 10];
            unsigned end = i + 1 < n ? le16(p + (i + 1) * 12 + 8) : (unsigned)max;
            if (no > max || end > max || end < no) {
                r = fail(fs, "corrupt directory entry");
                break;
            }
            size_t nl = end - no;
            if (i + 1 == n)
                nl = strnlen((const char *)p + no, nl);
            const char *name = (const char *)p + no;
            if ((nl == 1 && name[0] == '.') || (nl == 2 && name[0] == '.' && name[1] == '.'))
                continue;
            if (nl)
                r = cb(ctx, name, nl, cnid, ft);
        }
    }
    free(d);
    return r < 0 ? -1 : r;
}

int erofs_readlink(erofs *fs, uint64_t nid, char **out)
{
    efile *f = efile_open(fs, nid);
    if (!f)
        return -1;
    if (f->st.size > 65536) {
        efile_close(f);
        return fail(fs, "symlink too long");
    }
    char *s = xmalloc((size_t)f->st.size + 1);
    if (efile_read(f, 0, s, (size_t)f->st.size) < 0) {
        free(s);
        efile_close(f);
        return -1;
    }
    s[f->st.size] = 0;
    efile_close(f);
    *out = s;
    return 0;
}

typedef struct {
    const char *want;
    size_t len;
    uint64_t found;
    int hit;
} elookup;

static int lookup_cb(void *ctx, const char *name, size_t nl, uint64_t nid, uint8_t ft)
{
    elookup *l = ctx;
    (void)ft;
    if (nl == l->len && !memcmp(name, l->want, nl)) {
        l->found = nid;
        l->hit = 1;
        return 1;
    }
    return 0;
}

int erofs_lookup(erofs *fs, const char *path, uint64_t *nid)
{
    uint64_t cur = fs->root;
    const char *s = path;
    while (*s) {
        while (*s == '/')
            s++;
        if (!*s)
            break;
        const char *e = strchr(s, '/');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        erofs_stat_t st;
        if (erofs_stat(fs, cur, &st) < 0 || (st.mode & 0xF000) != 0x4000)
            return -1;
        elookup l = {s, len, 0, 0};
        if (erofs_readdir(fs, cur, lookup_cb, &l) < 0 || !l.hit)
            return -1;
        cur = l.found;
        s += len;
    }
    *nid = cur;
    return 0;
}
