#include "formats/ext4.h"

#include <stdlib.h>
#include <string.h>

#define EXT4_MAGIC 0xEF53
#define INCOMPAT_COMPRESSION 0x1
#define INCOMPAT_JOURNAL_DEV 0x8
#define INCOMPAT_META_BG 0x10
#define INCOMPAT_64BIT 0x80
#define RO_COMPAT_HUGE_FILE 0x8
#define FL_ENCRYPT 0x800
#define FL_HUGE_FILE 0x40000
#define FL_EXTENTS 0x80000
#define FL_INLINE_DATA 0x10000000
#define EXTENT_MAGIC 0xF30A
#define XATTR_MAGIC 0xEA020000U
#define MAX_DIR_BYTES (256u << 20)

typedef struct {
    uint64_t lblk;
    uint64_t pblk;
    uint64_t len;
    int uninit;
} run_t;

struct ext4 {
    rsrc *src;
    uint32_t bs;
    uint64_t blocks;
    uint32_t ipg, bpg, inode_size, first_data;
    uint32_t ngroups;
    uint64_t *itable;
    uint32_t incompat, ro_compat;
    uint32_t inodes_count;

    uint32_t map_ino;
    uint64_t map_size;
    run_t *runs;
    size_t nruns, capruns;
    int map_inline;
    buf_t inline_data;
};

int ext4_probe(rsrc *src)
{
    unsigned char m[2];
    if (src->size < 2048 || rsrc_read(src, m, 2, 1024 + 56) < 0)
        return 0;
    return le16(m) == EXT4_MAGIC;
}

const char *ext4_name(ext4 *fs)
{
    return fs->src->name;
}

ext4 *ext4_open(rsrc *src, char *err, size_t errlen)
{
    unsigned char sb[1024];
    if (rsrc_read(src, sb, sizeof sb, 1024) < 0 || le16(sb + 56) != EXT4_MAGIC) {
        snprintf(err, errlen, "not an ext2/3/4 filesystem");
        return NULL;
    }
    ext4 *fs = xcalloc(1, sizeof *fs);
    fs->src = src;
    uint32_t log_bs = le32(sb + 24);
    if (log_bs > 6) {
        snprintf(err, errlen, "bad block size");
        free(fs);
        return NULL;
    }
    fs->bs = 1024u << log_bs;
    fs->inodes_count = le32(sb + 0);
    fs->bpg = le32(sb + 32);
    fs->ipg = le32(sb + 40);
    fs->first_data = le32(sb + 20);
    fs->incompat = le32(sb + 96);
    fs->ro_compat = le32(sb + 100);
    fs->inode_size = le32(sb + 76) >= 1 ? le16(sb + 88) : 128;
    fs->blocks = le32(sb + 4);
    if (fs->incompat & INCOMPAT_64BIT)
        fs->blocks |= (uint64_t)le32(sb + 0x150) << 32;
    if (fs->incompat & (INCOMPAT_COMPRESSION | INCOMPAT_JOURNAL_DEV)) {
        snprintf(err, errlen, "unsupported ext4 features (0x%x)", fs->incompat);
        free(fs);
        return NULL;
    }
    if (fs->incompat & INCOMPAT_META_BG) {
        snprintf(err, errlen, "ext4 meta_bg layout is not supported; extract the image with another tool");
        free(fs);
        return NULL;
    }
    if (!fs->bpg || !fs->ipg || fs->inode_size < 128 || fs->inode_size > fs->bs) {
        snprintf(err, errlen, "corrupt ext4 superblock");
        free(fs);
        return NULL;
    }
    uint32_t desc_size = 32;
    if (fs->incompat & INCOMPAT_64BIT) {
        desc_size = le16(sb + 254);
        if (desc_size < 32)
            desc_size = 32;
    }
    fs->ngroups = (uint32_t)((fs->blocks - fs->first_data + fs->bpg - 1) / fs->bpg);
    if (!fs->ngroups || fs->ngroups > (1u << 24)) {
        snprintf(err, errlen, "corrupt ext4 group count");
        free(fs);
        return NULL;
    }
    size_t gdt_len = (size_t)fs->ngroups * desc_size;
    unsigned char *gdt = xmalloc(gdt_len);
    uint64_t gdt_off = ((uint64_t)fs->first_data + 1) * fs->bs;
    if (rsrc_read(src, gdt, gdt_len, gdt_off) < 0) {
        snprintf(err, errlen, "cannot read ext4 group descriptors (truncated image?)");
        free(gdt);
        free(fs);
        return NULL;
    }
    fs->itable = xcalloc(fs->ngroups, sizeof(uint64_t));
    for (uint32_t g = 0; g < fs->ngroups; g++) {
        unsigned char *d = gdt + (size_t)g * desc_size;
        uint64_t t = le32(d + 8);
        if (desc_size >= 64)
            t |= (uint64_t)le32(d + 0x28) << 32;
        fs->itable[g] = t;
    }
    free(gdt);
    return fs;
}

void ext4_close(ext4 *fs)
{
    if (!fs)
        return;
    free(fs->itable);
    free(fs->runs);
    buf_free(&fs->inline_data);
    rsrc_close(fs->src);
    free(fs);
}

static int read_inode(ext4 *fs, uint32_t ino, unsigned char *raw)
{
    if (ino == 0 || ino > fs->inodes_count)
        return -1;
    uint32_t g = (ino - 1) / fs->ipg;
    uint32_t idx = (ino - 1) % fs->ipg;
    if (g >= fs->ngroups)
        return -1;
    uint64_t off = fs->itable[g] * fs->bs + (uint64_t)idx * fs->inode_size;
    return rsrc_read(fs->src, raw, fs->inode_size, off);
}

static void fill_stat(ext4 *fs, uint32_t ino, const unsigned char *raw, ext4_stat_t *st)
{
    (void)fs;
    st->ino = ino;
    st->mode = le16(raw + 0);
    st->uid = le16(raw + 2) | ((uint32_t)le16(raw + 120) << 16);
    st->gid = le16(raw + 24) | ((uint32_t)le16(raw + 122) << 16);
    st->size = le32(raw + 4) | ((uint64_t)le32(raw + 108) << 32);
    st->flags = le32(raw + 32);
    st->mtime = (int32_t)le32(raw + 16);
    st->encrypted = (st->flags & FL_ENCRYPT) != 0;
}

int ext4_stat(ext4 *fs, uint32_t ino, ext4_stat_t *st)
{
    unsigned char *raw = xmalloc(fs->inode_size);
    int r = read_inode(fs, ino, raw);
    if (r == 0)
        fill_stat(fs, ino, raw, st);
    free(raw);
    return r;
}

static void add_run(ext4 *fs, uint64_t lblk, uint64_t pblk, uint64_t len, int uninit)
{
    if (fs->nruns) {
        run_t *l = &fs->runs[fs->nruns - 1];
        if (l->uninit == uninit && l->lblk + l->len == lblk && l->pblk + l->len == pblk) {
            l->len += len;
            return;
        }
    }
    if (fs->nruns == fs->capruns) {
        fs->capruns = fs->capruns ? fs->capruns * 2 : 16;
        fs->runs = xrealloc(fs->runs, fs->capruns * sizeof(run_t));
    }
    fs->runs[fs->nruns++] = (run_t){lblk, pblk, len, uninit};
}

static int walk_extents(ext4 *fs, const unsigned char *node, size_t node_len, int depth_left)
{
    if (node_len < 12 || le16(node) != EXTENT_MAGIC)
        return -1;
    uint16_t entries = le16(node + 2);
    uint16_t depth = le16(node + 6);
    if (12 + (size_t)entries * 12 > node_len || depth_left <= 0)
        return -1;
    for (uint16_t i = 0; i < entries; i++) {
        const unsigned char *e = node + 12 + (size_t)i * 12;
        if (depth == 0) {
            uint32_t lblk = le32(e);
            uint16_t len = le16(e + 4);
            int uninit = 0;
            if (len > 32768) {
                len -= 32768;
                uninit = 1;
            }
            uint64_t pblk = ((uint64_t)le16(e + 6) << 32) | le32(e + 8);
            add_run(fs, lblk, pblk, len, uninit);
        } else {
            uint64_t leaf = ((uint64_t)le16(e + 8) << 32) | le32(e + 4);
            unsigned char *blk = xmalloc(fs->bs);
            if (rsrc_read(fs->src, blk, fs->bs, leaf * fs->bs) < 0 ||
                walk_extents(fs, blk, fs->bs, depth_left - 1) < 0) {
                free(blk);
                return -1;
            }
            free(blk);
        }
    }
    return 0;
}

static int walk_indirect(ext4 *fs, uint32_t blk, int level, uint64_t *l, uint64_t nb)
{
    uint64_t per = fs->bs / 4;
    if (*l >= nb)
        return 0;
    if (blk == 0) {
        uint64_t skip = 1;
        for (int i = 0; i < level; i++)
            skip *= per;
        *l += skip;
        return 0;
    }
    if (level == 0) {
        add_run(fs, *l, blk, 1, 0);
        (*l)++;
        return 0;
    }
    unsigned char *tab = xmalloc(fs->bs);
    if (rsrc_read(fs->src, tab, fs->bs, (uint64_t)blk * fs->bs) < 0) {
        free(tab);
        return -1;
    }
    for (uint64_t i = 0; i < per && *l < nb; i++) {
        if (walk_indirect(fs, le32(tab + i * 4), level - 1, l, nb) < 0) {
            free(tab);
            return -1;
        }
    }
    free(tab);
    return 0;
}

static int inline_xattr(ext4 *fs, const unsigned char *raw, buf_t *out)
{
    uint16_t extra = le16(raw + 128);
    if (fs->inode_size <= 128)
        return 0;
    size_t off = 128 + (size_t)extra;
    if (off + 4 > fs->inode_size || le32(raw + off) != XATTR_MAGIC)
        return 0;
    size_t base = off + 4;
    size_t p = base;
    while (p + 16 <= fs->inode_size && le32(raw + p) != 0) {
        uint8_t name_len = raw[p];
        uint8_t index = raw[p + 1];
        uint16_t voff = le16(raw + p + 2);
        uint32_t vsize = le32(raw + p + 8);
        if (p + 16 + name_len > fs->inode_size)
            break;
        if (index == 7 && name_len == 4 && !memcmp(raw + p + 16, "data", 4)) {
            if (base + voff + vsize <= fs->inode_size)
                buf_put(out, raw + base + voff, vsize);
            return 0;
        }
        p += (16 + name_len + 3) & ~(size_t)3;
    }
    return 0;
}

static int ensure_map(ext4 *fs, uint32_t ino)
{
    if (fs->map_ino == ino && ino)
        return 0;
    fs->map_ino = 0;
    fs->nruns = 0;
    fs->map_inline = 0;
    fs->inline_data.len = 0;
    unsigned char *raw = xmalloc(fs->inode_size);
    if (read_inode(fs, ino, raw) < 0) {
        free(raw);
        return -1;
    }
    ext4_stat_t st;
    fill_stat(fs, ino, raw, &st);
    fs->map_size = st.size;
    int r = 0;
    if (st.flags & FL_INLINE_DATA) {
        fs->map_inline = 1;
        buf_put(&fs->inline_data, raw + 40, 60);
        inline_xattr(fs, raw, &fs->inline_data);
    } else if (st.flags & FL_EXTENTS) {
        r = walk_extents(fs, raw + 40, 60, 8);
    } else {
        uint64_t nb = (st.size + fs->bs - 1) / fs->bs;
        uint64_t l = 0;
        for (int i = 0; i < 12 && l < nb; i++) {
            uint32_t b = le32(raw + 40 + i * 4);
            if (b)
                add_run(fs, l, b, 1, 0);
            l++;
        }
        for (int lvl = 1; lvl <= 3 && r == 0 && l < nb; lvl++)
            r = walk_indirect(fs, le32(raw + 40 + (11 + lvl) * 4), lvl, &l, nb);
    }
    free(raw);
    if (r < 0)
        return -1;
    fs->map_ino = ino;
    return 0;
}

int ext4_read(ext4 *fs, uint32_t ino, uint64_t off, void *buf, size_t len)
{
    unsigned char *b = buf;
    if (ensure_map(fs, ino) < 0)
        return -1;
    if (off >= fs->map_size) {
        memset(b, 0, len);
        return len ? -1 : 0;
    }
    if (len > fs->map_size - off) {
        size_t over = len - (size_t)(fs->map_size - off);
        memset(b + len - over, 0, over);
        len -= over;
    }
    if (fs->map_inline) {
        size_t have = fs->inline_data.len;
        for (size_t i = 0; i < len; i++)
            b[i] = (off + i < have) ? fs->inline_data.data[off + i] : 0;
        return 0;
    }
    while (len) {
        uint64_t lblk = off / fs->bs;
        uint64_t within = off % fs->bs;
        size_t lo = 0, hi = fs->nruns;
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (fs->runs[mid].lblk + fs->runs[mid].len <= lblk)
                lo = mid + 1;
            else
                hi = mid;
        }
        size_t take;
        if (lo < fs->nruns && fs->runs[lo].lblk <= lblk) {
            run_t *r = &fs->runs[lo];
            uint64_t avail = (r->lblk + r->len - lblk) * fs->bs - within;
            take = avail < len ? (size_t)avail : len;
            if (r->uninit) {
                memset(b, 0, take);
            } else {
                uint64_t phys = (r->pblk + (lblk - r->lblk)) * fs->bs + within;
                if (rsrc_read(fs->src, b, take, phys) < 0)
                    return -1;
            }
        } else {
            uint64_t avail = lo < fs->nruns ? (fs->runs[lo].lblk - lblk) * fs->bs - within : len;
            take = avail < len ? (size_t)avail : len;
            memset(b, 0, take);
        }
        b += take;
        off += take;
        len -= take;
    }
    return 0;
}

int ext4_readlink(ext4 *fs, uint32_t ino, char **out)
{
    unsigned char *raw = xmalloc(fs->inode_size);
    if (read_inode(fs, ino, raw) < 0) {
        free(raw);
        return -1;
    }
    ext4_stat_t st;
    fill_stat(fs, ino, raw, &st);
    if (st.size > 65536) {
        free(raw);
        return -1;
    }
    uint64_t blocks512 = le32(raw + 28);
    if ((fs->ro_compat & RO_COMPAT_HUGE_FILE) && (st.flags & FL_HUGE_FILE))
        blocks512 *= fs->bs / 512;
    uint64_t acl = le32(raw + 104) | ((uint64_t)le16(raw + 118) << 32);
    if (acl && blocks512 >= fs->bs / 512)
        blocks512 -= fs->bs / 512;
    int fast = !(st.flags & FL_INLINE_DATA) && blocks512 == 0 && st.size <= 60;
    char *s = xmalloc((size_t)st.size + 1);
    if (fast) {
        memcpy(s, raw + 40, (size_t)st.size);
    } else if (ext4_read(fs, ino, 0, s, (size_t)st.size) < 0) {
        free(s);
        free(raw);
        return -1;
    }
    s[st.size] = 0;
    free(raw);
    *out = s;
    return 0;
}

static int parse_dirents(const unsigned char *d, size_t len, size_t block, ext4_dir_cb cb, void *ctx)
{
    size_t p = 0;
    while (p + 8 <= len) {
        size_t block_end = block ? (p / block + 1) * block : len;
        if (block_end > len)
            block_end = len;
        uint32_t ino = le32(d + p);
        uint32_t rec = le16(d + p + 4);
        uint8_t nlen = d[p + 6];
        uint8_t type = d[p + 7];
        if (block >= 65536 && (rec == 65535 || rec == 0))
            rec = (uint32_t)block;
        if (rec < 8 || p + rec > block_end) {
            if (!block)
                break;
            p = block_end;
            continue;
        }
        if (ino && nlen && 8 + (size_t)nlen <= rec) {
            const char *name = (const char *)d + p + 8;
            int dot = (nlen == 1 && name[0] == '.') || (nlen == 2 && name[0] == '.' && name[1] == '.');
            if (!dot) {
                int r = cb(ctx, name, nlen, ino, type);
                if (r)
                    return r;
            }
        }
        p += rec;
    }
    return 0;
}

int ext4_readdir(ext4 *fs, uint32_t ino, ext4_dir_cb cb, void *ctx)
{
    unsigned char *raw = xmalloc(fs->inode_size);
    if (read_inode(fs, ino, raw) < 0) {
        free(raw);
        return -1;
    }
    ext4_stat_t st;
    fill_stat(fs, ino, raw, &st);
    if ((st.mode & 0xF000) != 0x4000) {
        free(raw);
        return -1;
    }
    int r;
    if (st.flags & FL_INLINE_DATA) {
        buf_t extra = {0};
        inline_xattr(fs, raw, &extra);
        r = parse_dirents(raw + 44, 56, 0, cb, ctx);
        if (!r && extra.len)
            r = parse_dirents(extra.data, extra.len, 0, cb, ctx);
        buf_free(&extra);
        free(raw);
        return r;
    }
    free(raw);
    if (st.size > MAX_DIR_BYTES)
        return -1;
    unsigned char *d = xmalloc((size_t)st.size + 1);
    if (ext4_read(fs, ino, 0, d, (size_t)st.size) < 0) {
        free(d);
        return -1;
    }
    r = parse_dirents(d, (size_t)st.size, fs->bs, cb, ctx);
    free(d);
    return r;
}

typedef struct {
    const char *want;
    size_t len;
    uint32_t found;
} lookup_ctx;

static int lookup_cb(void *ctx, const char *name, size_t namelen, uint32_t ino, uint8_t ftype)
{
    lookup_ctx *l = ctx;
    (void)ftype;
    if (namelen == l->len && !memcmp(name, l->want, namelen)) {
        l->found = ino;
        return 1;
    }
    return 0;
}

int ext4_lookup(ext4 *fs, const char *path, uint32_t *ino)
{
    uint32_t cur = EXT4_ROOT_INO;
    const char *s = path;
    while (*s) {
        while (*s == '/')
            s++;
        if (!*s)
            break;
        const char *e = strchr(s, '/');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        lookup_ctx l = {s, len, 0};
        ext4_stat_t st;
        if (ext4_stat(fs, cur, &st) < 0 || (st.mode & 0xF000) != 0x4000)
            return -1;
        if (ext4_readdir(fs, cur, lookup_cb, &l) < 0 || !l.found)
            return -1;
        cur = l.found;
        s += len;
    }
    *ino = cur;
    return 0;
}
