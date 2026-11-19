#include "core/vfs.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    zstream *s;
    uint64_t pos;
} zip_handle;

vnode *vfs_new_root(void)
{
    vnode *r = xcalloc(1, sizeof *r);
    r->name = xstrdup("");
    r->type = VN_DIR;
    r->mode = 0755;
    return r;
}

static void clear_payload(vnode *n)
{
    for (size_t i = 0; i < n->nkids; i++)
        vfs_free(n->kids[i]);
    free(n->kids);
    n->kids = NULL;
    n->nkids = n->capkids = 0;
    free(n->link);
    n->link = NULL;
    free(n->mem);
    n->mem = NULL;
    free(n->host);
    n->host = NULL;
    n->fs = NULL;
    n->ino = 0;
    n->zip = NULL;
    n->zentry = NULL;
    n->efs = NULL;
    n->src = VS_NONE;
    n->size = 0;
}

void vfs_free(vnode *n)
{
    if (!n)
        return;
    clear_payload(n);
    free(n->name);
    free(n);
}

vnode *vfs_child(vnode *dir, const char *name)
{
    if (!dir || dir->type != VN_DIR)
        return NULL;
    for (size_t i = 0; i < dir->nkids; i++)
        if (!strcmp(dir->kids[i]->name, name))
            return dir->kids[i];
    return NULL;
}

static vnode *walk_components(vnode *root, const char *path, int create, uint32_t mode)
{
    vnode *cur = root;
    const char *s = path;
    char comp[4096];
    while (*s) {
        while (*s == '/')
            s++;
        if (!*s)
            break;
        const char *e = strchr(s, '/');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        if (len >= sizeof comp)
            return NULL;
        memcpy(comp, s, len);
        comp[len] = 0;
        s += len;
        if (!strcmp(comp, "."))
            continue;
        vnode *next = vfs_child(cur, comp);
        if (!next) {
            if (!create)
                return NULL;
            next = vfs_put(cur, comp, VN_DIR);
            next->mode = mode;
        } else if (create && next->type != VN_DIR) {
            next = vfs_put(cur, comp, VN_DIR);
            next->mode = mode;
        }
        cur = next;
    }
    return cur;
}

vnode *vfs_lookup(vnode *root, const char *path)
{
    return walk_components(root, path, 0, 0);
}

vnode *vfs_mkdirs(vnode *root, const char *path, uint32_t mode)
{
    return walk_components(root, path, 1, mode);
}

vnode *vfs_resolve(vnode *root, const char *path)
{
    char *tmp = path[0] == '/' ? xstrdup(path) : xasprintf("/%s", path);
    char *cur = path_normalize(tmp);
    free(tmp);
    for (int hops = 0; cur && hops < 40; hops++) {
        vnode *node = root;
        const char *s = cur;
        int restarted = 0;
        while (*s) {
            while (*s == '/')
                s++;
            if (!*s)
                break;
            const char *e = strchr(s, '/');
            size_t len = e ? (size_t)(e - s) : strlen(s);
            char *comp = xstrndup(s, len);
            vnode *child = vfs_child(node, comp);
            free(comp);
            s += len;
            if (!child) {
                free(cur);
                return NULL;
            }
            if (child->type == VN_LINK) {
                char *base = vfs_path(node);
                char *joined = child->link[0] == '/' ? xasprintf("%s%s", child->link, s)
                                                     : xasprintf("%s/%s%s", base, child->link, s);
                free(base);
                free(cur);
                cur = path_normalize(joined);
                free(joined);
                restarted = 1;
                break;
            }
            if (child->type != VN_DIR && *s && strspn(s, "/") != strlen(s)) {
                free(cur);
                return NULL;
            }
            node = child;
        }
        if (!restarted) {
            free(cur);
            return node;
        }
    }
    free(cur);
    return NULL;
}

vnode *vfs_put(vnode *dir, const char *name, int type)
{
    vnode *n = vfs_child(dir, name);
    if (n) {
        if (n->type == VN_DIR && type == VN_DIR)
            return n;
        clear_payload(n);
        n->type = type;
        return n;
    }
    n = xcalloc(1, sizeof *n);
    n->name = xstrdup(name);
    n->parent = dir;
    n->type = type;
    n->mode = type == VN_DIR ? 0755 : 0644;
    if (dir->nkids == dir->capkids) {
        dir->capkids = dir->capkids ? dir->capkids * 2 : 8;
        dir->kids = xrealloc(dir->kids, dir->capkids * sizeof(vnode *));
    }
    dir->kids[dir->nkids++] = n;
    return n;
}

void vfs_remove(vnode *n)
{
    vnode *p = n->parent;
    if (!p)
        return;
    for (size_t i = 0; i < p->nkids; i++) {
        if (p->kids[i] == n) {
            memmove(&p->kids[i], &p->kids[i + 1], (p->nkids - i - 1) * sizeof(vnode *));
            p->nkids--;
            break;
        }
    }
    vfs_free(n);
}

char *vfs_path(vnode *n)
{
    if (!n->parent)
        return xstrdup("/");
    size_t depth = 0, total = 0;
    for (vnode *c = n; c->parent; c = c->parent) {
        depth++;
        total += strlen(c->name) + 1;
    }
    char *out = xmalloc(total + 1);
    size_t pos = total;
    out[pos] = 0;
    for (vnode *c = n; c->parent; c = c->parent) {
        size_t l = strlen(c->name);
        pos -= l;
        memcpy(out + pos, c->name, l);
        out[--pos] = '/';
    }
    (void)depth;
    return out;
}

void vfs_set_mem(vnode *n, unsigned char *data, size_t len)
{
    free(n->mem);
    free(n->host);
    n->host = NULL;
    n->fs = NULL;
    n->ino = 0;
    n->zip = NULL;
    n->zentry = NULL;
    n->efs = NULL;
    n->mem = data;
    n->size = len;
    n->src = VS_MEM;
}

int vfs_read(vnode *n, uint64_t off, void *buf, size_t len, void **handle)
{
    if (off > n->size || len > n->size - off)
        return -1;
    switch (n->src) {
    case VS_MEM:
        memcpy(buf, n->mem + off, len);
        return 0;
    case VS_EXT4:
        return ext4_read(n->fs, n->ino, off, buf, len);
    case VS_EROFS: {
        efile *ef = *handle;
        if (!ef) {
            ef = efile_open(n->efs, n->enid);
            if (!ef)
                return -1;
            *handle = ef;
        }
        return efile_read(ef, off, buf, len);
    }
    case VS_ZIP: {
        zip_handle *zh = *handle;
        if (zh && off < zh->pos) {
            zstream_close(zh->s);
            free(zh);
            zh = NULL;
        }
        if (!zh) {
            zh = xcalloc(1, sizeof *zh);
            zh->s = zstream_open(n->zip, n->zentry);
            if (!zh->s) {
                free(zh);
                *handle = NULL;
                return -1;
            }
            *handle = zh;
        }
        unsigned char skip[65536];
        while (zh->pos < off) {
            uint64_t want = off - zh->pos;
            long r = zstream_read(zh->s, skip, want > sizeof skip ? sizeof skip : (size_t)want);
            if (r <= 0)
                return -1;
            zh->pos += (uint64_t)r;
        }
        unsigned char *b = buf;
        size_t left = len;
        while (left) {
            long r = zstream_read(zh->s, b, left);
            if (r <= 0)
                return -1;
            b += r;
            left -= (size_t)r;
            zh->pos += (uint64_t)r;
        }
        return 0;
    }
    case VS_HOST: {
        FILE *f = *handle;
        if (!f) {
            f = fopen(n->host, "rb");
            if (!f)
                return -1;
            *handle = f;
        }
        if (fseeko(f, (off_t)off, SEEK_SET) < 0)
            return -1;
        return fread(buf, 1, len, f) == len ? 0 : -1;
    }
    default:
        if (len)
            memset(buf, 0, len);
        return n->size ? -1 : 0;
    }
}

void vfs_read_done(vnode *n, void **handle)
{
    if (n->src == VS_HOST && *handle)
        fclose(*handle);
    if (n->src == VS_EROFS && *handle)
        efile_close(*handle);
    if (n->src == VS_ZIP && *handle) {
        zip_handle *zh = *handle;
        zstream_close(zh->s);
        free(zh);
    }
    *handle = NULL;
}

int vfs_read_all(vnode *n, buf_t *out, size_t limit)
{
    if (n->type != VN_FILE)
        return -1;
    if (limit && n->size > limit)
        return -1;
    void *h = NULL;
    buf_reserve(out, (size_t)n->size);
    int r = vfs_read(n, 0, out->data + out->len, (size_t)n->size, &h);
    vfs_read_done(n, &h);
    if (r < 0)
        return -1;
    out->len += (size_t)n->size;
    out->data[out->len] = 0;
    return 0;
}

static int walk_rec(vnode *n, buf_t *path, vfs_walk_cb cb, void *ctx)
{
    size_t keep = path->len;
    if (n->parent) {
        if (path->len != 1)
            buf_putc(path, '/');
        buf_puts(path, n->name);
    }
    int r = cb(n, (const char *)path->data, ctx);
    if (r < 0 || r == 2) {
        path->len = keep;
        path->data[keep] = 0;
        return r;
    }
    if (r == 0 && n->type == VN_DIR) {
        for (size_t i = 0; i < n->nkids; i++) {
            vnode *k = n->kids[i];
            size_t before = n->nkids;
            int rr = walk_rec(k, path, cb, ctx);
            if (rr < 0) {
                path->len = keep;
                path->data[keep] = 0;
                return rr;
            }
            if (n->nkids < before)
                i--;
        }
    }
    path->len = keep;
    path->data[keep] = 0;
    return 0;
}

int vfs_walk(vnode *root, vfs_walk_cb cb, void *ctx)
{
    buf_t path = {0};
    buf_putc(&path, '/');
    int r = walk_rec(root, &path, cb, ctx);
    buf_free(&path);
    return r;
}

static int cmp_nodes(const void *a, const void *b)
{
    const vnode *x = *(const vnode *const *)a;
    const vnode *y = *(const vnode *const *)b;
    return strcmp(x->name, y->name);
}

void vfs_sort(vnode *root)
{
    if (root->type != VN_DIR)
        return;
    if (root->nkids > 1)
        qsort(root->kids, root->nkids, sizeof(vnode *), cmp_nodes);
    for (size_t i = 0; i < root->nkids; i++)
        vfs_sort(root->kids[i]);
}

void vfs_count(vnode *root, uint64_t *files, uint64_t *dirs, uint64_t *links, uint64_t *bytes)
{
    if (root->type == VN_DIR) {
        (*dirs)++;
        for (size_t i = 0; i < root->nkids; i++)
            vfs_count(root->kids[i], files, dirs, links, bytes);
    } else if (root->type == VN_LINK) {
        (*links)++;
    } else {
        (*files)++;
        *bytes += root->size;
    }
}

vnode *vfs_write_text(vnode *root, const char *path, const char *text, size_t len, uint32_t mode)
{
    char *dir = path_dirname(path);
    vnode *d = vfs_mkdirs(root, dir, 0755);
    free(dir);
    if (!d)
        return NULL;
    vnode *n = vfs_child(d, path_basename(path));
    int existed = n && n->type == VN_FILE;
    uint32_t old_mode = existed ? n->mode : mode;
    uint32_t uid = existed ? n->uid : 0, gid = existed ? n->gid : 0;
    n = vfs_put(d, path_basename(path), VN_FILE);
    unsigned char *copy = xmalloc(len + 1);
    memcpy(copy, text, len);
    copy[len] = 0;
    vfs_set_mem(n, copy, len);
    n->mode = old_mode;
    n->uid = uid;
    n->gid = gid;
    return n;
}
