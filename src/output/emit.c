#include "output/emit.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "core/codec.h"
#include "formats/cpio.h"
#include "core/rsrc.h"
#include "output/tar.h"
#include "output/zipw.h"

#define RAMDISK_LIMIT (120u << 20)
#define COPY_CHUNK (1u << 20)

typedef struct {
    tarw *t;
    zipw *z;
} aw;

static int aw_dir(aw *a, const char *name, const vnode *n)
{
    return a->z ? zipw_dir(a->z, name, n->mode, n->mtime) : tarw_dir(a->t, name, n->mode, n->uid, n->gid, n->mtime);
}

static int aw_link(aw *a, const char *name, const vnode *n)
{
    return a->z ? zipw_symlink(a->z, name, n->link, n->mtime)
                : tarw_symlink(a->t, name, n->link, 0777, n->uid, n->gid, n->mtime);
}

static int aw_begin(aw *a, const char *name, uint64_t size, uint32_t mode, uint32_t uid, uint32_t gid, int64_t mtime,
                    int compress)
{
    return a->z ? zipw_file_begin(a->z, name, size, mode, mtime, compress)
                : tarw_file_begin(a->t, name, size, mode, uid, gid, mtime);
}

static int aw_write(aw *a, const void *d, size_t len)
{
    return a->z ? zipw_write(a->z, d, len) : tarw_write(a->t, d, len);
}

static int aw_end(aw *a)
{
    return a->z ? zipw_file_end(a->z) : tarw_file_end(a->t);
}

static int compressible(const char *name)
{
    static const char *const stored[] = {".apk", ".jar", ".zip", ".apex", ".capex", ".png", ".jpg", ".jpeg",
                                         ".gif", ".webp", ".ogg", ".mp3", ".mp4", ".m4a", ".aac", ".gz",
                                         ".xz", ".br", ".lz4", ".zst", ".bz2", ".7z", ".flac", ".webm", NULL};
    for (int i = 0; stored[i]; i++)
        if (ends_with_ci(name, stored[i]))
            return 0;
    return 1;
}

typedef struct {
    uint64_t files, bytes, total_files, total_bytes;
} prog;

typedef struct {
    aw a;
    unsigned char *buf;
    uint64_t files;
    uint64_t bytes;
    prog *p;
} writer;

static void progress(prog *p, uint64_t partial, int force)
{
    if (!p || !p->total_bytes)
        return;
    uint64_t done = p->bytes + partial;
    if (done > p->total_bytes)
        done = p->total_bytes;
    char a[32], b[32];
    progress_show(force, "  writing  %3u%%  %llu/%llu files  %s / %s", (unsigned)(done * 100 / p->total_bytes),
                  (unsigned long long)p->files, (unsigned long long)p->total_files, human_size(done, a, sizeof a),
                  human_size(p->total_bytes, b, sizeof b));
}

static void count_node(const vnode *n, prog *p)
{
    if (n->type == VN_DIR) {
        for (size_t i = 0; i < n->nkids; i++)
            count_node(n->kids[i], p);
    } else if (n->type == VN_FILE) {
        p->total_files++;
        p->total_bytes += n->size;
    }
}

static void write_node(writer *w, vnode *n, const char *name)
{
    if (n->type == VN_DIR) {
        if (aw_dir(&w->a, name, n) < 0)
            die("write failed: %s", strerror(errno));
        for (size_t i = 0; i < n->nkids; i++) {
            char *child = xasprintf("%s/%s", name, n->kids[i]->name);
            write_node(w, n->kids[i], child);
            free(child);
        }
    } else if (n->type == VN_LINK) {
        if (aw_link(&w->a, name, n) < 0)
            die("write failed: %s", strerror(errno));
    } else {
        if (aw_begin(&w->a, name, n->size, n->mode, n->uid, n->gid, n->mtime, compressible(name)) < 0)
            die("write failed: %s", strerror(errno));
        void *h = NULL;
        uint64_t off = 0;
        while (off < n->size) {
            size_t chunk = n->size - off > COPY_CHUNK ? COPY_CHUNK : (size_t)(n->size - off);
            if (vfs_read(n, off, w->buf, chunk, &h) < 0)
                die("cannot read /%s from %s", name, n->origin ? n->origin : "input");
            if (aw_write(&w->a, w->buf, chunk) < 0)
                die("write failed: %s", strerror(errno));
            off += chunk;
            if (n->size > COPY_CHUNK)
                progress(w->p, off, 0);
        }
        vfs_read_done(n, &h);
        if (aw_end(&w->a) < 0)
            die("write failed: %s", strerror(errno));
        w->files++;
        w->bytes += n->size;
        if (w->p) {
            w->p->files++;
            w->p->bytes += n->size;
            progress(w->p, 0, 0);
        }
    }
}

static int is_extra_mount(const char *n)
{
    if (!strcmp(n, "odm") || !strcmp(n, "mi_ext") || !strcmp(n, "vgc") || !strcmp(n, "prism") || !strcmp(n, "optics"))
        return 1;
    return starts_with(n, "my_") && n[3];
}

typedef struct {
    buf_t cpio;
    uint32_t ino;
    size_t entries;
    uint64_t content;
} rdbuild;

static void cpio_node(rdbuild *r, vnode *n, const char *name)
{
    uint32_t perm = n->mode & 07777;
    if (n->type == VN_DIR) {
        cpio_write_entry(&r->cpio, r->ino++, name, 0x4000 | perm, n->uid, n->gid, n->mtime, NULL, 0);
        r->entries++;
        for (size_t i = 0; i < n->nkids; i++) {
            char *child = xasprintf("%s/%s", name, n->kids[i]->name);
            cpio_node(r, n->kids[i], child);
            free(child);
        }
    } else if (n->type == VN_LINK) {
        cpio_write_entry(&r->cpio, r->ino++, name, 0xA000 | (perm ? perm : 0777), n->uid, n->gid, n->mtime, n->link,
                         strlen(n->link));
        r->entries++;
    } else {
        if (r->content + n->size > RAMDISK_LIMIT)
            die("the root file system does not fit in a ramdisk (over %u MiB at /%s); remove large files from the root "
                "with --remove",
                RAMDISK_LIMIT >> 20, name);
        buf_t b = {0};
        if (vfs_read_all(n, &b, 0) < 0)
            die("cannot read /%s from %s", name, n->origin ? n->origin : "input");
        cpio_write_entry(&r->cpio, r->ino++, name, 0x8000 | perm, n->uid, n->gid, n->mtime, b.data, b.len);
        r->content += b.len;
        r->entries++;
        buf_free(&b);
    }
}

static int is_direct(const char *n, int zip)
{
    if (!strcmp(n, "system"))
        return 1;
    if (zip)
        return 0;
    return !strcmp(n, "vendor") || !strcmp(n, "oem");
}

static int is_ramdisk_root(const vnode *k, int zip)
{
    const char *n = k->name;
    if (is_direct(n, zip) || !strcmp(n, "dev") || !strcmp(n, "proc") || !strcmp(n, "sys"))
        return 0;
    if (zip && (!strcmp(n, "vendor") || !strcmp(n, "oem")) && k->type == VN_DIR)
        return 0;
    if (is_extra_mount(n) && k->type == VN_DIR && k->nkids)
        return 0;
    if (!strcmp(n, "data") && k->type == VN_DIR && k->nkids)
        return 0;
    return 1;
}

static int ramdisk_skip_name(const char *n, vnode *root, int zip)
{
    size_t l = strcspn(n, "/");
    char *top = xstrndup(n, l);
    vnode *k = vfs_child(root, top);
    int skip = !strcmp(top, "system") || !strcmp(top, "data") || !strcmp(top, "dev") || !strcmp(top, "proc") ||
               !strcmp(top, "sys") || (k && !is_ramdisk_root(k, zip));
    free(top);
    return skip;
}

static int cmp_entry(const void *a, const void *b)
{
    return strcmp(((const cpio_entry *)a)->name, ((const cpio_entry *)b)->name);
}

static int same_ramdisk(const cpio_list *orig, const unsigned char *cpio, size_t len, vnode *root, int zip)
{
    cpio_list now = {0};
    char err[128];
    if (cpio_parse(cpio, len, &now, err, sizeof err) < 0)
        return 0;
    cpio_entry *a = xcalloc(orig->n ? orig->n : 1, sizeof(cpio_entry));
    size_t na = 0;
    for (size_t i = 0; i < orig->n; i++)
        if (!ramdisk_skip_name(orig->e[i].name, root, zip))
            a[na++] = orig->e[i];
    cpio_entry *b = xcalloc(now.n ? now.n : 1, sizeof(cpio_entry));
    size_t nb = 0;
    for (size_t i = 0; i < now.n; i++)
        if (!ramdisk_skip_name(now.e[i].name, root, zip))
            b[nb++] = now.e[i];
    int same = na == nb;
    if (same) {
        qsort(a, na, sizeof *a, cmp_entry);
        qsort(b, nb, sizeof *b, cmp_entry);
        for (size_t i = 0; i < na && same; i++) {
            if (strcmp(a[i].name, b[i].name) || a[i].mode != b[i].mode || a[i].size != b[i].size ||
                (a[i].size && memcmp(a[i].data, b[i].data, a[i].size)))
                same = 0;
        }
    }
    free(a);
    free(b);
    cpio_free(&now);
    return same;
}

static void write_blob(writer *w, const char *name, const unsigned char *d, size_t len)
{
    if (aw_begin(&w->a, name, len, 0644, 0, 0, 0, 1) < 0 || aw_write(&w->a, d, len) < 0 || aw_end(&w->a) < 0)
        die("write failed: %s", strerror(errno));
}

static void write_boot(writer *w, rom_t *rom, const emit_opts *o)
{
    rdbuild r = {{0}, 300000, 0, 0};
    for (size_t i = 0; i < rom->root->nkids; i++) {
        vnode *k = rom->root->kids[i];
        if (is_ramdisk_root(k, o->zip))
            cpio_node(&r, k, k->name);
    }
    int have_kernel = rom->have_boot && rom->boot.kernel_size;
    if (!r.entries && !have_kernel) {
        buf_free(&r.cpio);
        note("  boot.img     none (no ramdisk files and no kernel)");
        return;
    }
    if (!o->force_new_boot && r.entries && rom->have_boot && rom->have_ramdisk && rom->ramdisk_source &&
        rom->boot_source && !strcmp(rom->ramdisk_source, rom->boot_source) && rom->boot_raw.len &&
        same_ramdisk(&rom->ramdisk, r.cpio.data, r.cpio.len, rom->root, o->zip)) {
        write_blob(w, "boot.img", rom->boot_raw.data, rom->boot_raw.len);
        note("  boot.img     original %s (ramdisk unchanged)", path_basename(rom->boot_source));
        buf_free(&r.cpio);
        return;
    }
    buf_t gz = {0};
    if (r.entries) {
        cpio_write_trailer(&r.cpio, r.ino++);
        if (gzip_compress(r.cpio.data, r.cpio.len, 9, &gz) < 0)
            die("ramdisk compression failed");
    }
    buf_t img = {0};
    bootimg_build_v0(rom->have_boot ? &rom->boot : NULL, have_kernel ? rom->boot.kernel : NULL,
                     have_kernel ? rom->boot.kernel_size : 0, gz.data, gz.len, &img);
    write_blob(w, "boot.img", img.data, img.len);
    char hs[32];
    note("  boot.img     rebuilt: %zu root entries (%s ramdisk), %s", r.entries, human_size(gz.len, hs, sizeof hs),
         have_kernel ? "original kernel" : "no kernel");
    buf_free(&img);
    buf_free(&gz);
    buf_free(&r.cpio);
}

static void write_nested(writer *w, vnode *k)
{
    FILE *tf = fdopen(temp_fd(), "w+b");
    if (!tf)
        die("cannot create a temporary file: %s", strerror(errno));
    writer inner = {{tarw_open_fp(tf), NULL}, w->buf, 0, 0, w->p};
    write_node(&inner, k, k->name);
    if (tarw_close(inner.a.t) < 0)
        die("cannot write the temporary %s.tar", k->name);
    off_t size = ftello(tf);
    if (size < 0 || fseeko(tf, 0, SEEK_SET) < 0)
        die("temporary file error: %s", strerror(errno));
    char *name = xasprintf("%s.tar", k->name);
    if (aw_begin(&w->a, name, (uint64_t)size, 0644, 0, 0, 0, 1) < 0)
        die("write failed: %s", strerror(errno));
    size_t n;
    while ((n = fread(w->buf, 1, COPY_CHUNK, tf)) > 0)
        if (aw_write(&w->a, w->buf, n) < 0)
            die("write failed: %s", strerror(errno));
    if (aw_end(&w->a) < 0)
        die("write failed: %s", strerror(errno));
    fclose(tf);
    uint64_t nf = 0, nd = 0, nl = 0, nb = 0;
    vfs_count(k, &nf, &nd, &nl, &nb);
    if (!inner.files && nl)
        note("  %-12s %llu symlinks (AEmulator files them under /%s)", name, (unsigned long long)nl, k->name);
    else
        note("  %-12s %llu files (AEmulator files them under /%s)", name, (unsigned long long)inner.files, k->name);
    w->files += inner.files;
    w->bytes += inner.bytes;
    free(name);
}

int emit_rom(rom_t *rom, const emit_opts *o)
{
    vfs_sort(rom->root);
    char *tmp = xasprintf("%s.partial", o->output);
    prog pr = {0, 0, 0, 0};
    writer w = {{NULL, NULL}, xmalloc(COPY_CHUNK), 0, 0, progress_enabled() ? &pr : NULL};
    if (o->zip)
        w.a.z = zipw_open(tmp, o->level);
    else
        w.a.t = tarw_open(tmp, o->level);
    if (!w.a.z && !w.a.t)
        die("cannot create %s: %s", tmp, strerror(errno));
    blank();
    note("Writing %s:", o->output);
    const char *const direct[] = {"system", "vendor", "oem", "data", NULL};
    if (w.p) {
        for (int i = 0; direct[i]; i++) {
            vnode *k = vfs_child(rom->root, direct[i]);
            if (!k)
                continue;
            if (!strcmp(direct[i], "data") ? !o->zip && k->type == VN_DIR && k->nkids : is_direct(direct[i], o->zip))
                count_node(k, &pr);
        }
        for (size_t i = 0; i < rom->root->nkids; i++) {
            vnode *k = rom->root->kids[i];
            if (k->type == VN_DIR && k->nkids &&
                (is_extra_mount(k->name) || (o->zip && (!strcmp(k->name, "vendor") || !strcmp(k->name, "oem")))))
                count_node(k, &pr);
        }
        progress(w.p, 0, 1);
    }
    for (int i = 0; direct[i]; i++) {
        vnode *k = vfs_child(rom->root, direct[i]);
        if (!k)
            continue;
        if (!strcmp(direct[i], "data")) {
            if (o->zip || k->type != VN_DIR || !k->nkids)
                continue;
        } else if (!is_direct(direct[i], o->zip)) {
            continue;
        }
        uint64_t before = w.files;
        write_node(&w, k, k->name);
        if (k->type == VN_LINK)
            note("  %-12s symlink -> %s", direct[i], k->link);
        else
            note("  %-12s %llu files", direct[i], (unsigned long long)(w.files - before));
    }
    for (size_t i = 0; i < rom->root->nkids; i++) {
        vnode *k = rom->root->kids[i];
        if (k->type != VN_DIR || !k->nkids)
            continue;
        if (is_extra_mount(k->name) || (o->zip && (!strcmp(k->name, "vendor") || !strcmp(k->name, "oem")))) {
            uint64_t f = 0, d = 0, l = 0, b = 0;
            vfs_count(k, &f, &d, &l, &b);
            if (!f && !l) {
                debug("/%s holds no files; %s.tar left out", k->name, k->name);
                continue;
            }
            write_nested(&w, k);
        }
    }
    progress_clear();
    write_boot(&w, rom, o);
    if (o->zip)
        for (size_t i = 0; i < rom->npass; i++) {
            if (zipw_raw_copy(w.a.z, rom->pass_zip[i], rom->pass_entry[i], path_basename(rom->pass_entry[i]->name)) < 0)
                die("cannot copy %s", rom->pass_entry[i]->name);
            note("  %-12s copied unchanged", path_basename(rom->pass_entry[i]->name));
        }
    uint64_t total = w.a.z ? zipw_bytes(w.a.z) : tarw_bytes(w.a.t);
    int rc = w.a.z ? zipw_close(w.a.z) : tarw_close(w.a.t);
    if (rc < 0) {
        unlink(tmp);
        die("writing %s failed: %s", o->output, strerror(errno));
    }
    if (rename(tmp, o->output) < 0) {
        unlink(tmp);
        die("cannot rename %s: %s", tmp, strerror(errno));
    }
    free(tmp);
    free(w.buf);
    char hs[32], hs2[32];
    note("  done: %llu files, %s of file data, archive %s%s", (unsigned long long)w.files,
         human_size(w.bytes, hs, sizeof hs), human_size(total, hs2, sizeof hs2),
         !o->zip && o->level ? " before compression" : "");
    return 0;
}
