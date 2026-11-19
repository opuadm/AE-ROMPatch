#include "rom/rom.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/codec.h"
#include "formats/lp.h"
#include "formats/ota.h"
#include "formats/ozip.h"
#include "core/rsrc.h"
#include "core/stream.h"
#include "formats/tarr.h"

#define MAX_RAMDISK (128u << 20)
#define MAX_BOOT (256u << 20)

static const char *const role_names[] = {
    "auto", "root", "system", "product", "system_ext", "vendor", "odm", "oem", "extra", "boot", "ramdisk", "zip", "tar", "super",
    "ozip", "payload", "skip", "unknown",
};

const char *role_name(role_t r)
{
    return (unsigned)r < sizeof role_names / sizeof *role_names ? role_names[r] : "?";
}

role_t role_parse(const char *s)
{
    for (size_t i = 0; i < sizeof role_names / sizeof *role_names; i++)
        if (!strcmp(s, role_names[i]))
            return (role_t)i;
    if (!strcmp(s, "system-ext"))
        return ROLE_SYSTEM_EXT;
    return ROLE_UNKNOWN;
}

void rom_init(rom_t *rom)
{
    memset(rom, 0, sizeof *rom);
    rom->root = vfs_new_root();
}

void rom_free(rom_t *rom)
{
    vfs_free(rom->root);
    for (size_t i = 0; i < rom->ninputs; i++) {
        free(rom->inputs[i].path);
        free(rom->inputs[i].extra);
    }
    free(rom->inputs);
    bootimg_free(&rom->boot);
    buf_free(&rom->boot_raw);
    free(rom->boot_source);
    free(rom->ramdisk_source);
    cpio_free(&rom->ramdisk);
    for (size_t i = 0; i < rom->nfs; i++)
        ext4_close(rom->fss[i]);
    free(rom->fss);
    for (size_t i = 0; i < rom->nefs; i++)
        erofs_close(rom->efss[i]);
    free(rom->efss);
    for (size_t i = 0; i < rom->nsrcs; i++)
        rsrc_close(rom->srcs[i]);
    free(rom->srcs);
    for (size_t i = 0; i < rom->nzips; i++)
        zipr_close(rom->zips[i]);
    free(rom->zips);
    strvec_free(&rom->loaded);
}

static int is_extra_partition(const char *n)
{
    if (!strcmp(n, "odm") || !strcmp(n, "mi_ext") || !strcmp(n, "vgc") || !strcmp(n, "prism") || !strcmp(n, "optics"))
        return 1;
    if (starts_with(n, "my_") && n[3]) {
        for (const char *p = n + 3; *p; p++)
            if (!islower((unsigned char)*p) && !isdigit((unsigned char)*p))
                return 0;
        return 1;
    }
    return 0;
}

static role_t role_from_name(const char *base, char *extra, size_t elen)
{
    char n[256];
    size_t l = strlen(base);
    if (l >= sizeof n)
        return ROLE_UNKNOWN;
    for (size_t i = 0; i <= l; i++)
        n[i] = (char)tolower((unsigned char)base[i]);
    static const char *const suffixes[] = {".img", ".ext4", ".raw", ".simg", ".bin", ".sparse", ".lz4", ".gz",
                                           ".cpio", ".win", ".emmc", ".unsparse", ".zst", ".xz"};
    int changed = 1;
    while (changed) {
        changed = 0;
        for (size_t i = 0; i < sizeof suffixes / sizeof *suffixes; i++) {
            if (ends_with(n, suffixes[i]) && strlen(n) > strlen(suffixes[i])) {
                n[strlen(n) - strlen(suffixes[i])] = 0;
                changed = 1;
            }
        }
    }
    if (ends_with(n, "_b"))
        return ROLE_SKIP;
    if (ends_with(n, "_a"))
        n[strlen(n) - 2] = 0;
    if (!strcmp(n, "system") || !strcmp(n, "system_root") || !strcmp(n, "factoryfs"))
        return ROLE_SYSTEM;
    if (!strcmp(n, "super"))
        return ROLE_SUPER;
    if (!strcmp(n, "vendor"))
        return ROLE_VENDOR;
    if (!strcmp(n, "product"))
        return ROLE_PRODUCT;
    if (!strcmp(n, "system_ext"))
        return ROLE_SYSTEM_EXT;
    if (!strcmp(n, "oem"))
        return ROLE_OEM;
    if (!strcmp(n, "odm"))
        return ROLE_ODM;
    if (is_extra_partition(n)) {
        snprintf(extra, elen, "%s", n);
        return ROLE_EXTRA;
    }
    if (!strcmp(n, "boot") || !strcmp(n, "kernel") || !strcmp(n, "boot_signed"))
        return ROLE_BOOT;
    if (!strcmp(n, "ramdisk") || !strcmp(n, "initrd") || !strcmp(n, "rootfs"))
        return ROLE_RAMDISK;
    if (!strcmp(n, "recovery") || !strcmp(n, "vendor_boot") || !strcmp(n, "init_boot") || starts_with(n, "vbmeta") ||
        !strcmp(n, "dtbo") || !strcmp(n, "dtb") || !strcmp(n, "userdata") || !strcmp(n, "cache") ||
        !strcmp(n, "metadata") || !strcmp(n, "persist") || !strcmp(n, "super_empty") || !strcmp(n, "cust") ||
        !strcmp(n, "vendor_dlkm") || !strcmp(n, "odm_dlkm") || !strcmp(n, "system_dlkm"))
        return ROLE_SKIP;
    return ROLE_UNKNOWN;
}

static const char *foreign_format(const unsigned char *h, size_t n)
{
    if (n >= 4 && !memcmp(h, "CrAU", 4))
        return "an OTA payload.bin: extract the partition images first (e.g. with payload-dumper-go)";
    if (n >= 4 && !memcmp(h, "7z\xbc\xaf", 4))
        return "a 7z archive: extract it first";
    if (n >= 4 && !memcmp(h, "Rar!", 4))
        return "a RAR archive: extract it first";
    if (n >= 262 && !memcmp(h + 257, "ustar", 5))
        return "a tar archive: extract it first (or import it into AEmulator Plus directly)";
    if (n >= 4 && (!memcmp(h, "hsqs", 4) || !memcmp(h, "sqsh", 4)))
        return "a SquashFS image: extract it with unsquashfs and pass the folder";
    if (n >= 1028 && le32(h + 1024) == 0xF2F52010U)
        return "an F2FS image: mount or extract it and pass the folder";
    if (n >= 4100 && le32(h + 4096) == 0x616c4467U)
        return "a super.img (dynamic partitions): unpack it with lpunpack and pass the partition images";
    if (n >= 4 && le32(h) == 0x616c4467U)
        return "a super.img (dynamic partitions): unpack it with lpunpack and pass the partition images";
    if (n >= 4 && !memcmp(h, "\xce\xb1\x3e\x2c", 4))
        return "a Brotli/OTA block payload: convert system.new.dat(.br) with brotli + sdat2img first";
    return NULL;
}

static void push_input(rom_t *rom, role_t role, const char *path, const char *extra)
{
    if (rom->ninputs == rom->capinputs) {
        rom->capinputs = rom->capinputs ? rom->capinputs * 2 : 8;
        rom->inputs = xrealloc(rom->inputs, rom->capinputs * sizeof(rom_input));
    }
    rom_input *in = &rom->inputs[rom->ninputs++];
    in->role = role;
    in->path = xstrdup(path);
    in->extra = extra && *extra ? xstrdup(extra) : NULL;
}

static int dir_has(const char *dir, const char *rel)
{
    char *p = path_join(dir, rel);
    struct stat st;
    int r = lstat(p, &st) == 0;
    free(p);
    return r;
}

static int looks_like_system_dir(const char *dir)
{
    return dir_has(dir, "build.prop") &&
           (dir_has(dir, "framework") || dir_has(dir, "app") || dir_has(dir, "bin") || dir_has(dir, "lib"));
}

static int looks_like_root_dir(const char *dir)
{
    return dir_has(dir, "system/build.prop") || dir_has(dir, "system/framework");
}

static role_t classify_file(const char *path, char *extra, size_t elen)
{
    unsigned char h[4200];
    memset(h, 0, sizeof h);
    FILE *f = fopen(path, "rb");
    if (!f)
        die("cannot open %s: %s", path, strerror(errno));
    size_t n = fread(h, 1, sizeof h, f);
    fclose(f);
    role_t by_name = role_from_name(path_basename(path), extra, elen);
    if (n >= 4 && !memcmp(h, "PK\3\4", 4))
        return ROLE_ZIP;
    if (ozip_head_is_encrypted(h, n))
        return ROLE_OZIP;
    if (tar_probe(h, n))
        return ROLE_TAR;
    if (n >= 4 && !memcmp(h, "CrAU", 4))
        return ROLE_PAYLOAD;
    if ((n >= 4100 && le32(h + 4096) == 0x616c4467U) || (by_name == ROLE_SUPER && n >= 4 && le32(h) == 0xed26ff3aU))
        return ROLE_SUPER;
    if (bootimg_probe(h, n))
        return by_name == ROLE_SKIP ? ROLE_SKIP : ROLE_BOOT;
    if ((n >= 4 && le32(h) == 0xed26ff3aU) || (n >= 1082 && le16(h + 1024 + 56) == 0xEF53) ||
        (n >= 1028 && le32(h + 1024) == 0xE0F5E1E2U)) {
        if (by_name == ROLE_BOOT || by_name == ROLE_RAMDISK || by_name == ROLE_UNKNOWN)
            return ROLE_SYSTEM;
        return by_name;
    }
    codec_t c = codec_detect(h, n);
    const char *bn = path_basename(path);
    if (c == CODEC_GZIP && (ends_with_ci(bn, ".tgz") || ends_with_ci(bn, ".tar.gz")))
        return ROLE_TAR;
    if (c != CODEC_NONE && c != CODEC_UNKNOWN &&
        (by_name == ROLE_SYSTEM || by_name == ROLE_VENDOR || by_name == ROLE_PRODUCT || by_name == ROLE_SYSTEM_EXT ||
         by_name == ROLE_ODM || by_name == ROLE_OEM || by_name == ROLE_EXTRA || by_name == ROLE_SUPER ||
         by_name == ROLE_BOOT))
        return by_name;
    if (c == CODEC_NONE || c == CODEC_GZIP || c == CODEC_LZ4_LEGACY || c == CODEC_LZ4_FRAME) {
        if (by_name == ROLE_SKIP)
            return ROLE_SKIP;
        return ROLE_RAMDISK;
    }
    const char *foreign = foreign_format(h, n);
    if (foreign) {
        if (by_name == ROLE_SKIP)
            return ROLE_SKIP;
        die("%s is %s", path, foreign);
    }
    return by_name == ROLE_SKIP ? ROLE_SKIP : ROLE_UNKNOWN;
}

static int is_tar_name(const char *n)
{
    return ends_with_ci(n, ".tar.md5") || ends_with_ci(n, ".tar") || ends_with_ci(n, ".tgz") ||
           ends_with_ci(n, ".tar.gz");
}

static int samsung_unused_tar(const char *base)
{
    return starts_with(base, "BL_") || starts_with(base, "CP_") || starts_with(base, "USERDATA_");
}

static int samsung_csc_tar(const char *base)
{
    return starts_with(base, "CSC_") || starts_with(base, "HOME_CSC_");
}

static void add_firmware_folder(rom_t *rom, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        die("cannot read %s: %s", dir, strerror(errno));
    strvec names = {0};
    struct dirent *e;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
            strvec_push(&names, e->d_name);
    closedir(d);
    size_t before = rom->ninputs;
    for (size_t i = 0; i < names.n; i++) {
        char *p = path_join(dir, names.v[i]);
        char extra[64] = "";
        role_t r = role_from_name(names.v[i], extra, sizeof extra);
        struct stat st;
        if (stat(p, &st) < 0) {
            free(p);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (r == ROLE_SYSTEM && looks_like_root_dir(p))
                r = ROLE_ROOT;
            if (r == ROLE_SYSTEM || r == ROLE_ROOT || r == ROLE_VENDOR || r == ROLE_PRODUCT || r == ROLE_SYSTEM_EXT ||
                r == ROLE_ODM || r == ROLE_OEM || r == ROLE_EXTRA)
                push_input(rom, r, p, extra);
            else
                debug("ignoring folder %s", p);
        } else if (S_ISREG(st.st_mode)) {
            if (is_tar_name(names.v[i]) || ends_with_ci(names.v[i], ".ozip") || !strcmp(names.v[i], "payload.bin")) {
                if (samsung_unused_tar(names.v[i]))
                    debug("skipping %s (bootloader/modem/userdata package)", p);
                else {
                    role_t c = classify_file(p, extra, sizeof extra);
                    if (c == ROLE_TAR || c == ROLE_OZIP || c == ROLE_PAYLOAD || c == ROLE_ZIP)
                        push_input(rom, c, p, extra);
                    else
                        debug("ignoring %s", p);
                }
            } else if (r == ROLE_SKIP) {
                debug("skipping %s (not used by AEmulator)", p);
            } else if (r != ROLE_UNKNOWN) {
                role_t c = classify_file(p, extra, sizeof extra);
                if (c == ROLE_SKIP || c == ROLE_UNKNOWN)
                    debug("ignoring %s", p);
                else
                    push_input(rom, c, p, extra);
            } else {
                debug("ignoring %s", p);
            }
        }
        free(p);
    }
    strvec_free(&names);
    if (rom->ninputs == before)
        die("%s: no ROM found (expected a root tree, a /system folder, or images such as system.img and boot.img)",
            dir);
}

void rom_add(rom_t *rom, role_t role, const char *path, const char *extra)
{
    struct stat st;
    if (stat(path, &st) < 0)
        die("cannot access %s: %s", path, strerror(errno));
    if (S_ISDIR(st.st_mode)) {
        if (role == ROLE_BOOT || role == ROLE_RAMDISK)
            die("%s: --%s needs a file", path, role_name(role));
        if (role != ROLE_AUTO) {
            if (role == ROLE_SYSTEM && looks_like_root_dir(path) && !looks_like_system_dir(path))
                role = ROLE_ROOT;
            push_input(rom, role, path, extra);
        } else if (looks_like_system_dir(path)) {
            push_input(rom, ROLE_SYSTEM, path, NULL);
        } else if (looks_like_root_dir(path)) {
            push_input(rom, ROLE_ROOT, path, NULL);
        } else {
            add_firmware_folder(rom, path);
        }
        return;
    }
    if (!S_ISREG(st.st_mode))
        die("%s: not a regular file or folder", path);
    char ex[64] = "";
    if (extra)
        snprintf(ex, sizeof ex, "%s", extra);
    if (role == ROLE_AUTO) {
        role = classify_file(path, ex, sizeof ex);
        if (role == ROLE_SKIP)
            die("%s: this partition is not used by AEmulator Plus", path);
        if (role == ROLE_UNKNOWN)
            die("%s: unrecognised file (expected boot.img, a ramdisk, or an ext4/sparse partition image)", path);
    }
    push_input(rom, role, path, ex);
}

static int priority(role_t r)
{
    switch (r) {
    case ROLE_ZIP:
    case ROLE_TAR:
    case ROLE_OZIP:
    case ROLE_PAYLOAD: return -1;
    case ROLE_ROOT: return 0;
    case ROLE_SUPER:
    case ROLE_SYSTEM: return 1;
    case ROLE_PRODUCT: return 2;
    case ROLE_SYSTEM_EXT: return 3;
    case ROLE_VENDOR: return 4;
    case ROLE_ODM: return 5;
    case ROLE_OEM: return 6;
    case ROLE_EXTRA: return 7;
    case ROLE_BOOT: return 8;
    case ROLE_RAMDISK: return 9;
    default: return 10;
    }
}

static int cmp_inputs(const void *a, const void *b)
{
    const rom_input *x = a, *y = b;
    return priority(x->role) - priority(y->role);
}

static char *fix_relocated_link(const char *orig_path, const char *target)
{
    if (target[0] == '/' || !orig_path)
        return xstrdup(target);
    char *dir = path_dirname(orig_path);
    char *joined = xasprintf("%s/%s", dir, target);
    char *norm = path_normalize(joined);
    free(dir);
    free(joined);
    return norm ? norm : xstrdup(target);
}

typedef struct {
    char *name;
    uint32_t ino;
} dent;

typedef struct {
    dent *v;
    size_t n, cap;
} dent_list;

static int collect_cb(void *ctx, const char *name, size_t namelen, uint32_t ino, uint8_t ftype)
{
    dent_list *l = ctx;
    (void)ftype;
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 32;
        l->v = xrealloc(l->v, l->cap * sizeof(dent));
    }
    l->v[l->n].name = xstrndup(name, namelen);
    l->v[l->n].ino = ino;
    l->n++;
    return 0;
}

typedef struct {
    rom_t *rom;
    ext4 *fs;
    const char *label;
    const char *orig_mount;
    unsigned depth_guard;
    uint64_t count;
} e4walk;

static void ext4_tree(e4walk *w, uint32_t dir_ino, vnode *dst, const char *orig_dir, int top)
{
    dent_list l = {0};
    if (w->depth_guard > 256) {
        warn("%s: directory nesting too deep at %s", w->label, orig_dir);
        return;
    }
    if (ext4_readdir(w->fs, dir_ino, collect_cb, &l) < 0)
        warn("%s: cannot read directory %s", w->label, orig_dir[0] ? orig_dir : "/");
    for (size_t i = 0; i < l.n; i++) {
        const char *name = l.v[i].name;
        uint32_t ino = l.v[i].ino;
        char *orig = xasprintf("%s/%s", orig_dir, name);
        ext4_stat_t st;
        if (top && !strcmp(name, "lost+found")) {
            free(orig);
            continue;
        }
        if (ext4_stat(w->fs, ino, &st) < 0) {
            warn("%s: cannot read inode of %s", w->label, orig);
            free(orig);
            continue;
        }
        if (st.encrypted) {
            w->rom->encrypted++;
            warn("%s: %s is encrypted (fscrypt) and cannot be read; skipped", w->label, orig);
            free(orig);
            continue;
        }
        uint16_t fmt = st.mode & 0xF000;
        vnode *n = NULL;
        if (fmt == 0x4000) {
            n = vfs_put(dst, name, VN_DIR);
        } else if (fmt == 0x8000) {
            n = vfs_put(dst, name, VN_FILE);
            n->src = VS_EXT4;
            n->fs = w->fs;
            n->ino = ino;
            n->size = st.size;
        } else if (fmt == 0xA000) {
            char *t = NULL;
            if (ext4_readlink(w->fs, ino, &t) < 0) {
                warn("%s: cannot read symlink %s", w->label, orig);
                free(orig);
                continue;
            }
            n = vfs_put(dst, name, VN_LINK);
            n->link = fix_relocated_link(w->orig_mount ? orig : NULL, t);
            free(t);
        } else {
            w->rom->special_skipped++;
            debug("%s: skipping special file %s", w->label, orig);
            free(orig);
            continue;
        }
        n->mode = st.mode & 07777;
        n->uid = st.uid;
        n->gid = st.gid;
        n->mtime = st.mtime;
        n->origin = w->label;
        w->count++;
        if (fmt == 0x4000) {
            w->depth_guard++;
            ext4_tree(w, ino, n, orig, 0);
            w->depth_guard--;
        }
        free(orig);
    }
    for (size_t i = 0; i < l.n; i++)
        free(l.v[i].name);
    free(l.v);
}

static const char *intern_label(rom_t *rom, const char *s)
{
    strvec_push(&rom->loaded, s);
    return rom->loaded.v[rom->loaded.n - 1];
}


typedef struct {
    rom_t *rom;
    erofs *fs;
    const char *label;
    const char *orig_mount;
    unsigned depth;
    uint64_t count;
} ewalk;

typedef struct {
    char *name;
    uint64_t nid;
} edent;

typedef struct {
    edent *v;
    size_t n, cap;
} edent_list;

static int ecollect(void *ctx, const char *name, size_t nl, uint64_t nid, uint8_t ft)
{
    edent_list *l = ctx;
    (void)ft;
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 32;
        l->v = xrealloc(l->v, l->cap * sizeof(edent));
    }
    l->v[l->n].name = xstrndup(name, nl);
    l->v[l->n].nid = nid;
    l->n++;
    return 0;
}

static void erofs_tree(ewalk *w, uint64_t dir, vnode *dst, const char *orig_dir, int top)
{
    edent_list l = {0};
    if (w->depth > 256) {
        warn("%s: directory nesting too deep at %s", w->label, orig_dir);
        return;
    }
    if (erofs_readdir(w->fs, dir, ecollect, &l) < 0)
        warn("%s: cannot read directory %s: %s", w->label, orig_dir[0] ? orig_dir : "/", erofs_error(w->fs));
    for (size_t i = 0; i < l.n; i++) {
        const char *name = l.v[i].name;
        char *orig = xasprintf("%s/%s", orig_dir, name);
        erofs_stat_t st;
        if (top && !strcmp(name, "lost+found")) {
            free(orig);
            continue;
        }
        if (erofs_stat(w->fs, l.v[i].nid, &st) < 0) {
            warn("%s: cannot read inode of %s", w->label, orig);
            free(orig);
            continue;
        }
        uint16_t fmt = st.mode & 0xF000;
        vnode *n;
        if (fmt == 0x4000) {
            n = vfs_put(dst, name, VN_DIR);
        } else if (fmt == 0x8000) {
            n = vfs_put(dst, name, VN_FILE);
            n->src = VS_EROFS;
            n->efs = w->fs;
            n->enid = l.v[i].nid;
            n->size = st.size;
        } else if (fmt == 0xA000) {
            char *t = NULL;
            if (erofs_readlink(w->fs, l.v[i].nid, &t) < 0) {
                warn("%s: cannot read symlink %s: %s", w->label, orig, erofs_error(w->fs));
                free(orig);
                continue;
            }
            n = vfs_put(dst, name, VN_LINK);
            n->link = fix_relocated_link(w->orig_mount ? orig : NULL, t);
            free(t);
        } else {
            w->rom->special_skipped++;
            free(orig);
            continue;
        }
        n->mode = st.mode & 07777;
        n->uid = st.uid;
        n->gid = st.gid;
        n->mtime = st.mtime;
        n->origin = w->label;
        w->count++;
        if (fmt == 0x4000) {
            w->depth++;
            erofs_tree(w, l.v[i].nid, n, orig, 0);
            w->depth--;
        }
        free(orig);
    }
    for (size_t i = 0; i < l.n; i++)
        free(l.v[i].name);
    free(l.v);
}

static void load_erofs(rom_t *rom, rsrc *src, role_t role, const char *label, const char *mount, const char *orig_mount)
{
    char err[256];
    erofs *fs = erofs_open(src, err, sizeof err);
    if (!fs) {
        rsrc_close(src);
        die("%s: %s", label, err);
    }
    rom->efss = xrealloc(rom->efss, (rom->nefs + 1) * sizeof(erofs *));
    rom->efss[rom->nefs++] = fs;
    const char *target = mount;
    uint64_t tmp;
    int sar_here = 0;
    if (role == ROLE_SYSTEM && erofs_lookup(fs, "init", &tmp) == 0 &&
        (erofs_lookup(fs, "system/build.prop", &tmp) == 0 || erofs_lookup(fs, "system/framework", &tmp) == 0)) {
        rom->sar = 1;
        sar_here = 1;
        target = "/";
    }
    vnode *dst = vfs_mkdirs(rom->root, target, 0755);
    ewalk w = {rom, fs, intern_label(rom, path_basename(label)), orig_mount, 0, 0};
    erofs_tree(&w, erofs_root(fs), dst, orig_mount ? orig_mount : (strcmp(target, "/") ? target : ""), 1);
    note("  %-11s %s -> %s (EROFS%s, %llu entries)", role_name(role), label, target, sar_here ? ", system-as-root" : "",
         (unsigned long long)w.count);
}

static void load_image_src(rom_t *rom, rsrc *src, role_t role, const char *label, const char *mount,
                           const char *orig_mount)
{
    if (!strvec_has(&rom->loaded, mount))
        strvec_push(&rom->loaded, mount);
    if (sparse_probe(src)) {
        rsrc *sp = rsrc_open_sparse(src);
        if (!sp)
            die("%s: corrupt sparse image", label);
        src = sp;
    }
    int sparse = strstr(src->name, "(sparse)") != NULL;
    if (erofs_probe(src)) {
        load_erofs(rom, src, role, label, mount, orig_mount);
        return;
    }
    if (!ext4_probe(src)) {
        unsigned char h[4200];
        size_t n = src->size < sizeof h ? (size_t)src->size : sizeof h;
        memset(h, 0, sizeof h);
        rsrc_read(src, h, n, 0);
        const char *foreign = foreign_format(h, n);
        rsrc_close(src);
        die("%s is %s", label, foreign ? foreign : "not an ext2/3/4 or EROFS image (other filesystems are not supported; extract it and pass the folder)");
    }
    char err[256];
    ext4 *fs = ext4_open(src, err, sizeof err);
    if (!fs) {
        rsrc_close(src);
        die("%s: %s", label, err);
    }
    rom->fss = xrealloc(rom->fss, (rom->nfs + 1) * sizeof(ext4 *));
    rom->fss[rom->nfs++] = fs;
    const char *target = mount;
    uint32_t tmp;
    int sar_here = 0;
    if (role == ROLE_SYSTEM) {
        int has_init = ext4_lookup(fs, "init", &tmp) == 0;
        int has_sys = ext4_lookup(fs, "system/build.prop", &tmp) == 0 || ext4_lookup(fs, "system/framework", &tmp) == 0;
        if (has_init && has_sys) {
            rom->sar = 1;
            sar_here = 1;
            target = "/";
        }
    }
    vnode *dst = vfs_mkdirs(rom->root, target, 0755);
    e4walk w = {rom, fs, intern_label(rom, path_basename(label)), orig_mount, 0, 0};
    ext4_tree(&w, EXT4_ROOT_INO, dst, orig_mount ? orig_mount : (strcmp(target, "/") ? target : ""), 1);
    note("  %-11s %s -> %s (ext4%s%s, %llu entries)", role_name(role), label, target, sparse ? ", sparse" : "",
         sar_here ? ", system-as-root" : "", (unsigned long long)w.count);
}

static rsrc *open_input_file(const char *path);

static void load_image(rom_t *rom, const rom_input *in, const char *mount, const char *orig_mount)
{
    load_image_src(rom, open_input_file(in->path), in->role, in->path, mount, orig_mount);
}

typedef struct {
    rom_t *rom;
    const char *label;
    const char *orig_mount;
    uint64_t count;
    int depth;
} dirwalk;

static void dir_tree(dirwalk *w, const char *host, vnode *dst, const char *orig_dir)
{
    DIR *d = opendir(host);
    if (!d) {
        warn("cannot read %s: %s", host, strerror(errno));
        return;
    }
    if (w->depth > 256) {
        closedir(d);
        warn("directory nesting too deep at %s", host);
        return;
    }
    strvec names = {0};
    struct dirent *e;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
            strvec_push(&names, e->d_name);
    closedir(d);
    for (size_t i = 0; i < names.n; i++) {
        char *p = path_join(host, names.v[i]);
        char *orig = xasprintf("%s/%s", orig_dir, names.v[i]);
        struct stat st;
        if (lstat(p, &st) < 0) {
            warn("cannot stat %s: %s", p, strerror(errno));
            free(p);
            free(orig);
            continue;
        }
        vnode *n = NULL;
        if (S_ISDIR(st.st_mode)) {
            n = vfs_put(dst, names.v[i], VN_DIR);
        } else if (S_ISREG(st.st_mode)) {
            n = vfs_put(dst, names.v[i], VN_FILE);
            n->src = VS_HOST;
            n->host = xstrdup(p);
            n->size = (uint64_t)st.st_size;
        } else if (S_ISLNK(st.st_mode)) {
            char t[8192];
            ssize_t l = readlink(p, t, sizeof t - 1);
            if (l < 0) {
                warn("cannot read symlink %s", p);
                free(p);
                free(orig);
                continue;
            }
            t[l] = 0;
            n = vfs_put(dst, names.v[i], VN_LINK);
            n->link = fix_relocated_link(w->orig_mount ? orig : NULL, t);
        } else {
            w->rom->special_skipped++;
            debug("skipping special file %s", p);
            free(p);
            free(orig);
            continue;
        }
        n->mode = st.st_mode & 07777;
        n->uid = 0;
        n->gid = 0;
        n->mtime = st.st_mtime;
        n->origin = w->label;
        w->count++;
        if (S_ISDIR(st.st_mode)) {
            w->depth++;
            dir_tree(w, p, n, orig);
            w->depth--;
        }
        free(p);
        free(orig);
    }
    strvec_free(&names);
}

static void load_dir(rom_t *rom, const rom_input *in, const char *mount, const char *orig_mount)
{
    vnode *dst = vfs_mkdirs(rom->root, mount, 0755);
    dirwalk w = {rom, intern_label(rom, path_basename(in->path)), orig_mount, 0, 0};
    dir_tree(&w, in->path, dst, orig_mount ? orig_mount : (strcmp(mount, "/") ? mount : ""));
    note("  %-11s %s -> %s (folder, %llu entries)", role_name(in->role), in->path, mount, (unsigned long long)w.count);
}

static int ramdisk_is_recovery(const cpio_list *l)
{
    if (!cpio_find(l, "sbin/recovery"))
        return 0;
    const cpio_entry *rc = cpio_find(l, "init.rc");
    if (!rc)
        return 1;
    for (size_t i = 0; i + 6 <= rc->size; i++)
        if (!memcmp(rc->data + i, "zygote", 6))
            return 0;
    return 1;
}

static int decode_ramdisk(const unsigned char *d, size_t len, cpio_list *out, int *codec, const char *what)
{
    buf_t raw = {0};
    char err[256];
    *codec = codec_detect(d, len);
    if (codec_decompress(d, len, &raw, MAX_RAMDISK, err, sizeof err) < 0) {
        warn("%s: ramdisk: %s", what, err);
        buf_free(&raw);
        return -1;
    }
    if (cpio_parse(raw.data, raw.len, out, err, sizeof err) < 0) {
        warn("%s: ramdisk: %s", what, err);
        buf_free(&raw);
        cpio_free(out);
        return -1;
    }
    buf_free(&raw);
    return 0;
}

static void load_boot_data(rom_t *rom, const unsigned char *data, size_t len, const char *label)
{
    if (rom->have_boot) {
        warn("%s: a boot image was already loaded from %s; ignored", label, rom->boot_source);
        return;
    }
    char err[256];
    if (bootimg_parse(data, len, &rom->boot, err, sizeof err) < 0)
        die("%s: %s", label, err);
    rom->have_boot = 1;
    rom->boot_source = xstrdup(label);
    buf_put(&rom->boot_raw, data, len);
    const char *what = "no ramdisk";
    if (rom->boot.ramdisk_size) {
        cpio_list l = {0};
        int codec = 0;
        if (decode_ramdisk(rom->boot.ramdisk, rom->boot.ramdisk_size, &l, &codec, label) == 0) {
            rom->boot_ramdisk_codec = codec;
            if (ramdisk_is_recovery(&l)) {
                rom->boot_ramdisk_recovery = 1;
                what = "recovery ramdisk, not used";
                cpio_free(&l);
            } else if (rom->have_ramdisk) {
                what = "ramdisk ignored, another ramdisk was given";
                cpio_free(&l);
            } else {
                rom->ramdisk = l;
                rom->have_ramdisk = 1;
                rom->ramdisk_source = xstrdup(rom->boot_source);
                what = "ramdisk";
            }
        } else {
            what = "ramdisk unreadable";
        }
    }
    note("  %-11s %s (boot image v%d, kernel %zu bytes, %s)", "boot", label, rom->boot.header_version,
         rom->boot.kernel_size, what);
}

static void load_boot(rom_t *rom, const rom_input *in)
{
    buf_t data = {0};
    if (read_file(in->path, &data, MAX_BOOT) < 0)
        die("cannot read %s: %s", in->path, strerror(errno));
    codec_t k = codec_detect(data.data, data.len);
    if (k != CODEC_NONE && k != CODEC_UNKNOWN && !bootimg_probe(data.data, data.len)) {
        buf_t raw = {0};
        char err[256];
        if (codec_decompress(data.data, data.len, &raw, MAX_BOOT, err, sizeof err) < 0)
            die("%s: %s", in->path, err);
        buf_free(&data);
        data = raw;
    }
    load_boot_data(rom, data.data, data.len, in->path);
    buf_free(&data);
}

static void load_ramdisk_data(rom_t *rom, const unsigned char *data, size_t len, const char *label)
{
    cpio_list l = {0};
    int codec;
    if (decode_ramdisk(data, len, &l, &codec, label) < 0)
        die("%s: cannot read the ramdisk", label);
    if (rom->have_ramdisk) {
        cpio_free(&rom->ramdisk);
        free(rom->ramdisk_source);
    }
    rom->ramdisk = l;
    rom->have_ramdisk = 1;
    rom->ramdisk_source = xstrdup(label);
    note("  %-11s %s (%s cpio, %zu entries)", "ramdisk", label, codec_name((codec_t)codec), l.n);
}

static void load_ramdisk(rom_t *rom, const rom_input *in)
{
    buf_t data = {0};
    if (read_file(in->path, &data, MAX_RAMDISK) < 0)
        die("cannot read %s: %s", in->path, strerror(errno));
    load_ramdisk_data(rom, data.data, data.len, in->path);
    buf_free(&data);
}


typedef struct {
    rom_t *rom;
    zipr *z;
    const char *wrap;
} zctx;

static void track_zip(rom_t *rom, zipr *z)
{
    rom->zips = xrealloc(rom->zips, (rom->nzips + 1) * sizeof(zipr *));
    rom->zips[rom->nzips++] = z;
}

static void track_src(rom_t *rom, rsrc *s)
{
    rom->srcs = xrealloc(rom->srcs, (rom->nsrcs + 1) * sizeof(rsrc *));
    rom->srcs[rom->nsrcs++] = s;
}

static int strncase_eq(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    return 1;
}

static char *find_system_root(zipr *z, size_t wrap_len)
{
    static const char *const markers[] = {"framework/", "app/", "bin/", "lib/", "etc/", NULL};
    char *best = NULL;
    int best_depth = 1 << 30, best_bp = 0;
    for (size_t i = 0; i < z->n; i++) {
        const char *n = z->e[i].name;
        if (strlen(n) < wrap_len || strstr(n, "__MACOSX/"))
            continue;
        n += wrap_len;
        while (*n == '/')
            n++;
        size_t start = 0, len = strlen(n);
        for (;;) {
            if (len - start >= 7 && strncase_eq(n + start, "system/", 7)) {
                const char *rest = n + start + 7;
                int bp = !strcmp(rest, "build.prop");
                int hit = start == 0 || bp;
                for (int m = 0; !hit && markers[m]; m++)
                    if (starts_with(rest, markers[m]))
                        hit = 1;
                if (hit) {
                    int depth = 0;
                    for (size_t k = 0; k < start; k++)
                        if (n[k] == '/')
                            depth++;
                    if (depth < best_depth || (depth == best_depth && bp && !best_bp)) {
                        free(best);
                        best = xstrndup(n, start);
                        best_depth = depth;
                        best_bp = bp;
                    }
                }
            }
            const char *sl = strchr(n + start, '/');
            if (!sl)
                break;
            start = (size_t)(sl - n) + 1;
        }
    }
    return best;
}

static void zip_system_entry(zctx *c, zip_entry *e, const char *srel, int is_dir)
{
    rom_t *rom = c->rom;
    char *path = xasprintf("/system/%s", srel);
    size_t pl = strlen(path);
    while (pl > 1 && path[pl - 1] == '/')
        path[--pl] = 0;
    if (!strcmp(path, "/system")) {
        free(path);
        return;
    }
    uint32_t mode = zip_entry_mode(e);
    if (is_dir) {
        vnode *d = vfs_mkdirs(rom->root, path, 0755);
        if (d && mode)
            d->mode = mode;
        free(path);
        return;
    }
    char *dir = path_dirname(path);
    vnode *parent = vfs_mkdirs(rom->root, dir, 0755);
    free(dir);
    const char *base = path_basename(path);
    if (zip_entry_is_symlink(e)) {
        buf_t t = {0};
        if (zipr_read_all(c->z, e, &t, 8192) == 0 && t.len) {
            while (t.len && (t.data[t.len - 1] == 0 || t.data[t.len - 1] == '\n' || t.data[t.len - 1] == '\r'))
                t.len--;
            vnode *n = vfs_put(parent, base, VN_LINK);
            n->link = xstrndup((const char *)t.data, t.len);
            n->mode = 0777;
            n->origin = c->z->path;
        }
        buf_free(&t);
        free(path);
        return;
    }
    vnode *n = vfs_put(parent, base, VN_FILE);
    n->src = VS_ZIP;
    n->zip = c->z;
    n->zentry = e;
    n->size = e->usize;
    n->mode = mode ? mode : 0644;
    n->origin = c->z->path;
    free(path);
}

static int script_args(const char *s, strvec *args)
{
    const char *p = s;
    while (*p && *p != '(')
        p++;
    if (*p != '(')
        return -1;
    p++;
    int depth = 1;
    buf_t cur = {0};
    int inq = 0;
    for (; *p && depth; p++) {
        char ch = *p;
        if (inq) {
            if (ch == '"')
                inq = 0;
            else
                buf_putc(&cur, ch);
            continue;
        }
        if (ch == '"') {
            inq = 1;
        } else if (ch == '(') {
            depth++;
        } else if (ch == ')') {
            if (--depth == 0)
                break;
        } else if (ch == ',') {
            strvec_push(args, cur.data ? (const char *)cur.data : "");
            cur.len = 0;
            if (cur.data)
                cur.data[0] = 0;
        } else if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') {
            buf_putc(&cur, ch);
        }
    }
    strvec_push(args, cur.data ? (const char *)cur.data : "");
    buf_free(&cur);
    return 0;
}

static int script_path_ok(const char *p)
{
    return starts_with(p, "/system/") || starts_with(p, "/vendor/") || !strcmp(p, "/system") || !strcmp(p, "/vendor");
}

typedef struct {
    uint32_t dmode, fmode;
} permrec;

static int perm_cb(vnode *n, const char *path, void *ctx)
{
    permrec *pr = ctx;
    (void)path;
    if (n->type == VN_DIR)
        n->mode = pr->dmode;
    else if (n->type == VN_FILE)
        n->mode = pr->fmode;
    return 0;
}

static void apply_updater_script(rom_t *rom, const char *text)
{
    unsigned links = 0, perms = 0;
    const char *p = text;
    while (*p) {
        const char *line_start = p;
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;
        if (*p == '#') {
            while (*p && *p != '\n')
                p++;
            continue;
        }
        const char *stmt = p;
        int depth = 0, inq = 0;
        while (*p) {
            if (*p == '"')
                inq = !inq;
            else if (!inq && *p == '(')
                depth++;
            else if (!inq && *p == ')')
                depth--;
            else if (!inq && depth <= 0 && *p == ';')
                break;
            p++;
        }
        size_t sl = (size_t)(p - stmt);
        char *st = xstrndup(stmt, sl);
        if (*p == ';')
            p++;
        const char *fn = st;
        strvec a = {0};
        if (starts_with(fn, "symlink") && script_args(fn, &a) == 0 && a.n >= 2) {
            for (size_t i = 1; i < a.n; i++) {
                char *np = path_normalize(a.v[i]);
                if (np && script_path_ok(np)) {
                    char *dir = path_dirname(np);
                    vnode *d = vfs_mkdirs(rom->root, dir, 0755);
                    free(dir);
                    vnode *existing = vfs_child(d, path_basename(np));
                    if (!existing || existing->type != VN_DIR) {
                        vnode *n = vfs_put(d, path_basename(np), VN_LINK);
                        n->link = xstrdup(a.v[0]);
                        n->mode = 0777;
                        links++;
                    }
                }
                free(np);
            }
        } else if (starts_with(fn, "set_perm_recursive") && script_args(fn, &a) == 0 && a.n >= 5) {
            vnode *n = vfs_lookup(rom->root, a.v[4]);
            if (n && script_path_ok(a.v[4])) {
                permrec pr = {(uint32_t)strtoul(a.v[2], NULL, 8) & 07777, (uint32_t)strtoul(a.v[3], NULL, 8) & 07777};
                vfs_walk(n, perm_cb, &pr);
                perms++;
            }
        } else if (starts_with(fn, "set_perm") && script_args(fn, &a) == 0 && a.n >= 4) {
            vnode *n = vfs_lookup(rom->root, a.v[3]);
            if (n && n->type != VN_LINK && script_path_ok(a.v[3])) {
                n->mode = (uint32_t)strtoul(a.v[2], NULL, 8) & 07777;
                perms++;
            }
        } else if (starts_with(fn, "set_metadata") && script_args(fn, &a) == 0 && a.n >= 3) {
            int rec = starts_with(fn, "set_metadata_recursive");
            vnode *n = vfs_lookup(rom->root, a.v[0]);
            if (n && script_path_ok(a.v[0])) {
                permrec pr = {0, 0};
                int have = 0;
                for (size_t i = 1; i + 1 < a.n; i += 2) {
                    if (!strcmp(a.v[i], "mode") || !strcmp(a.v[i], "fmode")) {
                        pr.fmode = (uint32_t)strtoul(a.v[i + 1], NULL, 8) & 07777;
                        have |= 1;
                    } else if (!strcmp(a.v[i], "dmode")) {
                        pr.dmode = (uint32_t)strtoul(a.v[i + 1], NULL, 8) & 07777;
                        have |= 2;
                    }
                }
                if (rec && have == 3) {
                    vfs_walk(n, perm_cb, &pr);
                    perms++;
                } else if (!rec && (have & 1) && n->type != VN_LINK) {
                    n->mode = pr.fmode;
                    perms++;
                }
            }
        }
        strvec_free(&a);
        free(st);
        if (p == line_start)
            p++;
    }
    if (links || perms)
        note("  %-11s updater-script: %u symlinks, %u permission rules applied", "script", links, perms);
}

static long zstream_reader(void *ctx, void *buf, size_t len)
{
    return zstream_read(ctx, buf, len);
}

static void load_zip(rom_t *rom, zipr *z, int depth);

static void load_payload(rom_t *rom, rsrc *src, const char *label)
{
    char err[256];
    payload *p = payload_open(src, err, sizeof err);
    if (!p)
        die("%s: %s", label, err);
    static const struct {
        const char *name;
        role_t role;
    } want[] = {{"system", ROLE_SYSTEM},   {"product", ROLE_PRODUCT}, {"system_ext", ROLE_SYSTEM_EXT},
                {"vendor", ROLE_VENDOR},   {"odm", ROLE_ODM},         {"oem", ROLE_OEM},
                {"boot", ROLE_BOOT},       {NULL, ROLE_UNKNOWN}};
    strvec names = {0};
    for (size_t i = 0; i < payload_count(p); i++)
        strvec_push(&names, payload_name(p, i));
    for (int w = 0; want[w].name; w++) {
        for (size_t i = 0; i < payload_count(p); i++) {
            if (strcmp(payload_name(p, i), want[w].name))
                continue;
            rsrc *img = payload_extract(p, i, err, sizeof err);
            if (!img)
                die("%s: %s", label, err);
            char *lab = xasprintf("%s:%s", label, want[w].name);
            if (want[w].role == ROLE_BOOT) {
                buf_t b = {0};
                b.data = xmalloc((size_t)img->size + 1);
                b.len = (size_t)img->size;
                b.cap = b.len + 1;
                if (rsrc_read(img, b.data, b.len, 0) < 0)
                    die("%s: cannot read the boot partition", lab);
                rsrc_close(img);
                load_boot_data(rom, b.data, b.len, lab);
                buf_free(&b);
            } else {
                const char *mount = want[w].role == ROLE_SYSTEM ? "/system"
                                    : want[w].role == ROLE_PRODUCT ? "/system/product"
                                    : want[w].role == ROLE_SYSTEM_EXT ? "/system/system_ext"
                                    : want[w].role == ROLE_VENDOR ? "/vendor"
                                    : want[w].role == ROLE_ODM ? "/odm" : "/oem";
                const char *orig = want[w].role == ROLE_PRODUCT ? "/product"
                                   : want[w].role == ROLE_SYSTEM_EXT ? "/system_ext" : NULL;
                if (want[w].role == ROLE_SYSTEM)
                    rom->have_system = 1;
                if (want[w].role == ROLE_VENDOR)
                    rom->have_vendor = 1;
                load_image_src(rom, img, want[w].role, lab, mount, orig);
            }
            free(lab);
        }
    }
    for (size_t i = 0; i < names.n; i++) {
        int used = 0;
        for (int w = 0; want[w].name; w++)
            if (!strcmp(names.v[i], want[w].name))
                used = 1;
        if (!used)
            debug("payload.bin: partition %s not needed", names.v[i]);
    }
    strvec_free(&names);
    payload_close(p);
}

typedef struct {
    zip_entry *dat;
    zip_entry *list;
    int brotli;
} datpair;

static role_t mount_role(const char *part, const char **mount, const char **orig)
{
    *orig = NULL;
    if (!strcmp(part, "system")) {
        *mount = "/system";
        return ROLE_SYSTEM;
    }
    if (!strcmp(part, "product")) {
        *mount = "/system/product";
        *orig = "/product";
        return ROLE_PRODUCT;
    }
    if (!strcmp(part, "system_ext")) {
        *mount = "/system/system_ext";
        *orig = "/system_ext";
        return ROLE_SYSTEM_EXT;
    }
    if (!strcmp(part, "vendor")) {
        *mount = "/vendor";
        return ROLE_VENDOR;
    }
    if (!strcmp(part, "odm")) {
        *mount = "/odm";
        return ROLE_ODM;
    }
    if (!strcmp(part, "oem")) {
        *mount = "/oem";
        return ROLE_OEM;
    }
    return ROLE_UNKNOWN;
}

static int compressed_codec(codec_t k)
{
    return k == CODEC_GZIP || k == CODEC_LZ4_LEGACY || k == CODEC_LZ4_FRAME || k == CODEC_XZ || k == CODEC_LZMA ||
           k == CODEC_BZIP2 || k == CODEC_ZSTD;
}

static rsrc *unpack_stream(sreader *in, const char *label, uint64_t size)
{
    unsigned char h[16];
    int n = sreader_peek(in, h, sizeof h);
    codec_t k = codec_detect(h, n > 0 ? (size_t)n : 0);
    if (compressed_codec(k))
        note("  %-11s %s (%llu MiB, %s) to a temporary file", "unpacking", label, (unsigned long long)(size >> 20),
             codec_name(k));
    else
        note("  %-11s %s (%llu MiB) to a temporary file", "extracting", label, (unsigned long long)(size >> 20));
    char err[256];
    rsrc *r = stream_decompress_to_temp(in, label, err, sizeof err);
    if (!r)
        die("%s", err);
    return r;
}

static rsrc *open_input_file(const char *path)
{
    rsrc *f = rsrc_open_file(path);
    if (!f)
        die("cannot open %s: %s", path, strerror(errno));
    unsigned char h[16];
    memset(h, 0, sizeof h);
    rsrc_read(f, h, f->size < sizeof h ? (size_t)f->size : sizeof h, 0);
    if (!compressed_codec(codec_detect(h, sizeof h)))
        return f;
    rsrc_seq rq = {f, 0, f->size};
    sreader sr;
    sreader_init(&sr, rsrc_seq_read, &rq, UINT64_MAX);
    rsrc *r = unpack_stream(&sr, path_basename(path), f->size);
    sreader_free(&sr);
    rsrc_close(f);
    return r;
}

static int part_loaded(rom_t *rom, const char *mount)
{
    return strvec_has(&rom->loaded, mount);
}

static void load_part_image(rom_t *rom, rsrc *src, role_t role, const char *extra, const char *label)
{
    const char *mount = NULL, *orig = NULL;
    char em[80];
    if (role == ROLE_EXTRA) {
        snprintf(em, sizeof em, "/%s", extra);
        mount = em;
    } else if (mount_role(role_name(role), &mount, &orig) == ROLE_UNKNOWN) {
        rsrc_close(src);
        return;
    }
    if (part_loaded(rom, mount)) {
        debug("%s: %s was already loaded; skipped", label, mount);
        rsrc_close(src);
        return;
    }
    if (role == ROLE_SYSTEM)
        rom->have_system = 1;
    if (role == ROLE_VENDOR)
        rom->have_vendor = 1;
    load_image_src(rom, src, role, label, mount, orig);
}

static const role_t PART_ORDER[] = {ROLE_SYSTEM, ROLE_PRODUCT, ROLE_SYSTEM_EXT, ROLE_VENDOR,
                                    ROLE_ODM,    ROLE_OEM,     ROLE_EXTRA};

static void load_super(rom_t *rom, rsrc *src, const char *label)
{
    if (sparse_probe(src)) {
        rsrc *sp = rsrc_open_sparse(src);
        if (!sp)
            die("%s: corrupt sparse image", label);
        src = sp;
    }
    if (!lp_probe(src)) {
        rsrc_close(src);
        die("%s: not a super image (no dynamic partition metadata)", label);
    }
    track_src(rom, src);
    lp_table t;
    char err[256];
    if (lp_read(src, &t, err, sizeof err) < 0)
        die("%s: %s", label, err);
    note("  %-11s %s (%zu dynamic partitions)", "super", label, t.n);
    for (size_t o = 0; o < sizeof PART_ORDER / sizeof *PART_ORDER; o++) {
        for (size_t i = 0; i < t.n; i++) {
            char extra[64] = "";
            if (!t.parts[i].size)
                continue;
            role_t r = role_from_name(t.parts[i].name, extra, sizeof extra);
            if (r != PART_ORDER[o])
                continue;
            char *lab = xasprintf("%s:%s", path_basename(label), t.parts[i].name);
            load_part_image(rom, lp_open_partition(src, &t.parts[i]), r, extra, lab);
            free(lab);
        }
    }
    for (size_t i = 0; i < t.n; i++) {
        char extra[64] = "";
        role_t r = role_from_name(t.parts[i].name, extra, sizeof extra);
        if (r == ROLE_SKIP || r == ROLE_UNKNOWN || !t.parts[i].size)
            debug("super: partition %s not needed", t.parts[i].name);
    }
    lp_free(&t);
}

static void load_boot_rsrc(rom_t *rom, rsrc *src, const char *label)
{
    if (src->size > MAX_BOOT) {
        warn("%s: too large for a boot image; ignored", label);
        rsrc_close(src);
        return;
    }
    buf_t b = {0};
    b.data = xmalloc((size_t)src->size + 1);
    b.len = (size_t)src->size;
    b.cap = b.len + 1;
    if (rsrc_read(src, b.data, b.len, 0) < 0)
        die("%s: read error", label);
    rsrc_close(src);
    if (!bootimg_probe(b.data, b.len))
        warn("%s: not an Android boot image (a bare kernel such as zImage carries its ramdisk inside the kernel, "
             "which is not supported); no boot.img is used",
             label);
    else
        load_boot_data(rom, b.data, b.len, label);
    buf_free(&b);
}

typedef struct {
    role_t role;
    char extra[64];
    rsrc *src;
    char *label;
} pending_img;

typedef struct {
    rom_t *rom;
    const char *tar;
    int csc;
    int rfs;
    pending_img v[24];
    size_t n;
} tarctx;

static int tar_member(void *vc, const char *name, uint64_t size, rsrc *base, uint64_t off, sreader *data)
{
    tarctx *c = vc;
    const char *bn = path_basename(name);
    if (ends_with_ci(bn, ".rfs")) {
        if (starts_with(bn, "factoryfs") || starts_with(bn, "system"))
            c->rfs = 1;
        return 0;
    }
    char extra[64] = "";
    role_t r = role_from_name(bn, extra, sizeof extra);
    int part = r == ROLE_SYSTEM || r == ROLE_VENDOR || r == ROLE_PRODUCT || r == ROLE_SYSTEM_EXT || r == ROLE_ODM ||
               r == ROLE_OEM || r == ROLE_EXTRA;
    if (!part && r != ROLE_BOOT && r != ROLE_SUPER)
        return 0;
    if (c->csc && r != ROLE_EXTRA)
        return 0;
    if (size < 64 || c->n == sizeof c->v / sizeof *c->v)
        return 0;
    if (r == ROLE_BOOT && c->rom->have_boot)
        return 0;
    for (size_t i = 0; i < c->n; i++)
        if (c->v[i].role == r && (r != ROLE_EXTRA || !strcmp(c->v[i].extra, extra)))
            return 0;
    unsigned char h[16];
    int n = sreader_peek(data, h, sizeof h);
    codec_t k = codec_detect(h, n > 0 ? (size_t)n : 0);
    char *label = xasprintf("%s:%s", path_basename(c->tar), name);
    rsrc *src;
    if (base && !compressed_codec(k))
        src = rsrc_open_slice(base, off, size, label);
    else
        src = unpack_stream(data, bn, size);
    pending_img *p = &c->v[c->n++];
    p->role = r;
    snprintf(p->extra, sizeof p->extra, "%s", extra);
    p->src = src;
    p->label = label;
    return 0;
}

static void load_tar(rom_t *rom, const char *label, rsrc *seekable, sreader *seq)
{
    tarctx *c = xcalloc(1, sizeof *c);
    c->rom = rom;
    c->tar = label;
    c->csc = samsung_csc_tar(path_basename(label));
    note("  %-11s %s%s", "tar", label, c->csc ? " (CSC package: only optics/prism images are used)" : "");
    unsigned char h[4] = {0};
    if (seekable)
        rsrc_read(seekable, h, seekable->size < 4 ? (size_t)seekable->size : 4, 0);
    else
        sreader_peek(seq, h, 4);
    int gz = h[0] == 0x1f && h[1] == 0x8b;
    char err[256] = "";
    int r;
    if (gz) {
        rsrc_seq rq = {seekable, 0, seekable ? seekable->size : 0};
        sreader base_sr;
        if (seekable)
            sreader_init(&base_sr, rsrc_seq_read, &rq, UINT64_MAX);
        gzseq *g = gzseq_open(sreader_read, seekable ? (void *)&base_sr : (void *)seq);
        if (!g)
            die("%s: cannot start gzip decompression", label);
        sreader gz_sr;
        sreader_init(&gz_sr, gzseq_read, g, UINT64_MAX);
        r = tar_scan_stream(&gz_sr, tar_member, c, err, sizeof err);
        sreader_free(&gz_sr);
        gzseq_close(g);
        if (seekable)
            sreader_free(&base_sr);
    } else if (seekable) {
        r = tar_scan_rsrc(seekable, tar_member, c, err, sizeof err);
    } else {
        r = tar_scan_stream(seq, tar_member, c, err, sizeof err);
    }
    if (r < 0)
        die("%s: %s", label, err);
    for (size_t i = 0; i < c->n; i++)
        if (c->v[i].role == ROLE_SUPER) {
            load_super(rom, c->v[i].src, c->v[i].label);
            c->v[i].src = NULL;
        }
    for (size_t o = 0; o < sizeof PART_ORDER / sizeof *PART_ORDER; o++)
        for (size_t i = 0; i < c->n; i++)
            if (c->v[i].src && c->v[i].role == PART_ORDER[o]) {
                load_part_image(rom, c->v[i].src, c->v[i].role, c->v[i].extra, c->v[i].label);
                c->v[i].src = NULL;
            }
    for (size_t i = 0; i < c->n; i++)
        if (c->v[i].src && c->v[i].role == ROLE_BOOT) {
            load_boot_rsrc(rom, c->v[i].src, c->v[i].label);
            c->v[i].src = NULL;
        }
    for (size_t i = 0; i < c->n; i++) {
        rsrc_close(c->v[i].src);
        free(c->v[i].label);
    }
    if (c->rfs && !rom->have_system)
        die("%s: the system image is RFS (Samsung's FAT-based filesystem of the Galaxy S/S II era), which is not "
            "supported; use a recovery-flashable zip of the same firmware instead",
            label);
    if (!c->n && !c->csc)
        note("  %-11s %s: no system, vendor, super or boot image inside", "tar", path_basename(label));
    free(c);
}

static int zip_has_entry(zipr *z, const char *name)
{
    for (size_t i = 0; i < z->n; i++)
        if (!strcmp(z->e[i].name, name))
            return 1;
    return 0;
}

static ozip_kind member_kind(zipr *z)
{
    return zip_has_entry(z, "oppo_metadata") ? OZIP_MEMBER : OZIP_SEGMENTED;
}

static int entry_encrypted(zipr *z, zip_entry *e)
{
    if (e->usize < 0x60)
        return 0;
    zstream *zs = zstream_open(z, e);
    if (!zs)
        return 0;
    unsigned char h[12];
    size_t got = 0;
    while (got < sizeof h) {
        long n = zstream_read(zs, h + got, sizeof h - got);
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    zstream_close(zs);
    return ozip_head_is_encrypted(h, got);
}

static void prime_ozip_key(zipr *z)
{
    if (ozip_have_key())
        return;
    ozip_kind kind = member_kind(z);
    for (int pass = 0; pass < 2 && !ozip_have_key(); pass++) {
        for (size_t i = 0; i < z->n && !ozip_have_key(); i++) {
            zip_entry *e = &z->e[i];
            const char *bn = path_basename(e->name);
            int preferred = starts_with(bn, "vbmeta") || starts_with(bn, "boot") || starts_with(bn, "recovery");
            if ((pass == 0) != preferred || e->usize > (256u << 20) || zip_entry_is_dir(e) || !entry_encrypted(z, e))
                continue;
            buf_t b = {0};
            if (zipr_read_all(z, e, &b, 256u << 20) == 0) {
                rsrc *m = rsrc_open_mem(b.data, b.len, e->name);
                ozip_find_key(m, kind);
                rsrc_close(m);
            }
            buf_free(&b);
        }
    }
}

static rsrc *decrypt_member(rom_t *rom, zipr *z, rsrc *s, const char *name)
{
    prime_ozip_key(z);
    char err[400];
    rsrc *d = ozip_open(s, member_kind(z), name, err, sizeof err);
    if (!d) {
        rsrc_close(s);
        die("%s", err);
    }
    rom->ozip_members++;
    debug("%s: OPPO-encrypted, decrypted on the fly", name);
    return d;
}

static rsrc *open_entry(rom_t *rom, zipr *z, zip_entry *e)
{
    rsrc *s = zipr_open_entry(z, e);
    if (!s || !ozip_is_encrypted(s))
        return s;
    return decrypt_member(rom, z, s, e->name);
}

static int read_entry(rom_t *rom, zipr *z, zip_entry *e, buf_t *out, size_t limit)
{
    if (zipr_read_all(z, e, out, limit) < 0)
        return -1;
    if (!ozip_head_is_encrypted(out->data, out->len))
        return 0;
    rsrc *d = decrypt_member(rom, z, rsrc_open_mem(out->data, out->len, e->name), e->name);
    buf_t plain = {0};
    plain.data = xmalloc((size_t)d->size + 1);
    plain.len = (size_t)d->size;
    plain.cap = plain.len + 1;
    int r = rsrc_read(d, plain.data, plain.len, 0);
    rsrc_close(d);
    buf_free(out);
    *out = plain;
    return r;
}

static void load_zip_tars(rom_t *rom, zipr *z, zip_entry **tars, size_t ntars)
{
    int have_csc = 0;
    for (size_t i = 0; i < ntars; i++)
        if (starts_with(path_basename(tars[i]->name), "CSC_"))
            have_csc = 1;
    for (int pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < ntars; i++) {
            zip_entry *e = tars[i];
            const char *bn = path_basename(e->name);
            if ((pass == 0) != starts_with(bn, "AP_"))
                continue;
            if (samsung_unused_tar(bn) || (have_csc && starts_with(bn, "HOME_CSC_"))) {
                debug("skipping %s (bootloader/modem/userdata package)", e->name);
                continue;
            }
            if (e->method == 0) {
                rsrc *s = zipr_open_entry(z, e);
                if (!s)
                    die("%s: cannot open %s", z->path, e->name);
                track_src(rom, s);
                load_tar(rom, e->name, s, NULL);
            } else {
                zstream *zs = zstream_open(z, e);
                if (!zs)
                    die("%s: cannot read %s", z->path, e->name);
                sreader sr;
                sreader_init(&sr, zstream_reader, zs, UINT64_MAX);
                load_tar(rom, e->name, NULL, &sr);
                sreader_free(&sr);
                zstream_close(zs);
            }
        }
    }
}

static void load_zip(rom_t *rom, zipr *z, int depth)
{
    if (depth > 3)
        return;
    rom->from_zip = 1;
    char *wrap = xstrdup("");
    zip_entry *script = NULL;
    for (size_t i = 0; i < z->n; i++) {
        const char *n = z->e[i].name;
        const char *m = strstr(n, "META-INF/com/google/android/updater-script");
        if (m && !strcmp(m, "META-INF/com/google/android/updater-script")) {
            script = &z->e[i];
            size_t pl = (size_t)(m - n);
            size_t slashes = 0;
            for (size_t k = 0; k < pl; k++)
                if (n[k] == '/')
                    slashes++;
            if (pl && slashes == 1) {
                free(wrap);
                wrap = xstrndup(n, pl);
            }
            break;
        }
    }
    size_t wl = strlen(wrap);
    char *sysroot = find_system_root(z, wl);
    zctx c = {rom, z, wrap};
    zip_entry *boot = NULL;
    int boot_depth = 1 << 30;
    zip_entry *rd = NULL;
    zip_entry *payload_e = NULL;
    zip_entry *images[ROLE_UNKNOWN + 1];
    char extra_names[8][64];
    zip_entry *extras[8];
    size_t nextras = 0;
    memset(images, 0, sizeof images);
    static const char *const dat_parts[] = {"system", "product", "system_ext", "vendor", "odm", NULL};
    datpair dats[5];
    memset(dats, 0, sizeof dats);
    zip_entry *nested[8];
    size_t nnested = 0;
    zip_entry *tars[8];
    size_t ntars = 0;
    size_t sys_entries = 0;
    for (size_t i = 0; i < z->n; i++) {
        zip_entry *e = &z->e[i];
        if (strncmp(e->name, wrap, wl) || strstr(e->name, "__MACOSX/"))
            continue;
        const char *n = e->name + wl;
        const char *base = path_basename(n);
        if (base[0] == '.' && base[1] == '_')
            continue;
        if (sysroot) {
            size_t sl = strlen(sysroot);
            if (!strncmp(n, sysroot, sl) && strlen(n) >= sl + 7 && strncase_eq(n + sl, "system/", 7)) {
                zip_system_entry(&c, e, n + sl + 7, zip_entry_is_dir(e));
                sys_entries++;
                continue;
            }
        }
        if (zip_entry_is_dir(e))
            continue;
        int d = 0;
        for (const char *q = n; *q; q++)
            if (*q == '/')
                d++;
        int handled = 0;
        for (int k = 0; dat_parts[k]; k++) {
            size_t pl = strlen(dat_parts[k]);
            if (strncmp(base, dat_parts[k], pl))
                continue;
            if (!strcmp(base + pl, ".new.dat")) {
                dats[k].dat = e;
                dats[k].brotli = 0;
                handled = 1;
            } else if (!strcmp(base + pl, ".new.dat.br")) {
                dats[k].dat = e;
                dats[k].brotli = 1;
                handled = 1;
            } else if (!strcmp(base + pl, ".transfer.list")) {
                dats[k].list = e;
                handled = 1;
            } else if (!strcmp(base + pl, ".patch.dat")) {
                handled = 1;
            }
        }
        if (handled)
            continue;
        if (!strcmp(base, "payload.bin")) {
            payload_e = e;
            continue;
        }
        char extra[64] = "";
        role_t r = role_from_name(base, extra, sizeof extra);
        if (is_tar_name(base)) {
            if (ntars < 8)
                tars[ntars++] = e;
            continue;
        }
        if (ends_with_ci(base, ".ozip") && nnested < 8) {
            nested[nnested++] = e;
            continue;
        }
        if (ends_with_ci(base, ".zip")) {
            if ((starts_with(base, "image-") || (depth == 0 && e->usize > 50000000)) && nnested < 8)
                nested[nnested++] = e;
            continue;
        }
        if (!strcmp(base, "recovery.img") && rom->npass < 8 && !entry_encrypted(z, e)) {
            rom->pass_zip[rom->npass] = z;
            rom->pass_entry[rom->npass++] = e;
            continue;
        }
        if (r == ROLE_BOOT && (ends_with_ci(base, ".img") || !strchr(base, '.'))) {
            if (d < boot_depth) {
                boot = e;
                boot_depth = d;
            }
        } else if (r == ROLE_RAMDISK && !rd) {
            rd = e;
        } else if (r == ROLE_EXTRA && nextras < 8 && ends_with_ci(base, ".img")) {
            snprintf(extra_names[nextras], 64, "%s", extra);
            extras[nextras++] = e;
        } else if ((r == ROLE_SYSTEM || r == ROLE_VENDOR || r == ROLE_PRODUCT || r == ROLE_SYSTEM_EXT ||
                    r == ROLE_ODM || r == ROLE_OEM || r == ROLE_SUPER) &&
                   (ends_with_ci(base, ".img") || ends_with_ci(base, ".ext4") || !strchr(base, '.')) &&
                   e->usize > 4096) {
            if (!images[r])
                images[r] = e;
        } else if (strstr(base, "sparsechunk")) {
            warn("%s: split sparse images (%s) are not supported; merge them with simg2img first", z->path, base);
        }
    }
    if (sys_entries)
        note("  %-11s %s: system/ folder (%zu entries%s%s)", "system", z->path, sys_entries, sysroot[0] ? " under " : "",
             sysroot);
    if (sys_entries)
        rom->have_system = 1;
    if (script && sys_entries) {
        buf_t t = {0};
        if (zipr_read_all(z, script, &t, 8u << 20) == 0)
            apply_updater_script(rom, (const char *)t.data);
        buf_free(&t);
    }
    if (ntars)
        load_zip_tars(rom, z, tars, ntars);
    if (payload_e) {
        rsrc *src = open_entry(rom, z, payload_e);
        if (!src)
            die("%s: cannot open payload.bin", z->path);
        track_src(rom, src);
        load_payload(rom, src, "payload.bin");
    }
    for (int k = 0; dat_parts[k]; k++) {
        if (!dats[k].dat)
            continue;
        if (!dats[k].list) {
            warn("%s: %s has no transfer list; skipped", z->path, dats[k].dat->name);
            continue;
        }
        buf_t list = {0};
        if (read_entry(rom, z, dats[k].list, &list, 64u << 20) < 0)
            die("%s: cannot read %s", z->path, dats[k].list->name);
        rsrc *dec = entry_encrypted(z, dats[k].dat) ? open_entry(rom, z, dats[k].dat) : NULL;
        zstream *zs = dec ? NULL : zstream_open(z, dats[k].dat);
        if (!zs && !dec)
            die("%s: cannot read %s", z->path, dats[k].dat->name);
        note("  converting  %s (%llu MiB) to an image", dats[k].dat->name,
             (unsigned long long)(dats[k].dat->usize >> 20));
        char err[256];
        char *label = xasprintf("%s.new.dat%s", dat_parts[k], dats[k].brotli ? ".br" : "");
        rsrc_seq rq = {dec, 0, dec ? dec->size : 0};
        rsrc *img = dec ? ota_from_dat((const char *)list.data, list.len, rsrc_seq_read, &rq, dats[k].brotli, label,
                                       err, sizeof err)
                        : ota_from_dat((const char *)list.data, list.len, zstream_reader, zs, dats[k].brotli, label,
                                       err, sizeof err);
        if (zs)
            zstream_close(zs);
        rsrc_close(dec);
        buf_free(&list);
        if (!img)
            die("%s: %s", z->path, err);
        const char *mount, *orig;
        role_t r = mount_role(dat_parts[k], &mount, &orig);
        if (r == ROLE_SYSTEM)
            rom->have_system = 1;
        if (r == ROLE_VENDOR)
            rom->have_vendor = 1;
        load_image_src(rom, img, r, label, mount, orig);
        free(label);
    }
    if (images[ROLE_SUPER]) {
        rsrc *src = open_entry(rom, z, images[ROLE_SUPER]);
        if (!src)
            die("%s: cannot open %s", z->path, images[ROLE_SUPER]->name);
        load_super(rom, src, images[ROLE_SUPER]->name);
    }
    static const role_t order[] = {ROLE_SYSTEM, ROLE_PRODUCT, ROLE_SYSTEM_EXT, ROLE_VENDOR, ROLE_ODM, ROLE_OEM};
    for (size_t k = 0; k < sizeof order / sizeof *order; k++) {
        zip_entry *e = images[order[k]];
        if (!e)
            continue;
        if (order[k] == ROLE_SYSTEM && sys_entries) {
            warn("%s: has both a system/ folder and %s; using the folder", z->path, e->name);
            continue;
        }
        rsrc *src = open_entry(rom, z, e);
        if (!src)
            die("%s: cannot open %s", z->path, e->name);
        const char *part = role_name(order[k]);
        const char *mount, *orig;
        mount_role(part, &mount, &orig);
        if (order[k] == ROLE_SYSTEM)
            rom->have_system = 1;
        if (order[k] == ROLE_VENDOR)
            rom->have_vendor = 1;
        load_image_src(rom, src, order[k], e->name, mount, orig);
    }
    for (size_t k = 0; k < nextras; k++) {
        rsrc *src = open_entry(rom, z, extras[k]);
        if (!src)
            die("%s: cannot open %s", z->path, extras[k]->name);
        char *mount = xasprintf("/%s", extra_names[k]);
        load_image_src(rom, src, ROLE_EXTRA, extras[k]->name, mount, NULL);
        free(mount);
    }
    if (boot) {
        buf_t b = {0};
        if (read_entry(rom, z, boot, &b, MAX_BOOT) < 0)
            die("%s: cannot read %s", z->path, boot->name);
        load_boot_data(rom, b.data, b.len, boot->name);
        buf_free(&b);
    }
    if (rd && !rom->have_ramdisk) {
        buf_t b = {0};
        if (read_entry(rom, z, rd, &b, MAX_RAMDISK) == 0)
            load_ramdisk_data(rom, b.data, b.len, rd->name);
        buf_free(&b);
    }
    for (size_t k = 0; k < nnested; k++) {
        if (rom->have_system && rom->have_boot)
            break;
        rsrc *src = zipr_open_entry(z, nested[k]);
        if (!src)
            continue;
        char err[400];
        if (ozip_is_encrypted(src)) {
            rsrc *d = ozip_open(src, OZIP_WHOLE, nested[k]->name, err, sizeof err);
            if (!d) {
                rsrc_close(src);
                die("%s", err);
            }
            note("  %-11s %s (OPPO/realme encrypted, decrypted on the fly)", "ozip", nested[k]->name);
            src = d;
        }
        zipr *inner = zipr_open_rsrc(src, nested[k]->name, err, sizeof err);
        if (!inner) {
            rsrc_close(src);
            continue;
        }
        track_zip(rom, inner);
        note("  %-11s %s (nested zip)", "zip", nested[k]->name);
        load_zip(rom, inner, depth + 1);
    }
    free(sysroot);
    free(wrap);
}

static void load_zip_file(rom_t *rom, const char *path)
{
    char err[256];
    zipr *z = zipr_open(path, err, sizeof err);
    if (!z)
        die("%s: %s", path, err);
    track_zip(rom, z);
    note("  %-11s %s (%zu entries)", "zip", path, z->n);
    unsigned before = rom->ozip_members;
    load_zip(rom, z, 0);
    if (rom->ozip_members > before)
        note("  %-11s %u OPPO/realme-encrypted entries decrypted on the fly", "ozip", rom->ozip_members - before);
}

static void load_ozip_file(rom_t *rom, const char *path)
{
    rsrc *f = rsrc_open_file(path);
    if (!f)
        die("cannot open %s: %s", path, strerror(errno));
    char err[400];
    rsrc *d = ozip_open(f, OZIP_WHOLE, path, err, sizeof err);
    if (!d) {
        rsrc_close(f);
        die("%s", err);
    }
    zipr *z = zipr_open_rsrc(d, path, err, sizeof err);
    if (!z) {
        rsrc_close(d);
        die("%s: decrypted, but the result is not a zip (%s)", path, err);
    }
    track_zip(rom, z);
    note("  %-11s %s (OPPO/realme encrypted, decrypted on the fly; %zu entries)", "ozip", path, z->n);
    load_zip(rom, z, 0);
}

static int ramdisk_skipped(const char *n)
{
    static const char *const tops[] = {"system", "data", "dev", "proc", "sys"};
    for (size_t i = 0; i < sizeof tops / sizeof *tops; i++) {
        size_t l = strlen(tops[i]);
        if (!strncmp(n, tops[i], l) && (n[l] == 0 || n[l] == '/'))
            return 1;
    }
    return 0;
}

static void overlay_ramdisk(rom_t *rom)
{
    if (!rom->have_ramdisk)
        return;
    const char *label = intern_label(rom, "ramdisk");
    size_t used = 0;
    for (size_t i = 0; i < rom->ramdisk.n; i++) {
        cpio_entry *e = &rom->ramdisk.e[i];
        if (ramdisk_skipped(e->name))
            continue;
        char *dir = path_dirname(e->name);
        vnode *parent = strcmp(dir, ".") ? vfs_mkdirs(rom->root, dir, 0755) : rom->root;
        free(dir);
        const char *base = path_basename(e->name);
        uint32_t fmt = e->mode & 0xF000;
        vnode *n;
        if (fmt == 0x4000) {
            n = vfs_put(parent, base, VN_DIR);
        } else if (fmt == 0x8000) {
            n = vfs_put(parent, base, VN_FILE);
            unsigned char *copy = xmalloc(e->size + 1);
            memcpy(copy, e->data, e->size);
            vfs_set_mem(n, copy, e->size);
        } else if (fmt == 0xA000) {
            n = vfs_put(parent, base, VN_LINK);
            n->link = xstrndup((const char *)e->data, e->size);
        } else {
            rom->special_skipped++;
            continue;
        }
        n->mode = e->mode & 07777;
        n->uid = e->uid;
        n->gid = e->gid;
        n->mtime = e->mtime;
        n->origin = label;
        used++;
    }
    debug("ramdisk: %zu of %zu entries laid over the root", used, rom->ramdisk.n);
}

void rom_load(rom_t *rom)
{
    if (!rom->ninputs)
        die("no input given");
    qsort(rom->inputs, rom->ninputs, sizeof(rom_input), cmp_inputs);
    note("Loading ROM:");
    for (size_t i = 0; i < rom->ninputs; i++) {
        rom_input *in = &rom->inputs[i];
        int dir = is_dir(in->path);
        const char *mount = NULL, *orig = NULL;
        char extra_mount[80];
        switch (in->role) {
        case ROLE_ROOT: mount = "/"; break;
        case ROLE_SYSTEM: mount = "/system"; break;
        case ROLE_PRODUCT: mount = "/system/product"; orig = "/product"; break;
        case ROLE_SYSTEM_EXT: mount = "/system/system_ext"; orig = "/system_ext"; break;
        case ROLE_VENDOR: mount = "/vendor"; break;
        case ROLE_ODM: mount = "/odm"; break;
        case ROLE_OEM: mount = "/oem"; break;
        case ROLE_EXTRA:
            snprintf(extra_mount, sizeof extra_mount, "/%s", in->extra ? in->extra : "extra");
            mount = extra_mount;
            break;
        case ROLE_ZIP: load_zip_file(rom, in->path); continue;
        case ROLE_TAR: {
            rsrc *t = rsrc_open_file(in->path);
            if (!t)
                die("cannot open %s: %s", in->path, strerror(errno));
            track_src(rom, t);
            load_tar(rom, in->path, t, NULL);
            continue;
        }
        case ROLE_OZIP: load_ozip_file(rom, in->path); continue;
        case ROLE_SUPER: load_super(rom, open_input_file(in->path), in->path); continue;
        case ROLE_PAYLOAD: {
            rsrc *p = rsrc_open_file(in->path);
            if (!p)
                die("cannot open %s: %s", in->path, strerror(errno));
            track_src(rom, p);
            load_payload(rom, p, in->path);
            continue;
        }
        case ROLE_BOOT: load_boot(rom, in); continue;
        case ROLE_RAMDISK: load_ramdisk(rom, in); continue;
        default: continue;
        }
        if (in->role == ROLE_VENDOR)
            rom->have_vendor = 1;
        if (in->role == ROLE_SYSTEM || in->role == ROLE_ROOT)
            rom->have_system = 1;
        if (dir) {
            load_dir(rom, in, mount, orig);
        } else {
            load_image(rom, in, mount, orig);
        }
    }
    overlay_ramdisk(rom);
    vnode *sys = vfs_lookup(rom->root, "/system");
    if (!sys || sys->type != VN_DIR || (!vfs_lookup(rom->root, "/system/build.prop") &&
                                         !vfs_lookup(rom->root, "/system/framework")))
        warn("no Android system found (no /system/build.prop or /system/framework); AEmulator Plus will reject this ROM");
    vfs_sort(rom->root);
}
