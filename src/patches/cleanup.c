#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>

#include "core/util.h"
#include "core/vfs.h"
#include "patches/patches.h"
#include "patches/support.h"
#include "rom/check.h"

typedef struct {
    unsigned removed;
} sanitize_ctx;

static int sanitize_cb(vnode *n, const char *path, void *ctx)
{
    sanitize_ctx *s = ctx;
    if (!n->parent)
        return 0;
    const char *why = NULL;
    if (name_unsafe(n->name))
        why = "unsafe name";
    else if (n->type == VN_LINK && link_bad(n->link))
        why = "invalid symlink target";
    else if (n->type == VN_LINK && link_escapes(path, n->link))
        why = "symlink escapes the ROM";
    if (!why)
        return 0;
    if (n->type == VN_LINK)
        debug("sanitize: dropping %s -> %s (%s)", path, n->link, why);
    else
        debug("sanitize: dropping %s (%s)", path, why);
    s->removed++;
    vfs_remove(n);
    return 2;
}

void patch_sanitize(rom_t *rom, const patch_opts *opts)
{
    sanitize_ctx s = {0};
    vfs_walk(rom->root, sanitize_cb, &s);
    if (s.removed)
        change("sanitize: dropped %u entr%s that would abort the import (use -v for the list)", s.removed,
               s.removed == 1 ? "y" : "ies");
}

void patch_strip_data(rom_t *rom, const patch_opts *opts)
{
    const char *const names[] = {"data", "cache", NULL};
    for (int i = 0; names[i]; i++) {
        vnode *n = vfs_child(rom->root, names[i]);
        if (!n || n->type != VN_DIR || !n->nkids)
            continue;
        uint64_t f = 0, d = 0, l = 0, b = 0;
        vfs_count(n, &f, &d, &l, &b);
        char hs[32];
        change("left out /%s (%llu files, %s)", names[i], (unsigned long long)f, human_size(b, hs, sizeof hs));
        for (size_t k = n->nkids; k > 0; k--)
            vfs_remove(n->kids[k - 1]);
    }
}

typedef struct {
    const char *pattern;
    nodelist hits;
} glob_ctx;

static int glob_cb(vnode *n, const char *path, void *ctx)
{
    glob_ctx *g = ctx;
    if (!n->parent)
        return 0;
    if (fnmatch(g->pattern, path, FNM_PATHNAME) == 0) {
        nl_push(&g->hits, n, path);
        return 1;
    }
    return 0;
}

void remove_path(rom_t *rom, const char *pattern)
{
    char *pat = pattern[0] == '/' ? xstrdup(pattern) : xasprintf("/%s", pattern);
    size_t l = strlen(pat);
    while (l > 1 && pat[l - 1] == '/')
        pat[--l] = 0;
    if (!strcmp(pat, "/")) {
        warn("refusing to remove /");
        free(pat);
        return;
    }
    glob_ctx g = {pat, {0}};
    vfs_walk(rom->root, glob_cb, &g);
    if (!g.hits.n)
        warn("--remove %s: nothing matched", pattern);
    for (size_t i = 0; i < g.hits.n; i++) {
        if (!strcmp(g.hits.paths[i], "/system"))
            warn("removing /system: the ROM will not import");
        change("removed %s%s", g.hits.paths[i], g.hits.v[i]->type == VN_DIR ? "/" : "");
        vfs_remove(g.hits.v[i]);
    }
    nl_free(&g.hits);
    free(pat);
}

void remove_app(rom_t *rom, const char *name)
{
    const char *const dirs[] = {"/system/app", "/system/priv-app", "/system/product/app", "/system/product/priv-app",
                                "/system/system_ext/app", "/system/system_ext/priv-app", "/vendor/app",
                                "/system/vendor/app", "/system/preinstall", "/system/preload", "/system/delapp", NULL};
    const char *const suffixes[] = {"", ".apk", ".odex", NULL};
    int hits = 0;
    if (strchr(name, '/') || name_unsafe(name)) {
        warn("--remove-app %s: give the app folder or file name, not a path", name);
        return;
    }
    for (int d = 0; dirs[d]; d++) {
        vnode *dir = vfs_lookup(rom->root, dirs[d]);
        if (!dir || dir->type != VN_DIR)
            continue;
        for (int s = 0; suffixes[s]; s++) {
            char *n = xasprintf("%s%s", name, suffixes[s]);
            vnode *k = vfs_child(dir, n);
            if (k) {
                change("removed app %s/%s%s", dirs[d], n, k->type == VN_DIR ? "/" : "");
                vfs_remove(k);
                hits++;
            }
            free(n);
        }
    }
    if (!hits)
        warn("--remove-app %s: no such app in system, product, system_ext or vendor", name);
}

void patch_etc_alias(rom_t *rom, const patch_opts *opts)
{
    vnode *etc = vfs_child(rom->root, "etc");
    vnode *sys_etc = vfs_lookup(rom->root, "/system/etc");
    if (etc || !sys_etc || sys_etc->type != VN_DIR)
        return;
    vnode *n = vfs_put(rom->root, "etc", VN_LINK);
    n->link = xstrdup("/system/etc");
    n->mode = 0777;
    change("added /etc -> /system/etc");
}
