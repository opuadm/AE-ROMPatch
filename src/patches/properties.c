#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "core/props.h"
#include "core/util.h"
#include "core/vfs.h"
#include "patches/support.h"

typedef struct {
    vnode *nodes[32];
    char *paths[32];
    size_t n;
} propfiles;

static void gather_prop_files(rom_t *rom, propfiles *pf)
{
    pf->n = 0;
    for (int i = 0; PROP_FILES[i] && pf->n < 32; i++) {
        vnode *n = vfs_resolve(rom->root, PROP_FILES[i]);
        if (!n || n->type != VN_FILE)
            continue;
        int dup = 0;
        for (size_t k = 0; k < pf->n; k++)
            if (pf->nodes[k] == n)
                dup = 1;
        if (dup)
            continue;
        pf->nodes[pf->n] = n;
        pf->paths[pf->n] = xstrdup(PROP_FILES[i]);
        pf->n++;
    }
}

static void free_prop_files(propfiles *pf)
{
    for (size_t i = 0; i < pf->n; i++)
        free(pf->paths[i]);
    pf->n = 0;
}

static vnode *ensure_build_prop(rom_t *rom)
{
    vnode *n = vfs_resolve(rom->root, "/system/build.prop");
    if (n && n->type == VN_FILE)
        return n;
    vnode *sys = vfs_lookup(rom->root, "/system");
    if (!sys || sys->type != VN_DIR)
        return NULL;
    return vfs_write_text(rom->root, "/system/build.prop", "", 0, 0644);
}

void edit_prop(rom_t *rom, const char *key, const char *val)
{
    propfiles pf;
    gather_prop_files(rom, &pf);
    int found = 0;
    for (size_t i = 0; i < pf.n; i++) {
        buf_t b = {0};
        if (vfs_read_all(pf.nodes[i], &b, 16u << 20) < 0) {
            buf_free(&b);
            continue;
        }
        if (!props_text_has((const char *)b.data, b.len, key)) {
            buf_free(&b);
            continue;
        }
        found = 1;
        int changed = 0;
        char *t = val ? props_text_set((const char *)b.data, b.len, key, val, &changed)
                      : props_text_del((const char *)b.data, b.len, key, &changed);
        buf_free(&b);
        if (changed) {
            replace_text(pf.nodes[i], t);
            if (val)
                change("%s: %s=%s", pf.paths[i], key, val);
            else
                change("%s: removed %s", pf.paths[i], key);
        } else {
            free(t);
            debug("%s: %s already set", pf.paths[i], key);
        }
    }
    if (!found && val) {
        vnode *bp = ensure_build_prop(rom);
        if (!bp) {
            warn("cannot set %s: the ROM has no /system folder", key);
        } else {
            buf_t b = {0};
            vfs_read_all(bp, &b, 16u << 20);
            int changed = 0;
            char *t = props_text_set(b.data ? (const char *)b.data : "", b.len, key, val, &changed);
            buf_free(&b);
            replace_text(bp, t);
            change("/system/build.prop: added %s=%s", key, val);
        }
    } else if (!found) {
        debug("%s is not set anywhere; nothing to remove", key);
    }
    free_prop_files(&pf);
}

int prop_defined(rom_t *rom, const char *key)
{
    propfiles pf;
    gather_prop_files(rom, &pf);
    int found = 0;
    for (size_t i = 0; i < pf.n && !found; i++) {
        buf_t b = {0};
        if (vfs_read_all(pf.nodes[i], &b, 16u << 20) == 0 && props_text_has((const char *)b.data, b.len, key))
            found = 1;
        buf_free(&b);
    }
    free_prop_files(&pf);
    return found;
}

int valid_prop_key(const char *k)
{
    if (!*k)
        return 0;
    for (const char *p = k; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-' || *p == ':' || *p == '@'))
            return 0;
    return 1;
}
