#include "rom/check.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

int name_unsafe(const char *name)
{
    return strchr(name, '\\') != NULL || !strcmp(name, ".") || !strcmp(name, "..") || !*name;
}

int link_bad(const char *target)
{
    return !*target || strchr(target, '\\') != NULL;
}

int link_escapes(const char *node_path, const char *target)
{
    if (target[0] == '/')
        return 0;
    char *dir = path_dirname(node_path);
    char *joined = xasprintf("%s/%s", dir, target);
    char *norm = path_normalize(joined);
    free(dir);
    free(joined);
    if (!norm)
        return 1;
    free(norm);
    return 0;
}

static int partition_stem(const char *base)
{
    static const char *const stems[] = {"system", "vendor", "product", "system_ext", "odm", "oem", "boot", "recovery", NULL};
    for (int i = 0; stems[i]; i++) {
        size_t l = strlen(stems[i]);
        if (!strncasecmp(base, stems[i], l) && (base[l] == '.' || base[l] == '_'))
            return 1;
    }
    return 0;
}

const char *import_trap(const char *path, uint64_t size)
{
    const char *base = path_basename(path);
    if (ends_with_ci(base, ".zip") && size > 20000000ULL)
        return "zip larger than 20 MB";
    if ((ends_with_ci(base, ".tar") || ends_with_ci(base, ".tar.md5")) && (size > 20000000ULL || partition_stem(base)))
        return "tar archive";
    if (ends_with_ci(base, ".sin") || ends_with_ci(base, ".ftf"))
        return "Sony firmware name";
    if (!strcasecmp(base, "system.img") || !strcasecmp(base, "system_a.img") || !strcasecmp(base, "factoryfs.img") ||
        !strcasecmp(base, "factoryfs.rfs") || !strcasecmp(base, "system.img.lz4"))
        return "system image name";
    return NULL;
}

typedef struct {
    check_report *rep;
} cctx;

static int check_cb(vnode *n, const char *path, void *ctx)
{
    cctx *c = ctx;
    if (!n->parent)
        return 0;
    if (name_unsafe(n->name)) {
        c->rep->unsafe_names++;
        return 1;
    }
    if (n->type == VN_LINK) {
        if (link_bad(n->link))
            c->rep->bad_links++;
        else if (link_escapes(path, n->link))
            c->rep->escaping_links++;
    } else if (n->type == VN_FILE &&
               (starts_with(path, "/system/") || starts_with(path, "/vendor/") || starts_with(path, "/oem/"))) {
        const char *why = import_trap(path, n->size);
        if (why && c->rep->traps.n < 20) {
            char *s = xasprintf("%s (%s)", path, why);
            strvec_push(&c->rep->traps, s);
            free(s);
        }
    }
    return 0;
}

void check_tree(vnode *root, check_report *rep)
{
    memset(rep, 0, sizeof *rep);
    vnode *sys = vfs_child(root, "system");
    if (sys && sys->type != VN_DIR)
        rep->system_not_dir = 1;
    cctx c = {rep};
    vfs_walk(root, check_cb, &c);
}

void check_free(check_report *rep)
{
    strvec_free(&rep->traps);
}
