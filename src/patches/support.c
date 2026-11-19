#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "patches/support.h"
#include "core/props.h"
#include "rom/analyze.h"

static unsigned g_changes;

void changes_reset(void)
{
    g_changes = 0;
}

unsigned changes_count(void)
{
    return g_changes;
}

void change(const char *fmt, ...)
{
    va_list ap;
    g_changes++;
    if (g_quiet)
        return;
    fputs("  * ", stdout);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
}

void replace_contents(vnode *n, unsigned char *data, size_t len)
{
    uint32_t mode = n->mode, uid = n->uid, gid = n->gid;
    vfs_set_mem(n, data, len);
    n->mode = mode;
    n->uid = uid;
    n->gid = gid;
}

void replace_text(vnode *n, char *text)
{
    replace_contents(n, (unsigned char *)text, strlen(text));
}

int rom_api_level(rom_t *rom)
{
    proplist props = {0};
    props_collect(rom->root, &props);
    int api = effective_api(props_get(&props, "ro.build.version.sdk"), props_get(&props, "ro.build.version.codename"),
                            props_get(&props, "ro.build.version.release"));
    props_free(&props);
    return api;
}

void nl_push(nodelist *l, vnode *n, const char *path)
{
    for (size_t i = 0; i < l->n; i++)
        if (l->v[i] == n)
            return;
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 32;
        l->v = xrealloc(l->v, l->cap * sizeof(vnode *));
        l->paths = xrealloc(l->paths, l->cap * sizeof(char *));
    }
    l->v[l->n] = n;
    l->paths[l->n] = xstrdup(path);
    l->n++;
}

void nl_free(nodelist *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->paths[i]);
    free(l->v);
    free(l->paths);
    memset(l, 0, sizeof *l);
}

char *write_target(vnode *root, const char *path)
{
    char *cur = path_normalize(path);
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
            if (!child)
                return cur;
            if (child->type == VN_LINK && *s) {
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
            if (child->type != VN_DIR && *s) {
                free(cur);
                return NULL;
            }
            node = child;
        }
        if (!restarted)
            return cur;
    }
    free(cur);
    return NULL;
}

const char *find_str(const char *s, const char *end, const char *pat)
{
    size_t n = strlen(pat);
    for (; s + n <= end; s++)
        if (!strncmp(s, pat, n))
            return s;
    return NULL;
}
