#include "core/props.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

const char *const PROP_FILES[] = {
    "/default.prop",
    "/prop.default",
    "/system/etc/prop.default",
    "/system/build.prop",
    "/system/default.prop",
    "/system/product/build.prop",
    "/system/product/etc/build.prop",
    "/system/system_ext/build.prop",
    "/system/system_ext/etc/build.prop",
    "/vendor/build.prop",
    "/vendor/default.prop",
    "/system/vendor/build.prop",
    "/odm/build.prop",
    "/odm/etc/build.prop",
    NULL,
};

static int line_key(const char *line, size_t len, const char **kstart, size_t *klen, const char **vstart, size_t *vlen)
{
    size_t i = 0;
    while (i < len && isspace((unsigned char)line[i]))
        i++;
    if (i >= len || line[i] == '#')
        return 0;
    const char *eq = memchr(line + i, '=', len - i);
    if (!eq)
        return 0;
    size_t ks = i, ke = (size_t)(eq - line);
    while (ke > ks && isspace((unsigned char)line[ke - 1]))
        ke--;
    if (ke == ks)
        return 0;
    size_t vs = ke + 1;
    while (line + vs < eq + 1)
        vs++;
    while (vs < len && isspace((unsigned char)line[vs]))
        vs++;
    size_t ve = len;
    while (ve > vs && (isspace((unsigned char)line[ve - 1])))
        ve--;
    *kstart = line + ks;
    *klen = ke - ks;
    *vstart = line + vs;
    *vlen = ve - vs;
    return 1;
}

static void push(proplist *p, const char *k, size_t kl, const char *v, size_t vl)
{
    if (p->n == p->cap) {
        p->cap = p->cap ? p->cap * 2 : 64;
        p->v = xrealloc(p->v, p->cap * sizeof(prop_t));
    }
    p->v[p->n].key = xstrndup(k, kl);
    p->v[p->n].val = xstrndup(v, vl);
    p->n++;
}

static prop_t *find(const proplist *p, const char *key)
{
    for (size_t i = 0; i < p->n; i++)
        if (!strcmp(p->v[i].key, key))
            return &p->v[i];
    return NULL;
}

void props_parse(const char *text, size_t len, proplist *out)
{
    size_t i = 0;
    while (i < len) {
        const char *nl = memchr(text + i, '\n', len - i);
        size_t ll = nl ? (size_t)(nl - (text + i)) : len - i;
        const char *k, *v;
        size_t kl, vl;
        if (line_key(text + i, ll, &k, &kl, &v, &vl)) {
            char *key = xstrndup(k, kl);
            prop_t *ex = find(out, key);
            if (ex) {
                if (strncmp(key, "ro.", 3)) {
                    free(ex->val);
                    ex->val = xstrndup(v, vl);
                }
            } else {
                push(out, k, kl, v, vl);
            }
            free(key);
        }
        i += ll + 1;
    }
}

void props_merge(proplist *dst, const proplist *src, int keep_ro)
{
    for (size_t i = 0; i < src->n; i++) {
        prop_t *ex = find(dst, src->v[i].key);
        if (!ex) {
            push(dst, src->v[i].key, strlen(src->v[i].key), src->v[i].val, strlen(src->v[i].val));
        } else if (!(keep_ro && !strncmp(ex->key, "ro.", 3))) {
            free(ex->val);
            ex->val = xstrdup(src->v[i].val);
        }
    }
}

void props_set_default(proplist *dst, const char *key, const char *val)
{
    if (!find(dst, key))
        push(dst, key, strlen(key), val, strlen(val));
}

const char *props_get(const proplist *p, const char *key)
{
    prop_t *e = find(p, key);
    return e ? e->val : NULL;
}

void props_free(proplist *p)
{
    for (size_t i = 0; i < p->n; i++) {
        free(p->v[i].key);
        free(p->v[i].val);
    }
    free(p->v);
    p->v = NULL;
    p->n = p->cap = 0;
}

static char *edit(const char *text, size_t len, const char *key, const char *val, int *changed)
{
    buf_t out = {0};
    size_t i = 0;
    int done = 0;
    *changed = 0;
    while (i < len) {
        const char *nl = memchr(text + i, '\n', len - i);
        size_t ll = nl ? (size_t)(nl - (text + i)) : len - i;
        const char *k, *v;
        size_t kl, vl;
        int match = line_key(text + i, ll, &k, &kl, &v, &vl) && kl == strlen(key) && !memcmp(k, key, kl);
        if (match) {
            if (val && !done) {
                if (vl != strlen(val) || memcmp(v, val, vl))
                    *changed = 1;
                buf_printf(&out, "%s=%s", key, val);
                if (nl)
                    buf_putc(&out, '\n');
                done = 1;
            } else {
                *changed = 1;
            }
        } else {
            buf_put(&out, text + i, ll);
            if (nl)
                buf_putc(&out, '\n');
        }
        i += ll + (nl ? 1 : 0);
    }
    if (!out.data)
        buf_reserve(&out, 0);
    return (char *)buf_steal(&out, NULL);
}

char *props_text_set(const char *text, size_t len, const char *key, const char *val, int *changed)
{
    if (!props_text_has(text, len, key)) {
        buf_t out = {0};
        buf_put(&out, text, len);
        if (len && text[len - 1] != '\n')
            buf_putc(&out, '\n');
        buf_printf(&out, "%s=%s\n", key, val);
        *changed = 1;
        return (char *)buf_steal(&out, NULL);
    }
    return edit(text, len, key, val, changed);
}

char *props_text_del(const char *text, size_t len, const char *key, int *changed)
{
    return edit(text, len, key, NULL, changed);
}

int props_text_has(const char *text, size_t len, const char *key)
{
    size_t i = 0;
    while (i < len) {
        const char *nl = memchr(text + i, '\n', len - i);
        size_t ll = nl ? (size_t)(nl - (text + i)) : len - i;
        const char *k, *v;
        size_t kl, vl;
        if (line_key(text + i, ll, &k, &kl, &v, &vl) && kl == strlen(key) && !memcmp(k, key, kl))
            return 1;
        i += ll + 1;
    }
    return 0;
}

static void read_props(vnode *root, const char *path, proplist *out)
{
    vnode *n = vfs_resolve(root, path);
    if (!n || n->type != VN_FILE)
        return;
    buf_t b = {0};
    if (vfs_read_all(n, &b, 16u << 20) == 0)
        props_parse((const char *)b.data, b.len, out);
    buf_free(&b);
}

void props_collect(vnode *root, proplist *out)
{
    proplist deflt = {0}, build = {0};
    const char *const defaults[] = {"/default.prop", "/etc/default.prop", "/system/etc/prop.default", NULL};
    for (int i = 0; defaults[i]; i++) {
        vnode *n = vfs_resolve(root, defaults[i]);
        if (n && n->type == VN_FILE) {
            read_props(root, defaults[i], &deflt);
            break;
        }
    }
    read_props(root, "/system/build.prop", &build);
    props_merge(out, &deflt, 0);
    props_merge(out, &build, 1);
    const char *const extra[] = {"/system/product/etc/build.prop", "/system/product/build.prop", "/odm/etc/build.prop",
                                 "/odm/build.prop", "/vendor/build.prop", "/system/system_ext/etc/build.prop",
                                 "/system/system_ext/build.prop", NULL};
    for (int i = 0; extra[i]; i++) {
        proplist p = {0};
        read_props(root, extra[i], &p);
        for (size_t k = 0; k < p.n; k++)
            props_set_default(out, p.v[k].key, p.v[k].val);
        props_free(&p);
    }
    props_free(&deflt);
    props_free(&build);
}
