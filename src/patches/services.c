#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "core/util.h"
#include "core/vfs.h"
#include "patches/support.h"

static int rc_collect_cb(vnode *n, const char *path, void *ctx)
{
    (void)path;
    if (n->type == VN_FILE && ends_with(n->name, ".rc")) {
        char *real = vfs_path(n);
        nl_push(ctx, n, real);
        free(real);
    }
    return 0;
}

static void gather_rc(rom_t *rom, nodelist *l)
{
    for (size_t i = 0; i < rom->root->nkids; i++) {
        vnode *k = rom->root->kids[i];
        if (k->type == VN_FILE && ends_with(k->name, ".rc")) {
            char *p = vfs_path(k);
            nl_push(l, k, p);
            free(p);
        }
    }
    const char *const dirs[] = {"/system/etc/init", "/vendor/etc/init", "/system/vendor/etc/init", "/odm/etc/init",
                                "/system/product/etc/init", "/system/system_ext/etc/init", NULL};
    for (int i = 0; dirs[i]; i++) {
        vnode *d = vfs_resolve(rom->root, dirs[i]);
        if (d && d->type == VN_DIR)
            vfs_walk(d, rc_collect_cb, l);
    }
}

static int is_section(const char *line, size_t len)
{
    size_t i = 0;
    while (i < len && (line[i] == ' ' || line[i] == '\t'))
        i++;
    const char *const kw[] = {"service", "on", "import", NULL};
    for (int k = 0; kw[k]; k++) {
        size_t l = strlen(kw[k]);
        if (i + l < len && !strncmp(line + i, kw[k], l) && (line[i + l] == ' ' || line[i + l] == '\t'))
            return 1;
        if (i + l == len && !strncmp(line + i, kw[k], l))
            return 1;
    }
    return 0;
}

static int service_name_is(const char *line, size_t len, const char *name)
{
    size_t i = 0;
    while (i < len && (line[i] == ' ' || line[i] == '\t'))
        i++;
    if (len - i < 8 || strncmp(line + i, "service", 7) || (line[i + 7] != ' ' && line[i + 7] != '\t'))
        return 0;
    i += 7;
    while (i < len && (line[i] == ' ' || line[i] == '\t'))
        i++;
    size_t s = i;
    while (i < len && line[i] != ' ' && line[i] != '\t' && line[i] != '\r')
        i++;
    return i - s == strlen(name) && !strncmp(line + s, name, i - s);
}

static int line_is_word(const char *line, size_t len, const char *word)
{
    size_t i = 0, e = len;
    while (i < len && isspace((unsigned char)line[i]))
        i++;
    while (e > i && isspace((unsigned char)line[e - 1]))
        e--;
    return e - i == strlen(word) && !strncmp(line + i, word, e - i);
}

static int continues(const char *line, size_t len)
{
    while (len && (line[len - 1] == '\r' || line[len - 1] == ' ' || line[len - 1] == '\t'))
        len--;
    return len && line[len - 1] == '\\';
}

static int disable_in_text(const char *text, size_t len, const char *name, buf_t *out, int *already)
{
    int hits = 0;
    size_t i = 0;
    *already = 0;
    while (i < len) {
        const char *nl = memchr(text + i, '\n', len - i);
        size_t ll = nl ? (size_t)(nl - (text + i)) : len - i;
        const char *line = text + i;
        buf_put(out, line, ll);
        if (nl)
            buf_putc(out, '\n');
        i += ll + (nl ? 1 : 0);
        if (!service_name_is(line, ll, name))
            continue;
        while (continues(line, ll) && i < len) {
            const char *nl2 = memchr(text + i, '\n', len - i);
            size_t l2 = nl2 ? (size_t)(nl2 - (text + i)) : len - i;
            buf_put(out, text + i, l2);
            if (nl2)
                buf_putc(out, '\n');
            line = text + i;
            ll = l2;
            i += l2 + (nl2 ? 1 : 0);
        }
        size_t j = i;
        int has = 0;
        while (j < len) {
            const char *nl3 = memchr(text + j, '\n', len - j);
            size_t l3 = nl3 ? (size_t)(nl3 - (text + j)) : len - j;
            if (is_section(text + j, l3))
                break;
            if (line_is_word(text + j, l3, "disabled"))
                has = 1;
            j += l3 + (nl3 ? 1 : 0);
        }
        if (has) {
            *already = 1;
        } else {
            if (!nl && out->len && out->data[out->len - 1] != '\n')
                buf_putc(out, '\n');
            buf_puts(out, "    disabled\n");
            hits++;
        }
    }
    return hits;
}

int disable_service(rom_t *rom, const char *name, int quiet)
{
    nodelist l = {0};
    gather_rc(rom, &l);
    int total = 0, already = 0;
    for (size_t i = 0; i < l.n; i++) {
        buf_t b = {0};
        if (vfs_read_all(l.v[i], &b, 8u << 20) < 0) {
            buf_free(&b);
            continue;
        }
        buf_t out = {0};
        int al = 0;
        int hits = disable_in_text((const char *)b.data, b.len, name, &out, &al);
        already |= al;
        buf_free(&b);
        if (hits) {
            if (!out.data)
                buf_reserve(&out, 0);
            replace_text(l.v[i], (char *)buf_steal(&out, NULL));
            change("%s: service %s disabled", l.paths[i], name);
            total += hits;
        } else {
            buf_free(&out);
        }
    }
    if (!quiet && !total && already)
        note("  - service %s is already disabled", name);
    else if (!quiet && !total)
        warn("service %s not found in any init script", name);
    nl_free(&l);
    return total;
}
