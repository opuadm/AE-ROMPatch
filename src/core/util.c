#include "core/about.h"
#include "core/util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int g_verbose = 0;
int g_quiet = 0;
unsigned g_warnings = 0;

static int g_progress_shown;
static int g_progress_tty = -1;
static double g_progress_last;

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

int progress_enabled(void)
{
    if (g_progress_tty < 0)
        g_progress_tty = isatty(2) && isatty(1);
    return g_progress_tty && !g_quiet;
}

void progress_show(int force, const char *fmt, ...)
{
    if (!progress_enabled())
        return;
    double t = now_seconds();
    if (!force && g_progress_shown && t - g_progress_last < 0.1)
        return;
    g_progress_last = t;
    va_list ap;
    fflush(stdout);
    fputs("\r\033[K", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
    g_progress_shown = 1;
}

void progress_clear(void)
{
    if (!g_progress_shown)
        return;
    fputs("\r\033[K", stderr);
    fflush(stderr);
    g_progress_shown = 0;
}

void die(const char *fmt, ...)
{
    va_list ap;
    progress_clear();
    fflush(stdout);
    fputs(AEP_BIN ": error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

void warn(const char *fmt, ...)
{
    va_list ap;
    g_warnings++;
    progress_clear();
    fflush(stdout);
    fputs(AEP_BIN ": warning: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void note(const char *fmt, ...)
{
    va_list ap;
    if (g_quiet)
        return;
    progress_clear();
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
}

void debug(const char *fmt, ...)
{
    va_list ap;
    if (!g_verbose)
        return;
    progress_clear();
    fflush(stdout);
    fputs("  . ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        die("out of memory (%zu bytes)", n);
    return p;
}

void *xcalloc(size_t n, size_t m)
{
    void *p = calloc(n ? n : 1, m ? m : 1);
    if (!p)
        die("out of memory");
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q)
        die("out of memory (%zu bytes)", n);
    return q;
}

char *xstrdup(const char *s)
{
    return xstrndup(s, strlen(s));
}

char *xstrndup(const char *s, size_t n)
{
    char *p = xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

char *xasprintf(const char *fmt, ...)
{
    va_list ap, ap2;
    int n;
    char *p;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        die("formatting failed");
    p = xmalloc((size_t)n + 1);
    vsnprintf(p, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return p;
}

void buf_reserve(buf_t *b, size_t extra)
{
    size_t want = b->len + extra + 1;
    if (want <= b->cap)
        return;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < want)
        cap *= 2;
    b->data = xrealloc(b->data, cap);
    b->cap = cap;
}

void buf_put(buf_t *b, const void *p, size_t n)
{
    buf_reserve(b, n);
    if (n)
        memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = 0;
}

void buf_putc(buf_t *b, int c)
{
    unsigned char ch = (unsigned char)c;
    buf_put(b, &ch, 1);
}

void buf_puts(buf_t *b, const char *s)
{
    buf_put(b, s, strlen(s));
}

void buf_printf(buf_t *b, const char *fmt, ...)
{
    va_list ap, ap2;
    int n;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        die("formatting failed");
    buf_reserve(b, (size_t)n);
    vsnprintf((char *)b->data + b->len, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
}

void buf_free(buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

unsigned char *buf_steal(buf_t *b, size_t *len)
{
    unsigned char *p = b->data;
    if (!p)
        p = xcalloc(1, 1);
    if (len)
        *len = b->len;
    b->data = NULL;
    b->len = b->cap = 0;
    return p;
}

void strvec_push(strvec *sv, const char *s)
{
    if (sv->n == sv->cap) {
        sv->cap = sv->cap ? sv->cap * 2 : 8;
        sv->v = xrealloc(sv->v, sv->cap * sizeof(char *));
    }
    sv->v[sv->n++] = xstrdup(s);
}

void strvec_free(strvec *sv)
{
    for (size_t i = 0; i < sv->n; i++)
        free(sv->v[i]);
    free(sv->v);
    sv->v = NULL;
    sv->n = sv->cap = 0;
}

int strvec_has(const strvec *sv, const char *s)
{
    for (size_t i = 0; i < sv->n; i++)
        if (!strcmp(sv->v[i], s))
            return 1;
    return 0;
}

int read_file(const char *path, buf_t *out, size_t limit)
{
    FILE *f = fopen(path, "rb");
    unsigned char tmp[65536];
    size_t n;
    if (!f)
        return -1;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0) {
        if (limit && out->len + n > limit) {
            fclose(f);
            errno = EFBIG;
            return -1;
        }
        buf_put(out, tmp, n);
    }
    if (ferror(f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    if (!out->data)
        buf_reserve(out, 0);
    return 0;
}

uint16_t le16(const void *p)
{
    const unsigned char *b = p;
    return (uint16_t)(b[0] | (b[1] << 8));
}

uint32_t le32(const void *p)
{
    const unsigned char *b = p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

uint64_t le64(const void *p)
{
    const unsigned char *b = p;
    return (uint64_t)le32(b) | ((uint64_t)le32(b + 4) << 32);
}

void put_le32(void *p, uint32_t v)
{
    unsigned char *b = p;
    b[0] = (unsigned char)v;
    b[1] = (unsigned char)(v >> 8);
    b[2] = (unsigned char)(v >> 16);
    b[3] = (unsigned char)(v >> 24);
}

int starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

int ends_with(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && !strcmp(s + a - b, suffix);
}

int ends_with_ci(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && !strcasecmp(s + a - b, suffix);
}

char *path_join(const char *a, const char *b)
{
    size_t la = strlen(a);
    if (la && a[la - 1] == '/')
        return xasprintf("%s%s", a, b[0] == '/' ? b + 1 : b);
    return xasprintf("%s/%s", a, b[0] == '/' ? b + 1 : b);
}

char *path_normalize(const char *p)
{
    size_t n = strlen(p);
    char *out = xmalloc(n + 2);
    size_t *marks = xmalloc((n + 2) * sizeof(size_t));
    size_t depth = 0, o = 0;
    const char *s = p;
    out[o++] = '/';
    while (*s) {
        while (*s == '/')
            s++;
        if (!*s)
            break;
        const char *e = strchr(s, '/');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        if (len == 1 && s[0] == '.') {
        } else if (len == 2 && s[0] == '.' && s[1] == '.') {
            if (depth == 0) {
                free(out);
                free(marks);
                return NULL;
            }
            o = marks[--depth];
        } else {
            marks[depth++] = o;
            if (o > 1)
                out[o++] = '/';
            memcpy(out + o, s, len);
            o += len;
        }
        s += len;
    }
    out[o] = 0;
    free(marks);
    return out;
}

char *path_dirname(const char *p)
{
    const char *s = strrchr(p, '/');
    if (!s)
        return xstrdup(".");
    if (s == p)
        return xstrdup("/");
    return xstrndup(p, (size_t)(s - p));
}

const char *path_basename(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

char *path_relative(const char *from_dir, const char *to)
{
    const char *a = from_dir, *b = to;
    size_t common = 0, i = 0;
    buf_t out = {0};
    while (a[i] && b[i] && a[i] == b[i]) {
        if (a[i] == '/')
            common = i;
        i++;
    }
    if (!a[i] && (b[i] == '/' || !b[i]))
        common = i;
    else if (!b[i] && a[i] == '/')
        common = i;
    const char *rest_a = a + common;
    const char *rest_b = b + common;
    while (*rest_a) {
        while (*rest_a == '/')
            rest_a++;
        if (!*rest_a)
            break;
        buf_puts(&out, out.len ? "/.." : "..");
        while (*rest_a && *rest_a != '/')
            rest_a++;
    }
    while (*rest_b == '/')
        rest_b++;
    if (*rest_b) {
        if (out.len)
            buf_putc(&out, '/');
        buf_puts(&out, rest_b);
    }
    if (!out.len)
        buf_puts(&out, ".");
    return (char *)buf_steal(&out, NULL);
}

int is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int is_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

const char *human_size(uint64_t n, char *buf, size_t len)
{
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = (double)n;
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        u++;
    }
    if (u == 0)
        snprintf(buf, len, "%llu B", (unsigned long long)n);
    else
        snprintf(buf, len, "%.1f %s", v, units[u]);
    return buf;
}

void blank(void)
{
    progress_clear();
    if (!g_quiet)
        fputc('\n', stdout);
}
