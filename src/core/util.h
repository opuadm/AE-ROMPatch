#ifndef AEP_UTIL_H
#define AEP_UTIL_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int g_verbose;
extern int g_quiet;
extern unsigned g_warnings;

#if defined(__GNUC__)
#define AEP_NORETURN __attribute__((noreturn))
#define AEP_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define AEP_NORETURN
#define AEP_PRINTF(a, b)
#endif

AEP_NORETURN void die(const char *fmt, ...) AEP_PRINTF(1, 2);
void warn(const char *fmt, ...) AEP_PRINTF(1, 2);
void note(const char *fmt, ...) AEP_PRINTF(1, 2);
void debug(const char *fmt, ...) AEP_PRINTF(1, 2);
void blank(void);
int progress_enabled(void);
void progress_show(int force, const char *fmt, ...) AEP_PRINTF(2, 3);
void progress_clear(void);

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t m);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);
char *xasprintf(const char *fmt, ...) AEP_PRINTF(1, 2);

typedef struct {
    unsigned char *data;
    size_t len, cap;
} buf_t;

void buf_reserve(buf_t *b, size_t extra);
void buf_put(buf_t *b, const void *p, size_t n);
void buf_putc(buf_t *b, int c);
void buf_puts(buf_t *b, const char *s);
void buf_printf(buf_t *b, const char *fmt, ...) AEP_PRINTF(2, 3);
void buf_free(buf_t *b);
unsigned char *buf_steal(buf_t *b, size_t *len);

typedef struct {
    char **v;
    size_t n, cap;
} strvec;

void strvec_push(strvec *sv, const char *s);
void strvec_free(strvec *sv);
int strvec_has(const strvec *sv, const char *s);

int read_file(const char *path, buf_t *out, size_t limit);

uint16_t le16(const void *p);
uint32_t le32(const void *p);
uint64_t le64(const void *p);
void put_le32(void *p, uint32_t v);

int starts_with(const char *s, const char *prefix);
int ends_with(const char *s, const char *suffix);
int ends_with_ci(const char *s, const char *suffix);

char *path_join(const char *a, const char *b);
char *path_normalize(const char *abs_path);
char *path_dirname(const char *p);
const char *path_basename(const char *p);
char *path_relative(const char *from_dir, const char *to);

int is_dir(const char *path);
int is_file(const char *path);

const char *human_size(uint64_t n, char *buf, size_t len);

#endif
