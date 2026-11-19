#ifndef AEP_PROPS_H
#define AEP_PROPS_H

#include <stddef.h>

#include "core/vfs.h"

typedef struct {
    char *key, *val;
} prop_t;

typedef struct {
    prop_t *v;
    size_t n, cap;
} proplist;

void props_parse(const char *text, size_t len, proplist *out);
void props_merge(proplist *dst, const proplist *src, int keep_ro);
void props_set_default(proplist *dst, const char *key, const char *val);
const char *props_get(const proplist *p, const char *key);
void props_free(proplist *p);

char *props_text_set(const char *text, size_t len, const char *key, const char *val, int *changed);
char *props_text_del(const char *text, size_t len, const char *key, int *changed);
int props_text_has(const char *text, size_t len, const char *key);

extern const char *const PROP_FILES[];

void props_collect(vnode *root, proplist *out);

#endif
