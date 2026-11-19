#ifndef AEP_CPIO_H
#define AEP_CPIO_H

#include <stddef.h>
#include <stdint.h>

#include "core/util.h"

typedef struct {
    char *name;
    uint32_t mode, uid, gid;
    int64_t mtime;
    unsigned char *data;
    size_t size;
} cpio_entry;

typedef struct {
    cpio_entry *e;
    size_t n, cap;
} cpio_list;

int cpio_parse(const unsigned char *d, size_t len, cpio_list *out, char *err, size_t errlen);
void cpio_free(cpio_list *l);
const cpio_entry *cpio_find(const cpio_list *l, const char *name);

void cpio_write_entry(buf_t *out, uint32_t ino, const char *name, uint32_t mode, uint32_t uid, uint32_t gid,
                      int64_t mtime, const void *data, size_t size);
void cpio_write_trailer(buf_t *out, uint32_t ino);

#endif
