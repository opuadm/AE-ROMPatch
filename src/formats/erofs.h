#ifndef AEP_EROFS_H
#define AEP_EROFS_H

#include <stddef.h>
#include <stdint.h>

#include "core/rsrc.h"

typedef struct erofs erofs;
typedef struct efile efile;

typedef struct {
    uint64_t nid;
    uint16_t mode;
    uint32_t uid, gid;
    uint64_t size;
    int64_t mtime;
    int layout;
} erofs_stat_t;

typedef int (*erofs_dir_cb)(void *ctx, const char *name, size_t namelen, uint64_t nid, uint8_t ftype);

int erofs_probe(rsrc *src);
erofs *erofs_open(rsrc *src, char *err, size_t errlen);
void erofs_close(erofs *fs);
uint64_t erofs_root(erofs *fs);
int erofs_stat(erofs *fs, uint64_t nid, erofs_stat_t *st);
int erofs_readdir(erofs *fs, uint64_t nid, erofs_dir_cb cb, void *ctx);
int erofs_readlink(erofs *fs, uint64_t nid, char **out);
int erofs_lookup(erofs *fs, const char *path, uint64_t *nid);
const char *erofs_error(erofs *fs);

efile *efile_open(erofs *fs, uint64_t nid);
int efile_read(efile *f, uint64_t off, void *buf, size_t len);
void efile_close(efile *f);

#endif
