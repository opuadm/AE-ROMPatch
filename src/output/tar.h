#ifndef AEP_TAR_H
#define AEP_TAR_H

#include <stdint.h>
#include <stdio.h>

typedef struct tarw tarw;

tarw *tarw_open(const char *path, int gzip_level);
tarw *tarw_open_fp(FILE *fp);
int tarw_dir(tarw *t, const char *name, uint32_t mode, uint32_t uid, uint32_t gid, int64_t mtime);
int tarw_symlink(tarw *t, const char *name, const char *target, uint32_t mode, uint32_t uid, uint32_t gid,
                 int64_t mtime);
int tarw_file_begin(tarw *t, const char *name, uint64_t size, uint32_t mode, uint32_t uid, uint32_t gid,
                    int64_t mtime);
int tarw_write(tarw *t, const void *data, size_t len);
int tarw_file_end(tarw *t);
int tarw_close(tarw *t);
uint64_t tarw_bytes(const tarw *t);

#endif
