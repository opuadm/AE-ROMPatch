#ifndef AEP_EXT4_H
#define AEP_EXT4_H

#include <stddef.h>
#include <stdint.h>

#include "core/rsrc.h"
#include "core/util.h"

#define EXT4_ROOT_INO 2

typedef struct ext4 ext4;

typedef struct {
    uint32_t ino;
    uint16_t mode;
    uint32_t uid, gid;
    uint64_t size;
    uint32_t flags;
    int64_t mtime;
    int encrypted;
} ext4_stat_t;

typedef int (*ext4_dir_cb)(void *ctx, const char *name, size_t namelen, uint32_t ino, uint8_t ftype);

int ext4_probe(rsrc *src);
ext4 *ext4_open(rsrc *src, char *err, size_t errlen);
void ext4_close(ext4 *fs);
const char *ext4_name(ext4 *fs);

int ext4_stat(ext4 *fs, uint32_t ino, ext4_stat_t *st);
int ext4_readdir(ext4 *fs, uint32_t ino, ext4_dir_cb cb, void *ctx);
int ext4_readlink(ext4 *fs, uint32_t ino, char **out);
int ext4_read(ext4 *fs, uint32_t ino, uint64_t off, void *buf, size_t len);
int ext4_lookup(ext4 *fs, const char *path, uint32_t *ino);

#endif
