#ifndef AEP_VFS_H
#define AEP_VFS_H

#include <stddef.h>
#include <stdint.h>

#include "formats/erofs.h"
#include "formats/ext4.h"
#include "core/util.h"
#include "formats/zipr.h"

enum { VN_DIR = 1, VN_FILE, VN_LINK };
enum { VS_NONE = 0, VS_MEM, VS_HOST, VS_EXT4, VS_ZIP, VS_EROFS };

typedef struct vnode vnode;

struct vnode {
    char *name;
    vnode *parent;
    vnode **kids;
    size_t nkids, capkids;
    int type;
    uint32_t mode, uid, gid;
    int64_t mtime;
    char *link;
    uint64_t size;
    int src;
    unsigned char *mem;
    char *host;
    ext4 *fs;
    uint32_t ino;
    zipr *zip;
    erofs *efs;
    uint64_t enid;
    zip_entry *zentry;
    const char *origin;
};

typedef int (*vfs_walk_cb)(vnode *n, const char *path, void *ctx);

vnode *vfs_new_root(void);
void vfs_free(vnode *n);
vnode *vfs_child(vnode *dir, const char *name);
vnode *vfs_lookup(vnode *root, const char *path);
vnode *vfs_resolve(vnode *root, const char *path);
vnode *vfs_mkdirs(vnode *root, const char *path, uint32_t mode);
vnode *vfs_put(vnode *dir, const char *name, int type);
void vfs_remove(vnode *n);
char *vfs_path(vnode *n);
void vfs_set_mem(vnode *n, unsigned char *data, size_t len);
int vfs_read_all(vnode *n, buf_t *out, size_t limit);
int vfs_read(vnode *n, uint64_t off, void *buf, size_t len, void **handle);
void vfs_read_done(vnode *n, void **handle);
int vfs_walk(vnode *root, vfs_walk_cb cb, void *ctx);
void vfs_sort(vnode *root);
void vfs_count(vnode *root, uint64_t *files, uint64_t *dirs, uint64_t *links, uint64_t *bytes);
vnode *vfs_write_text(vnode *root, const char *path, const char *text, size_t len, uint32_t mode);

#endif
