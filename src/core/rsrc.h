#ifndef AEP_RSRC_H
#define AEP_RSRC_H

#include <stddef.h>
#include <stdint.h>

typedef struct rsrc rsrc;

struct rsrc {
    uint64_t size;
    char *name;
    int (*pread)(rsrc *s, void *buf, size_t len, uint64_t off);
    void (*close)(rsrc *s);
    void *priv;
};

rsrc *rsrc_open_file(const char *path);
rsrc *rsrc_open_fd(int fd, const char *name);
int temp_fd(void);
void temp_dir_default(const char *dir);
const char *temp_dir(void);
rsrc *rsrc_open_mem(const unsigned char *data, size_t len, const char *name);
rsrc *rsrc_open_sparse(rsrc *base);
rsrc *rsrc_open_auto(const char *path);
int rsrc_read(rsrc *s, void *buf, size_t len, uint64_t off);
void rsrc_close(rsrc *s);

int sparse_probe(rsrc *s);

#endif
