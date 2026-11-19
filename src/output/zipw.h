#ifndef AEP_ZIPW_H
#define AEP_ZIPW_H

#include <stdint.h>

#include "formats/zipr.h"

typedef struct zipw zipw;

zipw *zipw_open(const char *path, int level);
int zipw_dir(zipw *w, const char *name, uint32_t mode, int64_t mtime);
int zipw_symlink(zipw *w, const char *name, const char *target, int64_t mtime);
int zipw_file_begin(zipw *w, const char *name, uint64_t size, uint32_t mode, int64_t mtime, int compress);
int zipw_write(zipw *w, const void *data, size_t len);
int zipw_file_end(zipw *w);
int zipw_raw_copy(zipw *w, zipr *src, zip_entry *e, const char *name);
int zipw_close(zipw *w);
uint64_t zipw_bytes(const zipw *w);

#endif
