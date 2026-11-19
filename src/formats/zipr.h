#ifndef AEP_ZIPR_H
#define AEP_ZIPR_H

#include <stddef.h>
#include <stdint.h>

#include "core/rsrc.h"
#include "core/util.h"

typedef struct {
    char *name;
    uint16_t method;
    uint16_t flags;
    uint16_t made_by;
    uint32_t crc;
    uint64_t csize, usize;
    uint64_t lho;
    uint64_t data_off;
    uint32_t ext_attr;
    uint16_t dos_time, dos_date;
} zip_entry;

typedef struct zipr {
    rsrc *src;
    char *path;
    zip_entry *e;
    size_t n;
} zipr;

zipr *zipr_open(const char *path, char *err, size_t errlen);
zipr *zipr_open_rsrc(rsrc *src, const char *label, char *err, size_t errlen);
void zipr_close(zipr *z);
int zipr_probe(const char *path);

int zip_entry_is_dir(const zip_entry *e);
int zip_entry_is_symlink(const zip_entry *e);
uint32_t zip_entry_mode(const zip_entry *e);

int zipr_data_offset(zipr *z, zip_entry *e);
int zipr_read_all(zipr *z, zip_entry *e, buf_t *out, size_t limit);
rsrc *zipr_open_entry(zipr *z, zip_entry *e);

typedef struct zstream zstream;
zstream *zstream_open(zipr *z, zip_entry *e);
long zstream_read(zstream *s, void *buf, size_t len);
void zstream_close(zstream *s);

rsrc *rsrc_open_slice(rsrc *base, uint64_t off, uint64_t size, const char *name);

#endif
