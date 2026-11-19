#ifndef AEP_OTA_H
#define AEP_OTA_H

#include <stddef.h>
#include <stdint.h>

#include "core/rsrc.h"

typedef long (*seq_read_fn)(void *ctx, void *buf, size_t len);

rsrc *ota_from_dat(const char *list, size_t list_len, seq_read_fn rd, void *ctx, int brotli, const char *label,
                   char *err, size_t errlen);

typedef struct payload payload;

payload *payload_open(rsrc *src, char *err, size_t errlen);
size_t payload_count(const payload *p);
const char *payload_name(const payload *p, size_t i);
uint64_t payload_size(const payload *p, size_t i);
rsrc *payload_extract(payload *p, size_t i, char *err, size_t errlen);
void payload_close(payload *p);

const char *ota_codecs(void);

#endif
