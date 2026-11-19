#ifndef AEP_OZIP_H
#define AEP_OZIP_H

#include <stddef.h>

#include "core/rsrc.h"

typedef enum { OZIP_WHOLE, OZIP_MEMBER, OZIP_SEGMENTED } ozip_kind;

int ozip_is_encrypted(rsrc *s);
int ozip_head_is_encrypted(const unsigned char *h, size_t n);
int ozip_find_key(rsrc *s, ozip_kind kind);
int ozip_have_key(void);
rsrc *ozip_open(rsrc *base, ozip_kind kind, const char *label, char *err, size_t errlen);

#endif
