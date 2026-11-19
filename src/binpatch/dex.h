#ifndef AEP_DEX_H
#define AEP_DEX_H

#include <stddef.h>

#include "core/util.h"

int dex_stub_void_method(unsigned char *dex, size_t len, const char *class_desc, const char *method, char *err,
                         size_t errlen);
void dex_fix_checksums(unsigned char *dex, size_t len);
int jar_stub_void_method(buf_t *jar, const char *class_desc, const char *method, char *err, size_t errlen);

#endif
