#ifndef AEP_BOOTIMG_H
#define AEP_BOOTIMG_H

#include <stddef.h>
#include <stdint.h>

#include "core/util.h"

typedef struct {
    int header_version;
    uint32_t page_size;
    uint32_t kernel_addr, ramdisk_addr, second_addr, tags_addr;
    uint32_t os_version;
    char name[17];
    char cmdline[1536 + 1];
    unsigned char *kernel;
    size_t kernel_size;
    unsigned char *ramdisk;
    size_t ramdisk_size;
    int mtk_header;
    int htc_signed;
} bootimg;

int bootimg_probe(const unsigned char *d, size_t len);
int bootimg_parse(const unsigned char *d, size_t len, bootimg *out, char *err, size_t errlen);
void bootimg_free(bootimg *b);
void bootimg_build_v0(const bootimg *tmpl, const unsigned char *kernel, size_t kernel_size,
                      const unsigned char *ramdisk, size_t ramdisk_size, buf_t *out);
const char *bootimg_kernel_banner(const bootimg *b, char *buf, size_t len);

#endif
