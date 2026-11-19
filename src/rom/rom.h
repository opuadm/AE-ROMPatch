#ifndef AEP_ROM_H
#define AEP_ROM_H

#include "formats/bootimg.h"
#include "formats/cpio.h"
#include "formats/ext4.h"
#include "core/util.h"
#include "core/vfs.h"
#include "formats/zipr.h"

typedef enum {
    ROLE_AUTO = 0,
    ROLE_ROOT,
    ROLE_SYSTEM,
    ROLE_PRODUCT,
    ROLE_SYSTEM_EXT,
    ROLE_VENDOR,
    ROLE_ODM,
    ROLE_OEM,
    ROLE_EXTRA,
    ROLE_BOOT,
    ROLE_RAMDISK,
    ROLE_ZIP,
    ROLE_TAR,
    ROLE_SUPER,
    ROLE_OZIP,
    ROLE_PAYLOAD,
    ROLE_SKIP,
    ROLE_UNKNOWN
} role_t;

typedef struct {
    role_t role;
    char *path;
    char *extra;
} rom_input;

typedef struct {
    vnode *root;
    rom_input *inputs;
    size_t ninputs, capinputs;

    int sar;
    int have_system;
    int have_vendor;
    int have_boot;
    bootimg boot;
    buf_t boot_raw;
    char *boot_source;
    int boot_ramdisk_recovery;
    int boot_ramdisk_codec;
    cpio_list ramdisk;
    int have_ramdisk;
    char *ramdisk_source;

    ext4 **fss;
    size_t nfs;
    erofs **efss;
    size_t nefs;
    rsrc **srcs;
    size_t nsrcs;
    zipr **zips;
    size_t nzips;
    zipr *pass_zip[8];
    zip_entry *pass_entry[8];
    size_t npass;
    int from_zip;
    strvec loaded;
    unsigned encrypted;
    unsigned special_skipped;
    unsigned ozip_members;
} rom_t;

const char *role_name(role_t r);
role_t role_parse(const char *s);

void rom_init(rom_t *rom);
void rom_free(rom_t *rom);
void rom_add(rom_t *rom, role_t role, const char *path, const char *extra);
void rom_load(rom_t *rom);

#endif
