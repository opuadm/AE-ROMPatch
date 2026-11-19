#ifndef AEP_PATCH_H
#define AEP_PATCH_H

#include "core/util.h"
#include "rom/rom.h"

#define PATCH_MAX 32

typedef struct {
    int enabled[PATCH_MAX];
    strvec set_props;
    strvec del_props;
    strvec disable_services;
    strvec remove_paths;
    strvec remove_apps;
    int density;
} patch_opts;

typedef enum {
    STAGE_CLEANUP,
    STAGE_FIXES,
    STAGE_FINISH,
} patch_stage;

typedef void (*patch_fn)(rom_t *rom, const patch_opts *opts);

typedef struct {
    const char *name;
    int default_on;
    patch_stage stage;
    patch_fn apply;
    const char *summary;
} patch_desc;

extern const patch_desc PATCHES[];

void patch_opts_init(patch_opts *o);
void patch_opts_free(patch_opts *o);
int patch_index(const char *name);
unsigned patch_apply(rom_t *rom, const patch_opts *o);

#endif
