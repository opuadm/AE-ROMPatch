#ifndef AEP_EMIT_H
#define AEP_EMIT_H

#include "rom/rom.h"

typedef struct {
    const char *output;
    int zip;
    int level;
    int force_new_boot;
} emit_opts;

int emit_rom(rom_t *rom, const emit_opts *o);

#endif
