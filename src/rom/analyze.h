#ifndef AEP_ANALYZE_H
#define AEP_ANALYZE_H

#include "core/props.h"
#include "rom/rom.h"
#include "rom/sim.h"

enum { SEV_OK, SEV_INFO, SEV_WARN, SEV_ERROR };

typedef struct {
    int sev;
    char *text;
} finding;

typedef struct {
    proplist props;
    int api;
    const char *release;
    char brand[128];
    char model[128];
    char skin[128];
    const char *abi;
    char arch[48];
    int arch_supported;
    int rc_files;
    int has_init_rc;
    int bcp_in_rc;
    int treble;
    char banner[256];
    sim_info sim;
    uint64_t files, dirs, links, bytes;
    finding *f;
    size_t nf, capf;
} rom_info;

void analyze_rom(rom_t *rom, rom_info *info);
void analyze_print(const rom_t *rom, const rom_info *info);
void analyze_free(rom_info *info);
int effective_api(const char *sdk, const char *codename, const char *release);

#endif
