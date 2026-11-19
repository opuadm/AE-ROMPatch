#ifndef AEP_PATCHES_PATCHES_H
#define AEP_PATCHES_PATCHES_H

#include "patches/patch.h"

void patch_sanitize(rom_t *rom, const patch_opts *opts);
void patch_strip_data(rom_t *rom, const patch_opts *opts);
void patch_etc_alias(rom_t *rom, const patch_opts *opts);

void patch_sim(rom_t *rom, const patch_opts *opts);
void patch_gsm_modem(rom_t *rom, const patch_opts *opts);
void patch_single_sim(rom_t *rom, const patch_opts *opts);
void patch_dual_sim(rom_t *rom, const patch_opts *opts);
void patch_apn(rom_t *rom, const patch_opts *opts);

void patch_crash_guards(rom_t *rom, const patch_opts *opts);
void patch_no_hcm(rom_t *rom, const patch_opts *opts);

void patch_fake_battery(rom_t *rom, const patch_opts *opts);
void patch_oem_health(rom_t *rom, const patch_opts *opts);

void patch_exynos_gralloc(rom_t *rom, const patch_opts *opts);
void patch_fixed_resolution(rom_t *rom, const patch_opts *opts);
void patch_no_bootanim(rom_t *rom, const patch_opts *opts);

void patch_sensor_multihal(rom_t *rom, const patch_opts *opts);
void patch_sensor_hal(rom_t *rom, const patch_opts *opts);
void patch_sensor_retry(rom_t *rom, const patch_opts *opts);

void remove_path(rom_t *rom, const char *pattern);
void remove_app(rom_t *rom, const char *name);

#endif
