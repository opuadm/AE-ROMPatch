#include "patches/patch.h"

#include <stdlib.h>
#include <string.h>

#include "core/util.h"
#include "patches/patches.h"
#include "patches/support.h"

const patch_desc PATCHES[] = {
    {"sanitize", 1, STAGE_CLEANUP, patch_sanitize,
     "drop entries that make the AEmulator Plus importer abort (backslash names, empty or escaping symlinks)"},
    {"etc-alias", 0, STAGE_FINISH, patch_etc_alias,
     "add the /etc -> /system/etc link to the ramdisk (AEmulator adds it itself on import; only for unusual setups)"},
    {"strip-data", 1, STAGE_CLEANUP, patch_strip_data,
     "leave out /data and /cache of root-tree dumps (stale dalvik-cache and user data break the first boot)"},
    {"sim", 1, STAGE_FIXES, patch_sim,
     "make the SIM work with AEmulator's modem: drop custom-ROM RIL classes (ro.telephony.ril_class / ril.config) that misread its replies"},
    {"gsm-modem", 1, STAGE_FIXES, patch_gsm_modem,
     "on LTE-on-CDMA builds (telephony.lteOnCdmaDevice=1, e.g. China-market phones) use AEmulator's GSM modem: clears the flag and a CDMA default network mode"},
    {"single-sim", 1, STAGE_FIXES, patch_single_sim,
     "on dual-SIM ROMs, switch to one SIM slot (AEmulator's modem answers on one socket only) so SIM 1 registers cleanly"},
    {"dual-sim", 0, STAGE_FIXES, patch_dual_sim,
     "keep or turn on both SIM slots on ROMs built for dual SIM (overrides single-sim; see the note it prints)"},
    {"apn", 1, STAGE_FIXES, patch_apn,
     "add internet APNs for every operator preset of AEmulator's SIM settings, so mobile data works with any of them"},
    {"crash-guards", 1, STAGE_FIXES, patch_crash_guards,
     "neutralise known system_server crash sites under AEmulator (e.g. MIUI's USB-share receiver that dies when USB/charging is unplugged); run 'aerompatch patches' -v for the list"},
    {"fake-battery", 0, STAGE_FIXES, patch_fake_battery,
     "set ro.boot.fake_battery=1 when the ROM's healthd / health HAL supports it: the battery then reads a fixed 42% (it no longer follows the host or the level set in AEmulator Plus); a workaround for guests that read 0% and shut down at boot"},
    {"no-bootanim", 0, STAGE_FIXES, patch_no_bootanim,
     "set debug.sf.nobootanimation=1 so SurfaceFlinger never starts the boot animation"},
    {"oem-health", 1, STAGE_FIXES, patch_oem_health,
     "on Android 9+ ROMs with an OEM health HAL (e.g. Samsung's vendor.samsung.hardware.exthealth), declare it again in /odm/etc/vintf/manifest.xml: AEmulator Plus swaps the vendor HAL manifest for its own, and the OEM BatteryService then finds no health service and system_server dies"},
    {"exynos-gralloc", 1, STAGE_FIXES, patch_exynos_gralloc,
     "Samsung Exynos ROMs: Samsung's arm64 libgui.so takes every queued buffer for an Exynos gralloc one and writes through a null pointer when it is not (SurfaceFlinger dies on the first frame under AEmulator's gralloc); that write is skipped for foreign buffers"},
    {"sensor-multihal", 1, STAGE_FIXES, patch_sensor_multihal,
     "Android 8.0+: a sensors/hals.conf turns the sensors HAL into a multihal that loads the board's own sensor drivers (no sensor hardware under AEmulator; the sensors service dies and system_server aborts); removing it makes the HAL load AEmulator's sensors.default.so"},
    {"sensor-hal", 1, STAGE_FIXES, patch_sensor_hal,
     "Android 8.0+ arm64: ships its own sensors module (/odm/lib64/hw/sensors.aerompatch.so, picked by ro.hardware.sensors) with AEmulator's accelerometer, whose poll returns at least every 200 ms; AEmulator's module blocks until a reading arrives for the sensors service, so a poll never hangs and the service keeps running"},
    {"sensor-retry", 1, STAGE_FIXES, patch_sensor_retry,
     "Android 8.0+ arm64: system_server's SensorService aborts (and takes zygote down) after 50 failed sensor polls in a row; any other failed call to the sensors service (activate, batch, ...) aborts it at once; under AEmulator its connection to the sensors service can break while both stay alive, so the polls are retried once a second and the other calls count as done (sensors stop, the system keeps running)"},
    {"fixed-resolution", 1, STAGE_FIXES, patch_fixed_resolution,
     "Samsung floating_feature.xml: drop SEC_FLOATING_FEATURE_COMMON_CONFIG_DYN_RESOLUTION_CONTROL (the \"Screen resolution\" WQHD+/FHD+/HD+ switch); with it the system forces its own lower resolution over the one set in AEmulator Plus, so the picture is rendered smaller, upscaled (blurry) and does not follow the chosen size"},
    {"no-hcm", 1, STAGE_FIXES, patch_no_hcm,
     "Samsung Android 9+: remove /system/framework/hcm.jar (the HCM health-monitor service, which SystemServer skips when the jar is missing); it reads the battery over HIDL at BOOT_COMPLETED and one failed call there (\"HwBinder Error: (-32)\") throws inside system_server and kills the whole framework"},
    {NULL, 0, STAGE_FIXES, NULL, NULL},
};

void patch_opts_init(patch_opts *o)
{
    memset(o, 0, sizeof *o);
    for (int i = 0; PATCHES[i].name; i++)
        o->enabled[i] = PATCHES[i].default_on;
}

void patch_opts_free(patch_opts *o)
{
    strvec_free(&o->set_props);
    strvec_free(&o->del_props);
    strvec_free(&o->disable_services);
    strvec_free(&o->remove_paths);
    strvec_free(&o->remove_apps);
}

int patch_index(const char *name)
{
    for (int i = 0; PATCHES[i].name; i++)
        if (!strcmp(PATCHES[i].name, name))
            return i;
    return -1;
}

static void apply_user_removals(rom_t *rom, const patch_opts *o)
{
    for (size_t i = 0; i < o->remove_apps.n; i++)
        remove_app(rom, o->remove_apps.v[i]);
    for (size_t i = 0; i < o->remove_paths.n; i++)
        remove_path(rom, o->remove_paths.v[i]);
}

static void apply_user_props(rom_t *rom, const patch_opts *o)
{
    for (size_t i = 0; i < o->del_props.n; i++) {
        if (!valid_prop_key(o->del_props.v[i]))
            die("invalid property name: %s", o->del_props.v[i]);
        edit_prop(rom, o->del_props.v[i], NULL);
    }
    for (size_t i = 0; i < o->set_props.n; i++) {
        const char *kv = o->set_props.v[i];
        const char *eq = strchr(kv, '=');
        if (!eq || eq == kv)
            die("--set-prop expects KEY=VALUE, got %s", kv);
        char *key = xstrndup(kv, (size_t)(eq - kv));
        if (!valid_prop_key(key))
            die("invalid property name: %s", key);
        if (strchr(eq + 1, '\n'))
            die("property values cannot contain newlines");
        edit_prop(rom, key, eq + 1);
        free(key);
    }
    if (o->density > 0) {
        char v[16];
        snprintf(v, sizeof v, "%d", o->density);
        edit_prop(rom, "ro.sf.lcd_density", v);
    }
}

static void apply_stage(rom_t *rom, const patch_opts *o, patch_stage stage)
{
    for (int i = 0; PATCHES[i].name; i++)
        if (PATCHES[i].stage == stage && o->enabled[i])
            PATCHES[i].apply(rom, o);
}

unsigned patch_apply(rom_t *rom, const patch_opts *o)
{
    changes_reset();
    blank();
    note("Patching:");
    apply_user_removals(rom, o);
    apply_stage(rom, o, STAGE_CLEANUP);
    apply_user_props(rom, o);
    apply_stage(rom, o, STAGE_FIXES);
    for (size_t i = 0; i < o->disable_services.n; i++)
        disable_service(rom, o->disable_services.v[i], 0);
    apply_stage(rom, o, STAGE_FINISH);
    vfs_sort(rom->root);
    if (!changes_count())
        note("  (nothing to change)");
    return changes_count();
}
