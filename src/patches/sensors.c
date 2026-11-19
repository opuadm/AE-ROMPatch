#include <stdlib.h>
#include <string.h>

#include "binpatch/elfpatch.h"
#include "core/props.h"
#include "core/util.h"
#include "core/vfs.h"
#include "patches/patches.h"
#include "patches/sensorhal.h"
#include "patches/support.h"
#include "rom/analyze.h"

void patch_sensor_multihal(rom_t *rom, const patch_opts *opts)
{
    static const char *const confs[] = {"/vendor/etc/sensors/hals.conf", "/system/etc/sensors/hals.conf",
                                        "/system/vendor/etc/sensors/hals.conf", NULL};
    proplist props = {0};
    props_collect(rom->root, &props);
    int api = effective_api(props_get(&props, "ro.build.version.sdk"), props_get(&props, "ro.build.version.codename"),
                            props_get(&props, "ro.build.version.release"));
    props_free(&props);
    if (api < 26)
        return;
    for (int i = 0; confs[i]; i++) {
        vnode *n = vfs_resolve(rom->root, confs[i]);
        if (!n || n->type != VN_FILE)
            continue;
        buf_t b = {0};
        buf_t mods = {0};
        if (vfs_read_all(n, &b, 1u << 20) == 0) {
            const char *t = (const char *)b.data, *end = t + b.len;
            while (t < end) {
                const char *nl = memchr(t, '\n', (size_t)(end - t));
                const char *le = nl ? nl : end;
                const char *a = t, *z = le;
                while (a < z && (*a == ' ' || *a == '\t'))
                    a++;
                while (z > a && (z[-1] == '\r' || z[-1] == ' ' || z[-1] == '\t'))
                    z--;
                if (z > a && *a != '#') {
                    const char *base = a;
                    for (const char *c = a; c < z; c++)
                        if (*c == '/')
                            base = c + 1;
                    if (mods.len)
                        buf_put(&mods, ", ", 2);
                    buf_put(&mods, base, (size_t)(z - base));
                }
                t = nl ? nl + 1 : end;
            }
        }
        buf_put(&mods, "", 1);
        char *path = vfs_path(n);
        vfs_remove(n);
        change("%s: removed (sensors multihal config%s%s); the sensors HAL loads AEmulator's sensors.default.so "
               "instead of the board's sensor drivers, whose service died and took system_server down",
               path, mods.len > 1 ? ": " : "", (const char *)mods.data);
        free(path);
        buf_free(&mods);
        buf_free(&b);
    }
}

void patch_sensor_hal(rom_t *rom, const patch_opts *opts)
{
    static const char *const dst_path = "/odm/lib64/hw/sensors.aerompatch.so";
    proplist props = {0};
    props_collect(rom->root, &props);
    int api = effective_api(props_get(&props, "ro.build.version.sdk"), props_get(&props, "ro.build.version.codename"),
                            props_get(&props, "ro.build.version.release"));
    const char *abi = props_get(&props, "ro.product.cpu.abi");
    int arm64 = abi ? !strcmp(abi, "arm64-v8a") : vfs_resolve(rom->root, "/system/lib64") != NULL;
    props_free(&props);
    if (api < 26 || !arm64)
        return;
    char *dst = write_target(rom->root, dst_path);
    if (!dst) {
        warn("sensor-hal: %s cannot be written (a file is in the way)", dst_path);
        return;
    }
    vfs_write_text(rom->root, dst, (const char *)SENSORHAL_SO, sizeof SENSORHAL_SO, 0644);
    change("sensor-hal: added %s%s%s (AEmulator's accelerometer; a poll waits 200 ms at most)", dst_path,
           strcmp(dst, dst_path) ? " -> " : "", strcmp(dst, dst_path) ? dst : "");
    free(dst);
    edit_prop(rom, "ro.hardware.sensors", "aerompatch");
}

void patch_sensor_retry(rom_t *rom, const patch_opts *opts)
{
    static const char *const libs[] = {"/system/lib64/libsensorservice.so", "/system/system/lib64/libsensorservice.so",
                                       NULL};
    for (int i = 0; libs[i]; i++) {
        vnode *n = vfs_resolve(rom->root, libs[i]);
        if (!n || n->type != VN_FILE || n->size < 64 || n->size > (64u << 20))
            continue;
        buf_t b = {0};
        if (vfs_read_all(n, &b, 0) != 0) {
            buf_free(&b);
            continue;
        }
        char at[32] = "", guard[64] = "";
        int r = elf_sensor_retry(b.data, b.len, at, sizeof at);
        int g = elf_sensor_hidl_guard(b.data, b.len, guard, sizeof guard);
        if (r > 0 || g > 0) {
            size_t len;
            unsigned char *data = buf_steal(&b, &len);
            uint32_t mode = n->mode, uid = n->uid, gid = n->gid;
            vfs_set_mem(n, data, len);
            n->mode = mode;
            n->uid = uid;
            n->gid = gid;
            if (r > 0)
                change("%s: SensorService retries a failed sensor poll once a second instead of aborting system_server "
                       "after 50 failures (at %s)",
                       libs[i], at);
            if (g > 0)
                change("%s: a failed call to the sensors service (activate, batch, flush, ...) no longer aborts "
                       "system_server (%s)",
                       libs[i], guard);
        }
        if (r < 0) {
            warn("sensor-retry: %s has the sensor poll retry loop, but its code is laid out differently; left unchanged",
                 libs[i]);
        }
        buf_free(&b);
        break;
    }
}
