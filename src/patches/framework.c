#include <stdlib.h>
#include <string.h>

#include "binpatch/dex.h"
#include "core/util.h"
#include "core/vfs.h"
#include "patches/patches.h"
#include "patches/support.h"

typedef struct {
    const char *class_desc;
    const char *method;
    const char *why;
} crash_site;

static const crash_site CRASH_SITES[] = {
    {"Lcom/android/server/ethernet/EthernetNetworkFactory$UsbShareNetStateReceiver;", "onReceive",
     "MIUI USB-share receiver: on USB/charger unplug it brings up usbnet0, netd refuses and system_server dies"},
    {NULL, NULL, NULL},
};

typedef struct {
    nodelist jars;
} jarscan;

static int jar_collect_cb(vnode *n, const char *path, void *ctx)
{
    (void)path;
    if (n->type == VN_FILE && ends_with(n->name, ".jar")) {
        char *real = vfs_path(n);
        nl_push(&((jarscan *)ctx)->jars, n, real);
        free(real);
    }
    return 0;
}

static int jar_has_dex(const buf_t *jar)
{
    const char *needle = "classes";
    for (size_t i = 0; i + 30 < jar->len; i++) {
        if (le32(jar->data + i) != 0x04034b50U)
            continue;
        uint16_t nl = le16(jar->data + i + 26);
        if (i + 30 + nl <= jar->len && nl >= 11 && !memcmp(jar->data + i + 30, needle, 7) &&
            !memcmp(jar->data + i + 30 + nl - 4, ".dex", 4))
            return 1;
    }
    return 0;
}

void patch_crash_guards(rom_t *rom, const patch_opts *opts)
{
    vnode *fw = vfs_resolve(rom->root, "/system/framework");
    if (!fw || fw->type != VN_DIR)
        return;
    jarscan js = {{0}};
    vfs_walk(fw, jar_collect_cb, &js);
    int found[16] = {0};
    int odexed_jars = 0;
    for (size_t j = 0; j < js.jars.n; j++) {
        vnode *n = js.jars.v[j];
        if (n->size > (256u << 20))
            continue;
        buf_t jar = {0};
        if (vfs_read_all(n, &jar, 0) < 0) {
            buf_free(&jar);
            continue;
        }
        if (!jar_has_dex(&jar)) {
            odexed_jars++;
            buf_free(&jar);
            continue;
        }
        int touched = 0;
        for (int k = 0; CRASH_SITES[k].class_desc; k++) {
            char err[256];
            int r = jar_stub_void_method(&jar, CRASH_SITES[k].class_desc, CRASH_SITES[k].method, err, sizeof err);
            if (r < 0) {
                warn("crash-guards: %s: %s", js.jars.paths[j], err);
            } else if (r >= 1) {
                found[k] = 1;
                if (r == 1) {
                    touched = 1;
                    change("%s: neutralised %s (%s)", js.jars.paths[j], CRASH_SITES[k].method, CRASH_SITES[k].why);
                }
            }
        }
        if (touched) {
            size_t len;
            unsigned char *data = buf_steal(&jar, &len);
            uint32_t mode = n->mode, uid = n->uid, gid = n->gid;
            vfs_set_mem(n, data, len);
            n->mode = mode;
            n->uid = uid;
            n->gid = gid;
        }
        buf_free(&jar);
    }
    if (odexed_jars) {
        int miui = vfs_resolve(rom->root, "/system/app/miui/miui.apk") != NULL ||
                   vfs_resolve(rom->root, "/system/priv-app/SecurityCenter") != NULL;
        int any = 0;
        for (int k = 0; CRASH_SITES[k].class_desc; k++)
            any |= found[k];
        if (miui && !any)
            warn("crash-guards: %d framework jar(s) are odexed (code only in .odex/.oat), so known MIUI crash sites "
                 "cannot be patched; a deodexed build (e.g. xiaomi.eu) avoids this",
                 odexed_jars);
        else
            debug("crash-guards: %d odexed jar(s) skipped", odexed_jars);
    }
    nl_free(&js.jars);
}

void patch_no_hcm(rom_t *rom, const patch_opts *opts)
{
    static const char *const dirs[] = {"/system/framework", "/system/framework/oat/arm64", "/system/framework/oat/arm",
                                       "/system/framework/arm64", "/system/framework/arm", NULL};
    static const char *const names[] = {"hcm.jar", "hcm.odex", "hcm.vdex", "hcm.art", "hcm.oat", NULL};
    for (int d = 0; dirs[d]; d++) {
        vnode *dir = vfs_lookup(rom->root, dirs[d]);
        if (!dir || dir->type != VN_DIR)
            continue;
        for (int i = 0; names[i]; i++) {
            vnode *k = vfs_child(dir, names[i]);
            if (!k)
                continue;
            change("removed %s/%s (Samsung HCM service: SystemServer skips it without the jar; one failed battery call "
                   "from it kills system_server)",
                   dirs[d], names[i]);
            vfs_remove(k);
        }
    }
}
