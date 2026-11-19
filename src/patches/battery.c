#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "core/props.h"
#include "core/util.h"
#include "core/vfs.h"
#include "patches/patches.h"
#include "patches/support.h"
#include "rom/analyze.h"

static int health_binary_fakes(vnode *n)
{
    if (!n || n->type != VN_FILE || n->size < 64 || n->size > (64u << 20))
        return 0;
    buf_t b = {0};
    int r = vfs_read_all(n, &b, 0) == 0 && memmem(b.data, b.len, "ro.boot.fake_battery", 20) != NULL;
    buf_free(&b);
    return r;
}

void patch_fake_battery(rom_t *rom, const patch_opts *opts)
{
    static const char *const dirs[] = {"/sbin", "/system/bin", "/system/bin/hw", "/vendor/bin", "/vendor/bin/hw",
                                       "/system/lib/hw", "/system/lib64/hw", "/vendor/lib/hw", "/vendor/lib64/hw",
                                       NULL};
    if (prop_defined(rom, "ro.boot.fake_battery")) {
        debug("fake-battery: ro.boot.fake_battery is already set");
        return;
    }
    char *found = NULL;
    for (int d = 0; dirs[d] && !found; d++) {
        vnode *dir = vfs_resolve(rom->root, dirs[d]);
        if (!dir || dir->type != VN_DIR)
            continue;
        for (size_t i = 0; i < dir->nkids && !found; i++) {
            vnode *k = dir->kids[i];
            if ((strstr(k->name, "health") || !strcmp(k->name, "charger")) && health_binary_fakes(k))
                found = xasprintf("%s/%s", dirs[d], k->name);
        }
    }
    if (!found) {
        debug("fake-battery: no healthd / health HAL with ro.boot.fake_battery support found");
        return;
    }
    change("fake-battery: %s supports a fixed fake battery level (42%%), so a missed battery node cannot read as 0%%", found);
    edit_prop(rom, "ro.boot.fake_battery", "1");
    free(found);
}

static char *hal_name(const char *b, const char *e)
{
    const char *n = find_str(b, e, "<name>");
    if (!n)
        return NULL;
    n += 6;
    const char *ne = find_str(n, e, "</name>");
    if (!ne)
        return NULL;
    while (n < ne && isspace((unsigned char)*n))
        n++;
    while (ne > n && isspace((unsigned char)ne[-1]))
        ne--;
    return ne > n ? xstrndup(n, (size_t)(ne - n)) : NULL;
}

static int service_mentions(rom_t *rom, const char *word)
{
    static const char *const dirs[] = {"/vendor/bin/hw", "/vendor/bin", "/odm/bin/hw", "/odm/bin", NULL};
    size_t wl = strlen(word);
    for (int d = 0; dirs[d]; d++) {
        vnode *dir = vfs_resolve(rom->root, dirs[d]);
        if (!dir || dir->type != VN_DIR)
            continue;
        for (size_t i = 0; i < dir->nkids; i++) {
            vnode *k = dir->kids[i];
            if (k->type != VN_FILE || !strstr(k->name, "health") || k->size < 64 || k->size > (64u << 20))
                continue;
            buf_t b = {0};
            int hit = vfs_read_all(k, &b, 0) == 0 && memmem(b.data, b.len, word, wl) != NULL;
            buf_free(&b);
            if (hit)
                return 1;
        }
    }
    return 0;
}

void patch_oem_health(rom_t *rom, const patch_opts *opts)
{
    static const char *const manifests[] = {"/vendor/etc/vintf/manifest.xml", "/vendor/manifest.xml", NULL};
    static const char *const odm_manifest = "/odm/etc/vintf/manifest.xml";
    proplist props = {0};
    props_collect(rom->root, &props);
    int api = effective_api(props_get(&props, "ro.build.version.sdk"), props_get(&props, "ro.build.version.codename"),
                            props_get(&props, "ro.build.version.release"));
    props_free(&props);
    if (api < 28)
        return;
    buf_t src = {0};
    const char *from = NULL;
    for (int i = 0; manifests[i] && !from; i++) {
        vnode *m = vfs_resolve(rom->root, manifests[i]);
        if (m && m->type == VN_FILE && vfs_read_all(m, &src, 4u << 20) == 0)
            from = manifests[i];
        else
            buf_free(&src);
    }
    if (!from)
        return;
    buf_t odm = {0};
    vnode *om = vfs_resolve(rom->root, odm_manifest);
    if (om && om->type == VN_FILE && vfs_read_all(om, &odm, 4u << 20) != 0)
        buf_free(&odm);
    buf_t add = {0};
    strvec names = {0};
    const char *t = (const char *)src.data, *end = t + src.len;
    for (const char *b = t; (b = find_str(b, end, "<hal")) != NULL;) {
        const char *e = find_str(b, end, "</hal>");
        if (!e)
            break;
        e += 6;
        char *name = hal_name(b, e);
        const char *word = name ? strrchr(name, '.') : NULL;
        if (name && word && strstr(name, "health") && strcmp(name, "android.hardware.health") &&
            find_str(b, e, "hwbinder") && !(odm.data && memmem(odm.data, odm.len, name, strlen(name))) &&
            service_mentions(rom, word + 1)) {
            buf_put(&add, "    ", 4);
            buf_put(&add, b, (size_t)(e - b));
            buf_put(&add, "\n", 1);
            strvec_push(&names, name);
        }
        free(name);
        b = e;
    }
    if (names.n) {
        char *dst = write_target(rom->root, odm_manifest);
        if (!dst) {
            warn("oem-health: %s cannot be written (a file is in the way)", odm_manifest);
        } else {
            buf_t out = {0};
            const char *close = odm.data ? find_str((const char *)odm.data, (const char *)odm.data + odm.len, "</manifest>") : NULL;
            if (close) {
                buf_put(&out, odm.data, (size_t)(close - (const char *)odm.data));
                buf_put(&out, add.data, add.len);
                buf_put(&out, close, odm.len - (size_t)(close - (const char *)odm.data));
            } else {
                static const char head[] = "<manifest version=\"1.0\" type=\"device\">\n";
                buf_put(&out, head, sizeof head - 1);
                buf_put(&out, add.data, add.len);
                buf_put(&out, "</manifest>\n", 12);
            }
            vfs_write_text(rom->root, dst, (const char *)out.data, out.len, 0644);
            for (size_t i = 0; i < names.n; i++)
                change("oem-health: %s (declared in %s) is the ROM's health service; declared in %s%s%s, where "
                       "AEmulator Plus's own vendor manifest does not replace it",
                       names.v[i], from, odm_manifest, strcmp(dst, odm_manifest) ? " -> " : "",
                       strcmp(dst, odm_manifest) ? dst : "");
            buf_free(&out);
            free(dst);
        }
    } else {
        debug("oem-health: no OEM health HAL with a service binary in the vendor manifest");
    }
    strvec_free(&names);
    buf_free(&add);
    buf_free(&odm);
    buf_free(&src);
}
