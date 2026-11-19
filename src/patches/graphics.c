#include <stdlib.h>
#include <string.h>

#include "binpatch/elfpatch.h"
#include "core/util.h"
#include "core/vfs.h"
#include "patches/patches.h"
#include "patches/support.h"

void patch_exynos_gralloc(rom_t *rom, const patch_opts *opts)
{
    static const char *const libs[] = {"/system/lib64/libgui.so", "/system/system/lib64/libgui.so", NULL};
    for (int i = 0; libs[i]; i++) {
        vnode *n = vfs_resolve(rom->root, libs[i]);
        if (!n || n->type != VN_FILE || n->size < 64 || n->size > (64u << 20))
            continue;
        buf_t b = {0};
        if (vfs_read_all(n, &b, 0) != 0) {
            buf_free(&b);
            continue;
        }
        if (!memmem(b.data, b.len, "invalid gralloc handle (at %p)", 30)) {
            buf_free(&b);
            continue;
        }
        char at[32] = "";
        int r = elf_gralloc_guard(b.data, b.len, at, sizeof at);
        if (r > 0) {
            size_t len;
            unsigned char *data = buf_steal(&b, &len);
            vfs_set_mem(n, data, len);
            change("%s: Samsung's Exynos buffer-handle check (at %s) no longer writes through a null pointer for "
                   "buffers of another gralloc (SurfaceFlinger died on the first frame)",
                   libs[i], at);
        } else if (r < 0) {
            warn("exynos-gralloc: %s has Samsung's Exynos buffer-handle check, but its code is laid out differently; "
                 "left unchanged",
                 libs[i]);
        }
        buf_free(&b);
        break;
    }
}

void patch_fixed_resolution(rom_t *rom, const patch_opts *opts)
{
    static const char *const files[] = {"/system/etc/floating_feature.xml", "/vendor/etc/floating_feature.xml",
                                        "/system/vendor/etc/floating_feature.xml", NULL};
    static const char tag[] = "<SEC_FLOATING_FEATURE_COMMON_CONFIG_DYN_RESOLUTION_CONTROL>";
    for (int i = 0; files[i]; i++) {
        vnode *n = vfs_resolve(rom->root, files[i]);
        if (!n || n->type != VN_FILE)
            continue;
        buf_t b = {0};
        if (vfs_read_all(n, &b, 4u << 20) != 0) {
            buf_free(&b);
            continue;
        }
        const char *t = (const char *)b.data, *end = t + b.len;
        const char *hit = find_str(t, end, tag);
        if (!hit) {
            buf_free(&b);
            continue;
        }
        const char *ls = hit, *le;
        while (ls > t && ls[-1] != '\n')
            ls--;
        const char *close = find_str(hit, end, "</SEC_FLOATING_FEATURE_COMMON_CONFIG_DYN_RESOLUTION_CONTROL>");
        le = close ? close : hit + sizeof tag - 1;
        const char *nl = memchr(le, '\n', (size_t)(end - le));
        le = nl ? nl + 1 : end;
        const char *v = hit + sizeof tag - 1;
        char *val = xstrndup(v, close && close > v ? (size_t)(close - v) : 0);
        buf_t out = {0};
        buf_put(&out, t, (size_t)(ls - t));
        buf_put(&out, le, (size_t)(end - le));
        buf_put(&out, "", 1);
        replace_text(n, (char *)out.data);
        out.data = NULL;
        buf_free(&out);
        change("%s: removed the screen resolution switch (%s); the guest keeps the resolution set in AEmulator Plus "
               "instead of forcing its own lower one",
               files[i], *val ? val : "empty");
        free(val);
        buf_free(&b);
    }
}

void patch_no_bootanim(rom_t *rom, const patch_opts *opts)
{
    edit_prop(rom, "debug.sf.nobootanimation", "1");
}
