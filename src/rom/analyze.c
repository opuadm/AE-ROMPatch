#include "rom/analyze.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "rom/check.h"

static void add(rom_info *info, int sev, const char *fmt, ...) AEP_PRINTF(3, 4);

static void add(rom_info *info, int sev, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    char *s = xmalloc((size_t)n + 1);
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    if (info->nf == info->capf) {
        info->capf = info->capf ? info->capf * 2 : 16;
        info->f = xrealloc(info->f, info->capf * sizeof(finding));
    }
    info->f[info->nf].sev = sev;
    info->f[info->nf].text = s;
    info->nf++;
}

static int guess_api(const char *rel)
{
    if (!rel)
        return 19;
    static const struct {
        const char *p;
        int api;
    } t[] = {
        {"0.", 1},   {"1.0", 1},  {"1.1", 2},  {"1.5", 3},  {"1.6", 4},  {"2.0", 5},  {"2.1", 7},  {"2.2", 8},
        {"2.3", 10}, {"3.0", 11}, {"3.1", 12}, {"3.2", 13}, {"4.0", 15}, {"4.1", 16}, {"4.2", 17}, {"4.3", 18},
        {"4.4", 19}, {"5.0", 21}, {"5.1", 22}, {"6", 23},   {"7.0", 24}, {"7", 25},   {"8.0", 26}, {"8.1", 27},
        {"8", 26},   {"9", 28},   {"10", 29},  {"11", 30},  {"12", 31},  {"13", 33},  {"14", 34},  {"15", 35},
        {"16", 36},  {"17", 37},
    };
    if (!strcmp(rel, "N"))
        return 24;
    for (size_t i = 0; i < sizeof t / sizeof *t; i++)
        if (starts_with(rel, t[i].p))
            return t[i].api;
    return 19;
}

int effective_api(const char *sdk, const char *codename, const char *release)
{
    char code[64] = "", rel[64] = "";
    if (codename)
        for (size_t i = 0; codename[i] && i < sizeof code - 1; i++)
            code[i] = (char)toupper((unsigned char)codename[i]), code[i + 1] = 0;
    if (release)
        for (size_t i = 0; release[i] && i < sizeof rel - 1; i++)
            rel[i] = (char)toupper((unsigned char)release[i]), rel[i + 1] = 0;
    int preview = 0;
    if (!strcmp(code, "N"))
        preview = 24;
    else if (!strcmp(code, "NMR1"))
        preview = 25;
    else if (!strcmp(code, "TIRAMISU"))
        preview = 33;
    else if (!strcmp(code, "UPSIDEDOWNCAKE"))
        preview = 34;
    else if (!strcmp(code, "VANILLAICECREAM"))
        preview = 35;
    else if (!strcmp(code, "ICECREAMSANDWICH") || !strcmp(rel, "ICECREAMSANDWICH"))
        preview = 14;
    int s = sdk && *sdk ? atoi(sdk) : 0;
    if (s <= 0)
        return preview ? preview : guess_api(release);
    return preview && s < preview ? preview : s;
}

static int exists(rom_t *rom, const char *p)
{
    return vfs_resolve(rom->root, p) != NULL;
}

static const char *product(const proplist *p, const char *what, char *tmp, size_t len)
{
    snprintf(tmp, len, "ro.product.%s", what);
    const char *v = props_get(p, tmp);
    if (v && *v)
        return v;
    const char *parts[] = {"product", "odm", "vendor", "system"};
    for (int i = 0; i < 4; i++) {
        snprintf(tmp, len, "ro.product.%s.%s", parts[i], what);
        v = props_get(p, tmp);
        if (v && *v)
            return v;
    }
    return NULL;
}

static void detect_skin(rom_t *rom, rom_info *info, int api)
{
    const proplist *p = &info->props;
    const char *v;
    char *s = info->skin;
    size_t n = sizeof info->skin;
    const char *fp = props_get(p, "ro.build.fingerprint");
    char fpbrand[64] = "";
    if (fp) {
        size_t i = 0;
        while (fp[i] && fp[i] != '/' && i < sizeof fpbrand - 1) {
            fpbrand[i] = (char)tolower((unsigned char)fp[i]);
            i++;
        }
        fpbrand[i] = 0;
    }
    const char *chars = props_get(p, "ro.build.characteristics");
    const char *sysdev = props_get(p, "ro.product.system.device");
    if (fp && strcasestr(fp, "oogle/glass")) {
        snprintf(s, n, "Glass OS");
        return;
    }
    if (sysdev && !strcasecmp(sysdev, "desktop")) {
        snprintf(s, n, "Desktop");
        return;
    }
    if (chars) {
        int tv = strcasestr(chars, "tv") != NULL, watch = strcasestr(chars, "watch") != NULL;
        if (tv && !watch) {
            snprintf(s, n, "%s", api < 18 ? "Google TV" : "Android TV");
            return;
        }
        if (watch && !tv) {
            snprintf(s, n, "Wear");
            return;
        }
    }
    if ((v = props_get(p, "ro.mi.os.version.name")) || props_get(p, "ro.mi.os.version.code"))
        snprintf(s, n, "HyperOS %s", v ? v : "");
    else if (strstr(fpbrand, "infinix"))
        snprintf(s, n, "%s", api >= 23 ? "XOS" : api >= 21 ? "XUI" : "AOSP");
    else if (strstr(fpbrand, "tecno"))
        snprintf(s, n, "%s", api >= 23 ? "HiOS" : "AOSP");
    else if ((v = props_get(p, "ro.build.version.oneui")) || props_get(p, "ro.build.version.sep")) {
        int o = v ? atoi(v) : 0;
        if (o)
            snprintf(s, n, "One UI %d.%d", o / 10000, o / 100 % 100);
        else
            snprintf(s, n, "One UI");
    } else if ((v = props_get(p, "ro.build.version.realmeui")))
        snprintf(s, n, "realme UI %s", v[0] == 'V' ? v + 1 : v);
    else if ((v = props_get(p, "ro.build.version.oplusrom")))
        snprintf(s, n, "ColorOS %s", v[0] == 'V' ? v + 1 : v);
    else if ((v = props_get(p, "ro.vivo.os.version")) || props_get(p, "ro.vivo.os.name"))
        snprintf(s, n, "vivo %s", v ? v : "");
    else if ((v = props_get(p, "ro.miui.ui.version.name")) || props_get(p, "ro.miui.ui.version.code") ||
             exists(rom, "/system/app/MiuiHome.apk") || exists(rom, "/system/app/MiuiHome"))
        snprintf(s, n, "MIUI %s", v ? v : "");
    else if ((v = props_get(p, "ro.cm.version"))) {
        char tmp[64];
        snprintf(tmp, sizeof tmp, "%s", v);
        char *d = strchr(tmp, '-');
        if (d)
            *d = 0;
        snprintf(s, n, "CyanogenMod %s", tmp);
    } else if (props_get(p, "ro.lineage.version"))
        snprintf(s, n, "LineageOS");
    else if ((v = props_get(p, "ro.build.display.id")) && strcasestr(v, "Flyme"))
        snprintf(s, n, "Flyme");
    else if (props_get(p, "ro.build.version.emui"))
        snprintf(s, n, "EMUI");
    else if (props_get(p, "ro.build.version.opporom"))
        snprintf(s, n, "ColorOS");
    else if (exists(rom, "/system/framework/twframework.jar") || exists(rom, "/system/app/TwLauncher.apk") ||
             exists(rom, "/system/app/TwLauncher") || exists(rom, "/system/app/SecLauncher2.apk"))
        snprintf(s, n, "TouchWiz");
    else if (exists(rom, "/system/framework/com.htc.framework.jar") || exists(rom, "/system/framework/HTCExtension.jar"))
        snprintf(s, n, "HTC Sense");
    else
        snprintf(s, n, "AOSP");
    size_t l = strlen(s);
    while (l && s[l - 1] == ' ')
        s[--l] = 0;
}

static void detect_arch(rom_t *rom, rom_info *info)
{
    const char *const probes[] = {"/system/bin/app_process64", "/system/bin/app_process32", "/system/bin/app_process",
                                  "/system/bin/linker64",      "/system/bin/linker",        "/system/bin/surfaceflinger",
                                  "/system/bin/servicemanager", "/system/bin/toolbox",      NULL};
    snprintf(info->arch, sizeof info->arch, "unknown");
    info->arch_supported = 1;
    for (int i = 0; probes[i]; i++) {
        vnode *n = vfs_resolve(rom->root, probes[i]);
        if (!n || n->type != VN_FILE || n->size < 20)
            continue;
        unsigned char h[20];
        void *hd = NULL;
        int r = vfs_read(n, 0, h, sizeof h, &hd);
        vfs_read_done(n, &hd);
        if (r < 0 || memcmp(h, "\x7f" "ELF", 4))
            continue;
        int cls = h[4];
        unsigned m = h[5] == 2 ? (unsigned)((h[18] << 8) | h[19]) : le16(h + 18);
        const char *name;
        int ok = 1;
        if (cls == 1 && m == 40)
            name = "arm";
        else if (cls == 2 && m == 183)
            name = "arm64";
        else if (cls == 1 && m == 3)
            name = "x86";
        else if (cls == 2 && m == 62)
            name = "x86_64";
        else if (m == 8 || m == 10)
            name = "mips", ok = 0;
        else if (m == 243)
            name = "riscv", ok = 0;
        else
            name = "other", ok = 0;
        snprintf(info->arch, sizeof info->arch, "%s", name);
        info->arch_supported = ok;
        return;
    }
    const char *abi = info->abi;
    if (abi) {
        if (starts_with(abi, "x86_64"))
            snprintf(info->arch, sizeof info->arch, "x86_64 (from ro.product.cpu.abi)");
        else if (!strcmp(abi, "x86"))
            snprintf(info->arch, sizeof info->arch, "x86 (from ro.product.cpu.abi)");
        else if (starts_with(abi, "mips")) {
            snprintf(info->arch, sizeof info->arch, "mips (from ro.product.cpu.abi)");
            info->arch_supported = 0;
        } else if (starts_with(abi, "arm64"))
            snprintf(info->arch, sizeof info->arch, "arm64 (from ro.product.cpu.abi)");
        else
            snprintf(info->arch, sizeof info->arch, "arm (from ro.product.cpu.abi)");
    }
}

static int rc_scan_text(rom_info *info, vnode *n)
{
    buf_t b = {0};
    if (vfs_read_all(n, &b, 8u << 20) < 0)
        return 0;
    int found = 0;
    const char *t = (const char *)b.data;
    const char *p = t;
    while ((p = strstr(p, "BOOTCLASSPATH"))) {
        const char *ls = p;
        while (ls > t && ls[-1] != '\n')
            ls--;
        while (*ls == ' ' || *ls == '\t')
            ls++;
        if (starts_with(ls, "export"))
            found = 1;
        p++;
    }
    buf_free(&b);
    (void)info;
    return found;
}

static void scan_rc(rom_t *rom, rom_info *info)
{
    for (size_t i = 0; i < rom->root->nkids; i++) {
        vnode *k = rom->root->kids[i];
        if (k->type == VN_FILE && ends_with(k->name, ".rc")) {
            info->rc_files++;
            if (!strcmp(k->name, "init.rc"))
                info->has_init_rc = 1;
            if (rc_scan_text(info, k))
                info->bcp_in_rc = 1;
        }
    }
    vnode *d = vfs_resolve(rom->root, "/system/etc/init");
    if (d && d->type == VN_DIR)
        for (size_t i = 0; i < d->nkids; i++)
            if (d->kids[i]->type == VN_FILE && ends_with(d->kids[i]->name, ".rc") && rc_scan_text(info, d->kids[i]))
                info->bcp_in_rc = 1;
    vnode *legacy = vfs_lookup(rom->root, "/etc/init.rc");
    if (!info->has_init_rc && legacy && legacy->type == VN_FILE)
        info->has_init_rc = 1;
}

void analyze_rom(rom_t *rom, rom_info *info)
{
    char tmp[128];
    memset(info, 0, sizeof *info);
    props_collect(rom->root, &info->props);
    proplist *p = &info->props;
    info->release = props_get(p, "ro.build.version.release");
    info->api = effective_api(props_get(p, "ro.build.version.sdk"), props_get(p, "ro.build.version.codename"),
                              info->release);
    const char *brand = product(p, "brand", tmp, sizeof tmp);
    if (!brand)
        brand = product(p, "manufacturer", tmp, sizeof tmp);
    snprintf(info->brand, sizeof info->brand, "%s", brand ? brand : "");
    if (info->brand[0])
        info->brand[0] = (char)toupper((unsigned char)info->brand[0]);
    const char *model = product(p, "model", tmp, sizeof tmp);
    if (!model)
        model = product(p, "device", tmp, sizeof tmp);
    snprintf(info->model, sizeof info->model, "%s", model ? model : "Android");
    info->abi = props_get(p, "ro.product.cpu.abi");
    detect_skin(rom, info, info->api);
    detect_arch(rom, info);
    scan_rc(rom, info);
    info->treble = exists(rom, "/vendor/etc/vintf/manifest.xml") || exists(rom, "/vendor/manifest.xml");
    if (rom->have_boot)
        bootimg_kernel_banner(&rom->boot, info->banner, sizeof info->banner);
    vfs_count(rom->root, &info->files, &info->dirs, &info->links, &info->bytes);
    sim_inspect(rom->root, &info->props, &info->sim);

    vnode *sys = vfs_lookup(rom->root, "/system");
    int have_sys = sys && sys->type == VN_DIR;
    if (!have_sys)
        add(info, SEV_ERROR, "no /system: AEmulator Plus needs the system partition");
    else if (!vfs_lookup(rom->root, "/system/build.prop"))
        add(info, SEV_WARN, "no /system/build.prop: AEmulator Plus will guess the Android version from the file layout");
    if (!info->has_init_rc && !info->rc_files)
        add(info, SEV_WARN, "no init.rc: add the boot.img (or ramdisk) of this ROM, AEmulator Plus plans the boot services from it");
    if (!info->arch_supported)
        add(info, SEV_ERROR, "CPU architecture %s cannot run in AEmulator Plus (ARM, ARM64, x86 and x86-64 only)", info->arch);
    else if (starts_with(info->arch, "x86"))
        add(info, SEV_INFO, "x86 firmware: runs through AEmulator Plus's x86 translator (slower than ARM)");
    if (info->api >= 21)
        add(info, SEV_INFO, "Android %s (API %d): AEmulator Plus marks Android 5.0+ as experimental",
            info->release ? info->release : "?", info->api);
    if (!info->bcp_in_rc && info->has_init_rc)
        add(info, SEV_INFO, "BOOTCLASSPATH is not exported by the init scripts: AEmulator Plus will rebuild it from odex files or guess");
    if (rom->encrypted)
        add(info, SEV_WARN, "%u encrypted (fscrypt) entries were skipped", rom->encrypted);
    if (rom->special_skipped)
        add(info, SEV_INFO, "%u device nodes / fifos / sockets skipped (the emulator creates its own)", rom->special_skipped);
    if (rom->have_boot && rom->boot_ramdisk_recovery)
        add(info, SEV_INFO, "the boot image carries a recovery ramdisk (A/B device); the root file system comes from %s",
            rom->sar ? "the system partition" : "the inputs");
    if (rom->have_boot && rom->boot.header_version >= 3 && !rom->boot.ramdisk_size)
        add(info, SEV_INFO, "GKI boot image without ramdisk: only its kernel version is used");
    if (info->api >= SIM_FIRST_API && info->api <= SIM_LAST_API) {
        const sim_info *si = &info->sim;
        if (si->stack_kind == STACK_MTK)
            add(info, SEV_WARN, "MediaTek telephony: its framework talks a MediaTek-specific RIL protocol over extra sockets "
                "(rild2, rild-mtk-*); AEmulator Plus's AOSP-style modem usually leaves it with no SIM or crashes com.android.phone");
        else if (si->stack_kind == STACK_SPRD)
            add(info, SEV_WARN, "Spreadtrum/Unisoc telephony: a vendor RIL protocol; the SIM may not register with AEmulator Plus's modem");
        if (si->cdma_kind == CDMA_LTE)
            add(info, SEV_INFO, "LTE-on-CDMA phone (%s): the gsm-modem patch switches it to AEmulator Plus's GSM modem; "
                "use --disable gsm-modem to keep the CDMA modem", si->cdma_why);
        else if (si->cdma_kind == CDMA_ONLY)
            add(info, SEV_WARN, "CDMA phone (%s): turn on CDMA in the VM's SIM settings in AEmulator Plus, otherwise its "
                "GSM modem does not match what this framework expects", si->cdma_why);
        if (si->slots >= 2)
            add(info, SEV_INFO, "dual-SIM ROM (%s): the single-sim patch keeps only slot 1, the one AEmulator Plus emulates", si->why);
    }
    check_report rep;
    check_tree(rom->root, &rep);
    if (rep.unsafe_names)
        add(info, SEV_WARN, "%u entries with unsafe names (backslashes): AEmulator Plus aborts the import; the sanitize patch drops them",
            rep.unsafe_names);
    if (rep.escaping_links)
        add(info, SEV_WARN, "%u symlinks point outside the ROM: AEmulator Plus aborts the import; the sanitize patch drops them",
            rep.escaping_links);
    if (rep.bad_links)
        add(info, SEV_WARN, "%u symlinks have empty or invalid targets; the sanitize patch drops them", rep.bad_links);
    for (size_t i = 0; i < rep.traps.n; i++)
        add(info, SEV_WARN, "%s: AEmulator Plus's importer treats this file as a firmware container/partition, not as a plain file",
            rep.traps.v[i]);
    if (rep.system_not_dir)
        add(info, SEV_ERROR, "/system is not a folder");
    check_free(&rep);
}

static const char *sev_tag(int s)
{
    switch (s) {
    case SEV_OK: return "  ok  ";
    case SEV_INFO: return " info ";
    case SEV_WARN: return " warn ";
    default: return "ERROR ";
    }
}

void analyze_print(const rom_t *rom, const rom_info *info)
{
    char hs[32];
    const proplist *p = &info->props;
    const char *v;
    blank();
    note("ROM:");
    size_t bl = strlen(info->brand);
    int dup = bl && !strncasecmp(info->model, info->brand, bl) && (info->model[bl] == ' ' || !info->model[bl]);
    note("  Device       %s%s%s", dup ? "" : info->brand, info->brand[0] && !dup ? " " : "", info->model);
    note("  Android      %s (API %d)", info->release ? info->release : "?", info->api);
    if ((v = props_get(p, "ro.build.id")))
        note("  Build        %s", v);
    if ((v = props_get(p, "ro.build.fingerprint")))
        note("  Fingerprint  %s", v);
    note("  Skin         %s", info->skin);
    if (info->abi)
        note("  CPU          %s (ro.product.cpu.abi=%s)", info->arch, info->abi);
    else
        note("  CPU          %s", info->arch);
    if ((v = props_get(p, "ro.sf.lcd_density")))
        note("  Density      %s dpi", v);
    note("  Layout       %s%s%s", rom->sar ? "system-as-root" : "classic", info->treble ? ", Treble vendor" : "",
         rom->have_vendor ? ", separate vendor" : "");
    note("  Init         %s, %d root .rc file%s, ramdisk %s", info->has_init_rc ? "init.rc found" : "no init.rc",
         info->rc_files, info->rc_files == 1 ? "" : "s",
         rom->have_ramdisk ? (rom->ramdisk_source ? rom->ramdisk_source : "yes") : "none");
    if (info->banner[0])
        note("  Kernel       %.100s", info->banner);
    const sim_info *si = &info->sim;
    if (info->api >= SIM_FIRST_API && info->api <= SIM_LAST_API)
        note("  SIM          emulated by AEmulator Plus on this Android version; ROM has %d slot%s%s%s%s", si->slots,
             si->slots == 1 ? "" : "s", si->why[0] ? " (" : "", si->why, si->why[0] ? ")" : "");
    else
        note("  SIM          not emulated: AEmulator Plus's modem covers Android 2.3-7.1 (API %d-%d) only",
             SIM_FIRST_API, SIM_LAST_API);
    note("  Telephony    %s", si->stack);
    if (si->ril_class[0])
        note("  RIL class    %s (custom; the 'sim' patch removes it)", si->ril_class);
    note("  APNs         %s, %d of %d AEmulator operator presets covered",
         si->has_apn_file ? "/system/etc/apns-conf.xml" : "no apns-conf.xml", si->apn_presets_covered,
         si->apn_presets_total);
    note("  Contents     %llu files, %llu folders, %llu symlinks, %s", (unsigned long long)info->files,
         (unsigned long long)info->dirs, (unsigned long long)info->links, human_size(info->bytes, hs, sizeof hs));
    blank();
    note("AEmulator Plus compatibility:");
    if (!info->nf)
        note("  [%s] no problems found", sev_tag(SEV_OK));
    for (size_t i = 0; i < info->nf; i++)
        note("  [%s] %s", sev_tag(info->f[i].sev), info->f[i].text);
}

void analyze_free(rom_info *info)
{
    props_free(&info->props);
    for (size_t i = 0; i < info->nf; i++)
        free(info->f[i].text);
    free(info->f);
}
