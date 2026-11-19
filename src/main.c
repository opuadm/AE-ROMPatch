#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "core/about.h"
#include "rom/analyze.h"
#include "rom/check.h"
#include "output/emit.h"
#include "patches/patch.h"
#include "rom/rom.h"
#include "core/rsrc.h"
#include "core/util.h"
#include "cli/help.h"

static void toggle(patch_opts *po, const char *list, int on)
{
    char *copy = xstrdup(list);
    for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
        if (!strcmp(tok, "all")) {
            for (int i = 0; PATCHES[i].name; i++)
                po->enabled[i] = on;
            continue;
        }
        int idx = patch_index(tok);
        if (idx < 0)
            die("unknown patch '%s' (see '" AEP_BIN " patches')", tok);
        po->enabled[idx] = on;
    }
    free(copy);
}

enum {
    OPT_ROOT = 1000,
    OPT_SYSTEM,
    OPT_VENDOR,
    OPT_PRODUCT,
    OPT_SYSTEM_EXT,
    OPT_ODM,
    OPT_OEM,
    OPT_BOOT,
    OPT_RAMDISK,
    OPT_PARTITION,
    OPT_ENABLE,
    OPT_DISABLE,
    OPT_SET_PROP,
    OPT_DEL_PROP,
    OPT_DENSITY,
    OPT_DISABLE_SERVICE,
    OPT_REMOVE,
    OPT_REMOVE_APP,
    OPT_NEW_BOOT,
    OPT_VERSION,
};

static const struct option long_opts[] = {
    {"root", required_argument, 0, OPT_ROOT},
    {"system", required_argument, 0, OPT_SYSTEM},
    {"vendor", required_argument, 0, OPT_VENDOR},
    {"product", required_argument, 0, OPT_PRODUCT},
    {"system-ext", required_argument, 0, OPT_SYSTEM_EXT},
    {"odm", required_argument, 0, OPT_ODM},
    {"oem", required_argument, 0, OPT_OEM},
    {"boot", required_argument, 0, OPT_BOOT},
    {"ramdisk", required_argument, 0, OPT_RAMDISK},
    {"partition", required_argument, 0, OPT_PARTITION},
    {"output", required_argument, 0, 'o'},
    {"level", required_argument, 0, 'z'},
    {"enable", required_argument, 0, OPT_ENABLE},
    {"disable", required_argument, 0, OPT_DISABLE},
    {"set-prop", required_argument, 0, OPT_SET_PROP},
    {"del-prop", required_argument, 0, OPT_DEL_PROP},
    {"density", required_argument, 0, OPT_DENSITY},
    {"disable-service", required_argument, 0, OPT_DISABLE_SERVICE},
    {"remove", required_argument, 0, OPT_REMOVE},
    {"remove-app", required_argument, 0, OPT_REMOVE_APP},
    {"new-boot", no_argument, 0, OPT_NEW_BOOT},
    {"dry-run", no_argument, 0, 'n'},
    {"force", no_argument, 0, 'f'},
    {"verbose", no_argument, 0, 'v'},
    {"quiet", no_argument, 0, 'q'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, OPT_VERSION},
    {0, 0, 0, 0},
};

static int is_extra_name(const char *n)
{
    if (!strcmp(n, "odm") || !strcmp(n, "mi_ext") || !strcmp(n, "vgc") || !strcmp(n, "prism") || !strcmp(n, "optics"))
        return 1;
    if (!starts_with(n, "my_") || !n[3])
        return 0;
    for (const char *p = n + 3; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')))
            return 0;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage_short(stderr);
        return 2;
    }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
        if (argc > 2 && !strcmp(argv[2], "edits"))
            help_edits(stdout);
        else if (argc > 2 && !strcmp(argv[2], "patches"))
            help_patches(stdout);
        else
            usage(stdout);
        return 0;
    }
    if (!strcmp(cmd, "--version") || !strcmp(cmd, "version")) {
        printf(AEP_NAME " %s\n", AEP_VERSION);
        return 0;
    }
    if (!strcmp(cmd, "patches")) {
        help_patches(stdout);
        return 0;
    }
    int is_patch = !strcmp(cmd, "patch");
    if (!is_patch && strcmp(cmd, "info"))
        die("unknown command '%s' (try '" AEP_BIN " help')", cmd);

    rom_t rom;
    rom_init(&rom);
    patch_opts po;
    patch_opts_init(&po);
    emit_opts eo = {NULL, 0, 0, 0};
    int dry = 0, force = 0, level = 6, patch_only_opt = 0;

    optind = 2;
    int c;
    while ((c = getopt_long(argc, argv, "o:z:nfvqh", long_opts, NULL)) != -1) {
        switch (c) {
        case OPT_ROOT: rom_add(&rom, ROLE_ROOT, optarg, NULL); break;
        case OPT_SYSTEM: rom_add(&rom, ROLE_SYSTEM, optarg, NULL); break;
        case OPT_VENDOR: rom_add(&rom, ROLE_VENDOR, optarg, NULL); break;
        case OPT_PRODUCT: rom_add(&rom, ROLE_PRODUCT, optarg, NULL); break;
        case OPT_SYSTEM_EXT: rom_add(&rom, ROLE_SYSTEM_EXT, optarg, NULL); break;
        case OPT_ODM: rom_add(&rom, ROLE_ODM, optarg, NULL); break;
        case OPT_OEM: rom_add(&rom, ROLE_OEM, optarg, NULL); break;
        case OPT_BOOT: rom_add(&rom, ROLE_BOOT, optarg, NULL); break;
        case OPT_RAMDISK: rom_add(&rom, ROLE_RAMDISK, optarg, NULL); break;
        case OPT_PARTITION: {
            const char *eq = strchr(optarg, '=');
            if (!eq || eq == optarg || !eq[1])
                die("--partition expects NAME=PATH");
            char *name = xstrndup(optarg, (size_t)(eq - optarg));
            if (!strcmp(name, "odm"))
                rom_add(&rom, ROLE_ODM, eq + 1, NULL);
            else if (is_extra_name(name))
                rom_add(&rom, ROLE_EXTRA, eq + 1, name);
            else {
                role_t r = role_parse(name);
                if (r == ROLE_UNKNOWN || r == ROLE_AUTO || r == ROLE_SKIP || r == ROLE_EXTRA)
                    die("--partition: unknown partition '%s'", name);
                rom_add(&rom, r, eq + 1, NULL);
            }
            free(name);
            break;
        }
        case 'o': eo.output = optarg; patch_only_opt = 1; break;
        case 'z': {
            char *end;
            long l = strtol(optarg, &end, 10);
            if (*end || l < 0 || l > 9)
                die("--level must be 0..9");
            level = (int)l;
            patch_only_opt = 1;
            break;
        }
        case OPT_ENABLE: toggle(&po, optarg, 1); patch_only_opt = 1; break;
        case OPT_DISABLE: toggle(&po, optarg, 0); patch_only_opt = 1; break;
        case OPT_SET_PROP: strvec_push(&po.set_props, optarg); patch_only_opt = 1; break;
        case OPT_DEL_PROP: strvec_push(&po.del_props, optarg); patch_only_opt = 1; break;
        case OPT_DENSITY: {
            char *end;
            long d = strtol(optarg, &end, 10);
            if (*end || d < 80 || d > 1000)
                die("--density expects a dpi value between 80 and 1000");
            po.density = (int)d;
            patch_only_opt = 1;
            break;
        }
        case OPT_DISABLE_SERVICE: strvec_push(&po.disable_services, optarg); patch_only_opt = 1; break;
        case OPT_REMOVE: strvec_push(&po.remove_paths, optarg); patch_only_opt = 1; break;
        case OPT_REMOVE_APP: strvec_push(&po.remove_apps, optarg); patch_only_opt = 1; break;
        case OPT_NEW_BOOT: eo.force_new_boot = 1; patch_only_opt = 1; break;
        case 'n': dry = 1; break;
        case 'f': force = 1; break;
        case 'v': g_verbose++; break;
        case 'q': g_quiet = 1; break;
        case 'h': usage(stdout); return 0;
        case OPT_VERSION: printf(AEP_NAME " %s\n", AEP_VERSION); return 0;
        default: usage_short(stderr); return 2;
        }
    }
    if (is_patch && eo.output) {
        char *od = path_dirname(eo.output);
        temp_dir_default(od);
        free(od);
    }
    for (int i = optind; i < argc; i++)
        rom_add(&rom, ROLE_AUTO, argv[i], NULL);
    if (!rom.ninputs)
        die("no input given (try '" AEP_BIN " help')");
    if (!is_patch && patch_only_opt)
        die("patch options need the 'patch' command");

    if (is_patch && !dry) {
        if (!eo.output)
            die("no output file given (-o OUTPUT.tar)");
        int gz_name = ends_with_ci(eo.output, ".tar.gz") || ends_with_ci(eo.output, ".tgz");
        eo.zip = ends_with_ci(eo.output, ".zip");
        if (!eo.zip && !gz_name && !ends_with_ci(eo.output, ".tar"))
            die("the output must end in .zip (or .tar / .tar.gz / .tgz) so AEmulator Plus recognises it");
        eo.level = eo.zip || gz_name ? level : 0;
        struct stat st;
        if (stat(eo.output, &st) == 0 && !force)
            die("%s already exists (use -f to overwrite)", eo.output);
        for (size_t i = 0; i < rom.ninputs; i++) {
            struct stat a;
            if (stat(rom.inputs[i].path, &a) == 0 && stat(eo.output, &st) == 0 && a.st_ino == st.st_ino &&
                a.st_dev == st.st_dev)
                die("the output would overwrite the input %s", rom.inputs[i].path);
        }
    }

    rom_load(&rom);
    rom_info info;
    analyze_rom(&rom, &info);
    analyze_print(&rom, &info);
    int errors = 0;
    for (size_t i = 0; i < info.nf; i++)
        if (info.f[i].sev == SEV_ERROR)
            errors++;

    int rc = 0;
    if (!is_patch) {
        rc = errors ? 1 : 0;
    } else {
        if (errors && !force && !dry)
            die("%d error%s found; fix the inputs or use -f to write anyway", errors, errors == 1 ? "" : "s");
        patch_apply(&rom, &po);
        check_report rep;
        check_tree(rom.root, &rep);
        if (rep.unsafe_names || rep.escaping_links || rep.bad_links)
            warn("the output still has entries that abort the AEmulator Plus import (sanitize is off)");
        check_free(&rep);
        if (dry) {
            blank();
            note("Dry run: nothing written.");
        } else {
            emit_rom(&rom, &eo);
            blank();
            note("Import it on the phone: AEmulator Plus > Add firmware > %s", path_basename(eo.output));
            if (!eo.zip && eo.level)
                note("(an uncompressed .tar imports faster and needs less free space on the phone)");
        }
    }
    if (g_warnings && !g_quiet)
        fprintf(stderr, AEP_BIN ": %u warning%s\n", g_warnings, g_warnings == 1 ? "" : "s");
    analyze_free(&info);
    patch_opts_free(&po);
    rom_free(&rom);
    return rc;
}
