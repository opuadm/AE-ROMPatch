#include "core/about.h"
#include "cli/help.h"

#include <string.h>

#include "patches/patch.h"

#define WRAP_COLUMN 78

static void print_wrapped(FILE *f, const char *text, int indent)
{
    int col = indent;
    const char *p = text;
    while (*p) {
        const char *end = strchr(p, ' ');
        int len = end ? (int)(end - p) : (int)strlen(p);
        if (col > indent && col + 1 + len > WRAP_COLUMN) {
            fprintf(f, "\n%*s", indent, "");
            col = indent;
        } else if (col > indent) {
            fputc(' ', f);
            col++;
        }
        fprintf(f, "%.*s", len, p);
        col += len;
        p += len;
        while (*p == ' ')
            p++;
    }
    fputc('\n', f);
}

void help_edits(FILE *f)
{
    fprintf(f,
            "EDIT OPTIONS (apply only when given, on top of the patches)\n"
            "      --set-prop K=V      set a property in every file that defines it (added\n"
            "                          to /system/build.prop when defined nowhere)\n"
            "      --del-prop KEY      remove a property from every property file\n"
            "      --density DPI       set ro.sf.lcd_density (AEmulator derives the default\n"
            "                          VM screen from it at import)\n"
            "      --disable-service NAME\n"
            "                          mark an init service 'disabled' in every .rc file\n"
            "      --remove PATH       remove a guest path; shell globs allowed\n"
            "                          (e.g. '/system/app/*Weather*')\n"
            "      --remove-app NAME   remove an app from the (priv-)app folders of system,\n"
            "                          product, system_ext and vendor\n"
            "\n"
            "EXAMPLES\n"
            "  Set the screen density:\n"
            "    aerompatch patch --density 320 ROM.zip -o ROM-ae.zip\n"
            "  Remove apps and a service:\n"
            "    aerompatch patch --remove-app Bloat --disable-service vendor.foo ROM.zip -o out.zip\n"
            );
}

void help_patches(FILE *f)
{
    fprintf(f, "Patches (toggle with --enable NAME / --disable NAME; 'all' means every patch)\n\n");
    for (int i = 0; PATCHES[i].name; i++) {
        fprintf(f, "  %-16s [%s]\n", PATCHES[i].name, PATCHES[i].default_on ? "on by default" : "off by default");
        fprintf(f, "      ");
        print_wrapped(f, PATCHES[i].summary, 6);
        fputc('\n', f);
    }
    fprintf(f, "Option-driven edits (--set-prop, --remove-app, ...): 'aerompatch help edits'.\n");
}

void usage_short(FILE *f)
{
    fprintf(f,
            AEP_BANNER "\n"
            "\n"
            "Usage:\n"
            "  aerompatch patch [OPTIONS] INPUT... -o OUTPUT.zip\n"
            "  aerompatch info  INPUT...\n"
            "  aerompatch patches\n"
            "  aerompatch help [edits|patches]\n"
            "\n"
            "Run 'aerompatch help' for all options and examples.\n");
}

void usage(FILE *f)
{
    fprintf(f,
            AEP_BANNER "\n"
            "\n"
            "USAGE\n"
            "  aerompatch patch [OPTIONS] INPUT... -o OUTPUT.zip\n"
            "  aerompatch info  [INPUT OPTIONS] INPUT...\n"
            "  aerompatch patches\n"
            "  aerompatch help | --help | --version\n"
            "\n"
            "COMMANDS\n"
            "  patch    Read a ROM, apply the patches below and write a new zip that\n"
            "           AEmulator Plus imports with \"Add firmware\".\n"
            "  info     Analyse a ROM (Android version, ABI, partitions, known problems)\n"
            "           and write nothing. Exit status 1 when errors were found.\n"
            "  patches  List every patch with its default state and a full description.\n"
            "  help     Show this page.\n"
            "\n"
            "INPUTS\n"
            "  Give one or more files or folders; their roles are detected automatically\n"
            "  and several inputs are merged into one ROM.\n"
            "    Archives    recovery/flashable zips (system/ + updater-script),\n"
            "                system.new.dat[.br] + transfer.list, A/B payload.bin,\n"
            "                factory zips with a nested image-*.zip, Xiaomi fastboot\n"
            "                .tgz, OPPO/realme .ozip (published keys)\n"
            "    Samsung     the firmware zip, or AP_*.tar.md5 and CSC_*.tar.md5 (.lz4\n"
            "                images and super.img are unpacked)\n"
            "    Images      boot.img, ramdisk, super.img, raw/sparse ext4 and EROFS\n"
            "    Folders     a system tree or a full root tree\n"
            "\n"
            "INPUT OPTIONS (force the role of a file or folder)\n"
            "  --root PATH  --system PATH  --vendor PATH  --product PATH\n"
            "  --system-ext PATH  --odm PATH  --oem PATH  --boot PATH  --ramdisk PATH\n"
            "  --partition NAME=PATH   skin partitions (my_*, mi_ext, vgc, prism, optics)\n"
            "\n"
            "PATCH OPTIONS\n"
            "  -o, --output FILE       output ROM: .zip (recommended), .tar, .tar.gz, .tgz\n"
            "  -z, --level N           compression level 0-9 (default 6; 0 = store)\n"
            "      --enable NAME[,..]  turn a patch on\n"
            "      --disable NAME[,..] turn a patch off ('all' for every patch)\n"
            "      (more: --set-prop, --del-prop, --density, --disable-service, --remove,\n"
            "       --remove-app; see 'aerompatch help edits')\n"
            "      --new-boot          always rebuild boot.img, even if unchanged\n"
            "  -n, --dry-run           show what would change, write nothing\n"
            "  -f, --force             overwrite OUTPUT; write even if errors were found\n"
            "\n"
            "GENERAL OPTIONS\n"
            "  -v, --verbose           more detail (repeat for debug output)\n"
            "  -q, --quiet             only warnings and errors\n"
            "  -h, --help              this help\n"
            "      --version           print the version\n"
            "\n"
            "EXAMPLES\n"
            "  Patch a ROM with the default patches:\n"
            "    aerompatch patch ROM.zip -o ROM-ae.zip\n"
            "  Check what would change without writing anything:\n"
            "    aerompatch patch -n ROM.zip\n"
            "  Overwrite an earlier output, with fixed battery and no dual SIM handling:\n"
            "    aerompatch patch -f --enable fake-battery --disable single-sim ROM.zip -o ROM-ae.zip\n"
            "  Only the mandatory import fixes:\n"
            "    aerompatch patch --disable all --enable sanitize ROM.zip -o ROM-ae.zip\n"
            "  Merge separate partitions:\n"
            "    aerompatch patch --system system.img --vendor vendor.img boot.img -o out.zip\n"
            "\n"
            "NOTES\n"
            "  * Patches are rule-based: each one looks at what the ROM contains and acts\n"
            "    only when it applies, so they are safe on ROMs they do not concern.\n"
            "  * Temporary images go to $TMPDIR, else next to the output (/var/tmp without\n"
            "    one). Compressed images, block OTAs and payload.bin need free space there\n"
            "    about the size of the unpacked partitions.\n"
            "  * Import the result on the phone: AEmulator Plus > Add firmware.\n"
            "  * An uncompressed .tar imports faster and needs less space on the phone.\n"
            "\n");
    fprintf(f, "\nMore: 'aerompatch patches' (every patch), 'aerompatch help edits' (--set-prop, --remove-app, ...).\n");
}
