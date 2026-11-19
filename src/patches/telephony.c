#include <stdlib.h>
#include <string.h>

#include "core/props.h"
#include "core/util.h"
#include "core/vfs.h"
#include "patches/patches.h"
#include "patches/support.h"
#include "rom/sim.h"

static const int CDMA_NETWORK_MODES[] = {4, 5, 6, 7, 8, 10, 21, 22};

typedef struct {
    proplist props;
    sim_info sim;
    int api;
} sim_view;

static void sim_view_open(sim_view *v, rom_t *rom)
{
    memset(v, 0, sizeof *v);
    props_collect(rom->root, &v->props);
    v->api = rom_api_level(rom);
    sim_inspect(rom->root, &v->props, &v->sim);
}

static void sim_view_close(sim_view *v)
{
    props_free(&v->props);
}

static int api_in_sim_range(int api)
{
    return api >= SIM_FIRST_API && api <= SIM_LAST_API;
}

static void note_unsupported_api(const sim_view *v)
{
    static int noted;
    if (noted || api_in_sim_range(v->api))
        return;
    noted = 1;
    note("  - SIM: Android API %d; AEmulator Plus emulates a SIM card for Android 2.3-7.1 (API %d-%d) only, so no SIM "
         "will show up on this ROM (the SIM-slot and APN edits below are harmless)",
         v->api, SIM_FIRST_API, SIM_LAST_API);
}

static int is_cdma_mode(int mode)
{
    for (size_t i = 0; i < sizeof CDMA_NETWORK_MODES / sizeof *CDMA_NETWORK_MODES; i++)
        if (CDMA_NETWORK_MODES[i] == mode)
            return 1;
    return 0;
}

static char *gsm_network_modes(const char *modes, int *changed)
{
    buf_t out = {0};
    char *copy = xstrdup(modes);
    *changed = 0;
    for (char *save = NULL, *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        int mode = atoi(tok);
        int cdma = is_cdma_mode(mode);
        buf_printf(&out, "%s%d", out.len ? "," : "", cdma ? 9 : mode);
        *changed |= cdma;
    }
    free(copy);
    return (char *)buf_steal(&out, NULL);
}

void patch_sim(rom_t *rom, const patch_opts *opts)
{
    sim_view v;
    sim_view_open(&v, rom);
    note_unsupported_api(&v);
    if (v.sim.ril_class[0])
        edit_prop(rom, "ro.telephony.ril_class", NULL);
    if (v.sim.has_ril_config)
        edit_prop(rom, "ro.telephony.ril.config", NULL);
    sim_view_close(&v);
}

void patch_gsm_modem(rom_t *rom, const patch_opts *opts)
{
    sim_view v;
    sim_view_open(&v, rom);
    const char *lte = props_get(&v.props, "telephony.lteOnCdmaDevice");
    if (api_in_sim_range(v.api) && lte && atoi(lte) == 1) {
        change("gsm-modem: ROM declares LTE on CDMA; AEmulator Plus would start its CDMA modem, switching to GSM");
        edit_prop(rom, "telephony.lteOnCdmaDevice", "0");
        const char *net = props_get(&v.props, "ro.telephony.default_network");
        if (net) {
            int changed;
            char *modes = gsm_network_modes(net, &changed);
            if (changed)
                edit_prop(rom, "ro.telephony.default_network", modes);
            free(modes);
        }
        note("  - gsm-modem: to keep the CDMA modem instead, use --disable gsm-modem");
    }
    sim_view_close(&v);
}

static void set_multisim_props(rom_t *rom, const char *value)
{
    if (prop_defined(rom, "persist.radio.multisim.config"))
        edit_prop(rom, "persist.radio.multisim.config", value);
    if (prop_defined(rom, "persist.multisim.config"))
        edit_prop(rom, "persist.multisim.config", value);
    if (prop_defined(rom, "ro.multisim.simslotcount"))
        edit_prop(rom, "ro.multisim.simslotcount", !strcmp(value, "ss") ? "1" : "2");
    if (prop_defined(rom, "ro.telephony.sim.count"))
        edit_prop(rom, "ro.telephony.sim.count", !strcmp(value, "ss") ? "1" : "2");
}

void patch_single_sim(rom_t *rom, const patch_opts *opts)
{
    if (opts->enabled[patch_index("dual-sim")])
        return;
    sim_view v;
    sim_view_open(&v, rom);
    note_unsupported_api(&v);
    if (v.sim.slots >= 2) {
        change("single-sim: ROM declares %d SIM slots (%s), switching to one", v.sim.slots, v.sim.why);
        set_multisim_props(rom, "ss");
        if (!prop_defined(rom, "persist.radio.multisim.config") && !v.sim.mtk_gemini)
            edit_prop(rom, "persist.radio.multisim.config", "ss");
        if (v.sim.mtk_gemini)
            note("  - single-sim: MediaTek Gemini builds have dual SIM compiled into the framework; slot 2 stays empty");
        disable_service(rom, "ril-daemon2", 1);
        disable_service(rom, "ril-daemon1", 1);
    }
    sim_view_close(&v);
}

void patch_dual_sim(rom_t *rom, const patch_opts *opts)
{
    sim_view v;
    sim_view_open(&v, rom);
    note_unsupported_api(&v);
    if (v.sim.slots < 2) {
        warn("dual-sim: this ROM is built for one SIM slot; dual SIM cannot be turned on by properties alone");
    } else {
        if (prop_defined(rom, "persist.radio.multisim.config") || !v.sim.mtk_gemini)
            edit_prop(rom, "persist.radio.multisim.config", "dsds");
        if (prop_defined(rom, "ro.multisim.simslotcount"))
            edit_prop(rom, "ro.multisim.simslotcount", "2");
        if (prop_defined(rom, "ro.telephony.sim.count"))
            edit_prop(rom, "ro.telephony.sim.count", "2");
        note("  - dual-sim: both slots kept. AEmulator Plus currently runs one fake modem (socket \"rild\"), so "
             "slot 2 shows \"No SIM\" until the app serves a second modem (\"rild2\")");
    }
    sim_view_close(&v);
}

void patch_apn(rom_t *rom, const patch_opts *opts)
{
    buf_t xml = {0};
    int added = 0;
    int r = sim_apn_missing(rom->root, &xml, &added);
    if (r < 0) {
        warn("apn: /system/etc/apns-conf.xml has no </apns> end tag; left unchanged");
    } else if (added) {
        vnode *etc = vfs_resolve(rom->root, "/system/etc");
        if (!etc || etc->type != VN_DIR) {
            debug("apn: no /system/etc");
        } else {
            vnode *n = vfs_resolve(rom->root, "/system/etc/apns-conf.xml");
            if (n && n->type == VN_FILE)
                replace_text(n, (char *)buf_steal(&xml, NULL));
            else
                vfs_write_text(rom->root, "/system/etc/apns-conf.xml", (const char *)xml.data, xml.len, 0644);
            change("/system/etc/apns-conf.xml: %s %d APN%s for AEmulator's operator presets",
                   r ? "added" : "created with", added, added == 1 ? "" : "s");
        }
    }
    buf_free(&xml);
}
