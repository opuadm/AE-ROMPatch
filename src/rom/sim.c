#include "rom/sim.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
    const char *name, *mcc, *mnc;
} preset;

static const preset PRESETS[] = {
    {"Android", "310", "260"},     {"MEO", "268", "06"},          {"Vodafone P", "268", "01"},
    {"NOS", "268", "03"},          {"Vivo", "724", "06"},         {"Claro BR", "724", "05"},
    {"TIM BRASIL", "724", "02"},   {"Oi", "724", "31"},           {"AT&T", "310", "410"},
    {"Verizon", "311", "480"},     {"Rogers", "302", "720"},      {"Bell", "302", "610"},
    {"TELUS", "302", "220"},       {"Telcel", "334", "020"},      {"EE", "234", "30"},
    {"Vodafone UK", "234", "15"},  {"O2 - UK", "234", "10"},      {"3", "234", "20"},
    {"Movistar", "214", "07"},     {"Vodafone ES", "214", "01"},  {"Orange", "214", "03"},
    {"Orange F", "208", "01"},     {"SFR", "208", "10"},          {"Bouygues", "208", "20"},
    {"Free", "208", "15"},         {"Telekom.de", "262", "01"},   {"Vodafone.de", "262", "02"},
    {"o2 - de", "262", "03"},      {"TIM", "222", "01"},          {"Vodafone IT", "222", "10"},
    {"WINDTRE", "222", "88"},      {"Orange PL", "260", "03"},    {"T-Mobile PL", "260", "02"},
    {"Play", "260", "06"},         {"Plus", "260", "01"},         {"Turkcell", "286", "01"},
    {"Vodafone TR", "286", "02"},  {"MTS RUS", "250", "01"},      {"MegaFon", "250", "02"},
    {"Beeline", "250", "99"},      {"Kyivstar", "255", "03"},     {"Vodafone UA", "255", "01"},
    {"Airtel", "404", "10"},       {"Jio", "405", "857"},         {"Telkomsel", "510", "10"},
    {"NTT DOCOMO", "440", "10"},   {"SoftBank", "440", "20"},
};

#define NPRESETS (sizeof PRESETS / sizeof *PRESETS)

static int attr(const char *tag, size_t len, const char *name, char *out, size_t outlen)
{
    size_t nl = strlen(name);
    for (size_t i = 0; i + nl + 2 < len; i++) {
        if (memcmp(tag + i, name, nl))
            continue;
        if (i > 0 && tag[i - 1] != ' ' && tag[i - 1] != '\t' && tag[i - 1] != '\n' && tag[i - 1] != '\r')
            continue;
        size_t p = i + nl;
        while (p < len && (tag[p] == ' ' || tag[p] == '\t'))
            p++;
        if (p >= len || tag[p] != '=')
            continue;
        p++;
        while (p < len && (tag[p] == ' ' || tag[p] == '\t'))
            p++;
        if (p >= len || (tag[p] != '"' && tag[p] != '\''))
            continue;
        char q = tag[p++];
        size_t s = p;
        while (p < len && tag[p] != q)
            p++;
        size_t vl = p - s < outlen - 1 ? p - s : outlen - 1;
        memcpy(out, tag + s, vl);
        out[vl] = 0;
        return 1;
    }
    return 0;
}

static int covered(const char *xml, size_t len, const char *mcc, const char *mnc)
{
    const char *p = xml, *end = xml + len;
    while (p < end) {
        const char *t = strstr(p, "<apn");
        if (!t || t >= end)
            break;
        const char *close = strchr(t, '>');
        if (!close)
            break;
        size_t tl = (size_t)(close - t);
        char a[32], b[32], type[256], mvno[64];
        if (attr(t, tl, "mcc", a, sizeof a) && attr(t, tl, "mnc", b, sizeof b) && !strcmp(a, mcc) && !strcmp(b, mnc) &&
            !attr(t, tl, "mvno_type", mvno, sizeof mvno)) {
            if (!attr(t, tl, "type", type, sizeof type) || strstr(type, "default") || !strcmp(type, "*"))
                return 1;
        }
        p = close + 1;
    }
    return 0;
}

static void xml_escape(buf_t *b, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '&': buf_puts(b, "&amp;"); break;
        case '"': buf_puts(b, "&quot;"); break;
        case '<': buf_puts(b, "&lt;"); break;
        case '>': buf_puts(b, "&gt;"); break;
        default: buf_putc(b, *s);
        }
    }
}

static void apn_line(buf_t *b, const preset *p)
{
    buf_puts(b, "  <apn carrier=\"");
    xml_escape(b, p->name);
    buf_printf(b, " (AEmulator)\" mcc=\"%s\" mnc=\"%s\" apn=\"internet\" type=\"default,supl,mms\" />\n", p->mcc,
               p->mnc);
}

int sim_apn_missing(vnode *root, buf_t *out, int *added)
{
    *added = 0;
    vnode *n = vfs_resolve(root, "/system/etc/apns-conf.xml");
    buf_t xml = {0};
    if (n && n->type == VN_FILE && vfs_read_all(n, &xml, 32u << 20) == 0) {
        const char *x = (const char *)xml.data;
        const char *close = NULL;
        for (const char *q = x; (q = strstr(q, "</apns>")); q++)
            close = q;
        if (!close) {
            buf_free(&xml);
            return -1;
        }
        buf_t ins = {0};
        for (size_t i = 0; i < NPRESETS; i++) {
            if (!covered(x, xml.len, PRESETS[i].mcc, PRESETS[i].mnc)) {
                apn_line(&ins, &PRESETS[i]);
                (*added)++;
            }
        }
        size_t at = (size_t)(close - x);
        while (at > 0 && (x[at - 1] == ' ' || x[at - 1] == '\t'))
            at--;
        buf_put(out, x, at);
        if (at > 0 && x[at - 1] != '\n' && ins.len)
            buf_putc(out, '\n');
        if (ins.len)
            buf_put(out, ins.data, ins.len);
        buf_put(out, x + at, xml.len - at);
        buf_free(&ins);
        buf_free(&xml);
        return 1;
    }
    buf_free(&xml);
    buf_puts(out, "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<apns version=\"8\">\n");
    for (size_t i = 0; i < NPRESETS; i++) {
        apn_line(out, &PRESETS[i]);
        (*added)++;
    }
    buf_puts(out, "</apns>\n");
    return 0;
}

static int rc_mentions(vnode *root, const char *needle)
{
    const char *const dirs[] = {"/", "/system/etc/init", "/vendor/etc/init", NULL};
    for (int d = 0; dirs[d]; d++) {
        vnode *dir = vfs_resolve(root, dirs[d]);
        if (!dir || dir->type != VN_DIR)
            continue;
        for (size_t i = 0; i < dir->nkids; i++) {
            vnode *k = dir->kids[i];
            if (k->type != VN_FILE || !ends_with(k->name, ".rc") || k->size > (4u << 20))
                continue;
            buf_t b = {0};
            int hit = vfs_read_all(k, &b, 0) == 0 && strstr((const char *)b.data, needle);
            buf_free(&b);
            if (hit)
                return 1;
        }
    }
    return 0;
}

void sim_inspect(vnode *root, const proplist *props, sim_info *si)
{
    memset(si, 0, sizeof *si);
    si->slots = 1;
    const char *v;
    if ((v = props_get(props, "persist.radio.multisim.config")) &&
        (!strcasecmp(v, "dsds") || !strcasecmp(v, "dsda") || !strcasecmp(v, "tsts"))) {
        si->slots = !strcasecmp(v, "tsts") ? 3 : 2;
        snprintf(si->why, sizeof si->why, "persist.radio.multisim.config=%s", v);
    } else if ((v = props_get(props, "persist.multisim.config")) &&
               (!strcasecmp(v, "dsds") || !strcasecmp(v, "dsda") || !strcasecmp(v, "tsts"))) {
        si->slots = 2;
        snprintf(si->why, sizeof si->why, "persist.multisim.config=%s", v);
    } else if ((v = props_get(props, "ro.multisim.simslotcount")) && atoi(v) >= 2) {
        si->slots = atoi(v);
        snprintf(si->why, sizeof si->why, "ro.multisim.simslotcount=%s", v);
    } else if ((v = props_get(props, "ro.telephony.sim.count")) && atoi(v) >= 2) {
        si->slots = atoi(v);
        snprintf(si->why, sizeof si->why, "ro.telephony.sim.count=%s", v);
    } else if ((v = props_get(props, "ro.mediatek.gemini_support")) && !strcasecmp(v, "true")) {
        si->slots = 2;
        si->mtk_gemini = 1;
        snprintf(si->why, sizeof si->why, "ro.mediatek.gemini_support=true");
    } else if (rc_mentions(root, "ril-daemon2") || rc_mentions(root, "service ril-daemon1")) {
        si->slots = 2;
        snprintf(si->why, sizeof si->why, "init scripts start a second ril-daemon");
    }
    if ((v = props_get(props, "ro.mediatek.gemini_support")) && !strcasecmp(v, "true"))
        si->mtk_gemini = 1;
    if ((v = props_get(props, "ro.telephony.ril_class")) && *v)
        snprintf(si->ril_class, sizeof si->ril_class, "%s", v);
    si->has_ril_config = props_get(props, "ro.telephony.ril.config") != NULL;
    const char *plat = props_get(props, "ro.board.platform");
    const char *hw = props_get(props, "ro.hardware");
    const char *man = props_get(props, "ro.product.manufacturer");
    int mtk = si->mtk_gemini || props_get(props, "ro.mediatek.platform") || props_get(props, "ro.mediatek.version.release") ||
              (plat && (!strncasecmp(plat, "mt", 2))) || (hw && !strncasecmp(hw, "mt", 2)) ||
              vfs_resolve(root, "/system/framework/mediatek-telephony-common.jar") ||
              vfs_resolve(root, "/system/framework/mediatek-framework.jar");
    int sprd = (plat && (!strncasecmp(plat, "sc", 2) || !strncasecmp(plat, "sp", 2) || strcasestr(plat, "unisoc"))) ||
               vfs_resolve(root, "/system/framework/sprd-framework.jar") != NULL;
    int qcom = (plat && (!strncasecmp(plat, "msm", 3) || !strncasecmp(plat, "apq", 3) || !strncasecmp(plat, "sdm", 3) ||
                         !strncasecmp(plat, "sm", 2) || !strncasecmp(plat, "qsd", 3))) ||
               vfs_resolve(root, "/system/framework/qcrilhook.jar") || vfs_resolve(root, "/system/framework/qti-telephony-common.jar") ||
               vfs_resolve(root, "/system/lib/libril-qc-qmi-1.so") || vfs_resolve(root, "/vendor/lib/libril-qc-qmi-1.so");
    int samsung = man && !strcasecmp(man, "samsung");
    if (mtk) {
        si->stack_kind = STACK_MTK;
        snprintf(si->stack, sizeof si->stack, "MediaTek (%s)", plat ? plat : "mt*");
    } else if (sprd) {
        si->stack_kind = STACK_SPRD;
        snprintf(si->stack, sizeof si->stack, "Spreadtrum/Unisoc (%s)", plat ? plat : "sc*");
    } else if (samsung) {
        si->stack_kind = STACK_SAMSUNG;
        snprintf(si->stack, sizeof si->stack, "Samsung%s%s", qcom ? " on Qualcomm " : "", qcom && plat ? plat : "");
    } else if (qcom) {
        si->stack_kind = STACK_QCOM;
        snprintf(si->stack, sizeof si->stack, "Qualcomm CAF (%s)", plat ? plat : "msm*");
    } else {
        si->stack_kind = STACK_AOSP;
        snprintf(si->stack, sizeof si->stack, "AOSP");
    }
    const char *lte = props_get(props, "telephony.lteOnCdmaDevice");
    const char *net = props_get(props, "ro.telephony.default_network");
    const char *home = props_get(props, "ro.cdma.home.operator.numeric");
    int net0 = net ? atoi(net) : -1;
    if (lte && atoi(lte) == 1) {
        si->cdma_kind = CDMA_LTE;
        snprintf(si->cdma_why, sizeof si->cdma_why, "telephony.lteOnCdmaDevice=1");
    } else if (net0 >= 4 && net0 <= 6) {
        si->cdma_kind = CDMA_ONLY;
        snprintf(si->cdma_why, sizeof si->cdma_why, "ro.telephony.default_network=%s", net);
    } else if (home && *home && net0 != 0 && net0 != 1 && net0 != 2 && net0 != 3 && net0 != 9 && net0 != 12) {
        si->cdma_kind = CDMA_ONLY;
        snprintf(si->cdma_why, sizeof si->cdma_why, "ro.cdma.home.operator.numeric=%s", home);
    }
    vnode *apn = vfs_resolve(root, "/system/etc/apns-conf.xml");
    si->apn_presets_total = (int)NPRESETS;
    if (apn && apn->type == VN_FILE) {
        si->has_apn_file = 1;
        buf_t b = {0};
        if (vfs_read_all(apn, &b, 32u << 20) == 0)
            for (size_t i = 0; i < NPRESETS; i++)
                si->apn_presets_covered += covered((const char *)b.data, b.len, PRESETS[i].mcc, PRESETS[i].mnc);
        buf_free(&b);
    }
}
