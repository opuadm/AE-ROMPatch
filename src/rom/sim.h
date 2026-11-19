#ifndef AEP_SIM_H
#define AEP_SIM_H

#include "core/props.h"
#include "core/vfs.h"

#define SIM_FIRST_API 9
#define SIM_LAST_API 25

enum { CDMA_NONE, CDMA_LTE, CDMA_ONLY };
enum { STACK_AOSP, STACK_QCOM, STACK_MTK, STACK_SAMSUNG, STACK_SPRD };

typedef struct {
    int slots;
    char why[160];
    int mtk_gemini;
    char ril_class[128];
    int has_ril_config;
    int has_apn_file;
    int apn_presets_covered;
    int apn_presets_total;
    char stack[96];
    int cdma_kind;
    char cdma_why[96];
    int stack_kind;
} sim_info;

void sim_inspect(vnode *root, const proplist *props, sim_info *si);
int sim_apn_missing(vnode *root, buf_t *xml_out, int *added);

#endif
