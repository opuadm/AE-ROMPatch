#ifndef AEP_CHECK_H
#define AEP_CHECK_H

#include "core/util.h"
#include "core/vfs.h"

typedef struct {
    unsigned unsafe_names;
    unsigned escaping_links;
    unsigned bad_links;
    int system_not_dir;
    strvec traps;
} check_report;

int name_unsafe(const char *name);
int link_bad(const char *target);
int link_escapes(const char *node_path, const char *target);
const char *import_trap(const char *path, uint64_t size);
void check_tree(vnode *root, check_report *rep);
void check_free(check_report *rep);

#endif
