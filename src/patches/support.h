#ifndef AEP_PATCHES_SUPPORT_H
#define AEP_PATCHES_SUPPORT_H

#include "core/util.h"
#include "core/vfs.h"
#include "rom/rom.h"

typedef struct {
    vnode **v;
    char **paths;
    size_t n, cap;
} nodelist;

void nl_push(nodelist *l, vnode *n, const char *path);
void nl_free(nodelist *l);

void change(const char *fmt, ...) AEP_PRINTF(1, 2);
void changes_reset(void);
unsigned changes_count(void);

int rom_api_level(rom_t *rom);

void replace_text(vnode *n, char *text);
void replace_contents(vnode *n, unsigned char *data, size_t len);

int valid_prop_key(const char *key);
int prop_defined(rom_t *rom, const char *key);
void edit_prop(rom_t *rom, const char *key, const char *val);

int disable_service(rom_t *rom, const char *name, int quiet);

char *write_target(vnode *root, const char *path);
const char *find_str(const char *s, const char *end, const char *pat);

#endif
