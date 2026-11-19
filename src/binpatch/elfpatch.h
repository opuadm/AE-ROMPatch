#ifndef AEP_ELFPATCH_H
#define AEP_ELFPATCH_H

#include <stddef.h>

int elf_gralloc_guard(unsigned char *data, size_t len, char *msg, size_t msglen);
int elf_sensor_retry(unsigned char *data, size_t len, char *msg, size_t msglen);
int elf_sensor_hidl_guard(unsigned char *data, size_t len, char *msg, size_t msglen);

#endif
