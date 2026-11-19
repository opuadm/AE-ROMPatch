#!/bin/sh
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
${CROSS:-aarch64-linux-gnu-}gcc -O2 -fPIC -shared -nostdlib -ffreestanding -fno-builtin -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-unwind-tables -fvisibility=hidden -mbranch-protection=none -mno-outline-atomics \
    -Wl,-soname,sensors.aerompatch.so -Wl,--hash-style=both -Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack \
    -Wl,-z,max-page-size=4096 -Wl,--build-id=none -s -o "$out/sensors.so" "$here/sensors.c"
python3 - "$out/sensors.so" "$here/../src/patches/sensorhal.h" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
with open(sys.argv[2], "w") as f:
    f.write("#ifndef AEP_SENSORHAL_H\n#define AEP_SENSORHAL_H\n\nstatic const unsigned char SENSORHAL_SO[] = {\n")
    for i in range(0, len(d), 16):
        f.write("    " + ", ".join("0x%02x" % b for b in d[i:i + 16]) + ",\n")
    f.write("};\n\n#endif\n")
PY
