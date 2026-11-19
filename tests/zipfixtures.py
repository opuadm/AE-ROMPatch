#!/usr/bin/env python3
import bz2
import ctypes
import ctypes.util
import gzip
import lzma
import os
import struct
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures import ARM_ELF, ARM64_ELF, bootimg_v0, cpio, link, mkext4, sparse, w

BLK = 4096


def brotli_compress(data):
    lib = ctypes.CDLL(ctypes.util.find_library("brotlienc") or "libbrotlienc.so.1")
    lib.BrotliEncoderMaxCompressedSize.restype = ctypes.c_size_t
    lib.BrotliEncoderMaxCompressedSize.argtypes = [ctypes.c_size_t]
    lib.BrotliEncoderCompress.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_size_t, ctypes.c_char_p,
                                          ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p]
    cap = lib.BrotliEncoderMaxCompressedSize(len(data))
    out = ctypes.create_string_buffer(cap)
    size = ctypes.c_size_t(cap)
    assert lib.BrotliEncoderCompress(5, 22, 0, len(data), data, ctypes.byref(size), out) == 1
    return out.raw[:size.value]


def zstd_compress(data):
    lib = ctypes.CDLL(ctypes.util.find_library("zstd") or "libzstd.so.1")
    lib.ZSTD_compressBound.restype = ctypes.c_size_t
    lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    lib.ZSTD_compress.restype = ctypes.c_size_t
    lib.ZSTD_compress.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
    cap = lib.ZSTD_compressBound(len(data))
    out = ctypes.create_string_buffer(cap)
    n = lib.ZSTD_compress(out, cap, data, len(data), 3)
    return out.raw[:n]


def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def mini_dex(classes):
    import hashlib, zlib
    strs = sorted({c for c, _, _, _ in classes} | {m for _, m, _, _ in classes} | {sh for _, _, sh, _ in classes} | {"V"})
    sidx = {x: i for i, x in enumerate(strs)}
    types = sorted({c for c, _, _, _ in classes} | {"V"}, key=lambda t: sidx[t])
    tidx = {t: i for i, t in enumerate(types)}
    shorties = sorted({sh for _, _, sh, _ in classes}, key=lambda x: sidx[x])
    pidx = {x: i for i, x in enumerate(shorties)}
    n_s, n_t, n_p, n_m, n_c = len(strs), len(types), len(shorties), len(classes), len(classes)
    off = 0x70
    s_off = off; off += 4 * n_s
    t_off = off; off += 4 * n_t
    p_off = off; off += 12 * n_p
    m_off = off; off += 8 * n_m
    c_off = off; off += 32 * n_c
    data = bytearray()
    def place(b, align=1):
        nonlocal data
        while (off + len(data)) % align:
            data.append(0)
        at = off + len(data)
        data += b
        return at
    codes = []
    for _, _, _, insns in classes:
        body = struct.pack("<HHHHII", 3, 3, 0, 0, 0, len(insns)) + b"".join(struct.pack("<H", x) for x in insns)
        codes.append(place(body, 4))
    cdata = [place(uleb(0) + uleb(0) + uleb(0) + uleb(1) + uleb(i) + uleb(1) + uleb(codes[i])) for i in range(n_c)]
    sdata = [place(uleb(len(x)) + x.encode() + b"\0") for x in strs]
    total = off + len(data)
    d = bytearray(total)
    d[0:8] = b"dex\n035\0"
    struct.pack_into("<I", d, 0x20, total)
    struct.pack_into("<I", d, 0x24, 0x70)
    struct.pack_into("<I", d, 0x28, 0x12345678)
    struct.pack_into("<II", d, 0x38, n_s, s_off)
    struct.pack_into("<II", d, 0x40, n_t, t_off)
    struct.pack_into("<II", d, 0x48, n_p, p_off)
    struct.pack_into("<II", d, 0x58, n_m, m_off)
    struct.pack_into("<II", d, 0x60, n_c, c_off)
    struct.pack_into("<II", d, 0x68, len(data), off)
    for i, x in enumerate(strs):
        struct.pack_into("<I", d, s_off + 4 * i, sdata[i])
    for i, t in enumerate(types):
        struct.pack_into("<I", d, t_off + 4 * i, sidx[t])
    for i, sh in enumerate(shorties):
        struct.pack_into("<III", d, p_off + 12 * i, sidx[sh], tidx["V"], 0)
    for i, (c, m, sh, _) in enumerate(classes):
        struct.pack_into("<HHI", d, m_off + 8 * i, tidx[c], pidx[sh], sidx[m])
        struct.pack_into("<IIIIIIII", d, c_off + 32 * i, tidx[c], 1, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, cdata[i], 0)
    d[off:] = data
    d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
    struct.pack_into("<I", d, 8, zlib.adler32(bytes(d[12:])) & 0xFFFFFFFF)
    return bytes(d)


TARGET_CLASS = "Lcom/android/server/ethernet/EthernetNetworkFactory$UsbShareNetStateReceiver;"


def services_jar():
    import io
    keep = mini_dex([("Lcom/android/server/Keep;", "onReceive", "VLL", [0x1012, 0x1012, 0x000E])])
    target = mini_dex([("Lcom/android/server/Other;", "run", "V", [0x1012, 0x000E]),
                       (TARGET_CLASS, "onReceive", "VLL", [0x1012, 0x2012, 0x3012, 0x000E])])
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as j:
        j.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        j.writestr("classes.dex", keep)
        j.writestr("classes2.dex", target)
    return bio.getvalue()


def unix_entry(z, name, data, mode, compress=zipfile.ZIP_DEFLATED):
    info = zipfile.ZipInfo(name, (2015, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = compress
    z.writestr(info, data)


def legacy_boot(rc_extra=b""):
    rd = cpio([
        ("init", 0o100750, ARM_ELF),
        ("init.rc", 0o100750, b"on init\n    export BOOTCLASSPATH /system/framework/core.jar\n\n"
                              b"service zygote /system/bin/app_process -Xzygote /system/bin --zygote\n    class main\n\n"
                              b"service ril-daemon /system/bin/rild\n    class main\n\n"
                              b"service ril-daemon2 /system/bin/rild -c 2\n    class main\n" + rc_extra),
        ("default.prop", 0o100644, b"ro.secure=1\n"),
    ])
    return bootimg_v0(b"\0" * 32 + b"Linux version 3.4.67 (b@h) #1\0", gzip.compress(rd))


def cwm(base):
    out = os.path.join(base, "cwm.zip")
    with zipfile.ZipFile(out, "w") as z:
        unix_entry(z, "system/build.prop", "ro.build.version.sdk=17\nro.build.version.release=4.2.2\n"
                   "ro.product.brand=Xiaomi\nro.product.model=HM 1S\nro.miui.ui.version.name=V5\n"
                   "persist.radio.multisim.config=dsds\nro.telephony.ril_class=MediaTekRIL\n"
                   "ro.telephony.ril.config=signalstrength\nro.product.cpu.abi=armeabi-v7a\n"
                   "telephony.lteOnCdmaDevice=1\nro.telephony.default_network=22,1\n", 0o100644)
        z.writestr("system/bin/app_process", ARM_ELF)
        z.writestr("system/bin/toolbox", ARM_ELF + b"\0ls\0ps\0")
        unix_entry(z, "system/bin/mksh", ARM_ELF, 0o100755)
        unix_entry(z, "system/bin/sh", b"mksh", 0o120777, zipfile.ZIP_STORED)
        z.writestr("system/framework/core.jar", os.urandom(30000))
        z.writestr("system/framework/framework.jar", b"fw" * 40000)
        z.writestr("system/app/MiuiHome.apk", os.urandom(20000))
        z.writestr("system/app/Bloat.apk", os.urandom(10000))
        z.writestr("system/etc/apns-conf.xml",
                   '<?xml version="1.0"?>\n<apns version="7">\n  <apn carrier="T-Online" mcc="262" mnc="01" apn="internet.t-mobile" type="default,supl" />\n</apns>\n')
        z.writestr("system/xbin/su", ARM_ELF)
        z.writestr("system/framework/services.jar", services_jar())
        z.writestr("system/app/miui/miui.apk", b"PK")
        z.writestr("boot.img", legacy_boot())
        z.writestr("META-INF/com/google/android/update-binary", b"#!/sbin/sh\n")
        z.writestr("META-INF/com/google/android/updater-script",
                   'ui_print("installing");\nmount("ext4", "EMMC", "/dev/block/system", "/system");\n'
                   'package_extract_dir("system", "/system");\n'
                   'symlink("toolbox", "/system/bin/ls",\n        "/system/bin/ps");\n'
                   'symlink("/system/xbin/su", "/system/bin/su");\n'
                   'set_perm_recursive(0, 0, 0755, 0644, "/system");\n'
                   'set_perm_recursive(0, 2000, 0755, 0755, "/system/bin");\n'
                   'set_perm(0, 0, 06755, "/system/xbin/su");\n'
                   'set_metadata("/system/framework/core.jar", "uid", 0, "gid", 0, "mode", 0600);\n'
                   'symlink("/data/evil", "/data/x");\n')
        z.writestr("firmware-update/tz.mbn", b"\0" * 100)
    return out


def transfer_list(raw_path):
    data = open(raw_path, "rb").read()
    n = len(data) // BLK
    new, zero = [], []
    i = 0
    while i < n:
        isz = data[i * BLK:(i + 1) * BLK] == b"\0" * BLK
        j = i
        while j < n and (data[j * BLK:(j + 1) * BLK] == b"\0" * BLK) == isz:
            j += 1
        (zero if isz else new).append((i, j))
        i = j
    rs = lambda rr: "%d,%s" % (len(rr) * 2, ",".join("%d,%d" % r for r in rr))
    newdata = b"".join(data[a * BLK:b * BLK] for a, b in new)
    text = "4\n%d\n0\n0\nerase %s\nnew %s\nzero %s\n" % (n, rs([(0, n)]), rs(new), rs(zero))
    return text, newdata


def blockota(base):
    s = os.path.join(base, "ota-sys")
    w(s + "/build.prop", "ro.build.version.sdk=23\nro.build.version.release=6.0.1\nro.product.brand=samsung\n"
      "ro.product.manufacturer=samsung\nro.product.model=SM-G920F\nro.multisim.simslotcount=2\n"
      "persist.radio.multisim.config=dsds\nro.telephony.sim.count=2\n")
    w(s + "/framework/twframework.jar", b"tw")
    w(s + "/framework/framework.jar", os.urandom(300000))
    w(s + "/bin/app_process32", ARM_ELF, 0o755)
    w(s + "/bin/healthd", ARM_ELF + b"\0%s/%s/capacity\0ro.boot.fake_battery\0", 0o755)
    link("app_process32", s + "/bin/app_process")
    w(s + "/lib/libbig.so", bytes(range(256)) * 4000)
    mkext4(s, os.path.join(base, "ota-sys.raw"), 16)
    v = os.path.join(base, "ota-vendor")
    w(v + "/build.prop", "ro.product.vendor.model=SM-G920F\n")
    w(v + "/lib/libril.so", os.urandom(50000))
    mkext4(v, os.path.join(base, "ota-vendor.raw"), 8)
    out = os.path.join(base, "blockota.zip")
    st, sd = transfer_list(os.path.join(base, "ota-sys.raw"))
    vt, vd = transfer_list(os.path.join(base, "ota-vendor.raw"))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("system.transfer.list", st)
        z.writestr("system.new.dat.br", brotli_compress(sd), zipfile.ZIP_STORED)
        z.writestr("system.patch.dat", b"")
        z.writestr("vendor.transfer.list", vt)
        z.writestr("vendor.new.dat", vd)
        z.writestr("boot.img", legacy_boot())
        z.writestr("META-INF/com/google/android/updater-script", 'block_image_update("/dev/block/system", ...);\n')
    return out


def varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def field(num, wt, payload):
    key = varint((num << 3) | wt)
    if wt == 0:
        return key + varint(payload)
    return key + varint(len(payload)) + payload


def payload_bin(parts):
    blobs = bytearray()
    manifest = field(3, 0, BLK)
    for name, data, codec in parts:
        nb = (len(data) + BLK - 1) // BLK
        data = data + b"\0" * (nb * BLK - len(data))
        ops = b""
        chunk = 64
        for start in range(0, nb, chunk):
            cnt = min(chunk, nb - start)
            piece = data[start * BLK:(start + cnt) * BLK]
            ext = field(6, 2, field(1, 0, start) + field(2, 0, cnt))
            if piece == b"\0" * len(piece):
                ops += field(8, 2, field(1, 0, 6) + ext)
                continue
            t, comp = {"raw": (0, piece), "xz": (8, lzma.compress(piece)), "bz": (1, bz2.compress(piece)),
                       "zstd": (14, zstd_compress(piece))}[codec]
            off = len(blobs)
            blobs += comp
            ops += field(8, 2, field(1, 0, t) + field(2, 0, off) + field(3, 0, len(comp)) + ext)
        info = field(1, 0, nb * BLK)
        manifest += field(13, 2, field(1, 2, name.encode()) + field(7, 2, info) + ops)
    hdr = b"CrAU" + struct.pack(">QQI", 2, len(manifest), 0)
    return hdr + manifest + bytes(blobs)


def payload(base):
    r = os.path.join(base, "ab-root")
    w(r + "/init", ARM64_ELF, 0o750)
    w(r + "/init.rc", "import /init.environ.rc\nservice zygote /system/bin/app_process64 -Xzygote\n    class main\n")
    w(r + "/init.environ.rc", "on early-init\n    export BOOTCLASSPATH /system/framework/framework.jar\n")
    link("/system/etc", r + "/etc")
    os.makedirs(r + "/vendor")
    s = r + "/system"
    w(s + "/build.prop", "ro.build.version.sdk=25\nro.build.version.release=7.1.2\nro.product.system.brand=Xiaomi\n"
      "ro.product.system.model=Redmi Note 4\nro.lineage.version=14.1\nro.telephony.ril_class=XiaomiRIL\n"
      "ro.product.cpu.abi=arm64-v8a\n")
    w(s + "/framework/framework.jar", os.urandom(200000))
    w(s + "/bin/app_process64", ARM64_ELF, 0o755)
    w(s + "/etc/apns-conf.xml", '<apns version="8">\n</apns>\n')
    w(s + "/media/zeros.bin", b"\1" + b"\0" * 900000)
    mkext4(r, os.path.join(base, "ab-system.raw"), 24)
    v = os.path.join(base, "ab-vendor")
    w(v + "/build.prop", "ro.product.vendor.model=mido\npersist.radio.multisim.config=dsds\n")
    w(v + "/etc/vintf/manifest.xml", "<manifest/>")
    mkext4(v, os.path.join(base, "ab-vendor.raw"), 8)
    p = os.path.join(base, "ab-product")
    w(p + "/app/Gallery/Gallery.apk", os.urandom(8000))
    mkext4(p, os.path.join(base, "ab-product.raw"), 8)
    rd = cpio([("sbin", 0o40750, b""), ("sbin/recovery", 0o100750, ARM64_ELF), ("init.rc", 0o100750, b"on init\n")])
    boot = bootimg_v0(b"Linux version 3.18.31-perf (b@h) #1\0" + b"\0" * 3000, gzip.compress(rd))
    w(os.path.join(base, "ab-boot.img"), boot)
    pl = payload_bin([
        ("boot", boot, "raw"),
        ("system", open(os.path.join(base, "ab-system.raw"), "rb").read(), "xz"),
        ("vendor", open(os.path.join(base, "ab-vendor.raw"), "rb").read(), "bz"),
        ("product", open(os.path.join(base, "ab-product.raw"), "rb").read(), "zstd"),
        ("dtbo", b"\xd7\xb7\xab\x1e" + b"\0" * 5000, "raw"),
    ])
    out = os.path.join(base, "payload.zip")
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("payload.bin", pl, zipfile.ZIP_STORED)
        z.writestr("payload_properties.txt", "FILE_HASH=x\n")
        z.writestr("META-INF/com/android/metadata", "ota-type=AB\n")
    inc = os.path.join(base, "incremental.zip")
    with zipfile.ZipFile(inc, "w") as z:
        bad = payload_bin([("system", b"\1" * 8192, "raw")])
        bad = bad.replace(field(1, 0, 0) + field(2, 0, 0), field(1, 0, 5) + field(2, 0, 0), 1)
        z.writestr("payload.bin", bad, zipfile.ZIP_STORED)
    return out


def factory(base):
    s = os.path.join(base, "fac-sys")
    w(s + "/build.prop", "ro.build.version.sdk=22\nro.build.version.release=5.1.1\nro.product.brand=google\n"
      "ro.product.model=Nexus 5\n")
    w(s + "/framework/framework.jar", b"x" * 1000)
    w(s + "/bin/app_process32", ARM_ELF, 0o755)
    mkext4(s, os.path.join(base, "fac-sys.raw"), 8)
    sparse(os.path.join(base, "fac-sys.raw"), os.path.join(base, "fac-system.img"))
    inner = os.path.join(base, "image-hammerhead-lmy48m.zip")
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(os.path.join(base, "fac-system.img"), "system.img")
        z.writestr("boot.img", legacy_boot())
        z.writestr("recovery.img", b"ANDROID!" + b"\0" * 4000)
        z.writestr("android-info.txt", "require board=hammerhead\n")
    out = os.path.join(base, "factory.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(inner, "hammerhead-lmy48m/image-hammerhead-lmy48m.zip")
        z.writestr("hammerhead-lmy48m/flash-all.sh", "fastboot -w update image.zip\n")
        z.writestr("hammerhead-lmy48m/bootloader-hammerhead.img", b"\0" * 1000)
    return out


if __name__ == "__main__":
    base = sys.argv[1]
    os.makedirs(base, exist_ok=True)
    cwm(base)
    blockota(base)
    payload(base)
    factory(base)
