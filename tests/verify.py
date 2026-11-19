#!/usr/bin/env python3
import gzip
import io
import os
import re
import struct
import subprocess
import sys
import tarfile

failures = 0


def check(cond, msg):
    global failures
    if not cond:
        failures += 1
        print("    FAIL: " + msg)


def members(path):
    t = tarfile.open(path, "r:*")
    return t, {m.name.rstrip("/"): m for m in t.getmembers()}


def ramdisk(tar, m):
    img = tar.extractfile(m).read()
    assert img[:8] == b"ANDROID!"
    ksize, _, rsize = struct.unpack_from("<III", img, 8)
    page = struct.unpack_from("<I", img, 36)[0]
    roff = page * (1 + (ksize + page - 1) // page)
    rd = img[roff:roff + rsize]
    if not rd:
        return img, {}
    rd = gzip.decompress(rd) if rd[:2] == b"\x1f\x8b" else rd
    out, off = {}, 0
    while off + 110 <= len(rd):
        f = [int(rd[off + 6 + i * 8: off + 14 + i * 8], 16) for i in range(13)]
        ns = f[11]
        name = rd[off + 110: off + 110 + ns - 1].decode()
        d = (off + 110 + ns + 3) & ~3
        data = rd[d: d + f[6]]
        off = (d + f[6] + 3) & ~3
        if name == "TRAILER!!!":
            break
        out[name] = (f[1], data)
    return img, out


AE_ROOT = re.compile(r"^(system|data|dev|sbin|vendor|oem|etc)(/.*)?$")


def ae_accepts(name):
    return bool(AE_ROOT.match(name)) or bool(re.match(r"^[^/]+\.rc$", name)) or name == "default.prop" \
        or name == "boot.img" or re.match(r"^[a-z_0-9]+\.tar$", name)


def escapes(name, target):
    if target.startswith("/"):
        return False
    parts = []
    for p in (os.path.dirname(name) + "/" + target).split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if not parts:
                return True
            parts.pop()
        else:
            parts.append(p)
    return False


def common(tar, ms):
    for n, m in ms.items():
        check(ae_accepts(n), "AEmulator would drop top-level entry " + n)
        check("\\" not in n, "unsafe name " + n)
        if m.issym():
            check(not escapes(n, m.linkname), "escaping link " + n + " -> " + m.linkname)


def classic(path, srcdir):
    tar, ms = members(path)
    common(tar, ms)
    check("system/build.prop" in ms, "system/build.prop missing")
    bp = tar.extractfile(ms["system/build.prop"]).read().decode()
    check("ro.sf.lcd_density=213" in bp, "density not set in build.prop")
    check("debug.sf.nobootanimation=1" in bp, "no-bootanim prop missing")
    check("persist.test=yes" in bp, "set-prop missing")
    check("ro.build.id" not in bp, "del-prop not applied")
    check("system/etc/escaping" not in ms, "escaping link kept")
    check(not any("bad\\name" in n for n in ms), "backslash name kept")
    check("system/app/Bloat" not in ms and "system/app/Bloat/Bloat.apk" not in ms, "remove-app Bloat failed")
    check("system/app/Weather.apk" not in ms and "system/app/Weather.odex" not in ms, "remove-app Weather failed")
    check("system/media/big.bin" not in ms, "--remove glob failed")
    check(ms["system/bin/ls"].issym() and ms["system/bin/ls"].linkname == "toolbox", "relative link changed")
    check(ms["system/bin/app_process"].mode & 0o111, "exec bit lost")
    for rel in ("system/lib/libfoo.so", "system/framework/framework.jar", "system/etc/hosts"):
        a = tar.extractfile(ms[rel]).read()
        b = open(os.path.join(srcdir, "tree", rel), "rb").read()
        check(a == b, "content differs: " + rel)
    rc = tar.extractfile(ms["system/etc/init/vendorstuff.rc"]).read().decode()
    check(re.search(r"service qseecomd [^\n]*\n    disabled\n", rc) is not None, "service not disabled")
    check(rc.count("disabled") == 2, "already-disabled service changed")
    img, rd = ramdisk(tar, ms["boot.img"])
    check("init.rc" in rd and b"zygote" in rd["init.rc"][1], "init.rc not in ramdisk")
    check("default.prop" in rd and b"ro.sf.lcd_density=213" in rd["default.prop"][1], "density not in default.prop")
    check("etc" in rd and rd["etc"][1] == b"/system/etc", "/etc alias missing")
    qc = rd["init.qcom.rc"][1].decode()
    check(qc.startswith("service rmt_storage /system/bin/rmt_storage\n    disabled\n    class core \\\n        late\n"),
          "rmt_storage not disabled cleanly: " + repr(qc))
    check("fstab.qcom" in rd, "fstab lost")
    check(not any(k.startswith("system") for k in rd), "system in ramdisk")
    ksize = struct.unpack_from("<I", img, 8)[0]
    check(ksize > 0, "kernel lost")
    check(img[64:79] == b"console=ttyMSM0", "cmdline lost")


def sar(path):
    tar, ms = members(path)
    common(tar, ms)
    check("system/system" not in ms, "system-as-root not flattened")
    check("system/product/app/Maps/Maps.apk" in ms, "product not merged into system/product")
    m = ms.get("system/product/overlay/x/maps.apk")
    check(m is not None and m.issym() and m.linkname == "/product/app/Maps/Maps.apk",
          "relocated relative link not made absolute: %r" % (m.linkname if m else None))
    check(ms["system/product"].isdir(), "system/product symlink not replaced")
    check("vendor/etc/vintf/manifest.xml" in ms, "vendor missing")
    check("odm.tar" in ms, "odm.tar missing")
    inner = tarfile.open(fileobj=io.BytesIO(tar.extractfile(ms["odm.tar"]).read()))
    names = [x.name.rstrip("/") for x in inner.getmembers()]
    check("odm/lib/libodm.so" in names, "odm content missing")
    check(tar.extractfile(ms["system/inline.txt"]).read() == b"tiny", "inline data wrong")
    img, rd = ramdisk(tar, ms["boot.img"])
    check("init.environ.rc" in rd and "plat_property_contexts" in rd, "SAR root files not in ramdisk")
    check("sbin/recovery" not in rd, "recovery ramdisk leaked")
    check("default.prop" in rd and rd["default.prop"][1] == b"/system/etc/prop.default", "default.prop link wrong")
    check("data" not in rd or rd["data"][0] & 0o170000 == 0o040000, "data")
    check(struct.unpack_from("<I", img, 8)[0] > 0, "GKI kernel not kept")
    check(not any(n.startswith("dev") for n in rd), "dev in ramdisk")
    pd = tar.extractfile(ms["system/etc/prop.default"]).read().decode()
    check("ro.secure=0" in pd, "set-prop through default.prop symlink failed")


def unchanged_boot(path, orig):
    tar, ms = members(path)
    data = tar.extractfile(ms["boot.img"]).read()
    check(data == open(orig, "rb").read(), "unchanged boot.img was rebuilt")


def indirect(path, srcdir):
    tar, ms = members(path)
    a = tar.extractfile(ms["system/big.bin"]).read()
    b = open(os.path.join(srcdir, "ind/big.bin"), "rb").read()
    check(a == b, "ext2 indirect-block file differs")
    check(ms["system/ll"].linkname == "longlink_target_" + "x" * 150, "long symlink target")
    check(("system/longlink_target_" + "x" * 150) in ms, "long name")


def zmembers(path):
    import zipfile
    z = zipfile.ZipFile(path)
    check(z.testzip() is None, "zip CRC check failed")
    return z, {i.filename.rstrip("/"): i for i in z.infolist()}


def zmode(i):
    return (i.external_attr >> 16) & 0o177777


def zlink(z, ms, name):
    i = ms.get(name)
    if i is None or (zmode(i) & 0o170000) != 0o120000:
        return None
    return z.read(i).decode()


def zboot(z, ms):
    import tarfile as _t
    data = z.read(ms["boot.img"])
    bio = io.BytesIO()
    t = _t.open(fileobj=bio, mode="w")
    ti = _t.TarInfo("boot.img")
    ti.size = len(data)
    t.addfile(ti, io.BytesIO(data))
    t.close()
    bio.seek(0)
    t = _t.open(fileobj=bio)
    return ramdisk(t, t.getmember("boot.img"))


def zip_common(z, ms):
    for n in ms:
        top = n.split("/")[0]
        check(top in ("system",) or n in ("boot.img", "recovery.img") or re.match(r"^[a-z_0-9]+\.tar$", n),
              "unexpected top-level entry " + n)
        i = ms[n]
        if (zmode(i) & 0o170000) == 0o120000:
            check(not escapes(n, z.read(i).decode()), "escaping link " + n)


def cwm(path):
    z, ms = zmembers(path)
    zip_common(z, ms)
    bp = z.read(ms["system/build.prop"]).decode()
    check("ro.telephony.ril_class" not in bp, "ril_class not removed")
    check("ro.telephony.ril.config" not in bp, "ril.config not removed")
    check("persist.radio.multisim.config=ss" in bp, "single-sim not applied: " + bp)
    check("telephony.lteOnCdmaDevice=0" in bp and "ro.telephony.default_network=9,1" in bp, "gsm-modem not applied")
    check(zlink(z, ms, "system/bin/ls") == "toolbox", "updater-script symlink ls missing")
    check(zlink(z, ms, "system/bin/ps") == "toolbox", "multi-line symlink ps missing")
    check(zlink(z, ms, "system/bin/su") == "/system/xbin/su", "absolute symlink su missing")
    check(zlink(z, ms, "system/bin/sh") == "mksh", "zip unix symlink lost")
    check(zmode(ms["system/xbin/su"]) & 0o7777 == 0o6755, "set_perm su: %o" % zmode(ms["system/xbin/su"]))
    check(zmode(ms["system/bin/app_process"]) & 0o7777 == 0o755, "set_perm_recursive bin")
    check(zmode(ms["system/build.prop"]) & 0o7777 == 0o644, "set_perm_recursive files")
    check(zmode(ms["system/framework/core.jar"]) & 0o7777 == 0o600, "set_metadata")
    check("system/app/Bloat.apk" not in ms, "remove-app")
    apn = z.read(ms["system/etc/apns-conf.xml"]).decode()
    check('mcc="262" mnc="01"' in apn and apn.count('mcc="262" mnc="01"') == 1, "existing APN duplicated")
    check('carrier="AT&amp;T (AEmulator)"' in apn, "AT&T APN missing / not escaped")
    check(apn.rstrip().endswith("</apns>"), "apns end tag")
    check(not any(n.startswith("data") or n.startswith("META-INF") or n.startswith("firmware-update") for n in ms),
          "junk copied")
    img, rd = zboot(z, ms)
    rc = rd["init.rc"][1].decode()
    check("service ril-daemon2 /system/bin/rild -c 2\n    disabled\n" in rc, "ril-daemon2 not disabled")
    check(z.read(ms["system/framework/framework.jar"]) == b"fw" * 40000, "content")
    import zipfile as _zf, hashlib, zlib
    sj = _zf.ZipFile(io.BytesIO(z.read(ms["system/framework/services.jar"])))
    check(sj.testzip() is None, "services.jar CRC")
    d1, d2 = sj.read("classes.dex"), sj.read("classes2.dex")
    for d in (d1, d2):
        check(struct.unpack_from("<I", d, 8)[0] == zlib.adler32(d[12:]) & 0xFFFFFFFF, "dex adler32")
        check(d[12:32] == hashlib.sha1(d[32:]).digest(), "dex sha1")
    check(struct.pack("<3H", 0x1012, 0x1012, 0x000E) in d1, "unrelated class in classes.dex was modified")
    check(struct.pack("<2H", 0x1012, 0x000E) in d2, "unrelated method in classes2.dex was modified")
    check(struct.pack("<4H", 0x000E, 0, 0, 0) in d2 and struct.pack("<3H", 0x2012, 0x3012, 0x000E) not in d2,
          "crash site in classes2.dex not neutralised")


def blockota(path, base):
    z, ms = zmembers(path)
    zip_common(z, ms)
    bp = z.read(ms["system/build.prop"]).decode()
    check("ro.multisim.simslotcount=1" in bp and "ro.telephony.sim.count=1" in bp and
          "persist.radio.multisim.config=ss" in bp, "single-sim on samsung: " + bp)
    check("ro.boot.fake_battery=1" in bp, "fake-battery not applied")
    check(zlink(z, ms, "system/bin/app_process") == "app_process32", "ext4 symlink")
    check(z.read(ms["system/lib/libbig.so"]) == bytes(range(256)) * 4000, "brotli/transfer list content")
    check("vendor.tar" in ms, "vendor.tar missing")
    t = tarfile.open(fileobj=io.BytesIO(z.read(ms["vendor.tar"])))
    names = [m.name.rstrip("/") for m in t.getmembers()]
    check("vendor/lib/libril.so" in names, "vendor content")
    check(t.extractfile("vendor/lib/libril.so").read() == open(os.path.join(base, "ota-vendor/lib/libril.so"), "rb").read(),
          "vendor content differs")
    check(ms["system/framework/framework.jar"].compress_type == 0, "jar should be stored")
    check(ms["system/build.prop"].compress_type == 8, "text should be deflated")


def abota(path, base):
    z, ms = zmembers(path)
    zip_common(z, ms)
    bp = z.read(ms["system/build.prop"]).decode()
    check("ril_class" not in bp, "ril_class (lineage) not removed")
    check("fake_battery" not in bp, "fake-battery applied without a healthd that supports it")
    check("system/product/app/Gallery/Gallery.apk" in ms, "zstd product missing")
    check(z.read(ms["system/media/zeros.bin"]) == b"\1" + b"\0" * 900000, "ZERO op / xz content")
    check(z.read(ms["system/framework/framework.jar"]) ==
          open(os.path.join(base, "ab-root/system/framework/framework.jar"), "rb").read(), "xz content")
    t = tarfile.open(fileobj=io.BytesIO(z.read(ms["vendor.tar"])))
    vb = t.extractfile("vendor/build.prop").read().decode()
    check("persist.radio.multisim.config=ss" in vb, "vendor multisim prop not edited")
    img, rd = zboot(z, ms)
    check("init.environ.rc" in rd and "sbin/recovery" not in rd, "SAR ramdisk")
    check(b"3.18.31" in img[:8192], "kernel kept")
    apn = z.read(ms["system/etc/apns-conf.xml"]).decode()
    check(apn.count("<apn ") == 47, "apn count %d" % apn.count("<apn "))


def factory(path):
    z, ms = zmembers(path)
    zip_common(z, ms)
    check("system/build.prop" in ms, "nested image zip not read")
    check("recovery.img" in ms and z.read(ms["recovery.img"])[:8] == b"ANDROID!", "recovery passthrough")
    check("boot.img" in ms, "boot")


def samsung(path, base):
    abota(path, base)
    z, ms = zmembers(path)
    check("optics.tar" in ms, "optics.tar missing")
    t = tarfile.open(fileobj=io.BytesIO(z.read(ms["optics.tar"])))
    names = [m.name.rstrip("/") for m in t.getmembers()]
    check("optics/configs/carriers/single/XEU/conf/customer_carrier_feature.json" in names, "optics content")
    check("recovery.img" not in ms and "cache.tar" not in ms and "userdata.tar" not in ms, "unwanted images copied")


def tarimg(path):
    z, ms = zmembers(path)
    zip_common(z, ms)
    check("system/build.prop" in ms and "Nexus 5" in z.read(ms["system/build.prop"]).decode(), "system from tar")
    check("boot.img" in ms, "boot from tar")
    img, rd = zboot(z, ms)
    check("init.rc" in rd, "ramdisk")


if __name__ == "__main__":
    kind = sys.argv[1]
    globals()[kind](*sys.argv[2:])
    sys.exit(1 if failures else 0)
