#!/usr/bin/env python3
import gzip
import os
import shutil
import struct
import subprocess
import sys

ARM_ELF = b"\x7fELF\x01\x01\x01" + b"\0" * 9 + struct.pack("<HHI", 3, 40, 1) + b"\0" * 64
ARM64_ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<HHI", 3, 183, 1) + b"\0" * 64
MIPS_ELF = b"\x7fELF\x01\x01\x01" + b"\0" * 9 + struct.pack("<HHI", 3, 8, 1) + b"\0" * 64


def w(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, mode)


def link(target, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.symlink(target, path)


def cpio(entries):
    out = bytearray()
    ino = 1000
    for name, mode, data in entries + [("TRAILER!!!", 0, b"")]:
        nb = name.encode() + b"\0"
        hdr = "070701" + "".join("%08X" % v for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0))
        out += hdr.encode() + nb
        out += b"\0" * ((-len(out)) % 4)
        out += data
        out += b"\0" * ((-len(out)) % 4)
        ino += 1
    return bytes(out)


def bootimg_v0(kernel, ramdisk, page=2048, cmdline=b"console=ttyMSM0"):
    h = bytearray(page)
    h[0:8] = b"ANDROID!"
    struct.pack_into("<IIIIIIIII", h, 8, len(kernel), 0x10008000, len(ramdisk), 0x11000000, 0, 0x10F00000, 0x10000100, page, 0)
    h[48:48 + 8] = b"testboot"
    h[64:64 + len(cmdline)] = cmdline
    pad = lambda b: b + b"\0" * ((-len(b)) % page)
    return bytes(h) + pad(kernel) + pad(ramdisk)


def bootimg_v3(kernel, ramdisk):
    h = bytearray(4096)
    h[0:8] = b"ANDROID!"
    struct.pack_into("<IIII", h, 8, len(kernel), len(ramdisk), 0, 1580)
    struct.pack_into("<I", h, 40, 3)
    pad = lambda b: b + b"\0" * ((-len(b)) % 4096)
    return bytes(h) + pad(kernel) + pad(ramdisk)


def mkext4(src, img, size_mb, extra=()):
    os.makedirs(os.path.dirname(img), exist_ok=True)
    subprocess.run(["mke2fs", "-q", "-F", "-b", "4096", *extra, "-d", src, img, "%dM" % size_mb], check=True,
                   stdout=subprocess.DEVNULL)


def sparse(raw, out, blk=4096):
    data = open(raw, "rb").read()
    nblk = len(data) // blk
    chunks = []
    i = 0
    while i < nblk:
        b = data[i * blk:(i + 1) * blk]
        if b == b"\0" * blk:
            j = i
            while j < nblk and data[j * blk:(j + 1) * blk] == b"\0" * blk:
                j += 1
            chunks.append((0xCAC3, j - i, b""))
            i = j
        elif b == b[:4] * (blk // 4):
            j = i
            while j < nblk and data[j * blk:(j + 1) * blk] == b:
                j += 1
            chunks.append((0xCAC2, j - i, b[:4]))
            i = j
        else:
            j = i
            while j < nblk and j - i < 64:
                c = data[j * blk:(j + 1) * blk]
                if c == c[:4] * (blk // 4):
                    break
                j += 1
            chunks.append((0xCAC1, j - i, data[i * blk:j * blk]))
            i = j
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, nblk, len(chunks), 0))
        for t, n, payload in chunks:
            f.write(struct.pack("<HHII", t, 0, n, 12 + len(payload)))
            f.write(payload)


def classic(base):
    sysd = os.path.join(base, "tree/system")
    w(sysd + "/build.prop", "ro.build.version.sdk=19\nro.build.version.release=4.4.2\nro.product.brand=samsung\n"
      "ro.product.model=GT-I9505\nro.product.manufacturer=samsung\nro.build.id=KOT49H\nro.sf.lcd_density=480\n"
      "ro.product.cpu.abi=armeabi-v7a\n")
    w(sysd + "/framework/framework.jar", os.urandom(70000))
    w(sysd + "/framework/twframework.jar", b"tw")
    w(sysd + "/bin/app_process", ARM_ELF, 0o755)
    w(sysd + "/bin/toolbox", ARM_ELF + b"\0ls\0", 0o755)
    link("toolbox", sysd + "/bin/ls")
    link("/system/bin/toolbox", sysd + "/bin/ps")
    link("../../../../../../dev/null", sysd + "/etc/escaping")
    w(sysd + "/etc/bad\\name.txt", b"x")
    w(sysd + "/etc/hosts", b"127.0.0.1 localhost\n")
    w(sysd + "/etc/init/vendorstuff.rc", "service qseecomd /system/bin/qseecomd\n    class core\n    user root\n\n"
      "service already /system/bin/x\n    disabled\n")
    w(sysd + "/app/Bloat/Bloat.apk", os.urandom(5000))
    w(sysd + "/app/Weather.apk", os.urandom(3000))
    w(sysd + "/app/Weather.odex", os.urandom(300))
    w(sysd + "/media/big.bin", os.urandom(600000))
    w(sysd + "/lib/libfoo.so", os.urandom(200000))
    mkext4(sysd, os.path.join(base, "system.raw"), 32)
    rd = cpio([
        ("init", 0o100750, ARM_ELF),
        ("init.rc", 0o100750, b"import /init.qcom.rc\non init\n    export BOOTCLASSPATH /system/framework/core.jar:/system/framework/framework.jar\n\n"
                              b"service zygote /system/bin/app_process -Xzygote /system/bin --zygote --start-system-server\n    class main\n\n"
                              b"service bootanim /system/bin/bootanimation\n    class main\n    user graphics\n    disabled\n    oneshot\n"),
        ("init.qcom.rc", 0o100750, b"service rmt_storage /system/bin/rmt_storage\n    class core \\\n        late\n    user root\n"),
        ("default.prop", 0o100644, b"ro.secure=1\nro.adb.secure=1\nro.sf.lcd_density=320\n"),
        ("sbin", 0o40750, b""),
        ("sbin/healthd", 0o100750, ARM_ELF),
        ("system", 0o40755, b""),
        ("data", 0o40771, b""),
        ("fstab.qcom", 0o100640, b"/dev/block/system /system ext4 ro wait\n"),
    ])
    kernel = b"\0" * 64 + gzip.compress(b"junk Linux version 3.4.0-test (dev@host) (gcc 4.8) #1 SMP PREEMPT\n" + b"\0" * 100)
    w(os.path.join(base, "fw/boot.img"), bootimg_v0(kernel, gzip.compress(rd)))
    sparse(os.path.join(base, "system.raw"), os.path.join(base, "fw/system.img"))
    w(os.path.join(base, "fw/recovery.img"), b"ANDROID!" + b"\0" * 3000)
    w(os.path.join(base, "fw/userdata.img"), b"\0" * 100)
    w(os.path.join(base, "fw/README.txt"), b"hello")


def sar(base):
    r = os.path.join(base, "sar")
    w(r + "/init", ARM64_ELF, 0o750)
    w(r + "/init.rc", "import /init.environ.rc\nservice zygote /system/bin/app_process64 -Xzygote\n    class main\n")
    w(r + "/init.environ.rc", "on early-init\n    export BOOTCLASSPATH /system/framework/framework.jar\n")
    w(r + "/plat_property_contexts", b"ro. u:object_r:default_prop:s0\n")
    link("/system/etc", r + "/etc")
    link("/system/etc/prop.default", r + "/default.prop")
    link("/data/user_de/0/com.android.shell/files/bugreports", r + "/bugreports")
    os.makedirs(r + "/product")
    os.makedirs(r + "/vendor")
    os.makedirs(r + "/odm")
    os.makedirs(r + "/data")
    os.makedirs(r + "/dev")
    s = r + "/system"
    w(s + "/build.prop", "ro.build.version.sdk=30\nro.build.version.release=11\nro.product.system.brand=google\n"
      "ro.build.fingerprint=google/sargo/sargo:11/RQ3A/1:user/release-keys\nro.product.cpu.abi=arm64-v8a\n")
    w(s + "/etc/prop.default", "ro.secure=1\nro.sf.lcd_density=440\n")
    w(s + "/framework/framework.jar", b"fw")
    w(s + "/bin/app_process64", ARM64_ELF, 0o755)
    link("/product", s + "/product")
    w(s + "/etc/big.zip", b"PK" + b"\1" * 21000000)
    w(s + "/inline.txt", b"tiny")
    mkext4(r, os.path.join(base, "sarfw/system.img"), 64, ["-O", "inline_data", "-I", "256"])
    p = os.path.join(base, "product")
    w(p + "/build.prop", "ro.product.product.model=Pixel 3a\n")
    w(p + "/app/Maps/Maps.apk", os.urandom(4000))
    link("../../app/Maps/Maps.apk", p + "/overlay/x/maps.apk")
    mkext4(p, os.path.join(base, "sarfw/product.img"), 8)
    v = os.path.join(base, "vendor")
    w(v + "/build.prop", "ro.product.vendor.model=sargo\nro.sf.lcd_density=440\n")
    w(v + "/etc/vintf/manifest.xml", "<manifest/>")
    w(v + "/etc/init/hw.rc", "service vendor.thermal /vendor/bin/thermal\n    class hal\n")
    os.makedirs(v + "/odm")
    mkext4(v, os.path.join(base, "sarfw/vendor.img"), 8, ["-t", "ext3", "-O", "^extents"])
    o = os.path.join(base, "odm")
    w(o + "/etc/build.prop", "ro.odm.x=1\n")
    w(o + "/lib/libodm.so", os.urandom(90000))
    mkext4(o, os.path.join(base, "sarfw/odm.img"), 4)
    rd = cpio([("sbin", 0o40750, b""), ("sbin/recovery", 0o100750, ARM64_ELF), ("init.rc", 0o100750, b"on init\n")])
    lz = subprocess.run(["lz4", "-l", "-c", "-q"], input=rd, stdout=subprocess.PIPE, check=True).stdout
    w(os.path.join(base, "sarfw/boot_a.img"), bootimg_v3(b"Linux version 4.9.0-g (b@h) #1\0" + b"\0" * 5000, lz))
    w(os.path.join(base, "sarfw/boot_b.img"), b"ANDROID!" + b"\0" * 5000)
    w(os.path.join(base, "sarfw/vbmeta.img"), b"AVB0" + b"\0" * 100)


def mips(base):
    s = os.path.join(base, "mips/system")
    w(s + "/build.prop", "ro.build.version.release=2.3.6\n")
    w(s + "/framework/core.jar", b"x")
    w(s + "/bin/app_process", MIPS_ELF, 0o755)


def ext3_indirect(base):
    d = os.path.join(base, "ind")
    w(d + "/build.prop", "ro.build.version.sdk=10\n")
    w(d + "/framework/core.jar", b"c")
    blob = bytes((i * 7 + 3) & 0xFF for i in range(5 * 1024 * 1024 + 1234))
    w(d + "/big.bin", blob)
    w(d + "/longlink_target_" + "x" * 150, b"long")
    link("longlink_target_" + "x" * 150, d + "/ll")
    mkext4(d, os.path.join(base, "ind.img"), 16, ["-t", "ext2", "-b", "1024"])


if __name__ == "__main__":
    base = sys.argv[1]
    if os.path.exists(base):
        shutil.rmtree(base)
    os.makedirs(base)
    classic(base)
    sar(base)
    mips(base)
    ext3_indirect(base)
