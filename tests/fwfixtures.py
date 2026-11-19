#!/usr/bin/env python3
import io
import os
import struct
import subprocess
import sys
import tarfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures import mkext4, sparse, w
from zipfixtures import legacy_boot

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None

KEY = bytes.fromhex("D6DCCF0AD5ACD4E0292E522DB7C1381E")
SECTOR = 512


def rd(base, name):
    return open(os.path.join(base, name), "rb").read()


def lz4(data):
    return subprocess.run(["lz4", "-c", "-q"], input=data, stdout=subprocess.PIPE, check=True).stdout


def super_img(base, parts):
    data_start = 1 << 20
    blobs, entries, extents = [], b"", b""
    cur = data_start
    for i, (name, data) in enumerate(parts):
        data = data + b"\0" * ((-len(data)) % 4096)
        if data:
            extents += struct.pack("<QIQI", len(data) // SECTOR, 0, cur // SECTOR, 0)
            blobs.append((cur, data))
            cur += len(data)
            cur += (-cur) % (1 << 20)
        entries += name.encode().ljust(36, b"\0") + struct.pack("<IIII", 1, len(extents) // 24 - (1 if data else 0),
                                                                  1 if data else 0, 0)
    groups = b"default".ljust(36, b"\0") + struct.pack("<IQ", 0, 0)
    devs = struct.pack("<QIIQ", data_start // SECTOR, 1 << 20, 0, cur) + b"super".ljust(36, b"\0") + \
        struct.pack("<I", 0)
    tables = entries + extents + groups + devs
    h = bytearray(128)
    struct.pack_into("<IHHI", h, 0, 0x414C5030, 10, 0, 128)
    struct.pack_into("<I", h, 44, len(tables))
    off = 0
    for at, tab, size in ((80, entries, 52), (92, extents, 24), (104, groups, 48), (116, devs, 64)):
        struct.pack_into("<III", h, at, off, len(tab) // size, size)
        off += len(tab)
    geo = bytearray(4096)
    struct.pack_into("<II", geo, 0, 0x616C4467, 52)
    struct.pack_into("<III", geo, 40, 65536, 2, 4096)
    img = bytearray(cur)
    img[4096:8192] = geo
    img[8192:12288] = geo
    img[12288:12288 + 128] = h
    img[12288 + 128:12288 + 128 + len(tables)] = tables
    for at, data in blobs:
        img[at:at + len(data)] = data
    raw = os.path.join(base, "super.raw")
    w(raw, bytes(img))
    sparse(raw, os.path.join(base, "super.img"))
    return rd(base, "super.img")


def tar_bytes(members, md5=False):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.GNU_FORMAT) as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    out = bio.getvalue()
    if md5:
        out += b"0123456789abcdef0123456789abcdef  AP.tar\n"
    return out


def optics(base):
    o = os.path.join(base, "optics-src")
    w(o + "/configs/carriers/single/XEU/conf/customer_carrier_feature.json", '{"carrier":"XEU"}')
    mkext4(o, os.path.join(base, "optics.raw"), 4)
    return rd(base, "optics.raw")


def samsung(base, sup):
    boot = rd(base, "ab-boot.img")
    ap = tar_bytes([
        ("boot.img.lz4", lz4(boot)),
        ("recovery.img.lz4", lz4(b"ANDROID!" + b"\0" * 9000)),
        ("vbmeta.img", b"AVB0" + b"\0" * 8000),
        ("super.img.lz4", lz4(sup)),
        ("userdata.img.lz4", lz4(b"\0" * 100000)),
        ("meta-data/fota.zip", b"PK\5\6" + b"\0" * 18),
    ], md5=True)
    csc = tar_bytes([("cache.img.lz4", lz4(b"\0" * 50000)), ("optics.img.lz4", lz4(optics(base)))], md5=True)
    home = tar_bytes([("cache.img.lz4", lz4(b"\1" * 50000))], md5=True)
    bl = tar_bytes([("sboot.bin.lz4", lz4(b"\2" * 50000))], md5=True)
    out = os.path.join(base, "SM-G991B_EUX_G991BXXU5CVF1_fac.zip")
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("AP_G991BXXU5CVF1_CL1_REV00_user_low_ship_MULTI_CERT_meta_OS12.tar.md5", ap, zipfile.ZIP_STORED)
        z.writestr("BL_G991BXXU5CVF1_CL1_REV00_user_low_ship_MULTI_CERT.tar.md5", bl, zipfile.ZIP_DEFLATED)
        z.writestr("CSC_OXM_G991BOXM5CVF1_CL1_REV00_user_low_ship_MULTI_CERT.tar.md5", csc, zipfile.ZIP_DEFLATED)
        z.writestr("HOME_CSC_OXM_G991BOXM5CVF1_CL1_REV00_user_low_ship_MULTI_CERT.tar.md5", home,
                   zipfile.ZIP_DEFLATED)
    d = os.path.join(base, "samsung-dir")
    os.makedirs(d, exist_ok=True)
    w(d + "/AP_G991B.tar.md5", ap)
    w(d + "/CSC_OXM_G991B.tar.md5", csc)
    w(d + "/BL_G991B.tar.md5", bl)


def samsung_old(base):
    tar = tar_bytes([
        ("boot.img", legacy_boot()),
        ("recovery.img", b"ANDROID!" + b"\0" * 9000),
        ("system.img", rd(base, "fac-system.img")),
        ("cache.img", b"\0" * 8192),
    ], md5=True)
    w(os.path.join(base, "I9300XXUGNA7.tar.md5"), tar)
    rfs = tar_bytes([("zImage", b"\0" * 9000), ("factoryfs.rfs", b"\0" * 9000)], md5=True)
    w(os.path.join(base, "I9000XXJVU.tar.md5"), rfs)


def xiaomi_tgz(base, sup):
    boot = rd(base, "ab-boot.img")
    out = os.path.join(base, "mido_global_images_V12.tgz")
    with tarfile.open(out, "w:gz") as t:
        for name, data in (("mido_global_images_V12/flash_all.sh", b"fastboot flash super super.img\n"),
                           ("mido_global_images_V12/images/boot.img", boot),
                           ("mido_global_images_V12/images/super.img", sup)):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))


def oppo_header(size):
    h = bytearray(0x1050)
    h[0:12] = b"OPPOENCRYPT!"
    h[16:16 + len(str(size))] = str(size).encode()
    return bytes(h)


def ozip_whole(data):
    c = AES.new(KEY, AES.MODE_ECB)
    out = bytearray(oppo_header(len(data)))
    p = 0
    while p < len(data):
        blk = data[p:p + 16]
        out += c.encrypt(blk) if len(blk) == 16 else blk
        out += data[p + 16:p + 0x4010]
        p += 0x4010
    return bytes(out)


def oppo_member(data):
    c = AES.new(KEY, AES.MODE_ECB)
    pad = data + b"\0" * ((-len(data)) % 16)
    return oppo_header(len(data)) + c.encrypt(pad)


def oppo_segmented(data):
    c = AES.new(KEY, AES.MODE_ECB)
    out = bytearray()
    for s in range(0, max(len(data), 1), 0x40000):
        seg = data[s:s + 0x40000]
        hdr = bytearray(0x50)
        hdr[0:12] = b"OPPOENCRYPT!"
        hdr[16:16 + len(str(len(seg)))] = str(len(seg)).encode()
        out += hdr
        body = bytearray()
        for k in range(0, len(seg), 0x4000):
            blk = seg[k:k + 16]
            body += c.encrypt(blk.ljust(16, b"\0"))
            body += seg[k + 16:k + 0x4000]
        out += body
    return bytes(out)


def ozips(base):
    w(os.path.join(base, "CPH1607EX_11_OTA.ozip"), ozip_whole(rd(base, "cwm.zip")))
    src = zipfile.ZipFile(os.path.join(base, "blockota.zip"))
    enc = ["system.new.dat.br", "system.transfer.list", "vbmeta.img"]
    with zipfile.ZipFile(os.path.join(base, "RMX1851_member.ozip.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("oppo_metadata", "\n".join(enc) + "\n")
        z.writestr("vbmeta.img", oppo_member(b"AVB0" + b"\0" * 5000))
        for i in src.infolist():
            data = src.read(i)
            if i.filename in enc:
                data = oppo_member(data)
            z.writestr(i.filename, data, zipfile.ZIP_STORED if i.filename.endswith(".br") else zipfile.ZIP_DEFLATED)
    src = zipfile.ZipFile(os.path.join(base, "payload.zip"))
    with zipfile.ZipFile(os.path.join(base, "CPH1909_mode2.zip"), "w") as z:
        z.writestr("boot.img", oppo_segmented(rd(base, "ab-boot.img")), zipfile.ZIP_DEFLATED)
        for i in src.infolist():
            data = src.read(i)
            if i.filename == "payload.bin":
                data = oppo_segmented(data)
            z.writestr(i.filename, data, i.compress_type)
    with zipfile.ZipFile(os.path.join(base, "unknown-key.zip"), "w") as z:
        z.writestr("boot.img", oppo_header(5000) + os.urandom(5008))


if __name__ == "__main__":
    base = sys.argv[1]
    sup = super_img(base, [("system", rd(base, "ab-system.raw")), ("system_b", b""),
                           ("vendor", rd(base, "ab-vendor.raw")), ("product", rd(base, "ab-product.raw"))])
    samsung(base, sup)
    samsung_old(base)
    xiaomi_tgz(base, sup)
    if AES:
        ozips(base)
    else:
        w(os.path.join(base, "no-crypto"), "")
