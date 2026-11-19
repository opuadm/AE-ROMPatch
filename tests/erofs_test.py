#!/usr/bin/env python3
import os
import random
import shutil
import subprocess
import sys
import tarfile

aerompatch, mkfs, work = sys.argv[1], sys.argv[2], sys.argv[3]
fsck = sys.argv[4] if len(sys.argv) > 4 else None

VARIANTS = [
    ("plain", []),
    ("lz4", ["-zlz4"]),
    ("lz4hc-big", ["-zlz4hc,12", "-C65536"]),
    ("lz4-ztail", ["-zlz4", "-Eztailpacking"]),
    ("lz4-fragments", ["-zlz4hc", "-C32768", "-Efragments"]),
    ("lz4-allfrag", ["-zlz4", "-Eall-fragments"]),
    ("lz4-dedupe", ["-zlz4hc", "-Ededupe"]),
    ("lz4-legacy", ["-zlz4", "-Elegacy-compress"]),
    ("lzma", ["-zlzma", "-C65536"]),
    ("deflate", ["-zdeflate", "-Eztailpacking"]),
    ("chunked", ["--chunksize=65536"]),
    ("android", ["-zlz4hc,9", "-C262144", "-Eztailpacking", "-Efragments", "-T0", "--mount-point=/system"]),
]


def make_tree(root, seed):
    rnd = random.Random(seed)
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root + "/system/framework")
    with open(root + "/system/build.prop", "w") as f:
        f.write("ro.build.version.sdk=33\nro.build.version.release=13\nro.product.system.brand=Xiaomi\n"
                "ro.miui.ui.version.name=V140\n")
    open(root + "/init", "wb").write(b"\x7fELF" + bytes(60))
    os.chmod(root + "/init", 0o750)
    os.symlink("/system/etc", root + "/etc")
    words = [b"android", b"framework", b"miui", b"\x00\x01", b"lorem", b"ipsum", b"zygote", b"binder"]
    for i, size in enumerate([0, 1, 7, 4095, 4096, 4097, 8191, 12288, 65535, 65537, 200000, 1048577, 3 * 1048576 + 5]):
        p = root + "/system/framework/f%02d.bin" % i
        if i % 3 == 0:
            data = bytes(rnd.getrandbits(8) for _ in range(size))
        elif i % 3 == 1:
            data = b"".join(rnd.choice(words) for _ in range(size // 4 + 1))[:size]
        else:
            data = (b"\0" * 5000 + b"abc") * (size // 5003 + 1)
            data = data[:size]
        open(p, "wb").write(data)
    dup = open(root + "/system/framework/f11.bin", "rb").read()
    open(root + "/system/framework/dup.bin", "wb").write(dup + b"tail")
    d = root + "/system/app/many"
    os.makedirs(d)
    for i in range(700):
        name = "entry_%04d_%s" % (i, "x" * (i % 60))
        if i % 7 == 0:
            os.symlink("../../framework/f%02d.bin" % (i % 13), os.path.join(d, name))
        else:
            open(os.path.join(d, name), "wb").write(("file %d\n" % i).encode() * (i % 5))
    long_target = "/system/" + "t" * 300
    os.symlink(long_target, root + "/system/longlink")
    deep = root + "/system"
    for i in range(30):
        deep = os.path.join(deep, "d%d" % i)
    os.makedirs(deep)
    open(deep + "/leaf.txt", "w").write("deep\n")


def tree_snapshot(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = os.path.join(dp, n)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                out[rel] = ("l", os.readlink(p))
            elif os.path.isdir(p):
                out[rel] = ("d", None)
            else:
                out[rel] = ("f", open(p, "rb").read())
    return out


def tar_snapshot(path):
    t = tarfile.open(path)
    out = {}
    for m in t.getmembers():
        n = m.name.rstrip("/")
        if m.issym():
            out[n] = ("l", m.linkname)
        elif m.isdir():
            out[n] = ("d", None)
        elif m.isfile():
            out[n] = ("f", t.extractfile(m).read())
    return out


fails = 0
src = os.path.join(work, "erofs-src")
make_tree(src, 1)
want = tree_snapshot(src)
for name, opts in VARIANTS:
    img = os.path.join(work, "e-%s.img" % name)
    r = subprocess.run([mkfs, *opts, img, src], capture_output=True, text=True)
    if r.returncode:
        print("skip  %-14s mkfs: %s" % (name, r.stderr.strip().splitlines()[-1] if r.stderr else "failed"))
        continue
    out = os.path.join(work, "e-%s.tar" % name)
    r = subprocess.run([aerompatch, "patch", "-q", "-f", "--disable", "all", "--system", img, "-o", out],
                       capture_output=True, text=True)
    if r.returncode:
        print("FAIL  %-14s %s" % (name, r.stderr.strip()))
        fails += 1
        continue
    got = tar_snapshot(out)
    bad = []
    ref = want
    if fsck:
        ex = os.path.join(work, "e-%s.x" % name)
        shutil.rmtree(ex, ignore_errors=True)
        if subprocess.run([fsck, "--extract=" + ex, img], capture_output=True).returncode == 0:
            ref = tree_snapshot(ex)
            drift = [k for k in want if k not in ("etc", "init") and ref.get(k) != want[k]]
            if drift:
                print("note  %-14s mkfs stored %d file(s) differently from the source (checked against fsck.erofs)" % (name, len(drift)))
    for rel, v in ref.items():
        if rel == "etc" or rel == "init":
            continue
        g = got.get(rel)
        if g != v:
            bad.append(rel)
    if bad:
        fails += 1
        print("FAIL  %-14s %d mismatches, e.g. %s" % (name, len(bad), bad[:3]))
    else:
        print("ok    %-14s (%d KiB image)" % (name, os.path.getsize(img) >> 10))
sys.exit(1 if fails else 0)
