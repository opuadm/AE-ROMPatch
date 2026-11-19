import os
import struct
import sys
import tarfile

BASE = 0x1000
STR = 0x2000
MSG = b"invalid gralloc handle (at %p)\0"


def adrp(rd, pc, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | (imm & 3) << 29 | ((imm >> 2) & 0x7FFFF) << 5 | rd


def bcond(pc, target, cond):
    return 0x54000000 | (((target - pc) // 4) & 0x7FFFF) << 5 | cond


def bl(pc, target):
    return 0x94000000 | (((target - pc) // 4) & 0x3FFFFFF)


def code():
    a = lambda i: BASE + 4 * i
    return [
        bcond(a(0), a(3), 1),
        0x6B09011F,
        bcond(a(2), a(10), 0),
        adrp(1, a(3), STR),
        adrp(2, a(4), STR),
        0x91000021 | (STR & 0xFFF) << 10,
        0x91000042 | (STR & 0xFFF) << 10,
        0x321F07E0,
        bl(a(8), a(15)),
        0xAA1F03E3,
        0xB9409068,
        0xF94013EB,
        0x6B14011F,
        0x54000040,
        0xB9009074,
        0xD65F03C0,
    ]


SMSG = b"Max Hidl transport errors this cycle : %d\0"


def sensor_code():
    a = lambda i: BASE + 4 * i
    return [
        0x5292D000 | 23,
        0x72A01300 | 23,
        0xD503201F,
        0xD503201F,
        0x7100C81F | 20 << 5,
        bcond(a(5), a(2), 3),
        adrp(2, a(6), STR),
        0x91000042 | (STR & 0xFFF) << 10,
        bl(a(8), a(9)),
        0xD65F03C0,
    ]


def lib(ins=None, msg=MSG):
    ins = ins or code()
    MSG_ = msg
    size = STR + len(MSG_)
    d = bytearray(size)
    d[0:4] = b"\x7fELF"
    d[4], d[5], d[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", d, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", d, 64, 1, 5, 0, 0, 0, size, size, 0x1000)
    for i, v in enumerate(ins):
        struct.pack_into("<I", d, BASE + 4 * i, v)
    d[STR:STR + len(MSG_)] = MSG_
    return bytes(d)


def gen(root):
    os.makedirs(root + "/system/lib64", exist_ok=True)
    with open(root + "/system/build.prop", "w") as f:
        f.write("ro.build.version.sdk=28\nro.build.version.release=9\nro.product.system.brand=samsung\n")
    with open(root + "/system/lib64/libgui.so", "wb") as f:
        f.write(lib())


def gen_sensor(root):
    os.makedirs(root + "/system/lib64", exist_ok=True)
    with open(root + "/system/build.prop", "w") as f:
        f.write("ro.build.version.sdk=28\nro.build.version.release=9\n")
    with open(root + "/system/lib64/libsensorservice.so", "wb") as f:
        f.write(lib(sensor_code(), SMSG))


def check_sensor(tarpath):
    with tarfile.open(tarpath) as t:
        d = t.extractfile("system/lib64/libsensorservice.so").read()
    w = lambda i: struct.unpack_from("<I", d, BASE + 4 * i)[0]
    assert w(0) == 0x52994000 | 23, hex(w(0))
    assert w(1) == 0x72A77340 | 23, hex(w(1))
    assert w(5) == 0x14000000 | ((-3) & 0x3FFFFFF), hex(w(5))
    assert w(4) == 0x7100C81F | 20 << 5 and w(6) == adrp(2, BASE + 24, STR), "rest changed"


HMSG = b"Abort due to ISensors hidl service failure, detail: %s.\0"
ASSERT_OK = b"_ZNK7android8hardware7details13return_status8assertOkEv"
GOT, DYN, RELA, SYMS, STRS = 0x3000, 0x3100, 0x3200, 0x3300, 0x3400


def hidl_code():
    a = lambda i: BASE + 4 * i
    ins = [0xD503201F] * 32
    ins[0] = 0xA9BF7BFD
    ins[1] = adrp(2, a(1), STR)
    ins[2] = 0x91000042 | (STR & 0xFFF) << 10
    ins[3] = bl(a(3), a(30))
    ins[4] = 0
    ins[5] = 0xB94033E8
    ins[6] = 0x35000008 | ((a(12) - a(6)) // 4) << 5
    ins[7] = 0x910003E0
    ins[8] = bl(a(8), a(28))
    ins[9] = bl(a(9), a(24))
    ins[10] = 0xB9404FF3
    ins[11] = 0xD65F03C0
    ins[12] = 0x910043E0
    ins[13] = bl(a(13), a(28))
    ins[14] = 0x910043E0
    ins[15] = bl(a(15), a(0))
    ins[16] = 0
    ins[24] = adrp(16, a(24), GOT)
    ins[25] = 0xF9400211 | ((GOT & 0xFFF) // 8) << 10
    ins[26] = 0x91000210 | (GOT & 0xFFF) << 10
    ins[27] = 0xD61F0220
    ins[28] = 0xD65F03C0
    ins[30] = 0xD65F03C0
    return ins


def hidl_lib():
    strs = b"\0" + ASSERT_OK + b"\0"
    size = STRS + len(strs)
    d = bytearray(size)
    d[0:4] = b"\x7fELF"
    d[4], d[5], d[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", d, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", d, 64, 1, 5, 0, 0, 0, size, size, 0x1000)
    struct.pack_into("<IIQQQQQQ", d, 120, 2, 6, DYN, DYN, DYN, 96, 96, 8)
    for i, v in enumerate(hidl_code()):
        struct.pack_into("<I", d, BASE + 4 * i, v)
    d[STR:STR + len(HMSG)] = HMSG
    for i, (tag, val) in enumerate([(23, RELA), (2, 24), (6, SYMS), (5, STRS), (10, len(strs)), (0, 0)]):
        struct.pack_into("<QQ", d, DYN + 16 * i, tag, val)
    struct.pack_into("<QQq", d, RELA, GOT, 1 << 32 | 1026, 0)
    struct.pack_into("<I", d, SYMS + 24, 1)
    d[STRS:STRS + len(strs)] = strs
    return bytes(d)


def gen_hidl(root):
    os.makedirs(root + "/system/lib64", exist_ok=True)
    with open(root + "/system/build.prop", "w") as f:
        f.write("ro.build.version.sdk=28\nro.build.version.release=9\n")
    with open(root + "/system/lib64/libsensorservice.so", "wb") as f:
        f.write(hidl_lib())


def check_hidl(tarpath):
    with tarfile.open(tarpath) as t:
        d = t.extractfile("system/lib64/libsensorservice.so").read()
    w = lambda i: struct.unpack_from("<I", d, BASE + 4 * i)[0]
    want = hidl_code()
    want[6] = want[9] = 0xD503201F
    got = [w(i) for i in range(32)]
    assert got == want, [hex(i) for i, (x, y) in enumerate(zip(got, want)) if x != y]


def check(tarpath):
    with tarfile.open(tarpath) as t:
        d = t.extractfile("system/lib64/libgui.so").read()
    w = lambda i: struct.unpack_from("<I", d, BASE + 4 * i)[0]
    want_b = 0x14000000 | ((BASE + 4 * 15 - (BASE + 4 * 4)) // 4)
    assert w(3) == 0xF94013EB, hex(w(3))
    assert w(4) == want_b, hex(w(4))
    assert all(w(i) == 0xD503201F for i in range(5, 10)), "nops"
    assert w(10) == 0xB9409068 and w(14) == 0xB9009074, "valid path changed"


if __name__ == "__main__":
    {"gen": gen, "check": check, "gen-sensor": gen_sensor, "check-sensor": check_sensor, "gen-hidl": gen_hidl,
     "check-hidl": check_hidl}[sys.argv[1]](sys.argv[2])
