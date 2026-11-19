#include "binpatch/elfpatch.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_SEGS 16

typedef struct {
    uint64_t off, vaddr, size;
    int exec;
} seg;

typedef struct {
    unsigned char *d;
    size_t len;
    seg s[MAX_SEGS];
    int n;
} elf;

static uint16_t r16(const unsigned char *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t r32(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t r64(const unsigned char *p) { return (uint64_t)r32(p) | (uint64_t)r32(p + 4) << 32; }

static void w32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static int elf_open(elf *e, unsigned char *d, size_t len)
{
    memset(e, 0, sizeof *e);
    if (len < 64 || memcmp(d, "\177ELF", 4) || d[4] != 2 || d[5] != 1 || r16(d + 18) != 183)
        return -1;
    uint64_t phoff = r64(d + 32);
    uint16_t phent = r16(d + 54), phnum = r16(d + 56);
    if (phent < 56 || phoff > len || (uint64_t)phnum * phent > len - phoff)
        return -1;
    e->d = d;
    e->len = len;
    for (uint16_t i = 0; i < phnum && e->n < MAX_SEGS; i++) {
        const unsigned char *p = d + phoff + (uint64_t)i * phent;
        if (r32(p) != 1)
            continue;
        uint64_t off = r64(p + 8), va = r64(p + 16), fsz = r64(p + 32);
        if (off > len || fsz > len - off)
            continue;
        e->s[e->n].off = off;
        e->s[e->n].vaddr = va;
        e->s[e->n].size = fsz;
        e->s[e->n].exec = (r32(p + 4) & 1) != 0;
        e->n++;
    }
    return e->n ? 0 : -1;
}

static int off_to_va(const elf *e, uint64_t off, uint64_t *va)
{
    for (int i = 0; i < e->n; i++)
        if (off >= e->s[i].off && off < e->s[i].off + e->s[i].size) {
            *va = e->s[i].vaddr + (off - e->s[i].off);
            return 0;
        }
    return -1;
}

static int64_t sext(uint64_t v, int bits)
{
    uint64_t m = 1ull << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

static int branch_target(uint32_t ins, uint64_t pc, uint64_t *t)
{
    if ((ins & 0x7C000000u) == 0x14000000u) {
        *t = pc + (uint64_t)(sext(ins & 0x03FFFFFFu, 26) * 4);
        return 1;
    }
    if ((ins & 0xFF000010u) == 0x54000000u || (ins & 0x7E000000u) == 0x34000000u) {
        *t = pc + (uint64_t)(sext((ins >> 5) & 0x7FFFFu, 19) * 4);
        return 1;
    }
    if ((ins & 0x7E000000u) == 0x36000000u) {
        *t = pc + (uint64_t)(sext((ins >> 5) & 0x3FFFu, 14) * 4);
        return 1;
    }
    return 0;
}

static int adrp_page(uint32_t ins, uint64_t pc, uint64_t *page)
{
    if ((ins & 0x9F000000u) != 0x90000000u)
        return 0;
    uint64_t imm = ((ins >> 29) & 3u) | (uint64_t)((ins >> 5) & 0x7FFFFu) << 2;
    *page = (pc & ~0xFFFull) + (uint64_t)(sext(imm, 21) * 4096);
    return 1;
}

static void targets_in(const elf *e, uint64_t lo, uint64_t hi, unsigned *count, uint64_t *min)
{
    *count = 0;
    *min = UINT64_MAX;
    for (int i = 0; i < e->n; i++) {
        if (!e->s[i].exec)
            continue;
        for (uint64_t k = 0; k + 4 <= e->s[i].size; k += 4) {
            uint64_t t;
            if (!branch_target(r32(e->d + e->s[i].off + k), e->s[i].vaddr + k, &t) || t < lo || t > hi)
                continue;
            (*count)++;
            if (t < *min)
                *min = t;
        }
    }
}

static int guard_site(elf *e, const seg *s, uint64_t k, uint64_t str_va)
{
    unsigned char *base = e->d + s->off;
    uint64_t n_ins = s->size / 4;
    uint32_t add = r32(base + k * 4);
    if ((add & 0xFFC00000u) != 0x91000000u)
        return 0;
    unsigned rn = (add >> 5) & 31;
    uint64_t imm12 = (add >> 10) & 0xFFF;
    int found = 0;
    for (uint64_t j = 1; j <= 4 && j <= k && !found; j++) {
        uint64_t page;
        uint32_t a = r32(base + (k - j) * 4);
        if (adrp_page(a, s->vaddr + (k - j) * 4, &page) && (a & 31) == rn && page + imm12 == str_va)
            found = 1;
    }
    if (!found)
        return 0;
    uint64_t bl = 0;
    for (uint64_t j = k + 1; j <= k + 5 && j < n_ins; j++)
        if ((r32(base + j * 4) & 0xFC000000u) == 0x94000000u) {
            bl = j;
            break;
        }
    if (!bl || bl + 12 >= n_ins)
        return -1;
    uint32_t mov = r32(base + (bl + 1) * 4);
    if ((mov & 0xFFFFFFE0u) != 0xAA1F03E0u || (mov & 31) == 31)
        return -1;
    unsigned hreg = mov & 31;
    uint32_t ldr = r32(base + (bl + 2) * 4);
    if ((ldr & 0xFFC00000u) != 0xB9400000u || ((ldr >> 5) & 31) != hreg)
        return -1;
    unsigned areg = ldr & 31;
    uint32_t field = (ldr >> 10) & 0xFFF;
    uint32_t keep[3];
    int nkeep = 0;
    uint64_t done_va = 0;
    for (uint64_t q = bl + 3; q <= bl + 10 && q + 2 < n_ins && !done_va; q++) {
        uint32_t ins = r32(base + q * 4);
        if ((ins & 0xFF20FC1Fu) == 0x6B00001Fu && ((ins >> 5) & 31) == areg) {
            unsigned breg = (ins >> 16) & 31;
            uint32_t beq = r32(base + (q + 1) * 4);
            uint64_t t;
            if ((beq & 0xFF00001Fu) != 0x54000000u || !branch_target(beq, s->vaddr + (q + 1) * 4, &t))
                return -1;
            uint32_t want = 0xB9000000u | field << 10 | hreg << 5 | breg;
            if (r32(base + (q + 2) * 4) != want || t != s->vaddr + (q + 3) * 4)
                return -1;
            done_va = t;
            break;
        }
        unsigned irn = (ins >> 5) & 31, irt = ins & 31;
        int load = (ins & 0x3B000000u) == 0x39000000u && ((ins >> 22) & 1);
        if (!load || irn == hreg || irn == areg || irt == hreg || nkeep == 3)
            return -1;
        keep[nkeep++] = ins;
    }
    if (!done_va)
        return -1;
    uint64_t mov_va = s->vaddr + (bl + 1) * 4;
    uint64_t lo = s->vaddr + (k >= 6 ? k - 6 : 0) * 4;
    unsigned cnt;
    uint64_t start;
    targets_in(e, lo, s->vaddr + k * 4, &cnt, &start);
    if (!cnt)
        return -1;
    unsigned inner;
    uint64_t dummy;
    targets_in(e, start + 4, mov_va, &inner, &dummy);
    if (inner)
        return -1;
    targets_in(e, mov_va + 4, mov_va + 4, &cnt, &dummy);
    if (!cnt)
        return -1;
    uint64_t first = (start - s->vaddr) / 4;
    for (uint64_t j = first; j < bl; j++) {
        uint64_t t;
        if (branch_target(r32(base + j * 4), s->vaddr + j * 4, &t))
            return -1;
    }
    if (bl + 1 - first + 1 < (uint64_t)nkeep + 1)
        return -1;
    uint64_t at = first;
    for (int i = 0; i < nkeep; i++)
        w32(base + at++ * 4, keep[i]);
    w32(base + at * 4, 0x14000000u | (uint32_t)(((done_va - (s->vaddr + at * 4)) / 4) & 0x03FFFFFFu));
    at++;
    for (; at <= bl + 1; at++)
        w32(base + at * 4, 0xD503201Fu);
    return 1;
}

int elf_gralloc_guard(unsigned char *data, size_t len, char *msg, size_t msglen)
{
    static const char needle[] = "invalid gralloc handle (at %p)";
    elf e;
    if (elf_open(&e, data, len))
        return 0;
    int patched = 0, unsafe = 0;
    for (size_t pos = 0; pos + sizeof needle <= len;) {
        unsigned char *hit = memmem(data + pos, len - pos, needle, sizeof needle);
        if (!hit)
            break;
        pos = (size_t)(hit - data) + 1;
        uint64_t str_va;
        if (off_to_va(&e, (uint64_t)(hit - data), &str_va))
            continue;
        for (int i = 0; i < e.n; i++) {
            if (!e.s[i].exec)
                continue;
            for (uint64_t k = 1; k < e.s[i].size / 4; k++) {
                int r = guard_site(&e, &e.s[i], k, str_va);
                if (r > 0) {
                    patched++;
                    if (msg && msglen)
                        snprintf(msg, msglen, "0x%llx", (unsigned long long)(e.s[i].vaddr + k * 4));
                } else if (r < 0) {
                    unsafe++;
                }
            }
        }
    }
    if (!patched && unsafe)
        return -1;
    return patched;
}

static int str_ref(const unsigned char *base, uint64_t vaddr, uint64_t k, uint64_t str_va)
{
    uint32_t add = r32(base + k * 4);
    if ((add & 0xFFC00000u) != 0x91000000u)
        return 0;
    unsigned rn = (add >> 5) & 31;
    uint64_t imm12 = (add >> 10) & 0xFFF;
    for (uint64_t j = 1; j <= 4 && j <= k; j++) {
        uint64_t page;
        uint32_t a = r32(base + (k - j) * 4);
        if (adrp_page(a, vaddr + (k - j) * 4, &page) && (a & 31) == rn && page + imm12 == str_va)
            return 1;
    }
    return 0;
}

static int retry_site(const seg *s, unsigned char *base, uint64_t k)
{
    uint64_t at = 0;
    for (uint64_t j = 1; j <= 8 && j <= k && !at; j++) {
        uint32_t cmp = r32(base + (k - j) * 4);
        if ((cmp & 0xFFFFFC1Fu) == 0x7100C81Fu || (cmp & 0xFFFFFC1Fu) == 0x7100CC1Fu)
            at = k - j;
    }
    if (!at)
        return 0;
    uint32_t bc = r32(base + (at + 1) * 4);
    uint64_t t;
    if ((bc & 0xFC000000u) == 0x14000000u)
        return 0;
    if ((bc & 0xFF000010u) != 0x54000000u || !branch_target(bc, s->vaddr + (at + 1) * 4, &t) || t >= s->vaddr + at * 4)
        return -1;
    uint64_t tgt = (t - s->vaddr) / 4;
    if (tgt + 64 < at)
        return -1;
    uint64_t movz = 0, movk = 0;
    for (uint64_t q = at > 96 ? at - 96 : 0; q < at; q++) {
        uint32_t ins = r32(base + q * 4);
        if ((ins & 0xFFFFFFE0u) == 0x5292D000u)
            movz = q + 1;
        else if (movz && (ins & 0xFFFFFFE0u) == 0x72A01300u && (ins & 31) == (r32(base + (movz - 1) * 4) & 31))
            movk = q + 1;
    }
    if (!movz || !movk)
        return -1;
    unsigned rd = r32(base + (movz - 1) * 4) & 31;
    w32(base + (movz - 1) * 4, 0x52994000u | rd);
    w32(base + (movk - 1) * 4, 0x72A77340u | rd);
    w32(base + (at + 1) * 4, 0x14000000u | (uint32_t)((int64_t)(tgt - (at + 1)) & 0x03FFFFFF));
    return 1;
}

int elf_sensor_retry(unsigned char *data, size_t len, char *msg, size_t msglen)
{
    static const char needle[] = "Max Hidl transport errors this cycle";
    elf e;
    if (elf_open(&e, data, len))
        return 0;
    unsigned char *hit = memmem(data, len, needle, sizeof needle - 1);
    uint64_t str_va;
    if (!hit || off_to_va(&e, (uint64_t)(hit - data), &str_va))
        return 0;
    int patched = 0, unsafe = 0;
    for (int i = 0; i < e.n; i++) {
        if (!e.s[i].exec)
            continue;
        unsigned char *base = e.d + e.s[i].off;
        for (uint64_t k = 1; k < e.s[i].size / 4; k++) {
            if (!str_ref(base, e.s[i].vaddr, k, str_va))
                continue;
            int r = retry_site(&e.s[i], base, k);
            if (r > 0) {
                patched++;
                if (msg && msglen)
                    snprintf(msg, msglen, "0x%llx", (unsigned long long)(e.s[i].vaddr + k * 4));
            } else if (r < 0) {
                unsafe++;
            }
        }
    }
    if (!patched && unsafe)
        return -1;
    return patched;
}

static int va_to_off(const elf *e, uint64_t va, uint64_t n, uint64_t *off)
{
    for (int i = 0; i < e->n; i++)
        if (va >= e->s[i].vaddr && va - e->s[i].vaddr <= e->s[i].size && n <= e->s[i].size - (va - e->s[i].vaddr)) {
            *off = e->s[i].off + (va - e->s[i].vaddr);
            return 0;
        }
    return -1;
}

static int got_of(const elf *e, const char *sym, uint64_t *got)
{
    const unsigned char *d = e->d;
    uint64_t phoff = r64(d + 32);
    uint16_t phent = r16(d + 54), phnum = r16(d + 56);
    uint64_t dyn = 0, dynsz = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        const unsigned char *p = d + phoff + (uint64_t)i * phent;
        if (r32(p) == 2) {
            dyn = r64(p + 8);
            dynsz = r64(p + 32);
        }
    }
    if (!dyn || dyn > e->len || dynsz > e->len - dyn)
        return -1;
    uint64_t jmprel = 0, pltsz = 0, symtab = 0, strtab = 0, strsz = 0;
    for (uint64_t q = 0; q + 16 <= dynsz; q += 16) {
        uint64_t tag = r64(d + dyn + q), val = r64(d + dyn + q + 8);
        if (tag == 0)
            break;
        if (tag == 23)
            jmprel = val;
        else if (tag == 2)
            pltsz = val;
        else if (tag == 6)
            symtab = val;
        else if (tag == 5)
            strtab = val;
        else if (tag == 10)
            strsz = val;
    }
    uint64_t rel, syms, strs;
    if (!jmprel || !symtab || !strtab || va_to_off(e, jmprel, pltsz, &rel) || va_to_off(e, strtab, strsz, &strs) ||
        va_to_off(e, symtab, 24, &syms))
        return -1;
    size_t sl = strlen(sym);
    for (uint64_t q = 0; q + 24 <= pltsz; q += 24) {
        uint64_t info = r64(d + rel + q + 8), idx = info >> 32, so;
        if (va_to_off(e, symtab + idx * 24, 24, &so))
            continue;
        uint32_t name = r32(d + so);
        if (name < strsz && strsz - name > sl && !memcmp(d + strs + name, sym, sl + 1)) {
            *got = r64(d + rel + q);
            return 0;
        }
    }
    return -1;
}

static int calls_got(const elf *e, uint64_t target, uint64_t got)
{
    uint64_t off, page;
    if (va_to_off(e, target, 8, &off))
        return 0;
    uint32_t a = r32(e->d + off), l = r32(e->d + off + 4);
    if (!adrp_page(a, target, &page) || (a & 31) != 16 || (l & 0xFFC003FFu) != 0xF9400211u)
        return 0;
    return page + ((l >> 10) & 0xFFF) * 8 == got;
}

static int terminator(uint32_t ins)
{
    return ins == 0xD65F03C0u || (ins & 0xFFFF0000u) == 0 || (ins & 0xFC000000u) == 0x14000000u ||
           (ins & 0xFFFFFC1Fu) == 0xD61F0000u;
}

int elf_sensor_hidl_guard(unsigned char *data, size_t len, char *msg, size_t msglen)
{
    static const char needle[] = "Abort due to ISensors hidl service failure";
    elf e;
    if (elf_open(&e, data, len))
        return 0;
    unsigned char *hit = memmem(data, len, needle, sizeof needle - 1);
    uint64_t str_va, fn = 0;
    if (!hit || off_to_va(&e, (uint64_t)(hit - data), &str_va))
        return 0;
    for (int i = 0; i < e.n && !fn; i++) {
        if (!e.s[i].exec)
            continue;
        unsigned char *base = e.d + e.s[i].off;
        for (uint64_t k = 1; k < e.s[i].size / 4 && !fn; k++) {
            if (!str_ref(base, e.s[i].vaddr, k, str_va))
                continue;
            for (uint64_t j = 1; j <= 16 && j <= k; j++)
                if ((r32(base + (k - j) * 4) & 0xFFC07FFFu) == 0xA9807BFDu) {
                    fn = e.s[i].vaddr + (k - j) * 4;
                    break;
                }
        }
    }
    if (!fn)
        return 0;
    uint64_t got = 0;
    int have_got = got_of(&e, "_ZNK7android8hardware7details13return_status8assertOkEv", &got) == 0;
    int checks = 0, asserts = 0;
    for (int i = 0; i < e.n; i++) {
        if (!e.s[i].exec)
            continue;
        unsigned char *base = e.d + e.s[i].off;
        uint64_t nins = e.s[i].size / 4, va = e.s[i].vaddr;
        for (uint64_t c = 0; c < nins; c++) {
            uint64_t t;
            uint32_t ins = r32(base + c * 4);
            if ((ins & 0xFC000000u) != 0x94000000u || !branch_target(ins | 0x14000000u, va + c * 4, &t) || t != fn)
                continue;
            for (uint64_t x = 0; x < nins; x++) {
                uint32_t b = r32(base + x * 4);
                uint64_t bt;
                if ((b & 0x7E000000u) != 0x34000000u || !branch_target(b, va + x * 4, &bt) || bt > va + c * 4 ||
                    bt + 48 < va + c * 4 || (bt - va) % 4)
                    continue;
                int ok = 1, bls = 0;
                for (uint64_t q = (bt - va) / 4; q < c && ok; q++) {
                    uint32_t h = r32(base + q * 4);
                    if (terminator(h) || ((h & 0xFC000000u) == 0x94000000u && ++bls > 1))
                        ok = 0;
                }
                if (!ok)
                    continue;
                w32(base + x * 4, 0xD503201Fu);
                checks++;
                for (uint64_t y = x + 1; y < nins && y <= x + 24; y++) {
                    uint32_t h = r32(base + y * 4);
                    uint64_t ht;
                    if (terminator(h))
                        break;
                    if (have_got && (h & 0xFC000000u) == 0x94000000u && branch_target(h | 0x14000000u, va + y * 4, &ht) &&
                        calls_got(&e, ht, got)) {
                        w32(base + y * 4, 0xD503201Fu);
                        asserts++;
                        break;
                    }
                }
            }
        }
    }
    if (checks && msg && msglen)
        snprintf(msg, msglen, "%d checks, %d value asserts", checks, asserts);
    return checks;
}
