/*
 * AES-128-GCM on Windows on ARM: four implementations, the way SSH uses the
 * cipher -- one complete GCM message per 32 KB packet, fresh IV, 4 bytes of
 * AAD, 16-byte tag, one thread.  The ARM64 counterpart of gcmsustain.c.
 *
 *   gcmsustain_arm64 --check                 known-answer test, then exit
 *   gcmsustain_arm64 --peak <MB> <rounds>    interleaved rounds, best of N
 *   gcmsustain_arm64 <lib> <seconds>         one library flat out, "t,mbps"
 *                                            once a second on stdout
 *
 *   lib = neon | cng | openssl3 | libressl
 *
 * No network end here, unlike the x64 file: the ARM64 machine this ran on
 * has no Thunderbolt link to push into, so these are cipher numbers only.
 *
 * On ISA-L's slot
 * ---------------
 * ISA-L's AES-GCM is x86-64 assembly and has no MSVC-buildable ARM64
 * equivalent, so the fourth implementation here is a hand-written one using
 * the ARMv8 crypto instructions through MSVC's NEON intrinsics -- AESE/AESMC
 * for the counter mode and PMULL/PMULL2 for GHASH, four blocks in flight
 * with one reduction per four.  That is the same question ISA-L answers on
 * x64: what does the cipher cost if we do it ourselves rather than call the
 * platform?  It is a straightforward implementation rather than a tuned one:
 * read its number as roughly what a backend of this kind would deliver, not
 * as the ceiling of the instruction set.
 *
 * The GF(2^128) arithmetic
 * ------------------------
 * GCM puts the coefficient of a^0 in the leftmost bit of the block, where a
 * carry-less multiply wants it in bit 0, so every block goes through RBIT on
 * the way in and the accumulator comes back through it once at the end.
 * That is one instruction per block more than the pre-shifted-H trick the
 * assembly implementations use, and it is much easier to be sure of --
 * which mattered: --check compares against CNG, OpenSSL and LibreSSL over a
 * whole 32 KB packet, ciphertext and tag, and the first version of this file
 * passed the ciphertext half while quietly computing a different GHASH.
 *
 * Copyright (C) 2026 Max Vilimpoc, rsync CMake/Windows port.
 * Distributed under the same GPL-3.0-or-later terms as the rest of rsync.
 */
#include <windows.h>
#include <bcrypt.h>
#include <arm64_neon.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

#define CHUNK   (32u << 10)     /* SSH's big packet */
#define AADLEN  4               /* the 4-byte length field */
#define TAGLEN  16

static const char *OPENSSL3_DLL =
    "C:\\Users\\Max\\AppData\\Local\\Programs\\Python\\Python313-arm64\\DLLs\\libcrypto-3-arm64.dll";
static const char *LIBRESSL_DLL = "C:\\Windows\\System32\\libcrypto.dll";

static double now(void)
{
    LARGE_INTEGER f, t;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)f.QuadPart;
}

/* ===================================================================== */
/* NEON: AES-128 through AESE/AESMC, GHASH through PMULL                 */
/* ===================================================================== */

typedef uint8x16_t v128;

static const unsigned char sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

static void expand128(const unsigned char key[16], unsigned char rk[11][16])
{
    static const unsigned char rcon[10] = {1,2,4,8,16,32,64,128,0x1b,0x36};
    int i, r;
    memcpy(rk[0], key, 16);
    for (r = 1; r <= 10; r++) {
        unsigned char t[4];
        t[0] = (unsigned char)(sbox[rk[r-1][13]] ^ rcon[r-1]);
        t[1] = sbox[rk[r-1][14]];
        t[2] = sbox[rk[r-1][15]];
        t[3] = sbox[rk[r-1][12]];
        for (i = 0; i < 4; i++)
            rk[r][i] = rk[r-1][i] ^ t[i];
        for (i = 4; i < 16; i++)
            rk[r][i] = rk[r-1][i] ^ rk[r][i-4];
    }
}

/* AESE is AddRoundKey then SubBytes+ShiftRows, so the round keys line up one
 * behind the textbook order and the last round is a plain XOR. */
#define AESROUND(st, k) st = vaesmcq_u8(vaeseq_u8(st, k))

static v128 aes_block(v128 st, const v128 *k)
{
    int i;
    for (i = 0; i < 9; i++)
        AESROUND(st, k[i]);
    return veorq_u8(vaeseq_u8(st, k[9]), k[10]);
}

/* GCM's bit order into the one a carry-less multiply uses, and back.
 *
 * GCM numbers the bits of a block from the left: the coefficient of a^0 is
 * the top bit of byte 0.  A carry-less multiply wants the coefficient of a^i
 * in bit i of the 128-bit little-endian value, whose byte i/8 is the same
 * byte -- so only the bits within each byte move, and RBIT is the whole
 * transform.  Reversing the byte order as well, which looks like the obvious
 * thing to do, moves every coefficient by a multiple of 8 and quietly
 * computes a different product.  This is its own inverse. */
static v128 bitrev128(v128 x)
{
    return vrbitq_u8(x);
}

static v128 pmull_lo(v128 a, v128 b)
{
    return vreinterpretq_u8_p128(vmull_p64(
        vreinterpret_p64_u64(vget_low_u64(vreinterpretq_u64_u8(a))),
        vreinterpret_p64_u64(vget_low_u64(vreinterpretq_u64_u8(b)))));
}

static v128 pmull_hi(v128 a, v128 b)
{
    return vreinterpretq_u8_p128(vmull_high_p64(
        vreinterpretq_p64_u64(vreinterpretq_u64_u8(a)),
        vreinterpretq_p64_u64(vreinterpretq_u64_u8(b))));
}

/* v << k for a 128-bit little-endian value, 1 <= k <= 63 */
#define SHL128(v, k) \
    vreinterpretq_u8_u64(vorrq_u64( \
        vshlq_n_u64(vreinterpretq_u64_u8(v), (k)), \
        vreinterpretq_u64_u8(vextq_u8(vdupq_n_u8(0), \
            vreinterpretq_u8_u64(vshrq_n_u64(vreinterpretq_u64_u8(v), 64 - (k))), 8))))

/* 128x128 -> 256, Karatsuba: three PMULLs rather than four. */
static void clmul128(v128 a, v128 b, v128 *lo, v128 *hi)
{
    const v128 zero = vdupq_n_u8(0);
    v128 z0 = pmull_lo(a, b);
    v128 z2 = pmull_hi(a, b);
    v128 as = veorq_u8(a, vextq_u8(a, a, 8));
    v128 bs = veorq_u8(b, vextq_u8(b, b, 8));
    v128 zm = veorq_u8(pmull_lo(as, bs), veorq_u8(z0, z2));
    *lo = veorq_u8(z0, vextq_u8(zero, zm, 8));
    *hi = veorq_u8(z2, vextq_u8(zm, zero, 8));
}

/* mod a^128 + a^7 + a^2 + a + 1.  Folding the high half down pushes seven
 * bits back past 128, so it is done twice; the second time cannot overflow
 * because the carry has degree 6 at most. */
static v128 gf_reduce(v128 lo, v128 hi)
{
    uint64_t hh = vgetq_lane_u64(vreinterpretq_u64_u8(hi), 1);
    uint64_t c = (hh >> 63) ^ (hh >> 62) ^ (hh >> 57);
    uint64_t cf = c ^ (c << 1) ^ (c << 2) ^ (c << 7);
    v128 t = veorq_u8(veorq_u8(hi, SHL128(hi, 1)),
                      veorq_u8(SHL128(hi, 2), SHL128(hi, 7)));
    uint64x2_t r = vreinterpretq_u64_u8(veorq_u8(lo, t));
    r = vsetq_lane_u64(vgetq_lane_u64(r, 0) ^ cf, r, 0);
    return vreinterpretq_u8_u64(r);
}

static v128 gf_mul(v128 a, v128 b)
{
    v128 lo, hi;
    clmul128(a, b, &lo, &hi);
    return gf_reduce(lo, hi);
}

struct neon_gcm {
    v128 rk[11];
    v128 h1, h2, h3, h4;   /* H, H^2, H^3, H^4, all bit-reversed */
};

static void neon_gcm_init(struct neon_gcm *g, const unsigned char key[16])
{
    unsigned char rkb[11][16];
    int i;

    expand128(key, rkb);
    for (i = 0; i < 11; i++)
        g->rk[i] = vld1q_u8(rkb[i]);
    g->h1 = bitrev128(aes_block(vdupq_n_u8(0), g->rk));
    g->h2 = gf_mul(g->h1, g->h1);
    g->h3 = gf_mul(g->h2, g->h1);
    g->h4 = gf_mul(g->h3, g->h1);
    SecureZeroMemory(rkb, sizeof rkb);
}

static v128 ghash_block(v128 acc, v128 block, v128 h)
{
    return gf_mul(veorq_u8(acc, bitrev128(block)), h);
}

/* len must be a multiple of 64, aadlen <= 16: the shape SSH's packets have,
 * which is all this benchmark encrypts. */
static void neon_gcm_encrypt(const struct neon_gcm *g, const unsigned char iv[12],
                             const unsigned char *aad, unsigned aadlen,
                             const unsigned char *in, unsigned len,
                             unsigned char *out, unsigned char tag[TAGLEN])
{
    unsigned char blk[16];
    uint32x4_t base;
    v128 acc = vdupq_n_u8(0), e0;
    uint32_t ctr = 2;
    unsigned i;

    memcpy(blk, iv, 12);
    blk[12] = 0; blk[13] = 0; blk[14] = 0; blk[15] = 1;
    base = vreinterpretq_u32_u8(vld1q_u8(blk));
    e0 = aes_block(vld1q_u8(blk), g->rk);        /* E(J0), for the tag */

    memset(blk, 0, sizeof blk);
    memcpy(blk, aad, aadlen);
    acc = ghash_block(acc, vld1q_u8(blk), g->h1);

    for (i = 0; i < len; i += 64) {
        v128 b0 = vreinterpretq_u8_u32(vsetq_lane_u32(_byteswap_ulong(ctr + 0), base, 3));
        v128 b1 = vreinterpretq_u8_u32(vsetq_lane_u32(_byteswap_ulong(ctr + 1), base, 3));
        v128 b2 = vreinterpretq_u8_u32(vsetq_lane_u32(_byteswap_ulong(ctr + 2), base, 3));
        v128 b3 = vreinterpretq_u8_u32(vsetq_lane_u32(_byteswap_ulong(ctr + 3), base, 3));
        v128 c0, c1, c2, c3, l0, h0, l1, h1, l2, h2, l3, h3;
        int j;

        for (j = 0; j < 9; j++) {
            AESROUND(b0, g->rk[j]); AESROUND(b1, g->rk[j]);
            AESROUND(b2, g->rk[j]); AESROUND(b3, g->rk[j]);
        }
        b0 = veorq_u8(vaeseq_u8(b0, g->rk[9]), g->rk[10]);
        b1 = veorq_u8(vaeseq_u8(b1, g->rk[9]), g->rk[10]);
        b2 = veorq_u8(vaeseq_u8(b2, g->rk[9]), g->rk[10]);
        b3 = veorq_u8(vaeseq_u8(b3, g->rk[9]), g->rk[10]);

        c0 = veorq_u8(vld1q_u8(in + i +  0), b0);
        c1 = veorq_u8(vld1q_u8(in + i + 16), b1);
        c2 = veorq_u8(vld1q_u8(in + i + 32), b2);
        c3 = veorq_u8(vld1q_u8(in + i + 48), b3);
        vst1q_u8(out + i +  0, c0); vst1q_u8(out + i + 16, c1);
        vst1q_u8(out + i + 32, c2); vst1q_u8(out + i + 48, c3);

        /* ((acc ^ C0)*H^4) ^ (C1*H^3) ^ (C2*H^2) ^ (C3*H), reduced once:
         * the reduction is linear, so it can wait until the four are summed. */
        clmul128(veorq_u8(acc, bitrev128(c0)), g->h4, &l0, &h0);
        clmul128(bitrev128(c1), g->h3, &l1, &h1);
        clmul128(bitrev128(c2), g->h2, &l2, &h2);
        clmul128(bitrev128(c3), g->h1, &l3, &h3);
        acc = gf_reduce(veorq_u8(veorq_u8(l0, l1), veorq_u8(l2, l3)),
                        veorq_u8(veorq_u8(h0, h1), veorq_u8(h2, h3)));
        ctr += 4;
    }

    /* the length block: bit counts, big-endian */
    {
        unsigned long long ab = (unsigned long long)aadlen * 8;
        unsigned long long cb = (unsigned long long)len * 8;
        int k;
        for (k = 0; k < 8; k++) {
            blk[k]     = (unsigned char)(ab >> (56 - 8 * k));
            blk[8 + k] = (unsigned char)(cb >> (56 - 8 * k));
        }
        acc = ghash_block(acc, vld1q_u8(blk), g->h1);
    }
    vst1q_u8(tag, veorq_u8(bitrev128(acc), e0));
}

/* ===================================================================== */
/* CNG                                                                    */
/* ===================================================================== */
struct cng {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_KEY_HANDLE key;
};

static int cng_init(struct cng *c, const unsigned char key[16])
{
    memset(c, 0, sizeof *c);
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&c->alg, BCRYPT_AES_ALGORITHM, NULL, 0)) ||
        !BCRYPT_SUCCESS(BCryptSetProperty(c->alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) ||
        !BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(c->alg, &c->key, NULL, 0,
            (PUCHAR)key, 16, 0)))
        return 0;
    return 1;
}

static int cng_encrypt(struct cng *c, const unsigned char iv[12],
                       unsigned char *aad, unsigned aadlen,
                       const unsigned char *in, unsigned len,
                       unsigned char *out, unsigned char tag[TAGLEN])
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    unsigned char nonce[12];
    ULONG done = 0;

    memcpy(nonce, iv, sizeof nonce);
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce;
    info.cbNonce = sizeof nonce;
    info.pbAuthData = aad;
    info.cbAuthData = aadlen;
    info.pbTag = tag;
    info.cbTag = TAGLEN;
    return BCRYPT_SUCCESS(BCryptEncrypt(c->key, (PUCHAR)in, len, &info, NULL, 0,
                                        out, len, &done, 0)) && done == len;
}

/* ===================================================================== */
/* EVP, resolved out of whichever DLL we were pointed at                  */
/* ===================================================================== */
typedef void *(*fn_cipher)(void);
typedef void *(*fn_ctx_new)(void);
typedef int (*fn_init)(void *, void *, void *, const unsigned char *, const unsigned char *);
typedef int (*fn_update)(void *, unsigned char *, int *, const unsigned char *, int);
typedef int (*fn_final)(void *, unsigned char *, int *);
typedef int (*fn_ctrl)(void *, int, int, void *);

struct evp {
    fn_cipher aes_128_gcm;
    fn_ctx_new ctx_new;
    fn_init init;
    fn_update update;
    fn_final final;
    fn_ctrl ctrl;
    void *ctx;
};

static int evp_load(struct evp *e, const char *dll, const unsigned char key[16],
                    const unsigned char iv[12])
{
    HMODULE h = LoadLibraryA(dll);
    if (!h) {
        fprintf(stderr, "LoadLibrary(%s) failed: %lu\n", dll, GetLastError());
        return 0;
    }
    e->aes_128_gcm = (fn_cipher)GetProcAddress(h, "EVP_aes_128_gcm");
    e->ctx_new = (fn_ctx_new)GetProcAddress(h, "EVP_CIPHER_CTX_new");
    e->init = (fn_init)GetProcAddress(h, "EVP_EncryptInit_ex");
    e->update = (fn_update)GetProcAddress(h, "EVP_EncryptUpdate");
    e->final = (fn_final)GetProcAddress(h, "EVP_EncryptFinal_ex");
    e->ctrl = (fn_ctrl)GetProcAddress(h, "EVP_CIPHER_CTX_ctrl");
    if (!e->aes_128_gcm || !e->ctx_new || !e->init || !e->update || !e->final || !e->ctrl) {
        fprintf(stderr, "missing EVP symbols in %s\n", dll);
        return 0;
    }
    e->ctx = e->ctx_new();
    return e->ctx != NULL && e->init(e->ctx, e->aes_128_gcm(), NULL, key, iv) == 1;
}

static void evp_encrypt(struct evp *e, const unsigned char iv[12],
                        const unsigned char *aad, unsigned aadlen,
                        const unsigned char *in, unsigned len,
                        unsigned char *out, unsigned char tag[TAGLEN])
{
    int outl = 0;
    e->init(e->ctx, NULL, NULL, NULL, iv);
    e->update(e->ctx, NULL, &outl, aad, (int)aadlen);
    e->update(e->ctx, out, &outl, in, (int)len);
    e->final(e->ctx, out, &outl);
    e->ctrl(e->ctx, 0x10 /* EVP_CTRL_GCM_GET_TAG */, TAGLEN, tag);
}

/* ===================================================================== */

enum { L_NEON, L_CNG, L_OPENSSL3, L_LIBRESSL, NLIB };
static const char *LIBNAME[NLIB] = { "neon", "cng", "openssl3", "libressl" };

struct bench {
    struct neon_gcm neon;
    struct cng cng;
    struct evp evp[NLIB];      /* only the two EVP slots are used */
    int have[NLIB];
};

static const unsigned char KEY[16] = "0123456789abcdef";
static const unsigned char IV[12] = "0123456789ab";

static int setup(struct bench *b, int which)
{
    memset(b, 0, sizeof *b);
    if (which == L_NEON || which < 0) {
        neon_gcm_init(&b->neon, KEY);
        b->have[L_NEON] = 1;
    }
    if (which == L_CNG || which < 0)
        b->have[L_CNG] = cng_init(&b->cng, KEY);
    if (which == L_OPENSSL3 || which < 0)
        b->have[L_OPENSSL3] = evp_load(&b->evp[L_OPENSSL3], OPENSSL3_DLL, KEY, IV);
    if (which == L_LIBRESSL || which < 0)
        b->have[L_LIBRESSL] = evp_load(&b->evp[L_LIBRESSL], LIBRESSL_DLL, KEY, IV);
    return which < 0 || b->have[which];
}

static void one_packet(struct bench *b, int lib, unsigned char *aad,
                       const unsigned char *in, unsigned char *out,
                       unsigned char *tag)
{
    switch (lib) {
    case L_NEON:
        neon_gcm_encrypt(&b->neon, IV, aad, AADLEN, in, CHUNK, out, tag);
        break;
    case L_CNG:
        cng_encrypt(&b->cng, IV, aad, AADLEN, in, CHUNK, out, tag);
        break;
    default:
        evp_encrypt(&b->evp[lib], IV, aad, AADLEN, in, CHUNK, out, tag);
        break;
    }
}

/* --------------------------------------------------------------- check */
static int check(void)
{
    struct bench b;
    unsigned char *in, *neon_out, *ref_out;
    unsigned char aad[AADLEN] = { 0, 0, 0x80, 0 };
    unsigned char neon_tag[TAGLEN], ref_tag[TAGLEN];
    unsigned i;
    int bad = 0, lib;

    if (!setup(&b, -1))
        return 1;
    in = (unsigned char *)_aligned_malloc(CHUNK, 64);
    neon_out = (unsigned char *)_aligned_malloc(CHUNK, 64);
    ref_out = (unsigned char *)_aligned_malloc(CHUNK, 64);
    for (i = 0; i < CHUNK; i++)
        in[i] = (unsigned char)(i * 7 + (i >> 8));

    neon_gcm_encrypt(&b.neon, IV, aad, AADLEN, in, CHUNK, neon_out, neon_tag);

    for (lib = L_CNG; lib < NLIB; lib++) {
        if (!b.have[lib]) {
            printf("  %-9s not available, not compared\n", LIBNAME[lib]);
            continue;
        }
        memset(ref_out, 0, CHUNK);
        memset(ref_tag, 0, TAGLEN);
        one_packet(&b, lib, aad, in, ref_out, ref_tag);
        if (memcmp(neon_out, ref_out, CHUNK) != 0) {
            printf("  FAIL neon ciphertext differs from %s\n", LIBNAME[lib]);
            bad = 1;
        } else if (memcmp(neon_tag, ref_tag, TAGLEN) != 0) {
            printf("  FAIL neon tag differs from %s\n", LIBNAME[lib]);
            bad = 1;
        } else {
            printf("  neon == %-9s ciphertext and tag agree over %u KB\n",
                   LIBNAME[lib], CHUNK >> 10);
        }
    }
    _aligned_free(in); _aligned_free(neon_out); _aligned_free(ref_out);
    return bad;
}

/* ---------------------------------------------------------------- peak */
static void peak(double mb_per_round, int rounds)
{
    struct bench b;
    unsigned char *in, *out;
    unsigned char aad[AADLEN] = { 0, 0, 0x80, 0 };
    unsigned char tag[TAGLEN];
    unsigned long long n = (unsigned long long)(mb_per_round * 1e6) / CHUNK;
    double best[NLIB] = { 0, 0, 0, 0 };
    unsigned i;
    int r, lib;

    if (!setup(&b, -1))
        return;
    in = (unsigned char *)_aligned_malloc(CHUNK, 64);
    out = (unsigned char *)_aligned_malloc(CHUNK, 64);
    for (i = 0; i < CHUNK; i++)
        in[i] = (unsigned char)i;

    for (r = 0; r < rounds; r++) {
        for (lib = 0; lib < NLIB; lib++) {
            double t0, el, mbps;
            unsigned long long j;
            if (!b.have[lib])
                continue;
            t0 = now();
            for (j = 0; j < n; j++)
                one_packet(&b, lib, aad, in, out, tag);
            el = now() - t0;
            mbps = (double)n * CHUNK / el / 1e6;
            fprintf(stderr, "   round %d  %-9s %7.0f MB/s\n", r + 1, LIBNAME[lib], mbps);
            if (mbps > best[lib])
                best[lib] = mbps;
        }
    }
    printf("lib,mbps\n");
    for (lib = 0; lib < NLIB; lib++)
        if (b.have[lib])
            printf("%s,%.0f\n", LIBNAME[lib], best[lib]);
    _aligned_free(in); _aligned_free(out);
}

/* ----------------------------------------------------------- sustained */
static int sustain(const char *which, double secs)
{
    struct bench b;
    unsigned char *in, *out;
    unsigned char aad[AADLEN] = { 0, 0, 0x80, 0 };
    unsigned char tag[TAGLEN];
    double t0, mark;
    unsigned long long bytes = 0, at_mark = 0;
    unsigned i;
    int lib = -1;

    for (i = 0; i < NLIB; i++)
        if (!strcmp(which, LIBNAME[i]))
            lib = (int)i;
    if (lib < 0) {
        fprintf(stderr, "unknown library %s\n", which);
        return 1;
    }
    if (!setup(&b, lib)) {
        fprintf(stderr, "%s is not available here\n", which);
        return 1;
    }
    in = (unsigned char *)_aligned_malloc(CHUNK, 64);
    out = (unsigned char *)_aligned_malloc(CHUNK, 64);
    for (i = 0; i < CHUNK; i++)
        in[i] = (unsigned char)i;

    t0 = mark = now();
    printf("t,mbps\n");
    for (;;) {
        double t;
        for (i = 0; i < 64; i++) {      /* a few before checking the clock */
            one_packet(&b, lib, aad, in, out, tag);
            bytes += CHUNK;
        }
        t = now();
        if (t - mark >= 1.0) {
            printf("%.2f,%.0f\n", t - t0, (double)(bytes - at_mark) / (t - mark) / 1e6);
            fflush(stdout);
            mark = t;
            at_mark = bytes;
        }
        if (t - t0 >= secs)
            break;
    }
    _aligned_free(in); _aligned_free(out);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--check"))
        return check();
    if (argc > 1 && !strcmp(argv[1], "--peak"))
        return peak(argc > 2 ? atof(argv[2]) : 1000.0,
                    argc > 3 ? atoi(argv[3]) : 3), 0;
    if (argc > 2)
        return sustain(argv[1], atof(argv[2]));
    fprintf(stderr, "usage: %s --check | --peak <MB> <rounds> | <lib> <seconds>\n", argv[0]);
    return 2;
}
