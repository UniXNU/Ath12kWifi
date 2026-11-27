/* Self-contained NIST P-256/P-384/P-521 EC and bignum primitives for SAE.
 * Uses wpa_supplicant's internal static libtommath routines with zero external dependencies. */
#include "utils/includes.h"
#include "utils/common.h"
#include "crypto/crypto.h"
#include <limits.h>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif
#include "tls/libtommath.c"
#ifdef __clang__
#pragma clang diagnostic pop
#endif

struct crypto_bignum {
  mp_int mp;
};

struct crypto_ec_point {
  mp_int x;
  mp_int y;
  int infinity;
};

struct crypto_ec {
  int group;
  size_t prime_len;
  size_t prime_bits;
  size_t order_len;
  struct crypto_bignum prime;
  struct crypto_bignum order;
  struct crypto_bignum a;
  struct crypto_bignum b;
  struct crypto_ec_point generator;
};

struct nw_ec_curve_params {
  int group;
  size_t prime_len;
  size_t prime_bits;
  const u8 prime[66];
  const u8 a[66];
  const u8 b[66];
  const u8 order[66];
  const u8 gx[66];
  const u8 gy[66];
};

static const struct nw_ec_curve_params nw_ec_curves[] = {
  /* IANA Group 19: NIST P-256 (secp256r1) */
  {
    .group = 19,
    .prime_len = 32,
    .prime_bits = 256,
    .prime = {
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    },
    .a = {
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc
    },
    .b = {
      0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
      0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
      0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
      0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b
    },
    .order = {
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
      0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    },
    .gx = {
      0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
      0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
      0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
      0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
    },
    .gy = {
      0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
      0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
      0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
      0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
    },
  },
  /* IANA Group 20: NIST P-384 (secp384r1) */
  {
    .group = 20,
    .prime_len = 48,
    .prime_bits = 384,
    .prime = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
    },
    .a = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfc
    },
    .b = {
      0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4,
      0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19,
      0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12,
      0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a,
      0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d,
      0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef
    },
    .order = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
      0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
      0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73
    },
    .gx = {
      0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37,
      0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
      0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
      0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
      0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c,
      0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7
    },
    .gy = {
      0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f,
      0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
      0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
      0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
      0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d,
      0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f
    },
  },
  /* IANA Group 21: NIST P-521 (secp521r1) */
  {
    .group = 21,
    .prime_len = 66,
    .prime_bits = 521,
    .prime = {
      0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff
    },
    .a = {
      0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xfc
    },
    .b = {
      0x00, 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c,
      0x9a, 0x1f, 0x92, 0x9a, 0x21, 0xa0, 0xb6, 0x85,
      0x40, 0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3,
      0x15, 0xf3, 0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1,
      0x09, 0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e,
      0x93, 0x7b, 0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1,
      0xbf, 0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c,
      0x34, 0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50,
      0x3f, 0x00
    },
    .order = {
      0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f,
      0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
      0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
      0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
      0x64, 0x09
    },
    .gx = {
      0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04,
      0xe9, 0xcd, 0x9e, 0x3e, 0xcb, 0x66, 0x23, 0x95,
      0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f,
      0xb5, 0x21, 0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d,
      0x3d, 0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef, 0xe7,
      0x59, 0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2, 0xff,
      0xa8, 0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85, 0x6a,
      0x42, 0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2, 0xe5,
      0xbd, 0x66
    },
    .gy = {
      0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b,
      0xc0, 0x04, 0x5c, 0x8a, 0x5f, 0xb4, 0x2c, 0x7d,
      0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b,
      0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e,
      0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4,
      0x26, 0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad,
      0x07, 0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72,
      0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1,
      0x66, 0x50
    },
  },
};

static mp_int *bn_mp(const struct crypto_bignum *n)
{
  return (mp_int *)&n->mp;
}

static void mp_wipe_clear(mp_int *a)
{
  if (a->dp && a->alloc > 0)
    forced_memzero(a->dp, (size_t)a->alloc * sizeof(mp_digit));
  mp_clear(a);
}

static int mp_invmod_ext(mp_int *a, mp_int *m, mp_int *out)
{
  mp_int r0, r1, t0, t1, q, rem, qt1, tnext;
  int res = -1;

  if (m->sign == MP_NEG || mp_cmp_d(m, 1) != MP_GT)
    return -1;
  if (mp_init_multi(&r0, &r1, &t0, &t1, &q, &rem, &qt1, &tnext, NULL) != MP_OKAY)
    return -1;
  if (mp_copy(m, &r0) != MP_OKAY || mp_mod(a, m, &r1) != MP_OKAY)
    goto out;
  if (mp_iszero(&r1))
    goto out;
  mp_set(&t1, 1);

  while (!mp_iszero(&r1)) {
    if (mp_div(&r0, &r1, &q, &rem) != MP_OKAY)
      goto out;
    if (mp_mulmod(&q, &t1, m, &qt1) != MP_OKAY)
      goto out;
    if (mp_cmp(&t0, &qt1) == MP_LT) {
      if (mp_add(&t0, m, &tnext) != MP_OKAY ||
          mp_sub(&tnext, &qt1, &tnext) != MP_OKAY)
        goto out;
    } else {
      if (mp_sub(&t0, &qt1, &tnext) != MP_OKAY)
        goto out;
    }
    mp_exch(&r0, &r1);
    mp_exch(&r1, &rem);
    mp_exch(&t0, &t1);
    mp_exch(&t1, &tnext);
  }

  if (r0.sign == MP_ZPOS && mp_cmp_d(&r0, 1) == MP_EQ &&
      mp_copy(&t0, out) == MP_OKAY)
    res = 0;

out:
  mp_wipe_clear(&r0);
  mp_wipe_clear(&r1);
  mp_wipe_clear(&t0);
  mp_wipe_clear(&t1);
  mp_wipe_clear(&q);
  mp_wipe_clear(&rem);
  mp_wipe_clear(&qt1);
  mp_wipe_clear(&tnext);
  return res;
}

/* ---- crypto_bignum_* ---- */

struct crypto_bignum *crypto_bignum_init(void)
{
  struct crypto_bignum *bn = os_zalloc(sizeof(*bn));
  if (!bn)
    return NULL;
  if (mp_init(&bn->mp) != MP_OKAY) {
    os_free(bn);
    return NULL;
  }
  return bn;
}

struct crypto_bignum *crypto_bignum_init_set(const u8 *buf, size_t len)
{
  if (!buf || len > INT_MAX)
    return NULL;
  struct crypto_bignum *bn = crypto_bignum_init();
  if (!bn)
    return NULL;
  if (len > 0 && mp_read_unsigned_bin(&bn->mp, (u8 *)buf, (int)len) != MP_OKAY) {
    crypto_bignum_deinit(bn, 1);
    return NULL;
  }
  return bn;
}

struct crypto_bignum *crypto_bignum_init_uint(unsigned int val)
{
  u8 raw[4];
  WPA_PUT_BE32(raw, val);
  return crypto_bignum_init_set(raw, sizeof(raw));
}

void crypto_bignum_deinit(struct crypto_bignum *n, int clear)
{
  if (!n)
    return;
  if (clear) {
    mp_wipe_clear(&n->mp);
    forced_memzero(n, sizeof(*n));
  } else {
    mp_clear(&n->mp);
  }
  os_free(n);
}

int crypto_bignum_to_bin(const struct crypto_bignum *a,
                         u8 *buf, size_t buflen, size_t padlen)
{
  if (!a || !buf || a->mp.sign == MP_NEG || padlen > buflen || buflen > INT_MAX)
    return -1;
  size_t n = (size_t)mp_unsigned_bin_size(bn_mp(a));
  if (n > buflen || (padlen > 0 && n > padlen))
    return -1;
  size_t out_len = padlen > n ? padlen : n;
  size_t pad = out_len - n;
  if (pad > 0)
    os_memset(buf, 0, pad);
  if (n > 0 && mp_to_unsigned_bin(bn_mp(a), buf + pad) != MP_OKAY)
    return -1;
  return (int)out_len;
}

int crypto_bignum_rand(struct crypto_bignum *r, const struct crypto_bignum *m)
{
  if (!r || !m || m->mp.sign == MP_NEG || mp_iszero(bn_mp(m)))
    return -1;
  int bits = mp_count_bits(bn_mp(m));
  if (bits <= 0)
    return -1;
  size_t bytes = (size_t)(bits + 7) / 8;
  u8 *tmp = os_malloc(bytes);
  if (!tmp)
    return -1;
  unsigned top_bits = (unsigned)bits & 7u;
  u8 mask = top_bits ? (u8)((1u << top_bits) - 1u) : 0xffu;
  int ret = -1;

  for (unsigned attempt = 0; attempt < 256; attempt++) {
    if (os_get_random(tmp, bytes) < 0)
      break;
    tmp[0] &= mask;
    if (mp_read_unsigned_bin(&r->mp, tmp, (int)bytes) != MP_OKAY)
      break;
    if (mp_cmp(&r->mp, bn_mp(m)) == MP_LT) {
      ret = 0;
      break;
    }
  }

  forced_memzero(tmp, bytes);
  os_free(tmp);
  return ret;
}

int crypto_bignum_add(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *c)
{
  if (!a || !b || !c)
    return -1;
  return mp_add(bn_mp(a), bn_mp(b), &c->mp) == MP_OKAY ? 0 : -1;
}

int crypto_bignum_mod(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *c)
{
  if (!a || !b || !c || b->mp.sign == MP_NEG || mp_iszero(bn_mp(b)))
    return -1;
  return mp_mod(bn_mp(a), bn_mp(b), &c->mp) == MP_OKAY ? 0 : -1;
}

int crypto_bignum_exptmod(const struct crypto_bignum *a,
                          const struct crypto_bignum *b,
                          const struct crypto_bignum *c,
                          struct crypto_bignum *d)
{
  if (!a || !b || !c || !d || b->mp.sign == MP_NEG ||
      c->mp.sign == MP_NEG || mp_iszero(bn_mp(c)))
    return -1;
  return mp_exptmod(bn_mp(a), bn_mp(b), bn_mp(c), &d->mp) == MP_OKAY ? 0 : -1;
}

int crypto_bignum_inverse(const struct crypto_bignum *a,
                          const struct crypto_bignum *b,
                          struct crypto_bignum *c)
{
  if (!a || !b || !c)
    return -1;
  return mp_invmod_ext(bn_mp(a), bn_mp(b), &c->mp);
}

int crypto_bignum_sub(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *c)
{
  if (!a || !b || !c)
    return -1;
  return mp_sub(bn_mp(a), bn_mp(b), &c->mp) == MP_OKAY ? 0 : -1;
}

int crypto_bignum_div(const struct crypto_bignum *a,
                      const struct crypto_bignum *b,
                      struct crypto_bignum *c)
{
  if (!a || !b || !c || mp_iszero(bn_mp(b)))
    return -1;
  return mp_div(bn_mp(a), bn_mp(b), &c->mp, NULL) == MP_OKAY ? 0 : -1;
}

int crypto_bignum_addmod(const struct crypto_bignum *a,
                         const struct crypto_bignum *b,
                         const struct crypto_bignum *c,
                         struct crypto_bignum *d)
{
  mp_int tmp;
  int res;

  if (!a || !b || !c || !d || c->mp.sign == MP_NEG || mp_iszero(bn_mp(c)))
    return -1;
  if (mp_init(&tmp) != MP_OKAY)
    return -1;
  res = (mp_add(bn_mp(a), bn_mp(b), &tmp) == MP_OKAY &&
         mp_mod(&tmp, bn_mp(c), &d->mp) == MP_OKAY) ? 0 : -1;
  mp_wipe_clear(&tmp);
  return res;
}

int crypto_bignum_mulmod(const struct crypto_bignum *a,
                         const struct crypto_bignum *b,
                         const struct crypto_bignum *c,
                         struct crypto_bignum *d)
{
  if (!a || !b || !c || !d || c->mp.sign == MP_NEG || mp_iszero(bn_mp(c)))
    return -1;
  return mp_mulmod(bn_mp(a), bn_mp(b), bn_mp(c), &d->mp) == MP_OKAY ? 0 : -1;
}

int crypto_bignum_sqrmod(const struct crypto_bignum *a,
                         const struct crypto_bignum *b,
                         struct crypto_bignum *c)
{
  mp_int tmp;
  int res;

  if (!a || !b || !c || b->mp.sign == MP_NEG || mp_iszero(bn_mp(b)))
    return -1;
  if (mp_init(&tmp) != MP_OKAY)
    return -1;
  res = (mp_sqr(bn_mp(a), &tmp) == MP_OKAY &&
         mp_mod(&tmp, bn_mp(b), &c->mp) == MP_OKAY) ? 0 : -1;
  mp_wipe_clear(&tmp);
  return res;
}

int crypto_bignum_rshift(const struct crypto_bignum *a, int n,
                         struct crypto_bignum *r)
{
  if (!a || !r || n < 0 || a->mp.sign == MP_NEG)
    return -1;
  return mp_div_2d(bn_mp(a), n, &r->mp, NULL) == MP_OKAY ? 0 : -1;
}

int crypto_bignum_cmp(const struct crypto_bignum *a,
                      const struct crypto_bignum *b)
{
  if (!a || !b)
    return a == b ? 0 : (a ? 1 : -1);
  return mp_cmp(bn_mp(a), bn_mp(b));
}

int crypto_bignum_is_zero(const struct crypto_bignum *a)
{
  return a && mp_iszero(bn_mp(a)) == MP_YES ? 1 : 0;
}

int crypto_bignum_is_one(const struct crypto_bignum *a)
{
  return a && a->mp.sign == MP_ZPOS && mp_cmp_d(bn_mp(a), 1) == MP_EQ ? 1 : 0;
}

int crypto_bignum_is_odd(const struct crypto_bignum *a)
{
  return a && a->mp.sign == MP_ZPOS && mp_isodd(bn_mp(a)) == MP_YES ? 1 : 0;
}

int crypto_bignum_legendre(const struct crypto_bignum *a,
                           const struct crypto_bignum *p)
{
  mp_int amod, exp, res, res_plus_1;
  int ret = -2;

  if (!a || !p || p->mp.sign == MP_NEG ||
      mp_cmp_d(bn_mp(p), 2) != MP_GT || mp_isodd(bn_mp(p)) != MP_YES)
    return -2;
  if (mp_init_multi(&amod, &exp, &res, &res_plus_1, NULL) != MP_OKAY)
    return -2;
  if (mp_mod(bn_mp(a), bn_mp(p), &amod) != MP_OKAY)
    goto out;
  if (mp_iszero(&amod)) {
    ret = 0;
    goto out;
  }
  /* p is odd > 2, so p >> 1 == (p - 1) / 2. */
  if (mp_div_2d(bn_mp(p), 1, &exp, NULL) != MP_OKAY ||
      mp_exptmod(&amod, &exp, bn_mp(p), &res) != MP_OKAY)
    goto out;
  if (res.sign == MP_ZPOS && mp_cmp_d(&res, 1) == MP_EQ) {
    ret = 1;
  } else {
    mp_set(&exp, 1);
    if (mp_add(&res, &exp, &res_plus_1) == MP_OKAY &&
        mp_cmp(&res_plus_1, bn_mp(p)) == MP_EQ)
      ret = -1;
  }

out:
  mp_wipe_clear(&amod);
  mp_wipe_clear(&exp);
  mp_wipe_clear(&res);
  mp_wipe_clear(&res_plus_1);
  return ret;
}

/* ---- Jacobian projective EC helpers (y^2 = x^3 - 3x + b mod p) ---- */

struct nw_jac_point {
  mp_int x;
  mp_int y;
  mp_int z;
};

static int jac_init(struct nw_jac_point *p)
{
  return mp_init_multi(&p->x, &p->y, &p->z, NULL) == MP_OKAY ? 0 : -1;
}

static void jac_clear(struct nw_jac_point *p)
{
  mp_wipe_clear(&p->x);
  mp_wipe_clear(&p->y);
  mp_wipe_clear(&p->z);
}

static void jac_set_infinity(struct nw_jac_point *p)
{
  mp_set(&p->x, 1);
  mp_set(&p->y, 1);
  mp_zero(&p->z);
}

static int jac_copy(const struct nw_jac_point *src, struct nw_jac_point *dst)
{
  if (mp_copy((mp_int *)&src->x, &dst->x) != MP_OKAY ||
      mp_copy((mp_int *)&src->y, &dst->y) != MP_OKAY ||
      mp_copy((mp_int *)&src->z, &dst->z) != MP_OKAY)
    return -1;
  return 0;
}

static int jac_from_affine(const struct crypto_ec_point *src, struct nw_jac_point *dst)
{
  if (src->infinity) {
    jac_set_infinity(dst);
    return 0;
  }
  if (mp_copy((mp_int *)&src->x, &dst->x) != MP_OKAY ||
      mp_copy((mp_int *)&src->y, &dst->y) != MP_OKAY)
    return -1;
  mp_set(&dst->z, 1);
  return 0;
}

static int jac_to_affine(struct crypto_ec *e, const struct nw_jac_point *src,
                         struct crypto_ec_point *dst)
{
  mp_int z_inv, z_inv2, z_inv3;
  int ret = -1;

  if (mp_iszero((mp_int *)&src->z)) {
    mp_zero(&dst->x);
    mp_zero(&dst->y);
    dst->infinity = 1;
    return 0;
  }
  if (mp_init_multi(&z_inv, &z_inv2, &z_inv3, NULL) != MP_OKAY)
    return -1;
  if (mp_invmod_ext((mp_int *)&src->z, &e->prime.mp, &z_inv) == 0 &&
      mp_sqr(&z_inv, &z_inv2) == MP_OKAY &&
      mp_mod(&z_inv2, &e->prime.mp, &z_inv2) == MP_OKAY &&
      mp_mulmod(&z_inv2, &z_inv, &e->prime.mp, &z_inv3) == MP_OKAY &&
      mp_mulmod((mp_int *)&src->x, &z_inv2, &e->prime.mp, &dst->x) == MP_OKAY &&
      mp_mulmod((mp_int *)&src->y, &z_inv3, &e->prime.mp, &dst->y) == MP_OKAY) {
    dst->infinity = 0;
    ret = 0;
  }
  mp_wipe_clear(&z_inv);
  mp_wipe_clear(&z_inv2);
  mp_wipe_clear(&z_inv3);
  return ret;
}

static int mod_add(mp_int *a, mp_int *b, mp_int *r, mp_int *p)
{
  if (mp_add(a, b, r) != MP_OKAY)
    return -1;
  if (mp_cmp(r, p) != MP_LT && mp_sub(r, p, r) != MP_OKAY)
    return -1;
  return 0;
}

static int mod_sub(mp_int *a, mp_int *b, mp_int *r, mp_int *p)
{
  if (mp_cmp(a, b) == MP_LT) {
    mp_int tmp;
    if (mp_init(&tmp) != MP_OKAY)
      return -1;
    int ok = (mp_add(a, p, &tmp) == MP_OKAY && mp_sub(&tmp, b, r) == MP_OKAY) ? 0 : -1;
    mp_wipe_clear(&tmp);
    return ok;
  }
  return mp_sub(a, b, r) == MP_OKAY ? 0 : -1;
}

static int mod_sqr(mp_int *a, mp_int *r, mp_int *p)
{
  return (mp_sqr(a, r) == MP_OKAY && mp_mod(r, p, r) == MP_OKAY) ? 0 : -1;
}

static int mod_dbl(mp_int *a, mp_int *r, mp_int *p)
{
  return mod_add(a, a, r, p);
}

/* EFD dbl-2001-b for a = -3 (safe when out aliases in). */
static int jac_double(const struct nw_jac_point *in, struct nw_jac_point *out, mp_int *p)
{
  mp_int delta, gamma, beta, alpha, t1, t2, nx, ny, nz;
  int ret = -1;

  if (mp_iszero((mp_int *)&in->z) || mp_iszero((mp_int *)&in->y)) {
    jac_set_infinity(out);
    return 0;
  }
  if (mp_init_multi(&delta, &gamma, &beta, &alpha, &t1, &t2, &nx, &ny, &nz, NULL) != MP_OKAY)
    return -1;

  /* delta = Z1^2, gamma = Y1^2, beta = X1 * gamma */
  if (mod_sqr((mp_int *)&in->z, &delta, p) ||
      mod_sqr((mp_int *)&in->y, &gamma, p) ||
      mp_mulmod((mp_int *)&in->x, &gamma, p, &beta) != MP_OKAY)
    goto out;

  /* alpha = 3 * (X1 - delta) * (X1 + delta) mod p */
  if (mod_sub((mp_int *)&in->x, &delta, &t1, p) ||
      mod_add((mp_int *)&in->x, &delta, &t2, p) ||
      mp_mulmod(&t1, &t2, p, &alpha) != MP_OKAY ||
      mod_dbl(&alpha, &t1, p) ||
      mod_add(&t1, &alpha, &alpha, p))
    goto out;

  /* X3 = alpha^2 - 8 * beta mod p */
  if (mod_sqr(&alpha, &nx, p) ||
      mod_dbl(&beta, &t1, p) ||      /* 2 * beta */
      mod_dbl(&t1, &t1, p) ||        /* 4 * beta */
      mod_dbl(&t1, &t2, p) ||        /* 8 * beta */
      mod_sub(&nx, &t2, &nx, p))
    goto out;

  /* Z3 = (Y1 + Z1)^2 - gamma - delta mod p */
  if (mod_add((mp_int *)&in->y, (mp_int *)&in->z, &nz, p) ||
      mod_sqr(&nz, &nz, p) ||
      mod_sub(&nz, &gamma, &nz, p) ||
      mod_sub(&nz, &delta, &nz, p))
    goto out;

  /* Y3 = alpha * (4 * beta - X3) - 8 * gamma^2 mod p */
  if (mod_sub(&t1, &nx, &t1, p) ||
      mp_mulmod(&alpha, &t1, p, &ny) != MP_OKAY ||
      mod_sqr(&gamma, &t2, p) ||
      mod_dbl(&t2, &t2, p) ||
      mod_dbl(&t2, &t2, p) ||
      mod_dbl(&t2, &t2, p) ||
      mod_sub(&ny, &t2, &ny, p))
    goto out;

  if (mp_copy(&nx, &out->x) == MP_OKAY &&
      mp_copy(&ny, &out->y) == MP_OKAY &&
      mp_copy(&nz, &out->z) == MP_OKAY)
    ret = 0;

out:
  mp_wipe_clear(&delta);
  mp_wipe_clear(&gamma);
  mp_wipe_clear(&beta);
  mp_wipe_clear(&alpha);
  mp_wipe_clear(&t1);
  mp_wipe_clear(&t2);
  mp_wipe_clear(&nx);
  mp_wipe_clear(&ny);
  mp_wipe_clear(&nz);
  return ret;
}

/* EFD add-2007-bl complete Jacobian addition (handles infinity, P == Q, P == -Q, and aliasing). */
static int jac_add(const struct nw_jac_point *p1, const struct nw_jac_point *p2,
                   struct nw_jac_point *out, mp_int *p)
{
  mp_int z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v, t, nx, ny, nz;
  int ret = -1;

  if (mp_iszero((mp_int *)&p1->z))
    return jac_copy(p2, out);
  if (mp_iszero((mp_int *)&p2->z))
    return jac_copy(p1, out);

  if (mp_init_multi(&z1z1, &z2z2, &u1, &u2, &s1, &s2, &h, &i, &j, &r, &v, &t,
                    &nx, &ny, &nz, NULL) != MP_OKAY)
    return -1;

  if (mod_sqr((mp_int *)&p1->z, &z1z1, p) ||
      mod_sqr((mp_int *)&p2->z, &z2z2, p) ||
      mp_mulmod((mp_int *)&p1->x, &z2z2, p, &u1) != MP_OKAY ||
      mp_mulmod((mp_int *)&p2->x, &z1z1, p, &u2) != MP_OKAY ||
      mp_mulmod((mp_int *)&p2->z, &z2z2, p, &t) != MP_OKAY ||
      mp_mulmod((mp_int *)&p1->y, &t, p, &s1) != MP_OKAY ||
      mp_mulmod((mp_int *)&p1->z, &z1z1, p, &t) != MP_OKAY ||
      mp_mulmod((mp_int *)&p2->y, &t, p, &s2) != MP_OKAY)
    goto out;

  if (mp_cmp(&u1, &u2) == MP_EQ) {
    if (mp_cmp(&s1, &s2) == MP_EQ) {
      ret = jac_double(p1, out, p);
    } else {
      jac_set_infinity(out);
      ret = 0;
    }
    goto out;
  }

  /* h = u2 - u1; i = (2*h)^2; j = h * i; r = 2*(s2 - s1); v = u1 * i */
  if (mod_sub(&u2, &u1, &h, p) ||
      mod_dbl(&h, &i, p) ||
      mod_sqr(&i, &i, p) ||
      mp_mulmod(&h, &i, p, &j) != MP_OKAY ||
      mod_sub(&s2, &s1, &r, p) ||
      mod_dbl(&r, &r, p) ||
      mp_mulmod(&u1, &i, p, &v) != MP_OKAY)
    goto out;

  /* X3 = r^2 - j - 2*v */
  if (mod_sqr(&r, &nx, p) ||
      mod_sub(&nx, &j, &nx, p) ||
      mod_dbl(&v, &t, p) ||
      mod_sub(&nx, &t, &nx, p))
    goto out;

  /* Y3 = r * (v - X3) - 2 * s1 * j */
  if (mod_sub(&v, &nx, &t, p) ||
      mp_mulmod(&r, &t, p, &ny) != MP_OKAY ||
      mp_mulmod(&s1, &j, p, &t) != MP_OKAY ||
      mod_dbl(&t, &t, p) ||
      mod_sub(&ny, &t, &ny, p))
    goto out;

  /* Z3 = ((Z1 + Z2)^2 - z1z1 - z2z2) * h */
  if (mod_add((mp_int *)&p1->z, (mp_int *)&p2->z, &t, p) ||
      mod_sqr(&t, &t, p) ||
      mod_sub(&t, &z1z1, &t, p) ||
      mod_sub(&t, &z2z2, &t, p) ||
      mp_mulmod(&t, &h, p, &nz) != MP_OKAY)
    goto out;

  if (mp_copy(&nx, &out->x) == MP_OKAY &&
      mp_copy(&ny, &out->y) == MP_OKAY &&
      mp_copy(&nz, &out->z) == MP_OKAY)
    ret = 0;

out:
  mp_wipe_clear(&z1z1);
  mp_wipe_clear(&z2z2);
  mp_wipe_clear(&u1);
  mp_wipe_clear(&u2);
  mp_wipe_clear(&s1);
  mp_wipe_clear(&s2);
  mp_wipe_clear(&h);
  mp_wipe_clear(&i);
  mp_wipe_clear(&j);
  mp_wipe_clear(&r);
  mp_wipe_clear(&v);
  mp_wipe_clear(&t);
  mp_wipe_clear(&nx);
  mp_wipe_clear(&ny);
  mp_wipe_clear(&nz);
  return ret;
}

static uint32_t mp_test_bit_ct(const mp_int *a, size_t bit)
{
  size_t digit_idx = bit / (size_t)DIGIT_BIT;
  size_t bit_idx = bit % (size_t)DIGIT_BIT;
  return (uint32_t)((a->dp[digit_idx] >> bit_idx) & (mp_digit)1);
}

static int mp_cond_swap_ct(mp_int *a, mp_int *b, uint32_t swap, int limbs)
{
  if (a->used > limbs)
    limbs = a->used;
  if (b->used > limbs)
    limbs = b->used;
  if (mp_grow(a, limbs) != MP_OKAY || mp_grow(b, limbs) != MP_OKAY)
    return -1;
  for (int i = a->used; i < limbs; i++)
    a->dp[i] = 0;
  for (int i = b->used; i < limbs; i++)
    b->dp[i] = 0;
  mp_digit dmask = (mp_digit)0 - (mp_digit)(swap & 1u);
  for (int i = 0; i < limbs; i++) {
    mp_digit diff = (a->dp[i] ^ b->dp[i]) & dmask;
    a->dp[i] ^= diff;
    b->dp[i] ^= diff;
  }
  unsigned int umask = 0u - (unsigned int)(swap & 1u);
  unsigned int udiff = ((unsigned int)a->used ^ (unsigned int)b->used) & umask;
  a->used = (int)((unsigned int)a->used ^ udiff);
  b->used = (int)((unsigned int)b->used ^ udiff);
  unsigned int sdiff = ((unsigned int)a->sign ^ (unsigned int)b->sign) & umask;
  a->sign = (int)((unsigned int)a->sign ^ sdiff);
  b->sign = (int)((unsigned int)b->sign ^ sdiff);
  return 0;
}

static int jac_cond_swap_ct(struct nw_jac_point *a, struct nw_jac_point *b,
                            uint32_t swap, int limbs)
{
  if (mp_cond_swap_ct(&a->x, &b->x, swap, limbs) ||
      mp_cond_swap_ct(&a->y, &b->y, swap, limbs) ||
      mp_cond_swap_ct(&a->z, &b->z, swap, limbs))
    return -1;
  return 0;
}

/* ---- crypto_ec_* ---- */

struct crypto_ec *crypto_ec_init(int group)
{
  const struct nw_ec_curve_params *spec = NULL;
  for (size_t i = 0; i < ARRAY_SIZE(nw_ec_curves); i++) {
    if (nw_ec_curves[i].group == group) {
      spec = &nw_ec_curves[i];
      break;
    }
  }
  if (!spec)
    return NULL;

  struct crypto_ec *e = os_zalloc(sizeof(*e));
  if (!e)
    return NULL;
  e->group = spec->group;
  e->prime_len = spec->prime_len;
  e->prime_bits = spec->prime_bits;
  e->order_len = spec->prime_len;

  if (mp_init_multi(&e->prime.mp, &e->order.mp, &e->a.mp, &e->b.mp,
                    &e->generator.x, &e->generator.y, NULL) != MP_OKAY) {
    os_free(e);
    return NULL;
  }
  int len = (int)spec->prime_len;
  if (mp_read_unsigned_bin(&e->prime.mp, (u8 *)spec->prime, len) != MP_OKAY ||
      mp_read_unsigned_bin(&e->a.mp, (u8 *)spec->a, len) != MP_OKAY ||
      mp_read_unsigned_bin(&e->b.mp, (u8 *)spec->b, len) != MP_OKAY ||
      mp_read_unsigned_bin(&e->order.mp, (u8 *)spec->order, len) != MP_OKAY ||
      mp_read_unsigned_bin(&e->generator.x, (u8 *)spec->gx, len) != MP_OKAY ||
      mp_read_unsigned_bin(&e->generator.y, (u8 *)spec->gy, len) != MP_OKAY) {
    crypto_ec_deinit(e);
    return NULL;
  }
  e->generator.infinity = 0;
  return e;
}

void crypto_ec_deinit(struct crypto_ec *e)
{
  if (!e)
    return;
  mp_wipe_clear(&e->prime.mp);
  mp_wipe_clear(&e->order.mp);
  mp_wipe_clear(&e->a.mp);
  mp_wipe_clear(&e->b.mp);
  mp_wipe_clear(&e->generator.x);
  mp_wipe_clear(&e->generator.y);
  forced_memzero(e, sizeof(*e));
  os_free(e);
}

size_t crypto_ec_prime_len(struct crypto_ec *e)
{
  return e ? e->prime_len : 0;
}

size_t crypto_ec_prime_len_bits(struct crypto_ec *e)
{
  return e ? e->prime_bits : 0;
}

size_t crypto_ec_order_len(struct crypto_ec *e)
{
  return e ? e->order_len : 0;
}

const struct crypto_bignum *crypto_ec_get_prime(struct crypto_ec *e)
{
  return e ? &e->prime : NULL;
}

const struct crypto_bignum *crypto_ec_get_order(struct crypto_ec *e)
{
  return e ? &e->order : NULL;
}

const struct crypto_bignum *crypto_ec_get_a(struct crypto_ec *e)
{
  return e ? &e->a : NULL;
}

const struct crypto_bignum *crypto_ec_get_b(struct crypto_ec *e)
{
  return e ? &e->b : NULL;
}

const struct crypto_ec_point *crypto_ec_get_generator(struct crypto_ec *e)
{
  return e ? &e->generator : NULL;
}

struct crypto_ec_point *crypto_ec_point_init(struct crypto_ec *e)
{
  if (!e)
    return NULL;
  struct crypto_ec_point *p = os_zalloc(sizeof(*p));
  if (!p)
    return NULL;
  if (mp_init_multi(&p->x, &p->y, NULL) != MP_OKAY) {
    os_free(p);
    return NULL;
  }
  p->infinity = 1;
  return p;
}

void crypto_ec_point_deinit(struct crypto_ec_point *p, int clear)
{
  if (!p)
    return;
  if (clear) {
    mp_wipe_clear(&p->x);
    mp_wipe_clear(&p->y);
    forced_memzero(p, sizeof(*p));
  } else {
    mp_clear(&p->x);
    mp_clear(&p->y);
  }
  os_free(p);
}

int crypto_ec_point_x(struct crypto_ec *e, const struct crypto_ec_point *p,
                      struct crypto_bignum *x)
{
  if (!e || !p || !x || p->infinity)
    return -1;
  return mp_copy((mp_int *)&p->x, &x->mp) == MP_OKAY ? 0 : -1;
}

int crypto_ec_point_to_bin(struct crypto_ec *e,
                           const struct crypto_ec_point *point, u8 *x, u8 *y)
{
  if (!e || !point || point->infinity)
    return -1;
  if (x) {
    struct crypto_bignum bx = { .mp = point->x };
    if (crypto_bignum_to_bin(&bx, x, e->prime_len, e->prime_len) != (int)e->prime_len)
      return -1;
  }
  if (y) {
    struct crypto_bignum by = { .mp = point->y };
    if (crypto_bignum_to_bin(&by, y, e->prime_len, e->prime_len) != (int)e->prime_len)
      return -1;
  }
  return 0;
}

struct crypto_bignum *crypto_ec_point_compute_y_sqr(struct crypto_ec *e,
                                                    const struct crypto_bignum *x)
{
  if (!e || !x)
    return NULL;
  struct crypto_bignum *ysqr = crypto_bignum_init();
  if (!ysqr)
    return NULL;

  mp_int xm, t1, t2;
  if (mp_init_multi(&xm, &t1, &t2, NULL) != MP_OKAY) {
    crypto_bignum_deinit(ysqr, 1);
    return NULL;
  }

  /* Reduce x mod p first (sae.c passes unreduced x >= p on dummy constant-time iterations). */
  int ok = (mp_mod(bn_mp(x), &e->prime.mp, &xm) == MP_OKAY &&
            mod_sqr(&xm, &t1, &e->prime.mp) == 0 &&
            mp_mulmod(&t1, &xm, &e->prime.mp, &t1) == MP_OKAY &&
            mp_mulmod(&e->a.mp, &xm, &e->prime.mp, &t2) == MP_OKAY &&
            mod_add(&t1, &t2, &t1, &e->prime.mp) == 0 &&
            mod_add(&t1, &e->b.mp, &ysqr->mp, &e->prime.mp) == 0);

  mp_wipe_clear(&xm);
  mp_wipe_clear(&t1);
  mp_wipe_clear(&t2);
  if (!ok) {
    crypto_bignum_deinit(ysqr, 1);
    return NULL;
  }
  return ysqr;
}

int crypto_ec_point_is_at_infinity(struct crypto_ec *e,
                                   const struct crypto_ec_point *p)
{
  (void)e;
  return p && p->infinity ? 1 : 0;
}

int crypto_ec_point_is_on_curve(struct crypto_ec *e,
                                const struct crypto_ec_point *p)
{
  if (!e || !p || p->infinity)
    return 0;
  if (p->x.sign == MP_NEG || p->y.sign == MP_NEG ||
      mp_cmp((mp_int *)&p->x, &e->prime.mp) != MP_LT ||
      mp_cmp((mp_int *)&p->y, &e->prime.mp) != MP_LT)
    return 0;

  struct crypto_bignum bx = { .mp = p->x };
  struct crypto_bignum *rhs = crypto_ec_point_compute_y_sqr(e, &bx);
  if (!rhs)
    return 0;

  mp_int lhs;
  int on_curve = 0;
  if (mp_init(&lhs) == MP_OKAY) {
    if (mod_sqr((mp_int *)&p->y, &lhs, &e->prime.mp) == 0 &&
        mp_cmp(&lhs, &rhs->mp) == MP_EQ)
      on_curve = 1;
    mp_wipe_clear(&lhs);
  }
  crypto_bignum_deinit(rhs, 1);
  return on_curve;
}

struct crypto_ec_point *crypto_ec_point_from_bin(struct crypto_ec *e,
                                                 const u8 *val)
{
  if (!e || !val)
    return NULL;
  struct crypto_ec_point *p = crypto_ec_point_init(e);
  if (!p)
    return NULL;
  int len = (int)e->prime_len;
  if (mp_read_unsigned_bin(&p->x, (u8 *)val, len) != MP_OKAY ||
      mp_read_unsigned_bin(&p->y, (u8 *)(val + e->prime_len), len) != MP_OKAY) {
    crypto_ec_point_deinit(p, 1);
    return NULL;
  }
  p->infinity = 0;
  if (!crypto_ec_point_is_on_curve(e, p)) {
    crypto_ec_point_deinit(p, 1);
    return NULL;
  }
  return p;
}

int crypto_ec_point_add(struct crypto_ec *e, const struct crypto_ec_point *a,
                        const struct crypto_ec_point *b,
                        struct crypto_ec_point *c)
{
  if (!e || !a || !b || !c)
    return -1;
  if ((!a->infinity && !crypto_ec_point_is_on_curve(e, a)) ||
      (!b->infinity && !crypto_ec_point_is_on_curve(e, b)))
    return -1;

  struct nw_jac_point ja, jb, jc;
  int ret = -1;
  if (jac_init(&ja))
    return -1;
  if (jac_init(&jb)) {
    jac_clear(&ja);
    return -1;
  }
  if (jac_init(&jc)) {
    jac_clear(&jb);
    jac_clear(&ja);
    return -1;
  }
  if (jac_from_affine(a, &ja) == 0 &&
      jac_from_affine(b, &jb) == 0 &&
      jac_add(&ja, &jb, &jc, &e->prime.mp) == 0 &&
      jac_to_affine(e, &jc, c) == 0)
    ret = 0;

  jac_clear(&ja);
  jac_clear(&jb);
  jac_clear(&jc);
  return ret;
}

int crypto_ec_point_mul(struct crypto_ec *e, const struct crypto_ec_point *p,
                        const struct crypto_bignum *b,
                        struct crypto_ec_point *res)
{
  if (!e || !p || !b || !res || b->mp.sign == MP_NEG)
    return -1;
  if (!p->infinity && !crypto_ec_point_is_on_curve(e, p))
    return -1;
  if (p->infinity || mp_iszero(bn_mp(b))) {
    mp_zero(&res->x);
    mp_zero(&res->y);
    res->infinity = 1;
    return 0;
  }

  struct nw_jac_point r0, r1;
  mp_int k;
  int ret = -1;
  if (jac_init(&r0))
    return -1;
  if (jac_init(&r1)) {
    jac_clear(&r0);
    return -1;
  }
  if (mp_init(&k) != MP_OKAY) {
    jac_clear(&r1);
    jac_clear(&r0);
    return -1;
  }

  jac_set_infinity(&r0);
  if (jac_from_affine(p, &r1) != 0 || mp_copy(bn_mp(b), &k) != MP_OKAY)
    goto out;

  size_t scalar_bits = (size_t)mp_count_bits(&k);
  size_t nbits = scalar_bits > e->prime_bits ? scalar_bits : e->prime_bits;
  int k_limbs = (int)((nbits + (size_t)DIGIT_BIT - 1u) / (size_t)DIGIT_BIT);
  if (mp_grow(&k, k_limbs) != MP_OKAY)
    goto out;
  for (int i = k.used; i < k_limbs; i++)
    k.dp[i] = 0;

  int coord_limbs = e->prime.mp.used + 1;
  uint32_t prev_bit = 0;
  /* Constant-time conditional-swap Montgomery ladder removes secret-bit control-flow
   * branching (note: underlying libtommath limb arithmetic remains variable-time). */
  for (size_t idx = nbits; idx > 0; idx--) {
    uint32_t bit = mp_test_bit_ct(&k, idx - 1);
    if (jac_cond_swap_ct(&r0, &r1, bit ^ prev_bit, coord_limbs) != 0)
      goto out;
    prev_bit = bit;
    if (jac_add(&r0, &r1, &r1, &e->prime.mp) ||
        jac_double(&r0, &r0, &e->prime.mp))
      goto out;
  }
  if (jac_cond_swap_ct(&r0, &r1, prev_bit, coord_limbs) != 0)
    goto out;

  ret = jac_to_affine(e, &r0, res);

out:
  mp_wipe_clear(&k);
  jac_clear(&r0);
  jac_clear(&r1);
  return ret;
}

int crypto_ec_point_invert(struct crypto_ec *e, struct crypto_ec_point *p)
{
  if (!e || !p)
    return -1;
  if (p->infinity || mp_iszero(&p->y))
    return 0;
  if (!crypto_ec_point_is_on_curve(e, p))
    return -1;
  return mp_sub(&e->prime.mp, &p->y, &p->y) == MP_OKAY ? 0 : -1;
}

int crypto_ec_point_cmp(const struct crypto_ec *e,
                        const struct crypto_ec_point *a,
                        const struct crypto_ec_point *b)
{
  (void)e;
  if (!a || !b)
    return a == b ? 0 : 1;
  if (a->infinity || b->infinity)
    return a->infinity == b->infinity ? 0 : 1;
  return (mp_cmp((mp_int *)&a->x, (mp_int *)&b->x) == MP_EQ &&
          mp_cmp((mp_int *)&a->y, (mp_int *)&b->y) == MP_EQ) ? 0 : 1;
}

void crypto_ec_point_debug_print(const struct crypto_ec *e,
                                 const struct crypto_ec_point *p,
                                 const char *title)
{
  (void)e;
  (void)p;
  (void)title;
}
