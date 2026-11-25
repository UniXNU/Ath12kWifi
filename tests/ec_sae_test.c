/* ASan/UBSan host tests for nw_crypto_ec.c + real upstream sae.c/dragonfly.c. */
#include "utils/includes.h"
#include "utils/common.h"
#include "utils/wpabuf.h"
#include "common/ieee802_11_defs.h"
#include "common/sae.h"
#include "crypto/crypto.h"
#include <assert.h>
#include <stdio.h>

static void test_bignum_primitives(void)
{
  /* 1. 32-bit uint > 2^28 (guards against arm64e 28-bit mp_digit truncation). */
  struct crypto_bignum *u = crypto_bignum_init_uint(0xdeadbeefU);
  assert(u != NULL);
  u8 buf[16];
  assert(crypto_bignum_to_bin(u, buf, sizeof(buf), 0) == 4);
  assert(WPA_GET_BE32(buf) == 0xdeadbeefU);
  assert(crypto_bignum_to_bin(u, buf, sizeof(buf), 8) == 8);
  assert(buf[0] == 0 && buf[3] == 0 && WPA_GET_BE32(buf + 4) == 0xdeadbeefU);
  /* Overflow / padlen < num_bytes must fail with -1. */
  assert(crypto_bignum_to_bin(u, buf, 3, 0) == -1);
  assert(crypto_bignum_to_bin(u, buf, sizeof(buf), 3) == -1);
  assert(crypto_bignum_to_bin(u, buf, 4, 5) == -1);

  /* 2. Zero serialization: padlen == 0 -> 0 bytes, padlen > 0 -> zeroes. */
  struct crypto_bignum *zero = crypto_bignum_init_uint(0);
  struct crypto_bignum *one = crypto_bignum_init_uint(1);
  assert(zero && one);
  assert(crypto_bignum_is_zero(zero) == 1 && crypto_bignum_is_one(zero) == 0 && crypto_bignum_is_odd(zero) == 0);
  assert(crypto_bignum_is_zero(one) == 0 && crypto_bignum_is_one(one) == 1 && crypto_bignum_is_odd(one) == 1);
  os_memset(buf, 0xaa, sizeof(buf));
  assert(crypto_bignum_to_bin(zero, buf, sizeof(buf), 0) == 0 && buf[0] == 0xaa);
  assert(crypto_bignum_to_bin(zero, buf, sizeof(buf), 6) == 6);
  for (int i = 0; i < 6; i++) assert(buf[i] == 0);

  /* 3. Arithmetic, rshift (including in-place), sqrmod, addmod, mulmod, exptmod. */
  struct crypto_bignum *a = crypto_bignum_init_uint(100);
  struct crypto_bignum *b = crypto_bignum_init_uint(37);
  struct crypto_bignum *m = crypto_bignum_init_uint(97); /* prime */
  struct crypto_bignum *r = crypto_bignum_init();
  assert(a && b && m && r);
  assert(crypto_bignum_add(a, b, r) == 0);
  assert(crypto_bignum_sub(r, b, r) == 0 && crypto_bignum_cmp(r, a) == 0);
  assert(crypto_bignum_div(a, b, r) == 0); /* 100 / 37 = 2 */
  assert(crypto_bignum_mod(a, b, a) == 0); /* 100 % 37 = 26 */
  struct crypto_bignum *expect26 = crypto_bignum_init_uint(26);
  assert(crypto_bignum_cmp(a, expect26) == 0);
  assert(crypto_bignum_rshift(a, 1, a) == 0); /* 26 >> 1 = 13 */
  assert(crypto_bignum_is_odd(a) == 1);
  assert(crypto_bignum_rshift(a, -1, r) == -1);

  /* (26 + 80) mod 97 = 9; (26 * 26) mod 97 = 94 */
  struct crypto_bignum *eighty = crypto_bignum_init_uint(80);
  struct crypto_bignum *expect9 = crypto_bignum_init_uint(9);
  struct crypto_bignum *expect94 = crypto_bignum_init_uint(94);
  assert(crypto_bignum_addmod(expect26, eighty, m, r) == 0 && crypto_bignum_cmp(r, expect9) == 0);
  assert(crypto_bignum_sqrmod(expect26, m, r) == 0 && crypto_bignum_cmp(r, expect94) == 0);
  assert(crypto_bignum_mulmod(expect26, expect26, m, r) == 0 && crypto_bignum_cmp(r, expect94) == 0);

  /* Fermat: 26^96 mod 97 == 1 */
  struct crypto_bignum *m_minus_1 = crypto_bignum_init_uint(96);
  assert(crypto_bignum_exptmod(expect26, m_minus_1, m, r) == 0 && crypto_bignum_is_one(r) == 1);

  /* 4. Modular inverse on prime AND composite odd moduli + non-coprime failure. */
  assert(crypto_bignum_inverse(expect26, m, r) == 0);
  assert(crypto_bignum_mulmod(expect26, r, m, r) == 0 && crypto_bignum_is_one(r) == 1);

  struct crypto_bignum *comp = crypto_bignum_init_uint(11 * 13); /* 143, composite odd */
  assert(crypto_bignum_inverse(b, comp, r) == 0);
  assert(crypto_bignum_mulmod(b, r, comp, r) == 0 && crypto_bignum_is_one(r) == 1);
  struct crypto_bignum *non_coprime = crypto_bignum_init_uint(26); /* gcd(26, 143) = 13 */
  assert(crypto_bignum_inverse(non_coprime, comp, r) == -1);
  assert(crypto_bignum_inverse(zero, m, r) == -1);

  /* 5. Legendre symbol (a/97): 9 = 3^2 -> 1; 5 -> -1 (5^48 mod 97 = 96); 0 or 97 -> 0. */
  struct crypto_bignum *five = crypto_bignum_init_uint(5);
  assert(crypto_bignum_legendre(expect9, m) == 1);
  assert(crypto_bignum_legendre(five, m) == -1);
  assert(crypto_bignum_legendre(zero, m) == 0);
  assert(crypto_bignum_legendre(m, m) == 0);

  /* 6. Uniform random in [0, m - 1]. */
  for (int i = 0; i < 64; i++) {
    assert(crypto_bignum_rand(r, m) == 0);
    assert(crypto_bignum_cmp(r, zero) >= 0 && crypto_bignum_cmp(r, m) < 0);
  }

  crypto_bignum_deinit(u, 1);
  crypto_bignum_deinit(zero, 1);
  crypto_bignum_deinit(one, 1);
  crypto_bignum_deinit(a, 1);
  crypto_bignum_deinit(b, 1);
  crypto_bignum_deinit(m, 0);
  crypto_bignum_deinit(r, 1);
  crypto_bignum_deinit(expect26, 0);
  crypto_bignum_deinit(eighty, 0);
  crypto_bignum_deinit(expect9, 0);
  crypto_bignum_deinit(expect94, 0);
  crypto_bignum_deinit(m_minus_1, 0);
  crypto_bignum_deinit(comp, 0);
  crypto_bignum_deinit(non_coprime, 0);
  crypto_bignum_deinit(five, 0);
}

static void test_ec_group(int group, size_t expected_len, size_t expected_bits)
{
  struct crypto_ec *ec = crypto_ec_init(group);
  assert(ec != NULL);
  assert(crypto_ec_prime_len(ec) == expected_len);
  assert(crypto_ec_prime_len_bits(ec) == expected_bits);
  assert(crypto_ec_order_len(ec) == expected_len);

  const struct crypto_bignum *prime = crypto_ec_get_prime(ec);
  const struct crypto_bignum *order = crypto_ec_get_order(ec);
  const struct crypto_bignum *ca = crypto_ec_get_a(ec);
  const struct crypto_bignum *cb = crypto_ec_get_b(ec);
  const struct crypto_ec_point *gen = crypto_ec_get_generator(ec);
  assert(prime && order && ca && cb && gen);
  assert(crypto_ec_point_is_on_curve(ec, gen) == 1);
  assert(crypto_ec_point_is_at_infinity(ec, gen) == 0);

  /* Generator x-coordinate and compute_y_sqr(Gx) == Gy^2 mod p (and x + p >= p unreduced!). */
  struct crypto_bignum *gx = crypto_bignum_init();
  u8 raw[2 * SAE_MAX_ECC_PRIME_LEN];
  u8 x_only[SAE_MAX_ECC_PRIME_LEN];
  assert(crypto_ec_point_x(ec, gen, gx) == 0);
  assert(crypto_ec_point_to_bin(ec, gen, raw, raw + expected_len) == 0);
  assert(crypto_ec_point_to_bin(ec, gen, x_only, NULL) == 0);
  assert(os_memcmp(raw, x_only, expected_len) == 0);

  struct crypto_bignum *ysqr = crypto_ec_point_compute_y_sqr(ec, gx);
  assert(ysqr != NULL && crypto_bignum_legendre(ysqr, prime) == 1);
  struct crypto_bignum *gx_plus_p = crypto_bignum_init();
  assert(crypto_bignum_add(gx, prime, gx_plus_p) == 0);
  struct crypto_bignum *ysqr2 = crypto_ec_point_compute_y_sqr(ec, gx_plus_p);
  assert(ysqr2 != NULL && crypto_bignum_cmp(ysqr, ysqr2) == 0);

  /* Round-trip from_bin and off-curve rejection. */
  struct crypto_ec_point *g_rt = crypto_ec_point_from_bin(ec, raw);
  assert(g_rt != NULL && crypto_ec_point_cmp(ec, gen, g_rt) == 0);
  u8 bad[2 * SAE_MAX_ECC_PRIME_LEN];
  os_memcpy(bad, raw, 2 * expected_len);
  bad[2 * expected_len - 1] ^= 1; /* flip LSB of y -> off curve */
  assert(crypto_ec_point_from_bin(ec, bad) == NULL);

  /* Group law: order * G == O; (order - 1) * G == -G; G + (-G) == O; 2G + 3G == 5G; in-place aliasing. */
  struct crypto_ec_point *inf = crypto_ec_point_init(ec);
  struct crypto_ec_point *neg_g = crypto_ec_point_init(ec);
  struct crypto_ec_point *p2 = crypto_ec_point_init(ec);
  struct crypto_ec_point *p3 = crypto_ec_point_init(ec);
  struct crypto_ec_point *p5 = crypto_ec_point_init(ec);
  struct crypto_bignum *one = crypto_bignum_init_uint(1);
  struct crypto_bignum *two = crypto_bignum_init_uint(2);
  struct crypto_bignum *three = crypto_bignum_init_uint(3);
  struct crypto_bignum *five = crypto_bignum_init_uint(5);
  struct crypto_bignum *ord_m1 = crypto_bignum_init();
  assert(crypto_bignum_sub(order, one, ord_m1) == 0);

  assert(crypto_ec_point_mul(ec, gen, order, inf) == 0);
  assert(crypto_ec_point_is_at_infinity(ec, inf) == 1);
  assert(crypto_ec_point_to_bin(ec, inf, raw, raw + expected_len) == -1);

  assert(crypto_ec_point_mul(ec, gen, ord_m1, neg_g) == 0);
  assert(crypto_ec_point_is_on_curve(ec, neg_g) == 1);
  assert(crypto_ec_point_invert(ec, g_rt) == 0);
  assert(crypto_ec_point_cmp(ec, neg_g, g_rt) == 0);

  /* G + (-G) == infinity (with in-place aliasing c == a). */
  assert(crypto_ec_point_add(ec, neg_g, gen, neg_g) == 0);
  assert(crypto_ec_point_is_at_infinity(ec, neg_g) == 1);

  /* G + G == 2G, 2G + 3G == 5G, and in-place point_mul(ec, p2, three, p2) == 6G == 5G + G. */
  assert(crypto_ec_point_add(ec, gen, gen, p2) == 0);
  assert(crypto_ec_point_mul(ec, gen, three, p3) == 0);
  assert(crypto_ec_point_mul(ec, gen, five, p5) == 0);
  struct crypto_ec_point *sum = crypto_ec_point_init(ec);
  assert(crypto_ec_point_add(ec, p2, p3, sum) == 0);
  assert(crypto_ec_point_cmp(ec, sum, p5) == 0);
  assert(crypto_ec_point_mul(ec, p2, three, p2) == 0); /* in-place res == p: 3 * (2G) = 6G */
  assert(crypto_ec_point_add(ec, p5, gen, p5) == 0);  /* in-place c == a: 5G + G = 6G */
  assert(crypto_ec_point_cmp(ec, p2, p5) == 0);
  crypto_ec_point_debug_print(ec, p2, "6G");

  crypto_bignum_deinit(gx, 0);
  crypto_bignum_deinit(gx_plus_p, 0);
  crypto_bignum_deinit(ysqr, 0);
  crypto_bignum_deinit(ysqr2, 0);
  crypto_bignum_deinit(one, 0);
  crypto_bignum_deinit(two, 0);
  crypto_bignum_deinit(three, 0);
  crypto_bignum_deinit(five, 0);
  crypto_bignum_deinit(ord_m1, 0);
  crypto_ec_point_deinit(g_rt, 1);
  crypto_ec_point_deinit(inf, 1);
  crypto_ec_point_deinit(neg_g, 1);
  crypto_ec_point_deinit(p2, 1);
  crypto_ec_point_deinit(p3, 1);
  crypto_ec_point_deinit(p5, 1);
  crypto_ec_point_deinit(sum, 1);
  crypto_ec_deinit(ec);
}

static void test_sae_handshake(int group, int h2e)
{
  static const u8 sta_mac[ETH_ALEN] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
  static const u8 ap_mac[ETH_ALEN] = {0x02, 0x66, 0x77, 0x88, 0x99, 0xaa};
  static const char *ssid = "sheng-wpa3-test";
  static const char *pw = "wpa3-dragonfly-secret!";
  static const char *wrong_pw = "wrong-dragonfly-secret";
  int groups[2] = {group, 0};

  struct sae_data sta, ap;
  os_memset(&sta, 0, sizeof(sta));
  os_memset(&ap, 0, sizeof(ap));
  assert(sae_set_group(&sta, group) == 0);
  assert(sae_set_group(&ap, group) == 0);

  struct sae_pt *sta_pt = NULL, *ap_pt = NULL;
  if (h2e) {
    sta_pt = sae_derive_pt(groups, (const u8 *)ssid, strlen(ssid), (const u8 *)pw, strlen(pw), NULL, 0);
    ap_pt = sae_derive_pt(groups, (const u8 *)ssid, strlen(ssid), (const u8 *)pw, strlen(pw), NULL, 0);
    assert(sta_pt && ap_pt);
    assert(sae_prepare_commit_pt(&sta, sta_pt, sta_mac, ap_mac, NULL, NULL) == 0);
    assert(sae_prepare_commit_pt(&ap, ap_pt, ap_mac, sta_mac, NULL, NULL) == 0);
  } else {
    assert(sae_prepare_commit(sta_mac, ap_mac, (const u8 *)pw, strlen(pw), &sta) == 0);
    assert(sae_prepare_commit(ap_mac, sta_mac, (const u8 *)pw, strlen(pw), &ap) == 0);
  }

  struct wpabuf *sta_commit = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
  struct wpabuf *ap_commit = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
  struct wpabuf *sta_confirm = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
  struct wpabuf *ap_confirm = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
  assert(sta_commit && ap_commit && sta_confirm && ap_confirm);

  assert(sae_write_commit(&sta, sta_commit, NULL, NULL, 0) == 0);
  assert(sae_write_commit(&ap, ap_commit, NULL, NULL, 0) == 0);

  int ie_offset = 0;
  assert(sae_parse_commit(&ap, wpabuf_head(sta_commit), wpabuf_len(sta_commit),
                          NULL, NULL, groups, h2e, &ie_offset) == WLAN_STATUS_SUCCESS);
  assert(sae_parse_commit(&sta, wpabuf_head(ap_commit), wpabuf_len(ap_commit),
                          NULL, NULL, groups, h2e, &ie_offset) == WLAN_STATUS_SUCCESS);

  assert(sae_process_commit(&sta) == 0);
  assert(sae_process_commit(&ap) == 0);

  assert(sae_write_confirm(&sta, sta_confirm) == 0);
  assert(sae_write_confirm(&ap, ap_confirm) == 0);

  /* Tampered confirm token must be rejected before accepting real confirm. */
  u8 tampered[SAE_CONFIRM_MAX_LEN];
  assert(wpabuf_len(ap_confirm) <= sizeof(tampered));
  os_memcpy(tampered, wpabuf_head(ap_confirm), wpabuf_len(ap_confirm));
  tampered[wpabuf_len(ap_confirm) - 1] ^= 0x80;
  assert(sae_check_confirm(&sta, tampered, wpabuf_len(ap_confirm), &ie_offset) < 0);

  assert(sae_check_confirm(&ap, wpabuf_head(sta_commit), 0, &ie_offset) < 0);
  assert(sae_check_confirm(&ap, wpabuf_head(sta_confirm), wpabuf_len(sta_confirm), &ie_offset) == 0);
  assert(sae_check_confirm(&sta, wpabuf_head(ap_confirm), wpabuf_len(ap_confirm), &ie_offset) == 0);

  assert(sta.pmk_len == SAE_PMK_LEN && ap.pmk_len == SAE_PMK_LEN);
  assert(os_memcmp(sta.pmk, ap.pmk, SAE_PMK_LEN) == 0);
  assert(os_memcmp(sta.pmkid, ap.pmkid, SAE_PMKID_LEN) == 0);

  /* Wrong password peer must derive different KCK and fail confirm verification. */
  struct sae_data bad_ap;
  os_memset(&bad_ap, 0, sizeof(bad_ap));
  assert(sae_set_group(&bad_ap, group) == 0);
  assert(sae_prepare_commit(ap_mac, sta_mac, (const u8 *)wrong_pw, strlen(wrong_pw), &bad_ap) == 0);
  struct wpabuf *bad_commit = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
  struct wpabuf *bad_confirm = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
  assert(sae_write_commit(&bad_ap, bad_commit, NULL, NULL, 0) == 0);
  assert(sae_parse_commit(&bad_ap, wpabuf_head(sta_commit), wpabuf_len(sta_commit),
                          NULL, NULL, groups, 0, &ie_offset) == WLAN_STATUS_SUCCESS);
  assert(sae_process_commit(&bad_ap) == 0);
  assert(sae_write_confirm(&bad_ap, bad_confirm) == 0);
  if (!h2e) {
    assert(sae_check_confirm(&bad_ap, wpabuf_head(sta_confirm), wpabuf_len(sta_confirm), &ie_offset) < 0);
  }

  wpabuf_free(bad_commit);
  wpabuf_free(bad_confirm);
  sae_clear_data(&bad_ap);

  wpabuf_free(sta_commit);
  wpabuf_free(ap_commit);
  wpabuf_free(sta_confirm);
  wpabuf_free(ap_confirm);
  sae_deinit_pt(sta_pt);
  sae_deinit_pt(ap_pt);
  sae_clear_data(&sta);
  sae_clear_data(&ap);
}

int main(void)
{
  assert(crypto_ec_init(18) == NULL);
  assert(crypto_ec_init(99) == NULL);
  test_bignum_primitives();
  test_ec_group(19, 32, 256);
  test_ec_group(20, 48, 384);
  test_ec_group(21, 66, 521);
  for (int g = 19; g <= 21; g++) {
    test_sae_handshake(g, 0);
    test_sae_handshake(g, 1);
  }
  puts("ec-sae: bignum primitives, NIST P-256/P-384/P-521 group laws, off-curve rejection, and real upstream SAE H&P + H2E handshakes passed");
  return 0;
}
