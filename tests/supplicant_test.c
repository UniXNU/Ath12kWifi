/* Real upstream SME/WPA/SAE state machine against an offline AP over datagrams. */
#include "utils/includes.h"
#include "utils/common.h"
#include "utils/wpabuf.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_common.h"
#include "common/eapol_common.h"
#ifdef CONFIG_SAE
#include "common/sae.h"
#endif
#include "crypto/sha1.h"
#include "crypto/aes_wrap.h"
#include "crypto/crypto.h"
#include "drivers/driver.h"
#include "wpa_supplicant_i.h"
#include "config_ssid.h"
#include "nw_control_client.h"
#include "nw_supplicant_frontend.h"
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>

static const u8 station[6] = {2, 1, 2, 3, 4, 5}, ap[6] = {2, 6, 7, 8, 9, 10};
static const u8 ssid[] = "offline-wpa";
/* Pure WPA2-CCMP RSN IE */
static const u8 rsn_wpa2[] = {
  0x30, 0x14, 1, 0,
  0, 0x0f, 0xac, 4,
  1, 0, 0, 0x0f, 0xac, 4,
  1, 0, 0, 0x0f, 0xac, 2,
  0, 0
};
/* WPA/WPA2-Personal Mixed RSN IE: group=TKIP (2), pairwise={CCMP (4), TKIP (2)}, akm=PSK (2) */
static const u8 rsn_mixed[] = {
  0x30, 0x18, 1, 0,
  0, 0x0f, 0xac, 2,
  2, 0, 0, 0x0f, 0xac, 4, 0, 0x0f, 0xac, 2,
  1, 0, 0, 0x0f, 0xac, 2,
  0, 0
};
/* Microsoft WPA1 Vendor IE (pure TKIP): OUI 00:50:f2:01, group=TKIP, pairwise=TKIP, akm=PSK */
static const u8 wpa1_tkip_ie[] = {
  0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 1, 0,
  0x00, 0x50, 0xf2, 2,
  1, 0, 0x00, 0x50, 0xf2, 2,
  1, 0, 0x00, 0x50, 0xf2, 2
};
/* Pure WPA3-SAE RSN IE: group=CCMP (4), pairwise=CCMP (4), akm=SAE (8), capab=MFPC|MFPR (0x00c0) */
static const u8 rsn_sae[] = {
  0x30, 0x14, 1, 0,
  0, 0x0f, 0xac, 4,
  1, 0, 0, 0x0f, 0xac, 4,
  1, 0, 0, 0x0f, 0xac, 8,
  0xc0, 0x00
};
/* WPA2/WPA3-Transition RSN IE: group=CCMP (4), pairwise=CCMP (4), akm={PSK (2), SAE (8)}, capab=MFPC (0x0080) */
static const u8 rsn_transition[] = {
  0x30, 0x18, 1, 0,
  0, 0x0f, 0xac, 4,
  1, 0, 0, 0x0f, 0xac, 4,
  2, 0, 0, 0x0f, 0xac, 2, 0, 0x0f, 0xac, 8,
  0x80, 0x00
};
/* RSNXE IE advertising SAE Hash-to-Element (BIT(5) == 0x20) */
static const u8 rsnxe_h2e[] = {WLAN_EID_RSNX, 1, 0x20};

/* The passphrase; wpa2-marks and wpa3-sae-marks use one with a quote, a backslash and UTF-8 bytes. */
static const u8 *password = (const u8 *)"offline-passphrase";
static const char passphrase_marks[] = "pa\"ss\\w\xc3\xb6rd-1";
static int user_fd, kernel_fd, stopping, finished;
static _Atomic unsigned ptk_installs, gtk_installs, igtk_installs, m2_seen, m4_seen, rekey_seen, authorized, wrong_key_reports;
static _Atomic unsigned sae_commits_seen, sae_confirms_seen;
static uint64_t session = 0x123456789abULL, generation = 30;
static struct wpa_ptk ptk;
static u8 anonce[32], gtk[32], group2[32], igtk[16], message3[512];
static size_t message3_length;
static struct wpa_supplicant *supplicant;
static int passed;
static int open_network, wrong_password, scan_mode;
static int mixed_mode, wpa1_mode, sae_mode, transition_mode, wrong_sae, wrong_sae_local;
/* WPA2/WPA3 transition AP, station given the daemon's pre-derived PMK (IO80211 cipher 6): PSK, never SAE. */
static int transition_pmk;
static int marks_mode;
static unsigned scan_frequencies_seen;
#ifdef CONFIG_SAE
static struct sae_data ap_sae;
static struct sae_pt *ap_sae_pt;
#endif

/* The test replaces only socket opening, retaining the production client. */
struct nw_control_client *nw_control_client_open(void)
{
  int fd = user_fd; user_fd = -1;
  return nw_control_client_from_fd(fd, session);
}
static void send_packet(struct nw_control_builder *b)
{
  assert(send(kernel_fd, b->bytes, b->length, 0) == (ssize_t)b->length);
}
static void event_begin(struct nw_control_builder *b, void *bytes, size_t size, unsigned operation)
{
  assert(!nw_control_begin(b, bytes, size, NW_CONTROL_EVENT, operation, 0, session, generation, NW_CONTROL_OK));
}
static void eapol(const u8 *frame, size_t length)
{
  u8 bytes[1024]; struct nw_control_builder b;
  event_begin(&b, bytes, sizeof(bytes), NW_CONTROL_RX_EAPOL);
  assert(!nw_control_put(&b, NW_CONTROL_ATTR_BSSID, ap, sizeof(ap)));
  assert(!nw_control_put(&b, NW_CONTROL_ATTR_EAPOL, frame, length));
  assert(!nw_control_put_u32(&b, NW_CONTROL_ATTR_NO_ENCRYPT, 1));
  send_packet(&b);
}
static int active_akmp(void)
{
#ifdef CONFIG_SAE
  if (sae_mode || transition_mode) return WPA_KEY_MGMT_SAE;
#endif
  return WPA_KEY_MGMT_PSK;
}
static unsigned active_key_ver(void)
{
  if (wpa1_mode) return WPA_KEY_INFO_TYPE_HMAC_MD5_RC4;
  if (sae_mode || transition_mode) return WPA_KEY_INFO_TYPE_AKM_DEFINED;
  return WPA_KEY_INFO_TYPE_HMAC_SHA1_AES;
}
static size_t beacon_security_ies(u8 *dst)
{
  if (open_network) return 0;
  if (wpa1_mode) {
    os_memcpy(dst, wpa1_tkip_ie, sizeof(wpa1_tkip_ie));
    return sizeof(wpa1_tkip_ie);
  }
  if (mixed_mode) {
    os_memcpy(dst, rsn_mixed, sizeof(rsn_mixed));
    os_memcpy(dst + sizeof(rsn_mixed), wpa1_tkip_ie, sizeof(wpa1_tkip_ie));
    return sizeof(rsn_mixed) + sizeof(wpa1_tkip_ie);
  }
  if (sae_mode || wrong_sae || wrong_sae_local) {
    os_memcpy(dst, rsn_sae, sizeof(rsn_sae));
    os_memcpy(dst + sizeof(rsn_sae), rsnxe_h2e, sizeof(rsnxe_h2e));
    return sizeof(rsn_sae) + sizeof(rsnxe_h2e);
  }
  if (transition_mode || transition_pmk) {
    os_memcpy(dst, rsn_transition, sizeof(rsn_transition));
    os_memcpy(dst + sizeof(rsn_transition), rsnxe_h2e, sizeof(rsnxe_h2e));
    return sizeof(rsn_transition) + sizeof(rsnxe_h2e);
  }
  os_memcpy(dst, rsn_wpa2, sizeof(rsn_wpa2));
  return sizeof(rsn_wpa2);
}

static size_t key_message(u8 *frame, unsigned info, unsigned replay, const u8 *plain, size_t size)
{
  const size_t base = sizeof(struct ieee802_1x_hdr) + sizeof(struct wpa_eapol_key);
  os_memset(frame, 0, 512);
  struct ieee802_1x_hdr *header = (void *)frame;
  struct wpa_eapol_key *key = (void *)(header + 1);
  header->version = wpa1_mode ? 1 : 2;
  header->type = IEEE802_1X_TYPE_EAPOL_KEY;
  key->type = wpa1_mode ? EAPOL_KEY_TYPE_WPA : EAPOL_KEY_TYPE_RSN;
  WPA_PUT_BE16(key->key_info, info);
  WPA_PUT_BE16(key->key_length, wpa1_mode ? 32 : 16);
  WPA_PUT_BE64(key->replay_counter, replay);
  os_memcpy(key->key_nonce, anonce, sizeof(anonce));
  size_t payload_len = 0;
  if (wpa1_mode) {
    if (plain && size) {
      if (!(info & WPA_KEY_INFO_KEY_TYPE)) {
        /* WPA1 Group Key 1/2: RC4-encrypt GTK with Key-IV || KEK (256-byte drop). */
        u8 ek[32];
        for (unsigned i = 0; i < 16; i++) key->key_iv[i] = (u8)(0xa0 + i);
        os_memcpy(ek, key->key_iv, 16);
        os_memcpy(ek + 16, ptk.kek, 16);
        os_memcpy(frame + base + 18, plain, size);
        assert(!rc4_skip(ek, sizeof(ek), 256, frame + base + 18, size));
        forced_memzero(ek, sizeof(ek));
      } else {
        os_memcpy(frame + base + 18, plain, size);
      }
      payload_len = size;
    }
  } else {
    payload_len = size ? size + 8 : 0;
    if (size) assert(!aes_wrap(ptk.kek, ptk.kek_len, size / 8, plain, frame + base + 18));
  }
  WPA_PUT_BE16(frame + base + 16, payload_len);
  size_t length = base + 18 + payload_len;
  WPA_PUT_BE16((u8 *)&header->length, length - sizeof(*header));
  if (info & WPA_KEY_INFO_MIC)
    assert(!wpa_eapol_key_mic(ptk.kck, ptk.kck_len, active_akmp(),
                              wpa1_mode ? RSN_HASH_SHA1 : RSN_HASH_SHA256,
                              active_key_ver(), frame, length, frame + base));
  return length;
}
static void message1(void)
{
  u8 frame[512];
  size_t length = key_message(frame, active_key_ver() | WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_ACK, 1, NULL, 0);
  eapol(frame, length);
}
static void wpa1_group_send(unsigned replay, const u8 *gtk_bytes, unsigned keyidx)
{
  u8 frame[512];
  unsigned info = active_key_ver() | (keyidx << WPA_KEY_INFO_KEY_INDEX_SHIFT) |
                  WPA_KEY_INFO_ACK | WPA_KEY_INFO_MIC | WPA_KEY_INFO_SECURE;
  size_t length = key_message(frame, info, replay, gtk_bytes, 32);
  eapol(frame, length);
}
static void message3_send(void)
{
  if (wpa1_mode) {
    /* WPA1 M3 carries unencrypted WPA IE; GTK follows in Group Key Handshake 1/2 after M4. */
    message3_length = key_message(message3,
      active_key_ver() | WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_INSTALL | WPA_KEY_INFO_ACK | WPA_KEY_INFO_MIC,
      2, wpa1_tkip_ie, sizeof(wpa1_tkip_ie));
    eapol(message3, message3_length);
    return;
  }

  u8 plain[160];
  os_memset(plain, 0, sizeof(plain));
  size_t offset = 0;
  if (mixed_mode) {
    os_memcpy(plain + offset, rsn_mixed, sizeof(rsn_mixed));
    offset += sizeof(rsn_mixed);
    os_memcpy(plain + offset, wpa1_tkip_ie, sizeof(wpa1_tkip_ie));
    offset += sizeof(wpa1_tkip_ie);
  } else if (sae_mode) {
    os_memcpy(plain + offset, rsn_sae, sizeof(rsn_sae));
    offset += sizeof(rsn_sae);
    os_memcpy(plain + offset, rsnxe_h2e, sizeof(rsnxe_h2e));
    offset += sizeof(rsnxe_h2e);
  } else if (transition_mode || transition_pmk) {
    os_memcpy(plain + offset, rsn_transition, sizeof(rsn_transition));
    offset += sizeof(rsn_transition);
    os_memcpy(plain + offset, rsnxe_h2e, sizeof(rsnxe_h2e));
    offset += sizeof(rsnxe_h2e);
  } else {
    os_memcpy(plain + offset, rsn_wpa2, sizeof(rsn_wpa2));
    offset += sizeof(rsn_wpa2);
  }

  size_t gtk_len = mixed_mode ? 32 : 16;
  u8 *kde = plain + offset;
  kde[0] = 0xdd; kde[1] = (u8)(6 + gtk_len);
  kde[2] = 0; kde[3] = 0x0f; kde[4] = 0xac; kde[5] = 1;
  kde[6] = 1; kde[7] = 0;
  os_memcpy(kde + 8, gtk, gtk_len);
  offset += 8 + gtk_len;

  if (sae_mode || transition_mode || transition_pmk) {
    /* IEEE 802.11w IGTK KDE (OUI 00-0F-AC:9, 4B OUI+type + 2B keyid + 6B IPN + 16B key = 28B body, 30B total). */
    u8 *ikde = plain + offset;
    ikde[0] = 0xdd; ikde[1] = 28;
    ikde[2] = 0; ikde[3] = 0x0f; ikde[4] = 0xac; ikde[5] = 9;
    WPA_PUT_LE16(ikde + 6, 4);
    os_memset(ikde + 8, 0, 6);
    os_memcpy(ikde + 14, igtk, sizeof(igtk));
    offset += 30;
  }

  if (offset % 8 != 0) {
    plain[offset++] = 0xdd;
    while (offset % 8 != 0) plain[offset++] = 0;
  }

  message3_length = key_message(message3, active_key_ver() | WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_ACK |
    WPA_KEY_INFO_MIC | WPA_KEY_INFO_INSTALL | WPA_KEY_INFO_SECURE | WPA_KEY_INFO_ENCR_KEY_DATA, 2, plain, offset);
  /* A corrupt MIC must not install a key or open the port. */
  u8 corrupt[512]; os_memcpy(corrupt, message3, message3_length); corrupt[81] ^= 1;
  eapol(corrupt, message3_length);
  /* An otherwise valid frame from an earlier attempt must also be ignored. */
  generation--; eapol(message3, message3_length); generation++;
  eapol(message3, message3_length);
}
static void group_rekey(void)
{
  if (wpa1_mode) {
    wpa1_group_send(4, group2, 2);
    return;
  }
  size_t gtk_len = mixed_mode ? 32 : 16;
  u8 plain[48], frame[512];
  os_memset(plain, 0, sizeof(plain));
  plain[0] = 0xdd; plain[1] = (u8)(6 + gtk_len);
  plain[2] = 0; plain[3] = 0x0f; plain[4] = 0xac; plain[5] = 1;
  plain[6] = 2; plain[7] = 0;
  os_memcpy(plain + 8, group2, gtk_len);
  size_t offset = 8 + gtk_len;
  if (offset % 8 != 0) {
    plain[offset++] = 0xdd;
    while (offset % 8 != 0) plain[offset++] = 0;
  }
  size_t length = key_message(frame, active_key_ver() | WPA_KEY_INFO_ACK | WPA_KEY_INFO_MIC |
    WPA_KEY_INFO_SECURE | WPA_KEY_INFO_ENCR_KEY_DATA, 4, plain, offset);
  eapol(frame, length);
}
static void transmitted(const struct nw_control_view *request)
{
  size_t length; const u8 *data = nw_control_get(request, NW_CONTROL_ATTR_EAPOL, &length);
  assert(data && length >= 99 && length <= 512);
  const struct wpa_eapol_key *key = (const void *)(data + 4);
  unsigned info = WPA_GET_BE16(key->key_info);
  assert(!(info & WPA_KEY_INFO_ACK));
  int is_m2 = (info & WPA_KEY_INFO_KEY_TYPE) && WPA_GET_BE64(key->replay_counter) == 1;
  if (is_m2) {
    assert(++m2_seen == 1);
    u8 pmk[32];
#ifdef CONFIG_SAE
    if (sae_mode || transition_mode) {
      assert(ap_sae.pmk_len == 32);
      os_memcpy(pmk, ap_sae.pmk, 32);
    } else
#endif
    {
      assert(!pbkdf2_sha1((const char *)password, ssid, sizeof(ssid) - 1, 4096, pmk, sizeof(pmk)));
    }
    int pairwise_cipher = WPA_CIPHER_CCMP;
#ifndef CONFIG_NO_TKIP
    if (wpa1_mode) pairwise_cipher = WPA_CIPHER_TKIP;
#endif
    assert(!wpa_pmk_to_ptk(pmk, sizeof(pmk), "Pairwise key expansion", ap, station,
      anonce, key->key_nonce, &ptk, active_akmp(), pairwise_cipher, NULL, 0, 0));
    forced_memzero(pmk, sizeof(pmk));
  }
  u8 check[512], mic[16]; os_memcpy(check, data, length); os_memset(check + 81, 0, 16);
  assert(!wpa_eapol_key_mic(ptk.kck, ptk.kck_len, active_akmp(),
    wpa1_mode ? RSN_HASH_SHA1 : RSN_HASH_SHA256, active_key_ver(), check, length, mic));
  if (wrong_password) {
    assert(os_memcmp(mic, data + 81, 16) && m2_seen == 1);
    u8 bytes[128]; struct nw_control_builder b;
    event_begin(&b, bytes, sizeof(bytes), NW_CONTROL_DISCONNECTED);
    assert(!nw_control_put(&b, NW_CONTROL_ATTR_BSSID, ap, sizeof(ap)));
    assert(!nw_control_put_u32(&b, NW_CONTROL_ATTR_REASON, WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT));
    assert(!nw_control_put_u32(&b, NW_CONTROL_ATTR_LOCAL_ONLY, 0));
    send_packet(&b); return;
  }
  assert(!os_memcmp(mic, data + 81, 16));
  if (is_m2) {
    message3_send();
  } else if (info & WPA_KEY_INFO_KEY_TYPE) {
    if (wpa1_mode) {
      assert(++m4_seen == 1);
      wpa1_group_send(3, gtk, 1);
    } else {
      assert(++m4_seen <= 2);
      if (m4_seen == 2) group_rekey();
    }
  } else {
    if (wpa1_mode && rekey_seen == 0 && gtk_installs == 1) {
      /* Initial WPA1 group key 2/2 completed; now test WPA1 group rekey! */
      group_rekey();
    } else {
      assert(++rekey_seen == 1);
      __atomic_store_n(&finished, 1, __ATOMIC_RELEASE);
    }
  }
}

static void assert_tkip_swapped(const u8 *installed, const u8 *authenticator_key)
{
  /* Authenticator layout: [0..15] TK | [16..23] Auth-TX (=STA-RX) | [24..31] Auth-RX (=STA-TX).
   * Station driver/firmware layout: [0..15] TK | [16..23] STA-TX | [24..31] STA-RX. */
  assert(!os_memcmp(installed, authenticator_key, 16));
  assert(!os_memcmp(installed + 16, authenticator_key + 24, 8));
  assert(!os_memcmp(installed + 24, authenticator_key + 16, 8));
}

static void install(const struct nw_control_view *request)
{
  uint32_t flags, cipher, index;
  assert(!nw_control_get_u32(request, NW_CONTROL_ATTR_KEY_FLAGS, &flags));
  if (flags & NW_CONTROL_KEY_DELETE) return;
  assert(!nw_control_get_u32(request, NW_CONTROL_ATTR_CIPHER, &cipher));
  assert(!nw_control_get_u32(request, NW_CONTROL_ATTR_KEY_INDEX, &index));
  size_t length; const u8 *key = nw_control_get(request, NW_CONTROL_ATTR_KEY, &length);
  assert(key != NULL);

  if (index >= 4) {
    assert((sae_mode || transition_mode || transition_pmk) && index == 4 && !(flags & NW_CONTROL_KEY_PAIRWISE));
    assert(cipher == RSN_CIPHER_SUITE_AES_128_CMAC && length == 16);
    assert(!os_memcmp(key, igtk, 16));
    igtk_installs++;
    return;
  }

  if (flags & NW_CONTROL_KEY_PAIRWISE) {
    assert(index == 0 && ++ptk_installs == 1);
    if (wpa1_mode) {
      assert(cipher == RSN_CIPHER_SUITE_TKIP && length == 32);
      assert_tkip_swapped(key, ptk.tk);
    } else {
      assert(cipher == RSN_CIPHER_SUITE_CCMP && length == 16 && !os_memcmp(key, ptk.tk, 16));
    }
  } else {
    gtk_installs++;
    const u8 *expected_gtk = (index == 1) ? gtk : group2;
    assert((index == 1 && gtk_installs == 1) || (index == 2 && gtk_installs == 2));
    if (mixed_mode || wpa1_mode) {
      assert(cipher == RSN_CIPHER_SUITE_TKIP && length == 32);
      assert_tkip_swapped(key, expected_gtk);
    } else {
      assert(cipher == RSN_CIPHER_SUITE_CCMP && length == 16 && !os_memcmp(key, expected_gtk, 16));
    }
  }
}

static void handle_authenticate(const struct nw_control_view *request)
{
  uint32_t auth_type = 99, local = 0;
  assert(!nw_control_get_u32(request, NW_CONTROL_ATTR_AUTH_TYPE, &auth_type));
  nw_control_get_u32(request, NW_CONTROL_ATTR_LOCAL_ONLY, &local);
  if (local) return;

  struct nw_control_builder b;
  u8 event_bytes[1024];

  if (sae_mode || transition_mode || wrong_sae || wrong_sae_local) {
#ifdef CONFIG_SAE
    assert(auth_type == 4); /* NL80211_AUTHTYPE_SAE */
    size_t auth_len = 0;
    const u8 *auth_data = nw_control_get(request, NW_CONTROL_ATTR_AUTH_DATA, &auth_len);
    assert(auth_data && auth_len >= 6);
    u16 trans = WPA_GET_LE16(auth_data);
    u16 status = WPA_GET_LE16(auth_data + 2);
    const u8 *payload = auth_data + 4;
    size_t payload_len = auth_len - 4;

    u8 frame[512];
    os_memset(frame, 0, sizeof(frame));
    frame[0] = 0xb0;
    os_memcpy(frame + 4, station, 6);
    os_memcpy(frame + 10, ap, 6);
    os_memcpy(frame + 16, ap, 6);
    WPA_PUT_LE16(frame + 24, WLAN_AUTH_SAE);

    if (trans == 1) {
      sae_commits_seen++;
      assert(status == WLAN_STATUS_SAE_HASH_TO_ELEMENT);
      int groups[2] = {19, 0};
      const char *ap_pw = (wrong_sae || wrong_sae_local) ? "ap-different-password" : (const char *)password;
      sae_deinit_pt(ap_sae_pt);
      sae_clear_data(&ap_sae);
      ap_sae_pt = sae_derive_pt(groups, ssid, sizeof(ssid) - 1, (const u8 *)ap_pw, strlen(ap_pw), NULL, 0);
      assert(ap_sae_pt && sae_set_group(&ap_sae, 19) == 0);
      assert(sae_prepare_commit_pt(&ap_sae, ap_sae_pt, ap, station, NULL, NULL) == 0);
      int ie_offset = 0;
      assert(sae_parse_commit(&ap_sae, payload, payload_len, NULL, NULL, groups, 1, &ie_offset) == WLAN_STATUS_SUCCESS);
      assert(sae_process_commit(&ap_sae) == 0);
      struct wpabuf *commit = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
      assert(commit && sae_write_commit(&ap_sae, commit, NULL, NULL, 0) == 0);
      WPA_PUT_LE16(frame + 26, 1);
      WPA_PUT_LE16(frame + 28, WLAN_STATUS_SAE_HASH_TO_ELEMENT);
      os_memcpy(frame + 30, wpabuf_head(commit), wpabuf_len(commit));
      size_t total = 30 + wpabuf_len(commit);
      wpabuf_free(commit);
      event_begin(&b, event_bytes, sizeof(event_bytes), NW_CONTROL_AUTH_FRAME);
      assert(!nw_control_put(&b, NW_CONTROL_ATTR_FRAME, frame, total));
      send_packet(&b);
    } else {
      assert(trans == 2 && status == WLAN_STATUS_SUCCESS);
      sae_confirms_seen++;
      int ie_offset = 0;
      if (wrong_sae) {
        assert(sae_check_confirm(&ap_sae, payload, payload_len, &ie_offset) < 0);
        WPA_PUT_LE16(frame + 26, 2);
        WPA_PUT_LE16(frame + 28, WLAN_STATUS_CHALLENGE_FAIL);
        event_begin(&b, event_bytes, sizeof(event_bytes), NW_CONTROL_AUTH_FRAME);
        assert(!nw_control_put(&b, NW_CONTROL_ATTR_FRAME, frame, 30));
        send_packet(&b);
      } else if (wrong_sae_local) {
        assert(sae_check_confirm(&ap_sae, payload, payload_len, &ie_offset) < 0);
        struct wpabuf *confirm = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
        assert(confirm && sae_write_confirm(&ap_sae, confirm) == 0);
        WPA_PUT_LE16(frame + 26, 2);
        WPA_PUT_LE16(frame + 28, WLAN_STATUS_SUCCESS);
        os_memcpy(frame + 30, wpabuf_head(confirm), wpabuf_len(confirm));
        size_t total = 30 + wpabuf_len(confirm);
        wpabuf_free(confirm);
        event_begin(&b, event_bytes, sizeof(event_bytes), NW_CONTROL_AUTH_FRAME);
        assert(!nw_control_put(&b, NW_CONTROL_ATTR_FRAME, frame, total));
        send_packet(&b);
      } else {
        assert(sae_check_confirm(&ap_sae, payload, payload_len, &ie_offset) == 0);
        struct wpabuf *confirm = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
        assert(confirm && sae_write_confirm(&ap_sae, confirm) == 0);
        WPA_PUT_LE16(frame + 26, 2);
        WPA_PUT_LE16(frame + 28, WLAN_STATUS_SUCCESS);
        os_memcpy(frame + 30, wpabuf_head(confirm), wpabuf_len(confirm));
        size_t total = 30 + wpabuf_len(confirm);
        wpabuf_free(confirm);
        event_begin(&b, event_bytes, sizeof(event_bytes), NW_CONTROL_AUTH_FRAME);
        assert(!nw_control_put(&b, NW_CONTROL_ATTR_FRAME, frame, total));
        send_packet(&b);
      }
    }
    return;
#else
    assert(!"CONFIG_SAE not enabled in supplicant build");
#endif
  }

  assert(auth_type == 0);
  u8 frame[30] = {0xb0};
  os_memcpy(frame + 4, station, 6); os_memcpy(frame + 10, ap, 6); os_memcpy(frame + 16, ap, 6); frame[26] = 2;
  event_begin(&b, event_bytes, sizeof(event_bytes), NW_CONTROL_AUTH_FRAME);
  assert(!nw_control_put(&b, NW_CONTROL_ATTR_FRAME, frame, sizeof(frame)));
  send_packet(&b);
}

static void *kernel(void *unused)
{
  (void)unused;
  for (;;) {
    u8 bytes[8192], reply_bytes[8192]; struct nw_control_view request; struct nw_control_builder reply;
    ssize_t length = recv(kernel_fd, bytes, sizeof(bytes), 0);
    if (__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) break;
    assert(length > 0 && !nw_control_decode(bytes, length, &request));
    assert(request.header.session == session);
    assert(!nw_control_begin(&reply, reply_bytes, sizeof(reply_bytes), NW_CONTROL_REPLY,
      request.header.operation, request.header.sequence, session, generation, NW_CONTROL_OK));
    unsigned operation = request.header.operation;
    switch (operation) {
    case NW_CONTROL_INFO: {
      u8 ciphers[12];
      WPA_PUT_LE32(ciphers, RSN_CIPHER_SUITE_TKIP);
      WPA_PUT_LE32(ciphers + 4, RSN_CIPHER_SUITE_CCMP);
      WPA_PUT_LE32(ciphers + 8, RSN_CIPHER_SUITE_AES_128_CMAC);
      assert(!nw_control_put(&reply, NW_CONTROL_ATTR_MAC, station, sizeof(station)));
      assert(!nw_control_put(&reply, NW_CONTROL_ATTR_CIPHERS, ciphers, sizeof(ciphers)));
      assert(!nw_control_put_u32(&reply, NW_CONTROL_ATTR_MAX_SCAN_SSIDS, 16));
      break;
    }
    case NW_CONTROL_SCAN: break;
    case NW_CONTROL_GET_BSS: {
      uint32_t index; assert(!nw_control_get_u32(&request, NW_CONTROL_ATTR_BSS_INDEX, &index));
      if (index) { nw_control_reply_state(&reply, generation, NW_CONTROL_NOT_FOUND); break; }
      u8 ies[256] = {0, sizeof(ssid) - 1}; size_t count = 2;
      os_memcpy(ies + count, ssid, sizeof(ssid) - 1); count += sizeof(ssid) - 1;
      u8 rates[] = {1, 8, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c};
      os_memcpy(ies + count, rates, sizeof(rates)); count += sizeof(rates);
      count += beacon_security_ies(ies + count);
      assert(!nw_control_put(&reply, NW_CONTROL_ATTR_BSSID, ap, sizeof(ap)));
      assert(!nw_control_put(&reply, NW_CONTROL_ATTR_IE, ies, count));
      assert(!nw_control_put_u32(&reply, NW_CONTROL_ATTR_FREQUENCY, 5180));
      assert(!nw_control_put_u32(&reply, NW_CONTROL_ATTR_SIGNAL, (u32)-40));
      assert(!nw_control_put_u32(&reply, NW_CONTROL_ATTR_CAPABILITY, open_network ? 0x01 : 0x11));
      assert(!nw_control_put_u32(&reply, NW_CONTROL_ATTR_BEACON_INTERVAL, 100)); break;
    }
    case NW_CONTROL_AUTHENTICATE: break;
    case NW_CONTROL_ASSOCIATE: {
      uint32_t cipher, group_cipher, akm, mfp, wpa_versions;
      assert(!nw_control_get_u32(&request, NW_CONTROL_ATTR_PAIRWISE_CIPHER, &cipher));
      assert(!nw_control_get_u32(&request, NW_CONTROL_ATTR_GROUP_CIPHER, &group_cipher));
      assert(!nw_control_get_u32(&request, NW_CONTROL_ATTR_AKM, &akm));
      assert(!nw_control_get_u32(&request, NW_CONTROL_ATTR_MFP, &mfp));
      assert(!nw_control_get_u32(&request, NW_CONTROL_ATTR_WPA_VERSIONS, &wpa_versions));
      if (open_network) {
        assert(cipher == 0 && group_cipher == 0 && akm == 0 && mfp == 0 && wpa_versions == 0);
      } else if (mixed_mode) {
        assert(cipher == RSN_CIPHER_SUITE_CCMP && group_cipher == RSN_CIPHER_SUITE_TKIP);
        assert(akm == RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X && wpa_versions == 2);
      } else if (wpa1_mode) {
        assert(cipher == RSN_CIPHER_SUITE_TKIP && group_cipher == RSN_CIPHER_SUITE_TKIP);
        assert(akm == RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X && wpa_versions == 1);
      } else if (transition_pmk) {
        assert(cipher == RSN_CIPHER_SUITE_CCMP && group_cipher == RSN_CIPHER_SUITE_CCMP);
        assert(akm == RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X && mfp == 1 && wpa_versions == 2);
      } else if (sae_mode || transition_mode) {
        assert(cipher == RSN_CIPHER_SUITE_CCMP && group_cipher == RSN_CIPHER_SUITE_CCMP);
        assert(akm == RSN_AUTH_KEY_MGMT_SAE && mfp == 1 && wpa_versions == 4);
      } else {
        assert(cipher == RSN_CIPHER_SUITE_CCMP && group_cipher == RSN_CIPHER_SUITE_CCMP);
        assert(akm == RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X && wpa_versions == 2);
      }
      break;
    }
    case NW_CONTROL_SET_KEY: install(&request); break;
    case NW_CONTROL_SET_PORT: {
      uint32_t value; assert(!nw_control_get_u32(&request, NW_CONTROL_ATTR_AUTHORIZED, &value));
      if (value) { assert(open_network ? (!ptk_installs && !gtk_installs) : (ptk_installs == 1 && gtk_installs >= 1)); authorized++; } break;
    }
    case NW_CONTROL_SET_OPERSTATE: break;
    case NW_CONTROL_DEAUTHENTICATE: break;
    case NW_CONTROL_TX_EAPOL: transmitted(&request); break;
    case NW_CONTROL_REPORT_RESULT: {
      uint32_t status;
      assert((wrong_password || wrong_sae || wrong_sae_local) &&
             !nw_control_get_u32(&request, NW_CONTROL_ATTR_STATUS_CODE, &status) &&
             status == NW_CONTROL_AUTH_FAILED);
      wrong_key_reports++; __atomic_store_n(&finished, 1, __ATOMIC_RELEASE); break;
    }
    default: assert(!"unexpected driver request");
    }
    send_packet(&reply);
    struct nw_control_builder b; u8 event_bytes[1024];
    switch (operation) {
    case NW_CONTROL_INFO:
      generation++;
      if (scan_mode) {
        u8 frequencies[8]; WPA_PUT_LE32(frequencies, 2437); WPA_PUT_LE32(frequencies + 4, 5180);
        event_begin(&b, event_bytes, sizeof(event_bytes), NW_CONTROL_SCAN_REQUEST);
        assert(!nw_control_put(&b, NW_CONTROL_ATTR_SCAN_FREQUENCIES, frequencies, sizeof(frequencies)));
        send_packet(&b); break;
      }
      event_begin(&b, event_bytes, sizeof(event_bytes), NW_CONTROL_JOIN_REQUEST);
      assert(!nw_control_put(&b, NW_CONTROL_ATTR_SSID, ssid, sizeof(ssid) - 1));
      if (!open_network) assert(!nw_control_put_u32(&b, NW_CONTROL_ATTR_FREQUENCY, 5180));
      assert(!nw_control_put(&b, NW_CONTROL_ATTR_BSSID, ap, sizeof(ap)));
      if (!open_network) {
        if (wpa1_mode || transition_pmk) {
          /* Exercise 64-hex pre-derived PMK (IO80211 cipher=6 path). */
          u8 pmk[32];
          char pmk_hex[65];
          assert(!pbkdf2_sha1((const char *)password, ssid, sizeof(ssid) - 1, 4096, pmk, sizeof(pmk)));
          wpa_snprintf_hex(pmk_hex, sizeof(pmk_hex), pmk, sizeof(pmk));
          forced_memzero(pmk, sizeof(pmk));
          assert(!nw_control_put(&b, NW_CONTROL_ATTR_PASSWORD, pmk_hex, 64));
        } else {
          const char *pass = wrong_password ? "wrong-passphrase" : (const char *)password;
          assert(!nw_control_put(&b, NW_CONTROL_ATTR_PASSWORD, pass, strlen(pass)));
        }
      }
      send_packet(&b); break;
    case NW_CONTROL_SCAN:
      {
        size_t bytes; const u8 *frequencies = nw_control_get(&request, NW_CONTROL_ATTR_SCAN_FREQUENCIES, &bytes);
        if (scan_mode) {
          assert(frequencies && bytes == 8 && WPA_GET_LE32(frequencies) == 2437 && WPA_GET_LE32(frequencies + 4) == 5180);
          __atomic_add_fetch(&scan_frequencies_seen, 1, __ATOMIC_RELEASE);
        } else assert(open_network ? bytes == 0 : (frequencies && bytes == 4 && WPA_GET_LE32(frequencies) == 5180));
      }
      event_begin(&b, event_bytes, sizeof(event_bytes), NW_CONTROL_SCAN_DONE); send_packet(&b); break;
    case NW_CONTROL_AUTHENTICATE:
      handle_authenticate(&request);
      break;
    case NW_CONTROL_ASSOCIATE: {
      event_begin(&b, event_bytes, sizeof(event_bytes), NW_CONTROL_ASSOC_RESULT);
      assert(!nw_control_put(&b, NW_CONTROL_ATTR_BSSID, ap, 6));
      assert(!nw_control_put_u32(&b, NW_CONTROL_ATTR_STATUS_CODE, 0));
      assert(!nw_control_put_u32(&b, NW_CONTROL_ATTR_FREQUENCY, 5180));
      size_t size; const void *ies = nw_control_get(&request, NW_CONTROL_ATTR_IE, &size);
      assert(!nw_control_put(&b, NW_CONTROL_ATTR_REQUEST_IE, ies, size));
      u8 resp_ies[128];
      size_t resp_len = beacon_security_ies(resp_ies);
      assert(!nw_control_put(&b, NW_CONTROL_ATTR_IE, resp_ies, resp_len));
      send_packet(&b);
      if (!open_network) message1();
      break;
    }
    case NW_CONTROL_SET_OPERSTATE: {
      uint32_t state; assert(!nw_control_get_u32(&request, NW_CONTROL_ATTR_OPERSTATE, &state));
      if (state && !wpa1_mode && m4_seen == 1) {
        eapol(message3, message3_length); /* Exact replay must be dropped. */
        u8 retry[512]; os_memcpy(retry, message3, message3_length);
        WPA_PUT_BE64(retry + 9, 3); os_memset(retry + 81, 0, 16);
        assert(!wpa_eapol_key_mic(ptk.kck, ptk.kck_len, active_akmp(),
          RSN_HASH_SHA256, active_key_ver(), retry, message3_length, retry + 81));
        eapol(retry, message3_length); /* Legitimate AP retransmission. */
      }
      break;
    }
    }
    nw_control_clear(bytes, sizeof(bytes));
  }
  return NULL;
}
static void power_waits_for_selection(void)
{
  u8 bytes[96]; struct nw_control_builder builder; struct nw_control_view view;
  event_begin(&builder, bytes, sizeof(bytes), NW_CONTROL_POWER_REQUEST);
  assert(!nw_control_put_u32(&builder, NW_CONTROL_ATTR_OPERSTATE, 1));
  assert(!nw_control_decode(bytes, builder.length, &view));
  assert(!nw_supplicant_request(supplicant, &view));
  assert(supplicant->disconnected && supplicant->wpa_state == WPA_DISCONNECTED);
}
static void check(void *unused, void *unused2)
{
  (void)unused; (void)unused2;
  if (scan_mode && __atomic_load_n(&scan_frequencies_seen, __ATOMIC_ACQUIRE)) {
    assert(supplicant->wpa_state != WPA_COMPLETED && !authorized);
    passed = 1; eloop_terminate(); return;
  }
  if ((open_network && supplicant->wpa_state == WPA_COMPLETED) || __atomic_load_n(&finished, __ATOMIC_ACQUIRE)) {
    if (wrong_password) {
      assert(supplicant->wpa_state != WPA_COMPLETED && wrong_key_reports == 1 && m2_seen == 1);
      assert(!ptk_installs && !gtk_installs && !m4_seen && !authorized);
      passed = 1; eloop_terminate(); return;
    }
    if (wrong_sae || wrong_sae_local) {
      assert(supplicant->wpa_state != WPA_COMPLETED && wrong_key_reports == 1);
      assert(sae_commits_seen == 1 && sae_confirms_seen == 1);
      assert(!ptk_installs && !gtk_installs && !m2_seen && !authorized);
      passed = 1; eloop_terminate(); return;
    }
    assert(supplicant->wpa_state == WPA_COMPLETED);
    assert(supplicant->current_ssid && supplicant->current_ssid->bssid_set &&
           !os_memcmp(supplicant->current_ssid->bssid, ap, ETH_ALEN));
    if (open_network) {
      assert(!ptk_installs && !gtk_installs && !m2_seen && !m4_seen && !rekey_seen && authorized);
      power_waits_for_selection();
      passed = 1; eloop_terminate(); return;
    }
    if (wpa1_mode) {
      assert(ptk_installs == 1 && gtk_installs == 2 && m2_seen == 1 && m4_seen == 1 && rekey_seen == 1);
    } else {
      assert(ptk_installs == 1 && gtk_installs == 2 && m2_seen == 1 && m4_seen == 2 && rekey_seen == 1);
    }
    if (sae_mode || transition_mode) {
      assert(sae_commits_seen == 1 && sae_confirms_seen == 1 && igtk_installs == 1);
    }
    if (transition_pmk) {
      assert(sae_commits_seen == 0 && sae_confirms_seen == 0 && igtk_installs == 1);
    }
    assert(!wrong_key_reports);
    power_waits_for_selection();
    passed = 1; eloop_terminate(); return;
  }
  eloop_register_timeout(0, 1000, check, NULL, NULL);
}
static void timeout(void *unused, void *unused2)
{
  (void)unused; (void)unused2;
  fprintf(stderr, "timeout: state=%d m2=%u m4=%u ptk=%u gtk=%u igtk=%u rekey=%u sae=%u/%u\n",
    supplicant->wpa_state, m2_seen, m4_seen, ptk_installs, gtk_installs, igtk_installs,
    rekey_seen, sae_commits_seen, sae_confirms_seen);
  eloop_terminate();
}
int main(int argc, char **argv)
{
  assert(argc == 3);
  const char *mode = argv[2];
  open_network = !strcmp(mode, "open");
  wrong_password = !strcmp(mode, "wrong");
  scan_mode = !strcmp(mode, "scan");
  mixed_mode = !strcmp(mode, "wpa2-mixed-tkip");
  wpa1_mode = !strcmp(mode, "wpa1-tkip");
  sae_mode = !strcmp(mode, "wpa3-sae");
  transition_mode = !strcmp(mode, "wpa3-transition");
  transition_pmk = !strcmp(mode, "wpa3-transition-pmk");
  marks_mode = !strcmp(mode, "wpa2-marks") || !strcmp(mode, "wpa3-sae-marks");
  if (!strcmp(mode, "wpa3-sae-marks")) sae_mode = 1;
  if (marks_mode) password = (const u8 *)passphrase_marks;
  wrong_sae = !strcmp(mode, "wrong-sae");
  wrong_sae_local = !strcmp(mode, "wrong-sae-local");

#ifdef CONFIG_NO_TKIP
  if (mixed_mode || wpa1_mode) {
    fprintf(stderr, "CONFIG_NO_TKIP is still enabled for mode %s\n", mode);
    return 1;
  }
#endif
#ifndef CONFIG_SAE
  if (sae_mode || transition_mode || wrong_sae || wrong_sae_local) {
    fprintf(stderr, "CONFIG_SAE is not enabled for mode %s\n", mode);
    return 1;
  }
#endif

  int sockets[2]; assert(!socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
  user_fd = sockets[0]; kernel_fd = sockets[1];
  int wake_fd = dup(user_fd); assert(wake_fd >= 0);
  for (unsigned i = 0; i < 32; i++) {
    anonce[i] = i + 1;
    gtk[i] = i + 40;
    group2[i] = i + 80;
  }
  for (unsigned i = 0; i < 16; i++) igtk[i] = i + 120;
  pthread_t thread; assert(!pthread_create(&thread, NULL, kernel, NULL));
  struct wpa_params params; os_memset(&params, 0, sizeof(params)); params.wpa_debug_level = MSG_WARNING;
  struct wpa_global *global = wpa_supplicant_init(&params); assert(global);
  struct wpa_interface interface; os_memset(&interface, 0, sizeof(interface));
  interface.ifname = "en0"; interface.driver = "sheng"; interface.confname = argv[1];
  supplicant = wpa_supplicant_add_iface(global, &interface, NULL); assert(supplicant);
  eloop_register_timeout(0, 1000, check, NULL, NULL);
  eloop_register_timeout(12, 0, timeout, NULL, NULL);
  wpa_supplicant_run(global);
  eloop_cancel_timeout(check, NULL, NULL); eloop_cancel_timeout(timeout, NULL, NULL);
  wpa_supplicant_deinit(global);
#ifdef CONFIG_SAE
  sae_deinit_pt(ap_sae_pt);
  sae_clear_data(&ap_sae);
#endif
  __atomic_store_n(&stopping, 1, __ATOMIC_RELEASE);
  assert(send(wake_fd, "x", 1, 0) == 1);
  pthread_join(thread, NULL); close(kernel_fd); close(wake_fd);
  assert(passed);
  printf("supplicant[%s]: passed\n", mode);
  return 0;
}
