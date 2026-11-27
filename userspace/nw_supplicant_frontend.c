/* Settings selects networks; upstream wpa_supplicant owns the connection SME. */
#include "utils/includes.h"
#include "utils/common.h"
#include <limits.h>
#include "config.h"
#include "wpa_supplicant_i.h"
#ifdef CONFIG_SAE
#include "common/sae.h"
#endif
#include "ctrl_iface.h"
#include "nw_supplicant_frontend.h"

extern void nw_sheng_report_auth_failure(void *priv);
extern void nw_sheng_report_request_failure(void *priv, unsigned operation, int status);

static int command(struct wpa_supplicant *supplicant, char *text, int network_id)
{
  size_t length = 0;
  char *reply = wpa_supplicant_ctrl_iface_process(supplicant, text, &length);
  int result = -1;
  if (reply) {
    if (network_id) {
      char *end;
      long id = strtol(reply, &end, 10);
      if (end != reply && end <= reply + length && id >= 0 && id <= INT_MAX) result = id;
    } else if (length >= 2 && os_memcmp(reply, "OK", 2) == 0) {
      result = 0;
    }
    os_free(reply);
  } else if (!network_id && length == 2) {
    result = 0;
  }
  return result;
}
static int fixed_command(struct wpa_supplicant *supplicant, const char *text)
{
  char buffer[64];
  if (os_strlcpy(buffer, text, sizeof(buffer)) >= sizeof(buffer)) return -1;
  return command(supplicant, buffer, 0);
}
static int join(struct wpa_supplicant *supplicant, const struct nw_control_view *event)
{
  size_t ssid_length, password_length;
  const u8 *ssid = nw_control_get(event, NW_CONTROL_ATTR_SSID, &ssid_length);
  const u8 *password = nw_control_get(event, NW_CONTROL_ATTR_PASSWORD, &password_length);
  size_t bssid_length;
  const u8 *bssid = nw_control_get(event, NW_CONTROL_ATTR_BSSID, &bssid_length);
  if (!ssid || !ssid_length || ssid_length > 32 || password_length > 64 ||
      (password_length && password_length < 8) ||
      (bssid && (bssid_length != ETH_ALEN || is_zero_ether_addr(bssid) || is_multicast_ether_addr(bssid)))) return -1;
  int hex_pmk = 0;
  if (password_length == 64) {
    u8 psk[32];
    hex_pmk = hexstr2bin((const char *)password, psk, sizeof(psk)) == 0;
    forced_memzero(psk, sizeof(psk));
  }
  /* wifid retains saved networks. The supplicant holds only its active profile
   * in RAM; REMOVE_NETWORK also clears old SME, PMK and handshake ownership. */
  if (fixed_command(supplicant, "REMOVE_NETWORK all")) return -1;
#ifdef CONFIG_SAE
  if (fixed_command(supplicant, "SET sae_pwe 2")) return -1;
#endif
  char text[512] = "ADD_NETWORK";
  int id = command(supplicant, text, 1);
  if (id < 0) return -1;
  char ssid_hex[65]; wpa_snprintf_hex(ssid_hex, sizeof(ssid_hex), ssid, ssid_length);
  os_snprintf(text, sizeof(text), "SET_NETWORK %d ssid %s", id, ssid_hex);
  if (command(supplicant, text, 0)) goto fail;
  if (bssid) {
    os_snprintf(text, sizeof(text), "SET_NETWORK %d bssid " MACSTR, id, MAC2STR(bssid));
    if (command(supplicant, text, 0)) goto fail;
  }
  const char *key_mgmt = "NONE";
  if (password_length == 64 && !hex_pmk) {
#ifdef CONFIG_SAE
    key_mgmt = "SAE";
#else
    goto fail;
#endif
  } else if (password_length == 64 && hex_pmk) {
    /* A PMK the daemon derived (cipher 6) is no SAE password: SAE derives its PMK from the passphrase itself. With SAE
     * listed too, a WPA2/WPA3 transition network would be joined by SAE and fail as a wrong key. */
    key_mgmt = "WPA-PSK WPA-PSK-SHA256";
  } else if (password_length) {
#ifdef CONFIG_SAE
    key_mgmt = "WPA-PSK WPA-PSK-SHA256 SAE";
#else
    key_mgmt = "WPA-PSK WPA-PSK-SHA256";
#endif
  }
  os_snprintf(text, sizeof(text), "SET_NETWORK %d key_mgmt %s", id, key_mgmt);
  if (command(supplicant, text, 0)) goto fail;
  if (password_length) {
    char encoded[4 * 64 + 1];
    int result = 0;
    if (password_length == 64 && hex_pmk) {
      os_memcpy(encoded, password, 64); encoded[64] = 0;
      os_snprintf(text, sizeof(text), "SET_NETWORK %d psk %s", id, encoded);
      result = command(supplicant, text, 0);
    } else if (password_length == 64) {
      /* P"..." is the form wpa_config_parse_string decodes; a plain quoted value is kept as written. */
      printf_encode(encoded, sizeof(encoded), password, password_length);
      os_snprintf(text, sizeof(text), "SET_NETWORK %d sae_password P\"%s\"", id, encoded);
      result = command(supplicant, text, 0);
    } else if (memchr(password, 0, password_length)) {
      result = -1;
    } else {
      /* wpa_config_parse_psk keeps the bytes up to the last quote as they are (it decodes no escapes and refuses control
       * characters), so the passphrase goes in unchanged: a quote, a backslash or UTF-8 in it stays what the user typed. */
      os_snprintf(text, sizeof(text), "SET_NETWORK %d psk \"%.*s\"", id, (int)password_length, (const char *)password);
      result = command(supplicant, text, 0);
    }
    forced_memzero(encoded, sizeof(encoded)); forced_memzero(text, sizeof(text));
    if (result) goto fail;
    os_snprintf(text, sizeof(text), "SET_NETWORK %d proto WPA RSN", id);
    if (command(supplicant, text, 0)) goto fail;
    os_snprintf(text, sizeof(text), "SET_NETWORK %d pairwise CCMP TKIP", id);
    if (command(supplicant, text, 0)) goto fail;
    os_snprintf(text, sizeof(text), "SET_NETWORK %d group CCMP TKIP", id);
    if (command(supplicant, text, 0)) goto fail;
    os_snprintf(text, sizeof(text), "SET_NETWORK %d ieee80211w 1", id);
    if (command(supplicant, text, 0)) goto fail;
  }
  os_snprintf(text, sizeof(text), "SET_NETWORK %d scan_ssid 1", id);
  if (command(supplicant, text, 0)) goto fail;
  os_snprintf(text, sizeof(text), "SELECT_NETWORK %d", id);
  if (!command(supplicant, text, 0)) return 0;
fail:
  forced_memzero(text, sizeof(text));
  os_snprintf(text, sizeof(text), "REMOVE_NETWORK %d", id);
  command(supplicant, text, 0);
  return -1;
}
int nw_supplicant_request(void *context, const struct nw_control_view *event)
{
  struct wpa_supplicant *supplicant = context;
  int result = -1;
  switch (event->header.operation) {
  case NW_CONTROL_JOIN_REQUEST: result = join(supplicant, event); break;
  case NW_CONTROL_DISCONNECT_REQUEST: result = fixed_command(supplicant, "DISCONNECT"); break;
  case NW_CONTROL_SCAN_REQUEST: {
    size_t length; const u8 *ssid = nw_control_get(event, NW_CONTROL_ATTR_SSID, &length);
    if (ssid && length && length <= 32) {
      char hex[65], text[80]; wpa_snprintf_hex(hex, sizeof(hex), ssid, length);
      os_snprintf(text, sizeof(text), "SCAN ssid %s", hex); result = command(supplicant, text, 0);
    } else result = fixed_command(supplicant, "SCAN");
    /* The channels the UI asked for (at most 32, as the kernel limits them): a scan of every band takes about 16 s on WCN7850,
     * longer than the UI waits for it. "SCAN freq=" maps the list through the driver's channel table, which this driver does not
     * report, so the list goes to the manual scan the command just queued (it starts from the event loop, after this returns).
     * A malformed list scans every band. */
    size_t bytes; const u8 *frequencies = nw_control_get(event, NW_CONTROL_ATTR_SCAN_FREQUENCIES, &bytes);
    if (!result && frequencies && bytes && bytes % 4 == 0 && bytes / 4 <= 64 && supplicant->scan_req == MANUAL_SCAN_REQ) {
      int *list = os_calloc(bytes / 4 + 1, sizeof(int));
      if (list) {
        for (size_t i = 0; i < bytes / 4; i++) list[i] = (int)WPA_GET_LE32(frequencies + i * 4);
        os_free(supplicant->manual_scan_freqs); supplicant->manual_scan_freqs = list;
      }
    }
    break;
  }
  case NW_CONTROL_POWER_REQUEST: {
    uint32_t state;
    if (!nw_control_get_u32(event, NW_CONTROL_ATTR_OPERSTATE, &state))
      // Radio power does not select a network. Settings/wifid owns selection.
      result = fixed_command(supplicant, "DISCONNECT");
    break;
  }
  }
  if (result && event->header.operation == NW_CONTROL_JOIN_REQUEST)
    nw_sheng_report_request_failure(supplicant->drv_priv, event->header.operation, NW_CONTROL_INVALID);
  if (result && event->header.operation == NW_CONTROL_SCAN_REQUEST)
    nw_sheng_report_request_failure(supplicant->drv_priv, event->header.operation, NW_CONTROL_BUSY);
  return result;
}
void nw_supplicant_auth_failed(void *context, const char *reason)
{
  struct wpa_supplicant *supplicant = context;
  if (supplicant->driver && !os_strcmp(supplicant->driver->name, "sheng") &&
      (!os_strcmp(reason, "WRONG_KEY") || !os_strcmp(reason, "NO_PSK_AVAILABLE")))
    nw_sheng_report_auth_failure(supplicant->drv_priv);
}
int nw_supplicant_sae_confirm_pending(void *context, const uint8_t *bssid)
{
#ifdef CONFIG_SAE
  struct wpa_supplicant *supplicant = context;
  if (!supplicant || !bssid) return 0;
  return supplicant->wpa_state == WPA_AUTHENTICATING &&
         supplicant->sme.sae.state == SAE_CONFIRMED &&
         os_memcmp(supplicant->pending_bssid, bssid, ETH_ALEN) == 0;
#else
  (void)context; (void)bssid;
  return 0;
#endif
}
void nw_supplicant_sae_confirm_check(void *context, int was_pending)
{
#ifdef CONFIG_SAE
  struct wpa_supplicant *supplicant = context;
  /* Report WRONG_KEY only when local SAE confirm verification itself failed
   * (leaving sme.sae.state at SAE_CONFIRMED) rather than a post-confirm
   * association failure after SAE_ACCEPTED. */
  if (was_pending && supplicant &&
      supplicant->wpa_state == WPA_DISCONNECTED &&
      supplicant->sme.sae.state == SAE_CONFIRMED)
    nw_supplicant_auth_failed(supplicant, "WRONG_KEY");
#else
  (void)context; (void)was_pending;
#endif
}
