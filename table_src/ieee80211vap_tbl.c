#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ieee80211vap.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ieee80211vap.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ic_vaps_iv_media = 0,
    VT_ic_vaps_iv_ifp = 1,
    VT_ic_vaps_iv_rawbpf = 2,
    VT_ic_vaps_iv_sysctl = 3,
    VT_ic_vaps_iv_oid = 4,
    VT_ic_vaps_iv_next = 5,
    VT_ic_vaps_iv_ic = 6,
    VT_ic_vaps_iv_myaddr = 7,
    VT_ic_vaps_iv_debug = 8,
    VT_ic_vaps_iv_stats = 9,
    VT_ic_vaps_iv_flags = 10,
    VT_ic_vaps_iv_flags_ext = 11,
    VT_ic_vaps_iv_flags_ht = 12,
    VT_ic_vaps_iv_flags_ven = 13,
    VT_ic_vaps_iv_ifflags = 14,
    VT_ic_vaps_iv_caps = 15,
    VT_ic_vaps_iv_htcaps = 16,
    VT_ic_vaps_iv_htextcaps = 17,
    VT_ic_vaps_iv_com_state = 18,
    VT_ic_vaps_iv_opmode = 19,
    VT_ic_vaps_iv_state = 20,
    VT_ic_vaps_iv_nstate = 21,
    VT_ic_vaps_iv_nstate_b = 22,
    VT_ic_vaps_iv_nstate_n = 23,
    VT_ic_vaps_iv_nstates = 24,
    VT_ic_vaps_iv_nstate_args = 25,
    VT_ic_vaps_iv_nstate_task = 26,
    VT_ic_vaps_iv_swbmiss_task = 27,
    VT_ic_vaps_iv_mgtsend = 28,
    VT_ic_vaps_iv_inact_init = 29,
    VT_ic_vaps_iv_inact_auth = 30,
    VT_ic_vaps_iv_inact_run = 31,
    VT_ic_vaps_iv_inact_probe = 32,
    VT_ic_vaps_iv_vht_flags = 33,
    VT_ic_vaps_iv_vht_cap = 34,
    VT_ic_vaps_iv_vhtextcaps = 35,
    VT_ic_vaps_iv_vht_spare = 36,
    VT_ic_vaps_iv_des_nssid = 37,
    VT_ic_vaps_iv_des_ssid = 38,
    VT_ic_vaps_iv_des_bssid = 39,
    VT_ic_vaps_iv_des_chan = 40,
    VT_ic_vaps_iv_des_mode = 41,
    VT_ic_vaps_iv_nicknamelen = 42,
    VT_ic_vaps_iv_nickname = 43,
    VT_ic_vaps_iv_bgscanidle = 44,
    VT_ic_vaps_iv_bgscanintvl = 45,
    VT_ic_vaps_iv_scanvalid = 46,
    VT_ic_vaps_iv_scanreq_duration = 47,
    VT_ic_vaps_iv_scanreq_mindwell = 48,
    VT_ic_vaps_iv_scanreq_maxdwell = 49,
    VT_ic_vaps_iv_scanreq_flags = 50,
    VT_ic_vaps_iv_scanreq_nssid = 51,
    VT_ic_vaps_iv_scanreq_ssid = 52,
    VT_ic_vaps_iv_roaming = 53,
    VT_ic_vaps_iv_roamparms = 54,
    VT_ic_vaps_iv_bmissthreshold = 55,
    VT_ic_vaps_iv_bmiss_count = 56,
    VT_ic_vaps_iv_bmiss_max = 57,
    VT_ic_vaps_iv_swbmiss_count = 58,
    VT_ic_vaps_iv_swbmiss_period = 59,
    VT_ic_vaps_iv_swbmiss = 60,
    VT_ic_vaps_iv_ampdu_rxmax = 61,
    VT_ic_vaps_iv_ampdu_density = 62,
    VT_ic_vaps_iv_ampdu_limit = 63,
    VT_ic_vaps_iv_amsdu_limit = 64,
    VT_ic_vaps_iv_ampdu_mintraffic = 65,
    VT_ic_vaps_iv_bcn_off = 66,
    VT_ic_vaps_iv_aid_bitmap = 67,
    VT_ic_vaps_iv_max_aid = 68,
    VT_ic_vaps_iv_sta_assoc = 69,
    VT_ic_vaps_iv_ps_sta = 70,
    VT_ic_vaps_iv_ps_pending = 71,
    VT_ic_vaps_iv_txseq = 72,
    VT_ic_vaps_iv_tim_len = 73,
    VT_ic_vaps_iv_tim_bitmap = 74,
    VT_ic_vaps_iv_dtim_period = 75,
    VT_ic_vaps_iv_dtim_count = 76,
    VT_ic_vaps_iv_quiet = 77,
    VT_ic_vaps_iv_quiet_count = 78,
    VT_ic_vaps_iv_quiet_count_value = 79,
    VT_ic_vaps_iv_quiet_period = 80,
    VT_ic_vaps_iv_quiet_duration = 81,
    VT_ic_vaps_iv_quiet_offset = 82,
    VT_ic_vaps_iv_csa_count = 83,
    VT_ic_vaps_iv_bss = 84,
    VT_ic_vaps_iv_txparms = 85,
    VT_ic_vaps_iv_rtsthreshold = 86,
    VT_ic_vaps_iv_fragthreshold = 87,
    VT_ic_vaps_iv_inact_timer = 88,
    VT_ic_vaps_iv_appie_beacon = 89,
    VT_ic_vaps_iv_appie_probereq = 90,
    VT_ic_vaps_iv_appie_proberesp = 91,
    VT_ic_vaps_iv_appie_assocreq = 92,
    VT_ic_vaps_iv_appie_assocresp = 93,
    VT_ic_vaps_iv_appie_wpa = 94,
    VT_ic_vaps_iv_wpa_ie = 95,
    VT_ic_vaps_iv_rsn_ie = 96,
    VT_ic_vaps_iv_max_keyix = 97,
    VT_ic_vaps_iv_def_txkey = 98,
    VT_ic_vaps_iv_nw_keys = 99,
    VT_ic_vaps_iv_key_alloc = 100,
    VT_ic_vaps_iv_key_delete = 101,
    VT_ic_vaps_iv_key_set = 102,
    VT_ic_vaps_iv_key_update_begin = 103,
    VT_ic_vaps_iv_key_update_end = 104,
    VT_ic_vaps_iv_update_deftxkey = 105,
    VT_ic_vaps_iv_auth = 106,
    VT_ic_vaps_iv_ec = 107,
    VT_ic_vaps_iv_acl = 108,
    VT_ic_vaps_iv_as = 109,
    VT_ic_vaps_iv_rate = 110,
    VT_ic_vaps_iv_rs = 111,
    VT_ic_vaps_iv_tdma = 112,
    VT_ic_vaps_iv_mesh = 113,
    VT_ic_vaps_iv_hwmp = 114,
    VT_ic_vaps_iv_opdetach = 115,
    VT_ic_vaps_iv_input = 116,
    VT_ic_vaps_iv_recv_mgmt = 117,
    VT_ic_vaps_iv_recv_ctl = 118,
    VT_ic_vaps_iv_deliver_data = 119,
    VT_ic_vaps_iv_bmiss = 120,
    VT_ic_vaps_iv_reset = 121,
    VT_ic_vaps_iv_update_beacon = 122,
    VT_ic_vaps_iv_update_ps = 123,
    VT_ic_vaps_iv_set_tim = 124,
    VT_ic_vaps_iv_node_ps = 125,
    VT_ic_vaps_iv_sta_ps = 126,
    VT_ic_vaps_iv_recv_pspoll = 127,
    VT_ic_vaps_iv_newstate = 128,
    VT_ic_vaps_iv_update_bss = 129,
    VT_ic_vaps_iv_output = 130,
    VT_ic_vaps_iv_wme_update = 131,
    VT_ic_vaps_iv_wme_task = 132,
    VT_ic_vaps_iv_protmode = 133,
    VT_ic_vaps_iv_htprotmode = 134,
    VT_ic_vaps_iv_curhtprotmode = 135,
    VT_ic_vaps_iv_nonerpsta = 136,
    VT_ic_vaps_iv_longslotsta = 137,
    VT_ic_vaps_iv_ht_sta_assoc = 138,
    VT_ic_vaps_iv_ht40_sta_assoc = 139,
    VT_ic_vaps_iv_lastnonerp = 140,
    VT_ic_vaps_iv_lastnonht = 141,
    VT_ic_vaps_iv_updateslot = 142,
    VT_ic_vaps_iv_slot_task = 143,
    VT_ic_vaps_iv_erp_protmode_task = 144,
    VT_ic_vaps_iv_erp_protmode_update = 145,
    VT_ic_vaps_iv_preamble_task = 146,
    VT_ic_vaps_iv_preamble_update = 147,
    VT_ic_vaps_iv_ht_protmode_task = 148,
    VT_ic_vaps_iv_ht_protmode_update = 149,
    VT_ic_vaps_iv_uapsdinfo = 150,
    VT_ic_vaps_rx_histogram = 151,
    VT_ic_vaps_tx_histogram = 152,
    VT_ic_vaps_iv_spare = 153,
    VT_ic_vaps_NUM_COLUMNS
};

static int
copy_columns(struct ieee80211vap *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_ic_vaps_iv_media] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_ifp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_ifp, context);
    columns[VT_ic_vaps_iv_rawbpf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_rawbpf, context);
    columns[VT_ic_vaps_iv_sysctl] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_sysctl, context);
    columns[VT_ic_vaps_iv_oid] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_oid, context);
//    columns[VT_ic_vaps_iv_next] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_ic] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_ic, context);
//    columns[VT_ic_vaps_iv_myaddr] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_debug] = new_dbsc_int64(curEntry->iv_debug, context);
//    columns[VT_ic_vaps_iv_stats] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_flags] = new_dbsc_int64(curEntry->iv_flags, context);
    columns[VT_ic_vaps_iv_flags_ext] = new_dbsc_int64(curEntry->iv_flags_ext, context);
    columns[VT_ic_vaps_iv_flags_ht] = new_dbsc_int64(curEntry->iv_flags_ht, context);
    columns[VT_ic_vaps_iv_flags_ven] = new_dbsc_int64(curEntry->iv_flags_ven, context);
    columns[VT_ic_vaps_iv_ifflags] = new_dbsc_int64(curEntry->iv_ifflags, context);
    columns[VT_ic_vaps_iv_caps] = new_dbsc_int64(curEntry->iv_caps, context);
    columns[VT_ic_vaps_iv_htcaps] = new_dbsc_int64(curEntry->iv_htcaps, context);
    columns[VT_ic_vaps_iv_htextcaps] = new_dbsc_int64(curEntry->iv_htextcaps, context);
    columns[VT_ic_vaps_iv_com_state] = new_dbsc_int64(curEntry->iv_com_state, context);
    columns[VT_ic_vaps_iv_opmode] = new_dbsc_int64((int64_t)(curEntry->iv_opmode), context); // TODO: need better enum representation 
    columns[VT_ic_vaps_iv_state] = new_dbsc_int64((int64_t)(curEntry->iv_state), context); // TODO: need better enum representation 
    columns[VT_ic_vaps_iv_nstate] = new_dbsc_int64((int64_t)(curEntry->iv_nstate), context); // TODO: need better enum representation 
    columns[VT_ic_vaps_iv_nstate_b] = new_dbsc_int64(curEntry->iv_nstate_b, context);
    columns[VT_ic_vaps_iv_nstate_n] = new_dbsc_int64(curEntry->iv_nstate_n, context);
//    columns[VT_ic_vaps_iv_nstates] =  /* Unsupported type */
//    columns[VT_ic_vaps_iv_nstate_args] =  /* Unsupported type */
//    columns[VT_ic_vaps_iv_nstate_task] =  /* Unsupported type */
//    columns[VT_ic_vaps_iv_swbmiss_task] =  /* Unsupported type */
//    columns[VT_ic_vaps_iv_mgtsend] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_inact_init] = new_dbsc_int64(curEntry->iv_inact_init, context);
    columns[VT_ic_vaps_iv_inact_auth] = new_dbsc_int64(curEntry->iv_inact_auth, context);
    columns[VT_ic_vaps_iv_inact_run] = new_dbsc_int64(curEntry->iv_inact_run, context);
    columns[VT_ic_vaps_iv_inact_probe] = new_dbsc_int64(curEntry->iv_inact_probe, context);
    columns[VT_ic_vaps_iv_vht_flags] = new_dbsc_int64(curEntry->iv_vht_flags, context);
//    columns[VT_ic_vaps_iv_vht_cap] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_vhtextcaps] = new_dbsc_int64(curEntry->iv_vhtextcaps, context);
//    columns[VT_ic_vaps_iv_vht_spare] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_des_nssid] = new_dbsc_int64(curEntry->iv_des_nssid, context);
//    columns[VT_ic_vaps_iv_des_ssid] =  /* Unsupported type */
//    columns[VT_ic_vaps_iv_des_bssid] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_des_chan] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_des_chan, context);
    columns[VT_ic_vaps_iv_des_mode] = new_dbsc_int64(curEntry->iv_des_mode, context);
    columns[VT_ic_vaps_iv_nicknamelen] = new_dbsc_int64(curEntry->iv_nicknamelen, context);
//    columns[VT_ic_vaps_iv_nickname] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_bgscanidle] = new_dbsc_int64(curEntry->iv_bgscanidle, context);
    columns[VT_ic_vaps_iv_bgscanintvl] = new_dbsc_int64(curEntry->iv_bgscanintvl, context);
    columns[VT_ic_vaps_iv_scanvalid] = new_dbsc_int64(curEntry->iv_scanvalid, context);
    columns[VT_ic_vaps_iv_scanreq_duration] = new_dbsc_int64(curEntry->iv_scanreq_duration, context);
    columns[VT_ic_vaps_iv_scanreq_mindwell] = new_dbsc_int64(curEntry->iv_scanreq_mindwell, context);
    columns[VT_ic_vaps_iv_scanreq_maxdwell] = new_dbsc_int64(curEntry->iv_scanreq_maxdwell, context);
    columns[VT_ic_vaps_iv_scanreq_flags] = new_dbsc_int64(curEntry->iv_scanreq_flags, context);
    columns[VT_ic_vaps_iv_scanreq_nssid] = new_dbsc_int64(curEntry->iv_scanreq_nssid, context);
//    columns[VT_ic_vaps_iv_scanreq_ssid] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_roaming] = new_dbsc_int64((int64_t)(curEntry->iv_roaming), context); // TODO: need better enum representation 
//    columns[VT_ic_vaps_iv_roamparms] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_bmissthreshold] = new_dbsc_int64(curEntry->iv_bmissthreshold, context);
    columns[VT_ic_vaps_iv_bmiss_count] = new_dbsc_int64(curEntry->iv_bmiss_count, context);
    columns[VT_ic_vaps_iv_bmiss_max] = new_dbsc_int64(curEntry->iv_bmiss_max, context);
    columns[VT_ic_vaps_iv_swbmiss_count] = new_dbsc_int64(curEntry->iv_swbmiss_count, context);
    columns[VT_ic_vaps_iv_swbmiss_period] = new_dbsc_int64(curEntry->iv_swbmiss_period, context);
//    columns[VT_ic_vaps_iv_swbmiss] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_ampdu_rxmax] = new_dbsc_int64(curEntry->iv_ampdu_rxmax, context);
    columns[VT_ic_vaps_iv_ampdu_density] = new_dbsc_int64(curEntry->iv_ampdu_density, context);
    columns[VT_ic_vaps_iv_ampdu_limit] = new_dbsc_int64(curEntry->iv_ampdu_limit, context);
    columns[VT_ic_vaps_iv_amsdu_limit] = new_dbsc_int64(curEntry->iv_amsdu_limit, context);
//    columns[VT_ic_vaps_iv_ampdu_mintraffic] =  /* Unsupported type */
//    columns[VT_ic_vaps_iv_bcn_off] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_aid_bitmap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_aid_bitmap, context);
    columns[VT_ic_vaps_iv_max_aid] = new_dbsc_int64(curEntry->iv_max_aid, context);
    columns[VT_ic_vaps_iv_sta_assoc] = new_dbsc_int64(curEntry->iv_sta_assoc, context);
    columns[VT_ic_vaps_iv_ps_sta] = new_dbsc_int64(curEntry->iv_ps_sta, context);
    columns[VT_ic_vaps_iv_ps_pending] = new_dbsc_int64(curEntry->iv_ps_pending, context);
    columns[VT_ic_vaps_iv_txseq] = new_dbsc_int64(curEntry->iv_txseq, context);
    columns[VT_ic_vaps_iv_tim_len] = new_dbsc_int64(curEntry->iv_tim_len, context);
    columns[VT_ic_vaps_iv_tim_bitmap] = new_dbsc_text(curEntry->iv_tim_bitmap, strlen(curEntry->iv_tim_bitmap) + 1, context);
    columns[VT_ic_vaps_iv_dtim_period] = new_dbsc_int64(curEntry->iv_dtim_period, context);
    columns[VT_ic_vaps_iv_dtim_count] = new_dbsc_int64(curEntry->iv_dtim_count, context);
    columns[VT_ic_vaps_iv_quiet] = new_dbsc_int64(curEntry->iv_quiet, context);
    columns[VT_ic_vaps_iv_quiet_count] = new_dbsc_int64(curEntry->iv_quiet_count, context);
    columns[VT_ic_vaps_iv_quiet_count_value] = new_dbsc_int64(curEntry->iv_quiet_count_value, context);
    columns[VT_ic_vaps_iv_quiet_period] = new_dbsc_int64(curEntry->iv_quiet_period, context);
    columns[VT_ic_vaps_iv_quiet_duration] = new_dbsc_int64(curEntry->iv_quiet_duration, context);
    columns[VT_ic_vaps_iv_quiet_offset] = new_dbsc_int64(curEntry->iv_quiet_offset, context);
    columns[VT_ic_vaps_iv_csa_count] = new_dbsc_int64(curEntry->iv_csa_count, context);
    columns[VT_ic_vaps_iv_bss] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_bss, context);
//    columns[VT_ic_vaps_iv_txparms] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_rtsthreshold] = new_dbsc_int64(curEntry->iv_rtsthreshold, context);
    columns[VT_ic_vaps_iv_fragthreshold] = new_dbsc_int64(curEntry->iv_fragthreshold, context);
    columns[VT_ic_vaps_iv_inact_timer] = new_dbsc_int64(curEntry->iv_inact_timer, context);
    columns[VT_ic_vaps_iv_appie_beacon] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_appie_beacon, context);
    columns[VT_ic_vaps_iv_appie_probereq] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_appie_probereq, context);
    columns[VT_ic_vaps_iv_appie_proberesp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_appie_proberesp, context);
    columns[VT_ic_vaps_iv_appie_assocreq] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_appie_assocreq, context);
    columns[VT_ic_vaps_iv_appie_assocresp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_appie_assocresp, context);
    columns[VT_ic_vaps_iv_appie_wpa] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_appie_wpa, context);
    columns[VT_ic_vaps_iv_wpa_ie] = new_dbsc_text(curEntry->iv_wpa_ie, strlen(curEntry->iv_wpa_ie) + 1, context);
    columns[VT_ic_vaps_iv_rsn_ie] = new_dbsc_text(curEntry->iv_rsn_ie, strlen(curEntry->iv_rsn_ie) + 1, context);
    columns[VT_ic_vaps_iv_max_keyix] = new_dbsc_int64(curEntry->iv_max_keyix, context);
    columns[VT_ic_vaps_iv_def_txkey] = new_dbsc_int64(curEntry->iv_def_txkey, context);
//    columns[VT_ic_vaps_iv_nw_keys] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_key_alloc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_key_alloc, context);
    columns[VT_ic_vaps_iv_key_delete] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_key_delete, context);
    columns[VT_ic_vaps_iv_key_set] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_key_set, context);
    columns[VT_ic_vaps_iv_key_update_begin] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_key_update_begin, context);
    columns[VT_ic_vaps_iv_key_update_end] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_key_update_end, context);
    columns[VT_ic_vaps_iv_update_deftxkey] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_update_deftxkey, context);
    columns[VT_ic_vaps_iv_auth] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_auth, context);
    columns[VT_ic_vaps_iv_ec] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_ec, context);
    columns[VT_ic_vaps_iv_acl] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_acl, context);
    columns[VT_ic_vaps_iv_as] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_as, context);
    columns[VT_ic_vaps_iv_rate] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_rate, context);
    columns[VT_ic_vaps_iv_rs] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_rs, context);
    columns[VT_ic_vaps_iv_tdma] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_tdma, context);
    columns[VT_ic_vaps_iv_mesh] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_mesh, context);
    columns[VT_ic_vaps_iv_hwmp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_hwmp, context);
    columns[VT_ic_vaps_iv_opdetach] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_opdetach, context);
    columns[VT_ic_vaps_iv_input] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_input, context);
    columns[VT_ic_vaps_iv_recv_mgmt] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_recv_mgmt, context);
    columns[VT_ic_vaps_iv_recv_ctl] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_recv_ctl, context);
    columns[VT_ic_vaps_iv_deliver_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_deliver_data, context);
    columns[VT_ic_vaps_iv_bmiss] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_bmiss, context);
    columns[VT_ic_vaps_iv_reset] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_reset, context);
    columns[VT_ic_vaps_iv_update_beacon] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_update_beacon, context);
    columns[VT_ic_vaps_iv_update_ps] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_update_ps, context);
    columns[VT_ic_vaps_iv_set_tim] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_set_tim, context);
    columns[VT_ic_vaps_iv_node_ps] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_node_ps, context);
    columns[VT_ic_vaps_iv_sta_ps] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_sta_ps, context);
    columns[VT_ic_vaps_iv_recv_pspoll] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_recv_pspoll, context);
    columns[VT_ic_vaps_iv_newstate] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_newstate, context);
    columns[VT_ic_vaps_iv_update_bss] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_update_bss, context);
    columns[VT_ic_vaps_iv_output] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_output, context);
    columns[VT_ic_vaps_iv_wme_update] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_wme_update, context);
//    columns[VT_ic_vaps_iv_wme_task] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_protmode] = new_dbsc_int64((int64_t)(curEntry->iv_protmode), context); // TODO: need better enum representation 
    columns[VT_ic_vaps_iv_htprotmode] = new_dbsc_int64((int64_t)(curEntry->iv_htprotmode), context); // TODO: need better enum representation 
    columns[VT_ic_vaps_iv_curhtprotmode] = new_dbsc_int64(curEntry->iv_curhtprotmode, context);
    columns[VT_ic_vaps_iv_nonerpsta] = new_dbsc_int64(curEntry->iv_nonerpsta, context);
    columns[VT_ic_vaps_iv_longslotsta] = new_dbsc_int64(curEntry->iv_longslotsta, context);
    columns[VT_ic_vaps_iv_ht_sta_assoc] = new_dbsc_int64(curEntry->iv_ht_sta_assoc, context);
    columns[VT_ic_vaps_iv_ht40_sta_assoc] = new_dbsc_int64(curEntry->iv_ht40_sta_assoc, context);
    columns[VT_ic_vaps_iv_lastnonerp] = new_dbsc_int64(curEntry->iv_lastnonerp, context);
    columns[VT_ic_vaps_iv_lastnonht] = new_dbsc_int64(curEntry->iv_lastnonht, context);
    columns[VT_ic_vaps_iv_updateslot] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_updateslot, context);
//    columns[VT_ic_vaps_iv_slot_task] =  /* Unsupported type */
//    columns[VT_ic_vaps_iv_erp_protmode_task] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_erp_protmode_update] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_erp_protmode_update, context);
//    columns[VT_ic_vaps_iv_preamble_task] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_preamble_update] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_preamble_update, context);
//    columns[VT_ic_vaps_iv_ht_protmode_task] =  /* Unsupported type */
    columns[VT_ic_vaps_iv_ht_protmode_update] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_ht_protmode_update, context);
    columns[VT_ic_vaps_iv_uapsdinfo] = new_dbsc_int64(curEntry->iv_uapsdinfo, context);
    columns[VT_ic_vaps_rx_histogram] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rx_histogram, context);
    columns[VT_ic_vaps_tx_histogram] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tx_histogram, context);
//    columns[VT_ic_vaps_iv_spare] =  /* Unsupported type */

    return 0;
}
void
vtab_ieee80211vap_lock(void)
{
    sx_slock(&ic_vaps_lock);
}

void
vtab_ieee80211vap_unlock(void)
{
    sx_sunlock(&ic_vaps_lock);
}

void
vtab_ieee80211vap_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ieee80211vap *prc = LIST_FIRST(&ic_vaps);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ic_vaps_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_ic_vaps_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ieee80211vap digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ieee80211vapvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_ic_vaps_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ieee80211vap_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ieee80211vapvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ieee80211vapvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ieee80211vap_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ieee80211vap digest mismatch: UPDATE failed\n");
#endif
        return SQLITE_ABORT;
    }

    if ((argc == 1) && (argv[0] != NULL)) {
        int p_pid = sqlite3_value_int64(argv[0]);
#ifdef DEBUG
        printf("argc %d argv[0] %d, rowID, %lld\n", argc, p_pid, *pRowid);
        printf("Killing PID %d.\n", p_pid);
#endif
        kern_kill(curthread, p_pid, SIGKILL);
        return SQLITE_OK;
    }

    if ((argc > 1) && (sqlite3_value_type(argv[0]) != SQLITE_NULL)) {
        int core = sqlite3_value_int64(argv[2]);
        int pid = sqlite3_value_int64(argv[5]);
        cpuset_t *mask = malloc(sizeof(cpuset_t), M_TEMP, M_WAITOK | M_ZERO);
#ifdef DEBUG
        int row = sqlite3_value_int64(argv[0]);
        printf("UPDATE row %d core %d pid %d\n", row, core, pid);
#endif
        CPU_SET(core, mask);
        cpuset_setproc(pid, NULL, mask, NULL, false);
        free(mask, M_TEMP);
    }

    return SQLITE_OK;
}

/*
** This following structure defines all the methods for the
** virtual table.
*/
static sqlite3_module ieee80211vapvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ieee80211vapvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ieee80211vapvtabRowid,
    /* xUpdate     */ ieee80211vapvtabUpdate,
    /* xBegin      */ 0,
    /* xSync       */ 0,
    /* xCommit     */ 0,
    /* xRollback   */ 0,
    /* xFindMethod */ 0,
    /* xRename     */ 0,
    /* xSavepoint  */ 0,
    /* xRelease    */ 0,
    /* xRollbackTo */ 0,
    /* xShadowName */ 0,
    /* xIntegrity  */ 0
};

int
sqlite3_ieee80211vapvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ieee80211vapvtabModule,
        pAux);
}
void vtab_ieee80211vap_serialize(sqlite3 *real_db, struct timespec when) {
    struct ieee80211vap *entry = LIST_FIRST(&ic_vaps);

    const char *create_stmt =
        "CREATE TABLE all_ieee80211vaps (iv_debug INTEGER, iv_flags INTEGER, iv_flags_ext INTEGER, iv_flags_ht INTEGER, iv_flags_ven INTEGER, iv_ifflags INTEGER, iv_caps INTEGER, iv_htcaps INTEGER, iv_htextcaps INTEGER, iv_com_state INTEGER, iv_opmode INTEGER, iv_state INTEGER, iv_nstate INTEGER, iv_nstate_b INTEGER, iv_nstate_n INTEGER, iv_inact_init INTEGER, iv_inact_auth INTEGER, iv_inact_run INTEGER, iv_inact_probe INTEGER, iv_vht_flags INTEGER, iv_vhtextcaps INTEGER, iv_des_nssid INTEGER, iv_des_mode INTEGER, iv_nicknamelen INTEGER, iv_bgscanidle INTEGER, iv_bgscanintvl INTEGER, iv_scanvalid INTEGER, iv_scanreq_duration INTEGER, iv_scanreq_mindwell INTEGER, iv_scanreq_maxdwell INTEGER, iv_scanreq_flags INTEGER, iv_scanreq_nssid INTEGER, iv_roaming INTEGER, iv_bmissthreshold INTEGER, iv_bmiss_count INTEGER, iv_bmiss_max INTEGER, iv_swbmiss_count INTEGER, iv_swbmiss_period INTEGER, iv_ampdu_rxmax INTEGER, iv_ampdu_density INTEGER, iv_ampdu_limit INTEGER, iv_amsdu_limit INTEGER, iv_max_aid INTEGER, iv_sta_assoc INTEGER, iv_ps_sta INTEGER, iv_ps_pending INTEGER, iv_txseq INTEGER, iv_tim_len INTEGER, iv_tim_bitmap TEXT, iv_dtim_period INTEGER, iv_dtim_count INTEGER, iv_quiet INTEGER, iv_quiet_count INTEGER, iv_quiet_count_value INTEGER, iv_quiet_period INTEGER, iv_quiet_duration INTEGER, iv_quiet_offset INTEGER, iv_csa_count INTEGER, iv_rtsthreshold INTEGER, iv_fragthreshold INTEGER, iv_inact_timer INTEGER, iv_wpa_ie TEXT, iv_rsn_ie TEXT, iv_max_keyix INTEGER, iv_def_txkey INTEGER, iv_protmode INTEGER, iv_htprotmode INTEGER, iv_curhtprotmode INTEGER, iv_nonerpsta INTEGER, iv_longslotsta INTEGER, iv_ht_sta_assoc INTEGER, iv_ht40_sta_assoc INTEGER, iv_lastnonerp INTEGER, iv_lastnonht INTEGER, iv_uapsdinfo INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ieee80211vaps VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_debug);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_flags_ext);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_flags_ht);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_flags_ven);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_ifflags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_caps);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_htcaps);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_htextcaps);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_com_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_opmode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_nstate);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_nstate_b);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_nstate_n);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_inact_init);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_inact_auth);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_inact_run);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_inact_probe);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_vht_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_vhtextcaps);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_des_nssid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_des_mode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_nicknamelen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_bgscanidle);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_bgscanintvl);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_scanvalid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_scanreq_duration);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_scanreq_mindwell);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_scanreq_maxdwell);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_scanreq_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_scanreq_nssid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_roaming);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_bmissthreshold);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_bmiss_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_bmiss_max);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_swbmiss_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_swbmiss_period);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_ampdu_rxmax);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_ampdu_density);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_ampdu_limit);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_amsdu_limit);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_max_aid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_sta_assoc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_ps_sta);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_ps_pending);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_txseq);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_tim_len);
           sqlite3_bind_text(stmt, bindIndex++, entry->iv_tim_bitmap, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_dtim_period);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_dtim_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_quiet);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_quiet_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_quiet_count_value);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_quiet_period);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_quiet_duration);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_quiet_offset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_csa_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_rtsthreshold);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_fragthreshold);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_inact_timer);
           sqlite3_bind_text(stmt, bindIndex++, entry->iv_wpa_ie, -1, SQLITE_TRANSIENT);
           sqlite3_bind_text(stmt, bindIndex++, entry->iv_rsn_ie, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_max_keyix);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_def_txkey);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_protmode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_htprotmode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_curhtprotmode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_nonerpsta);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_longslotsta);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_ht_sta_assoc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_ht40_sta_assoc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_lastnonerp);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_lastnonht);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iv_uapsdinfo);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

