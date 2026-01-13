#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ic_head_ic_softc = 0,
    VT_ic_head_ic_name = 1,
    VT_ic_head_ic_comlock = 2,
    VT_ic_head_ic_txlock = 3,
    VT_ic_head_ic_fflock = 4,
    VT_ic_head_ic_next = 5,
    VT_ic_head_ic_vaps = 6,
    VT_ic_head_ic_headroom = 7,
    VT_ic_head_ic_phytype = 8,
    VT_ic_head_ic_opmode = 9,
    VT_ic_head_ic_inact = 10,
    VT_ic_head_ic_tq = 11,
    VT_ic_head_ic_parent_task = 12,
    VT_ic_head_ic_promisc_task = 13,
    VT_ic_head_ic_mcast_task = 14,
    VT_ic_head_ic_chan_task = 15,
    VT_ic_head_ic_bmiss_task = 16,
    VT_ic_head_ic_chw_task = 17,
    VT_ic_head_ic_restart_task = 18,
    VT_ic_head_ic_ierrors = 19,
    VT_ic_head_ic_oerrors = 20,
    VT_ic_head_ic_flags = 21,
    VT_ic_head_ic_flags_ext = 22,
    VT_ic_head_ic_flags_ht = 23,
    VT_ic_head_ic_flags_ven = 24,
    VT_ic_head_ic_caps = 25,
    VT_ic_head_ic_htcaps = 26,
    VT_ic_head_ic_htextcaps = 27,
    VT_ic_head_ic_sw_cryptocaps = 28,
    VT_ic_head_ic_cryptocaps = 29,
    VT_ic_head_ic_sw_keymgmtcaps = 30,
    VT_ic_head_ic_modecaps = 31,
    VT_ic_head_ic_promisc = 32,
    VT_ic_head_ic_allmulti = 33,
    VT_ic_head_ic_nrunning = 34,
    VT_ic_head_ic_curmode = 35,
    VT_ic_head_ic_macaddr = 36,
    VT_ic_head_ic_bintval = 37,
    VT_ic_head_ic_lintval = 38,
    VT_ic_head_ic_holdover = 39,
    VT_ic_head_ic_txpowlimit = 40,
    VT_ic_head_ic_sup_rates = 41,
    VT_ic_head_ic_sup_htrates = 42,
    VT_ic_head_ic_nchans = 43,
    VT_ic_head_ic_channels = 44,
    VT_ic_head_ic_chan_avail = 45,
    VT_ic_head_ic_chan_active = 46,
    VT_ic_head_ic_chan_scan = 47,
    VT_ic_head_ic_curchan = 48,
    VT_ic_head_ic_rt = 49,
    VT_ic_head_ic_bsschan = 50,
    VT_ic_head_ic_prevchan = 51,
    VT_ic_head_ic_regdomain = 52,
    VT_ic_head_ic_countryie = 53,
    VT_ic_head_ic_countryie_chan = 54,
    VT_ic_head_ic_csa_newchan = 55,
    VT_ic_head_ic_csa_mode = 56,
    VT_ic_head_ic_csa_count = 57,
    VT_ic_head_ic_dfs = 58,
    VT_ic_head_ic_scan = 59,
    VT_ic_head_ic_scan_methods = 60,
    VT_ic_head_ic_lastdata = 61,
    VT_ic_head_ic_lastscan = 62,
    VT_ic_head_ic_max_keyix = 63,
    VT_ic_head_ic_sta = 64,
    VT_ic_head_ic_stageq = 65,
    VT_ic_head_ic_hash_key = 66,
    VT_ic_head_ic_wme = 67,
    VT_ic_head_ic_protmode = 68,
    VT_ic_head_ic_htprotmode = 69,
    VT_ic_head_ic_curhtprotmode = 70,
    VT_ic_head_ic_rxstream = 71,
    VT_ic_head_ic_txstream = 72,
    VT_ic_head_ic_vht_flags = 73,
    VT_ic_head_ic_vht_cap = 74,
    VT_ic_head_ic_vhtextcaps = 75,
    VT_ic_head_ic_vht_spare = 76,
    VT_ic_head_ic_superg = 77,
    VT_ic_head_ic_th = 78,
    VT_ic_head_ic_txchan = 79,
    VT_ic_head_ic_rh = 80,
    VT_ic_head_ic_rxchan = 81,
    VT_ic_head_ic_montaps = 82,
    VT_ic_head_ic_vap_create = 83,
    VT_ic_head_ic_vap_delete = 84,
    VT_ic_head_ic_ioctl = 85,
    VT_ic_head_ic_parent = 86,
    VT_ic_head_ic_vattach = 87,
    VT_ic_head_ic_getradiocaps = 88,
    VT_ic_head_ic_setregdomain = 89,
    VT_ic_head_ic_set_quiet = 90,
    VT_ic_head_ic_transmit = 91,
    VT_ic_head_ic_send_mgmt = 92,
    VT_ic_head_ic_raw_xmit = 93,
    VT_ic_head_ic_updateslot = 94,
    VT_ic_head_ic_update_mcast = 95,
    VT_ic_head_ic_update_promisc = 96,
    VT_ic_head_ic_newassoc = 97,
    VT_ic_head_ic_tdma_update = 98,
    VT_ic_head_ic_node_alloc = 99,
    VT_ic_head_ic_node_init = 100,
    VT_ic_head_ic_node_free = 101,
    VT_ic_head_ic_node_cleanup = 102,
    VT_ic_head_ic_node_age = 103,
    VT_ic_head_ic_node_drain = 104,
    VT_ic_head_ic_node_getrssi = 105,
    VT_ic_head_ic_node_getsignal = 106,
    VT_ic_head_ic_node_getmimoinfo = 107,
    VT_ic_head_ic_scan_start = 108,
    VT_ic_head_ic_scan_end = 109,
    VT_ic_head_ic_set_channel = 110,
    VT_ic_head_ic_scan_curchan = 111,
    VT_ic_head_ic_scan_mindwell = 112,
    VT_ic_head_ic_recv_action = 113,
    VT_ic_head_ic_send_action = 114,
    VT_ic_head_ic_ampdu_enable = 115,
    VT_ic_head_ic_addba_request = 116,
    VT_ic_head_ic_addba_response = 117,
    VT_ic_head_ic_addba_stop = 118,
    VT_ic_head_ic_addba_response_timeout = 119,
    VT_ic_head_ic_bar_response = 120,
    VT_ic_head_ic_ampdu_rx_start = 121,
    VT_ic_head_ic_ampdu_rx_stop = 122,
    VT_ic_head_ic_update_chw = 123,
    VT_ic_head_ic_debugnet_meth = 124,
    VT_ic_head_ic_spare = 125,
    VT_ic_head_NUM_COLUMNS
};

static int
copy_columns(struct ic_head *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_ic_head_ic_softc] =  TODO: Handle other types
    columns[VT_ic_head_ic_name] = new_osdb_text(curEntry->ic_name, strlen(curEntry->ic_name) + 1, context);
//    columns[VT_ic_head_ic_comlock] =  TODO: Handle other types
//    columns[VT_ic_head_ic_txlock] =  TODO: Handle other types
//    columns[VT_ic_head_ic_fflock] =  TODO: Handle other types
//    columns[VT_ic_head_ic_next] =  TODO: Handle other types
//    columns[VT_ic_head_ic_vaps] =  TODO: Handle other types
    columns[VT_ic_head_ic_headroom] = new_osdb_int64(curEntry->ic_headroom, context);
    columns[VT_ic_head_ic_phytype] = new_osdb_int64(static_cast<int64_t>(curEntry->ic_phytype), context); // TODO: need better enum representation 
    columns[VT_ic_head_ic_opmode] = new_osdb_int64(static_cast<int64_t>(curEntry->ic_opmode), context); // TODO: need better enum representation 
//    columns[VT_ic_head_ic_inact] =  TODO: Handle other types
//    columns[VT_ic_head_ic_tq] =  TODO: Handle other types
//    columns[VT_ic_head_ic_parent_task] =  TODO: Handle other types
//    columns[VT_ic_head_ic_promisc_task] =  TODO: Handle other types
//    columns[VT_ic_head_ic_mcast_task] =  TODO: Handle other types
//    columns[VT_ic_head_ic_chan_task] =  TODO: Handle other types
//    columns[VT_ic_head_ic_bmiss_task] =  TODO: Handle other types
//    columns[VT_ic_head_ic_chw_task] =  TODO: Handle other types
//    columns[VT_ic_head_ic_restart_task] =  TODO: Handle other types
//    columns[VT_ic_head_ic_ierrors] =  TODO: Handle other types
//    columns[VT_ic_head_ic_oerrors] =  TODO: Handle other types
    columns[VT_ic_head_ic_flags] = new_osdb_int64(curEntry->ic_flags, context);
    columns[VT_ic_head_ic_flags_ext] = new_osdb_int64(curEntry->ic_flags_ext, context);
    columns[VT_ic_head_ic_flags_ht] = new_osdb_int64(curEntry->ic_flags_ht, context);
    columns[VT_ic_head_ic_flags_ven] = new_osdb_int64(curEntry->ic_flags_ven, context);
    columns[VT_ic_head_ic_caps] = new_osdb_int64(curEntry->ic_caps, context);
    columns[VT_ic_head_ic_htcaps] = new_osdb_int64(curEntry->ic_htcaps, context);
    columns[VT_ic_head_ic_htextcaps] = new_osdb_int64(curEntry->ic_htextcaps, context);
    columns[VT_ic_head_ic_sw_cryptocaps] = new_osdb_int64(curEntry->ic_sw_cryptocaps, context);
    columns[VT_ic_head_ic_cryptocaps] = new_osdb_int64(curEntry->ic_cryptocaps, context);
    columns[VT_ic_head_ic_sw_keymgmtcaps] = new_osdb_int64(curEntry->ic_sw_keymgmtcaps, context);
//    columns[VT_ic_head_ic_modecaps] =  TODO: Handle other types
    columns[VT_ic_head_ic_promisc] = new_osdb_int64(curEntry->ic_promisc, context);
    columns[VT_ic_head_ic_allmulti] = new_osdb_int64(curEntry->ic_allmulti, context);
    columns[VT_ic_head_ic_nrunning] = new_osdb_int64(curEntry->ic_nrunning, context);
    columns[VT_ic_head_ic_curmode] = new_osdb_int64(curEntry->ic_curmode, context);
//    columns[VT_ic_head_ic_macaddr] =  TODO: Handle other types
    columns[VT_ic_head_ic_bintval] = new_osdb_int64(curEntry->ic_bintval, context);
    columns[VT_ic_head_ic_lintval] = new_osdb_int64(curEntry->ic_lintval, context);
    columns[VT_ic_head_ic_holdover] = new_osdb_int64(curEntry->ic_holdover, context);
    columns[VT_ic_head_ic_txpowlimit] = new_osdb_int64(curEntry->ic_txpowlimit, context);
//    columns[VT_ic_head_ic_sup_rates] =  TODO: Handle other types
//    columns[VT_ic_head_ic_sup_htrates] =  TODO: Handle other types
    columns[VT_ic_head_ic_nchans] = new_osdb_int64(curEntry->ic_nchans, context);
//    columns[VT_ic_head_ic_channels] =  TODO: Handle other types
//    columns[VT_ic_head_ic_chan_avail] =  TODO: Handle other types
//    columns[VT_ic_head_ic_chan_active] =  TODO: Handle other types
//    columns[VT_ic_head_ic_chan_scan] =  TODO: Handle other types
//    columns[VT_ic_head_ic_curchan] =  TODO: Handle other types
//    columns[VT_ic_head_ic_rt] =  TODO: Handle other types
//    columns[VT_ic_head_ic_bsschan] =  TODO: Handle other types
//    columns[VT_ic_head_ic_prevchan] =  TODO: Handle other types
//    columns[VT_ic_head_ic_regdomain] =  TODO: Handle other types
//    columns[VT_ic_head_ic_countryie] =  TODO: Handle other types
//    columns[VT_ic_head_ic_countryie_chan] =  TODO: Handle other types
//    columns[VT_ic_head_ic_csa_newchan] =  TODO: Handle other types
    columns[VT_ic_head_ic_csa_mode] = new_osdb_int64(curEntry->ic_csa_mode, context);
    columns[VT_ic_head_ic_csa_count] = new_osdb_int64(curEntry->ic_csa_count, context);
//    columns[VT_ic_head_ic_dfs] =  TODO: Handle other types
//    columns[VT_ic_head_ic_scan] =  TODO: Handle other types
//    columns[VT_ic_head_ic_scan_methods] =  TODO: Handle other types
    columns[VT_ic_head_ic_lastdata] = new_osdb_int64(curEntry->ic_lastdata, context);
    columns[VT_ic_head_ic_lastscan] = new_osdb_int64(curEntry->ic_lastscan, context);
    columns[VT_ic_head_ic_max_keyix] = new_osdb_int64(curEntry->ic_max_keyix, context);
//    columns[VT_ic_head_ic_sta] =  TODO: Handle other types
//    columns[VT_ic_head_ic_stageq] =  TODO: Handle other types
    columns[VT_ic_head_ic_hash_key] = new_osdb_int64(curEntry->ic_hash_key, context);
//    columns[VT_ic_head_ic_wme] =  TODO: Handle other types
    columns[VT_ic_head_ic_protmode] = new_osdb_int64(static_cast<int64_t>(curEntry->ic_protmode), context); // TODO: need better enum representation 
    columns[VT_ic_head_ic_htprotmode] = new_osdb_int64(static_cast<int64_t>(curEntry->ic_htprotmode), context); // TODO: need better enum representation 
    columns[VT_ic_head_ic_curhtprotmode] = new_osdb_int64(curEntry->ic_curhtprotmode, context);
    columns[VT_ic_head_ic_rxstream] = new_osdb_int64(curEntry->ic_rxstream, context);
    columns[VT_ic_head_ic_txstream] = new_osdb_int64(curEntry->ic_txstream, context);
    columns[VT_ic_head_ic_vht_flags] = new_osdb_int64(curEntry->ic_vht_flags, context);
//    columns[VT_ic_head_ic_vht_cap] =  TODO: Handle other types
    columns[VT_ic_head_ic_vhtextcaps] = new_osdb_int64(curEntry->ic_vhtextcaps, context);
//    columns[VT_ic_head_ic_vht_spare] =  TODO: Handle other types
//    columns[VT_ic_head_ic_superg] =  TODO: Handle other types
//    columns[VT_ic_head_ic_th] =  TODO: Handle other types
//    columns[VT_ic_head_ic_txchan] =  TODO: Handle other types
//    columns[VT_ic_head_ic_rh] =  TODO: Handle other types
//    columns[VT_ic_head_ic_rxchan] =  TODO: Handle other types
    columns[VT_ic_head_ic_montaps] = new_osdb_int64(curEntry->ic_montaps, context);
//    columns[VT_ic_head_ic_vap_create] =  TODO: Handle other types
//    columns[VT_ic_head_ic_vap_delete] =  TODO: Handle other types
//    columns[VT_ic_head_ic_ioctl] =  TODO: Handle other types
//    columns[VT_ic_head_ic_parent] =  TODO: Handle other types
//    columns[VT_ic_head_ic_vattach] =  TODO: Handle other types
//    columns[VT_ic_head_ic_getradiocaps] =  TODO: Handle other types
//    columns[VT_ic_head_ic_setregdomain] =  TODO: Handle other types
//    columns[VT_ic_head_ic_set_quiet] =  TODO: Handle other types
//    columns[VT_ic_head_ic_transmit] =  TODO: Handle other types
//    columns[VT_ic_head_ic_send_mgmt] =  TODO: Handle other types
//    columns[VT_ic_head_ic_raw_xmit] =  TODO: Handle other types
//    columns[VT_ic_head_ic_updateslot] =  TODO: Handle other types
//    columns[VT_ic_head_ic_update_mcast] =  TODO: Handle other types
//    columns[VT_ic_head_ic_update_promisc] =  TODO: Handle other types
//    columns[VT_ic_head_ic_newassoc] =  TODO: Handle other types
//    columns[VT_ic_head_ic_tdma_update] =  TODO: Handle other types
//    columns[VT_ic_head_ic_node_alloc] =  TODO: Handle other types
//    columns[VT_ic_head_ic_node_init] =  TODO: Handle other types
//    columns[VT_ic_head_ic_node_free] =  TODO: Handle other types
//    columns[VT_ic_head_ic_node_cleanup] =  TODO: Handle other types
//    columns[VT_ic_head_ic_node_age] =  TODO: Handle other types
//    columns[VT_ic_head_ic_node_drain] =  TODO: Handle other types
//    columns[VT_ic_head_ic_node_getrssi] =  TODO: Handle other types
//    columns[VT_ic_head_ic_node_getsignal] =  TODO: Handle other types
//    columns[VT_ic_head_ic_node_getmimoinfo] =  TODO: Handle other types
//    columns[VT_ic_head_ic_scan_start] =  TODO: Handle other types
//    columns[VT_ic_head_ic_scan_end] =  TODO: Handle other types
//    columns[VT_ic_head_ic_set_channel] =  TODO: Handle other types
//    columns[VT_ic_head_ic_scan_curchan] =  TODO: Handle other types
//    columns[VT_ic_head_ic_scan_mindwell] =  TODO: Handle other types
//    columns[VT_ic_head_ic_recv_action] =  TODO: Handle other types
//    columns[VT_ic_head_ic_send_action] =  TODO: Handle other types
//    columns[VT_ic_head_ic_ampdu_enable] =  TODO: Handle other types
//    columns[VT_ic_head_ic_addba_request] =  TODO: Handle other types
//    columns[VT_ic_head_ic_addba_response] =  TODO: Handle other types
//    columns[VT_ic_head_ic_addba_stop] =  TODO: Handle other types
//    columns[VT_ic_head_ic_addba_response_timeout] =  TODO: Handle other types
//    columns[VT_ic_head_ic_bar_response] =  TODO: Handle other types
//    columns[VT_ic_head_ic_ampdu_rx_start] =  TODO: Handle other types
//    columns[VT_ic_head_ic_ampdu_rx_stop] =  TODO: Handle other types
//    columns[VT_ic_head_ic_update_chw] =  TODO: Handle other types
//    columns[VT_ic_head_ic_debugnet_meth] =  TODO: Handle other types
//    columns[VT_ic_head_ic_spare] =  TODO: Handle other types

    return 0;
}
void
vtab__lock(void)
{
    sx_slock(&ic_head_lock);
}

void
vtab__unlock(void)
{
    sx_sunlock(&ic_head_lock);
}

void
vtab__snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct  *prc = LIST_FIRST(&ic_head);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ic_head_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_ic_head_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf(" digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab__rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_ic_head_PID];
    *pRowid = pid_value->int64_value;
    printf("_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab__bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab__update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab__snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf(" digest mismatch: UPDATE failed\n");
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
static sqlite3_module vtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vtabRowid,
    /* xUpdate     */ vtabUpdate,
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
sqlite3_vtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vtabModule,
        pAux);
}
