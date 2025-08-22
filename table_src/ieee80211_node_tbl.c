#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ieee80211_node.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ieee80211_node.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_nt_node_ni_vap = 0,
    VT_nt_node_ni_ic = 1,
    VT_nt_node_ni_table = 2,
    VT_nt_node_ni_list = 3,
    VT_nt_node_ni_hash = 4,
    VT_nt_node_ni_refcnt = 5,
    VT_nt_node_ni_flags = 6,
    VT_nt_node_ni_associd = 7,
    VT_nt_node_ni_vlan = 8,
    VT_nt_node_ni_txpower = 9,
    VT_nt_node_ni_authmode = 10,
    VT_nt_node_ni_ath_flags = 11,
    VT_nt_node_ni_ath_defkeyix = 12,
    VT_nt_node_ni_txparms = 13,
    VT_nt_node_ni_jointime = 14,
    VT_nt_node_ni_challenge = 15,
    VT_nt_node_ni_ies = 16,
    VT_nt_node_ni_txseqs = 17,
    VT_nt_node_ni_rxseqs = 18,
    VT_nt_node_ni_rxfragstamp = 19,
    VT_nt_node_ni_rxfrag = 20,
    VT_nt_node_ni_ucastkey = 21,
    VT_nt_node_ni_avgrssi = 22,
    VT_nt_node_ni_noise = 23,
    VT_nt_node_ni_mimo_rssi_ctl = 24,
    VT_nt_node_ni_mimo_rssi_ext = 25,
    VT_nt_node_ni_mimo_noise_ctl = 26,
    VT_nt_node_ni_mimo_noise_ext = 27,
    VT_nt_node_ni_mimo_chains = 28,
    VT_nt_node_ni_macaddr = 29,
    VT_nt_node_ni_bssid = 30,
    VT_nt_node_ni_tstamp = 31,
    VT_nt_node_ni_intval = 32,
    VT_nt_node_ni_capinfo = 33,
    VT_nt_node_ni_esslen = 34,
    VT_nt_node_ni_essid = 35,
    VT_nt_node_ni_rates = 36,
    VT_nt_node_ni_chan = 37,
    VT_nt_node_ni_fhdwell = 38,
    VT_nt_node_ni_fhindex = 39,
    VT_nt_node_ni_erp = 40,
    VT_nt_node_ni_timoff = 41,
    VT_nt_node_ni_dtim_period = 42,
    VT_nt_node_ni_dtim_count = 43,
    VT_nt_node_ni_meshidlen = 44,
    VT_nt_node_ni_meshid = 45,
    VT_nt_node_ni_mlstate = 46,
    VT_nt_node_ni_mllid = 47,
    VT_nt_node_ni_mlpid = 48,
    VT_nt_node_ni_mltimer = 49,
    VT_nt_node_ni_mlrcnt = 50,
    VT_nt_node_ni_mltval = 51,
    VT_nt_node_ni_mlhtimer = 52,
    VT_nt_node_ni_mlhcnt = 53,
    VT_nt_node_ni_htcap = 54,
    VT_nt_node_ni_htparam = 55,
    VT_nt_node_ni_htctlchan = 56,
    VT_nt_node_ni_ht2ndchan = 57,
    VT_nt_node_ni_htopmode = 58,
    VT_nt_node_ni_htstbc = 59,
    VT_nt_node_ni_chw = 60,
    VT_nt_node_ni_htrates = 61,
    VT_nt_node_ni_tx_ampdu = 62,
    VT_nt_node_ni_rx_ampdu = 63,
    VT_nt_node_ni_vhtcap = 64,
    VT_nt_node_ni_vht_basicmcs = 65,
    VT_nt_node_ni_vht_pad2 = 66,
    VT_nt_node_ni_vht_mcsinfo = 67,
    VT_nt_node_ni_vht_chan1 = 68,
    VT_nt_node_ni_vht_chan2 = 69,
    VT_nt_node_ni_vht_chanwidth = 70,
    VT_nt_node_ni_vht_pad1 = 71,
    VT_nt_node_ni_vht_spare = 72,
    VT_nt_node_ni_tx_superg = 73,
    VT_nt_node_ni_inact = 74,
    VT_nt_node_ni_inact_reload = 75,
    VT_nt_node_ni_txrate = 76,
    VT_nt_node_ni_psq = 77,
    VT_nt_node_ni_stats = 78,
    VT_nt_node_ni_wdsvap = 79,
    VT_nt_node_ni_rctls = 80,
    VT_nt_node_ni_quiet_ie_set = 81,
    VT_nt_node_ni_quiet_ie = 82,
    VT_nt_node_ni_uapsd = 83,
    VT_nt_node_ni_drv_data = 84,
    VT_nt_node_ni_spare = 85,
    VT_nt_node_NUM_COLUMNS
};

static int
copy_columns(struct ieee80211_node *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_nt_node_ni_vap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ni_vap, context);
    columns[VT_nt_node_ni_ic] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ni_ic, context);
    columns[VT_nt_node_ni_table] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ni_table, context);
//    columns[VT_nt_node_ni_list] =  /* Unsupported type */
//    columns[VT_nt_node_ni_hash] =  /* Unsupported type */
    columns[VT_nt_node_ni_refcnt] = new_dbsc_int64(curEntry->ni_refcnt, context);
    columns[VT_nt_node_ni_flags] = new_dbsc_int64(curEntry->ni_flags, context);
    columns[VT_nt_node_ni_associd] = new_dbsc_int64(curEntry->ni_associd, context);
    columns[VT_nt_node_ni_vlan] = new_dbsc_int64(curEntry->ni_vlan, context);
    columns[VT_nt_node_ni_txpower] = new_dbsc_int64(curEntry->ni_txpower, context);
    columns[VT_nt_node_ni_authmode] = new_dbsc_int64(curEntry->ni_authmode, context);
    columns[VT_nt_node_ni_ath_flags] = new_dbsc_int64(curEntry->ni_ath_flags, context);
    columns[VT_nt_node_ni_ath_defkeyix] = new_dbsc_int64(curEntry->ni_ath_defkeyix, context);
    columns[VT_nt_node_ni_txparms] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ni_txparms, context);
    columns[VT_nt_node_ni_jointime] = new_dbsc_int64(curEntry->ni_jointime, context);
    columns[VT_nt_node_ni_challenge] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ni_challenge, context);
//    columns[VT_nt_node_ni_ies] =  /* Unsupported type */
//    columns[VT_nt_node_ni_txseqs] =  /* Unsupported type */
//    columns[VT_nt_node_ni_rxseqs] =  /* Unsupported type */
    columns[VT_nt_node_ni_rxfragstamp] = new_dbsc_int64(curEntry->ni_rxfragstamp, context);
//    columns[VT_nt_node_ni_rxfrag] =  /* Unsupported type */
//    columns[VT_nt_node_ni_ucastkey] =  /* Unsupported type */
    columns[VT_nt_node_ni_avgrssi] = new_dbsc_int64(curEntry->ni_avgrssi, context);
    columns[VT_nt_node_ni_noise] = new_dbsc_int64(curEntry->ni_noise, context);
//    columns[VT_nt_node_ni_mimo_rssi_ctl] =  /* Unsupported type */
//    columns[VT_nt_node_ni_mimo_rssi_ext] =  /* Unsupported type */
//    columns[VT_nt_node_ni_mimo_noise_ctl] =  /* Unsupported type */
//    columns[VT_nt_node_ni_mimo_noise_ext] =  /* Unsupported type */
    columns[VT_nt_node_ni_mimo_chains] = new_dbsc_int64(curEntry->ni_mimo_chains, context);
//    columns[VT_nt_node_ni_macaddr] =  /* Unsupported type */
//    columns[VT_nt_node_ni_bssid] =  /* Unsupported type */
//    columns[VT_nt_node_ni_tstamp] =  /* Unsupported type */
    columns[VT_nt_node_ni_intval] = new_dbsc_int64(curEntry->ni_intval, context);
    columns[VT_nt_node_ni_capinfo] = new_dbsc_int64(curEntry->ni_capinfo, context);
    columns[VT_nt_node_ni_esslen] = new_dbsc_int64(curEntry->ni_esslen, context);
//    columns[VT_nt_node_ni_essid] =  /* Unsupported type */
//    columns[VT_nt_node_ni_rates] =  /* Unsupported type */
    columns[VT_nt_node_ni_chan] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ni_chan, context);
    columns[VT_nt_node_ni_fhdwell] = new_dbsc_int64(curEntry->ni_fhdwell, context);
    columns[VT_nt_node_ni_fhindex] = new_dbsc_int64(curEntry->ni_fhindex, context);
    columns[VT_nt_node_ni_erp] = new_dbsc_int64(curEntry->ni_erp, context);
    columns[VT_nt_node_ni_timoff] = new_dbsc_int64(curEntry->ni_timoff, context);
    columns[VT_nt_node_ni_dtim_period] = new_dbsc_int64(curEntry->ni_dtim_period, context);
    columns[VT_nt_node_ni_dtim_count] = new_dbsc_int64(curEntry->ni_dtim_count, context);
    columns[VT_nt_node_ni_meshidlen] = new_dbsc_int64(curEntry->ni_meshidlen, context);
//    columns[VT_nt_node_ni_meshid] =  /* Unsupported type */
    columns[VT_nt_node_ni_mlstate] = new_dbsc_int64((int64_t)(curEntry->ni_mlstate), context); // TODO: need better enum representation 
    columns[VT_nt_node_ni_mllid] = new_dbsc_int64(curEntry->ni_mllid, context);
    columns[VT_nt_node_ni_mlpid] = new_dbsc_int64(curEntry->ni_mlpid, context);
//    columns[VT_nt_node_ni_mltimer] =  /* Unsupported type */
    columns[VT_nt_node_ni_mlrcnt] = new_dbsc_int64(curEntry->ni_mlrcnt, context);
    columns[VT_nt_node_ni_mltval] = new_dbsc_int64(curEntry->ni_mltval, context);
//    columns[VT_nt_node_ni_mlhtimer] =  /* Unsupported type */
    columns[VT_nt_node_ni_mlhcnt] = new_dbsc_int64(curEntry->ni_mlhcnt, context);
    columns[VT_nt_node_ni_htcap] = new_dbsc_int64(curEntry->ni_htcap, context);
    columns[VT_nt_node_ni_htparam] = new_dbsc_int64(curEntry->ni_htparam, context);
    columns[VT_nt_node_ni_htctlchan] = new_dbsc_int64(curEntry->ni_htctlchan, context);
    columns[VT_nt_node_ni_ht2ndchan] = new_dbsc_int64(curEntry->ni_ht2ndchan, context);
    columns[VT_nt_node_ni_htopmode] = new_dbsc_int64(curEntry->ni_htopmode, context);
    columns[VT_nt_node_ni_htstbc] = new_dbsc_int64(curEntry->ni_htstbc, context);
    columns[VT_nt_node_ni_chw] = new_dbsc_int64(curEntry->ni_chw, context);
//    columns[VT_nt_node_ni_htrates] =  /* Unsupported type */
//    columns[VT_nt_node_ni_tx_ampdu] =  /* Unsupported type */
//    columns[VT_nt_node_ni_rx_ampdu] =  /* Unsupported type */
    columns[VT_nt_node_ni_vhtcap] = new_dbsc_int64(curEntry->ni_vhtcap, context);
    columns[VT_nt_node_ni_vht_basicmcs] = new_dbsc_int64(curEntry->ni_vht_basicmcs, context);
    columns[VT_nt_node_ni_vht_pad2] = new_dbsc_int64(curEntry->ni_vht_pad2, context);
//    columns[VT_nt_node_ni_vht_mcsinfo] =  /* Unsupported type */
    columns[VT_nt_node_ni_vht_chan1] = new_dbsc_int64(curEntry->ni_vht_chan1, context);
    columns[VT_nt_node_ni_vht_chan2] = new_dbsc_int64(curEntry->ni_vht_chan2, context);
    columns[VT_nt_node_ni_vht_chanwidth] = new_dbsc_int64(curEntry->ni_vht_chanwidth, context);
    columns[VT_nt_node_ni_vht_pad1] = new_dbsc_int64(curEntry->ni_vht_pad1, context);
//    columns[VT_nt_node_ni_vht_spare] =  /* Unsupported type */
//    columns[VT_nt_node_ni_tx_superg] =  /* Unsupported type */
    columns[VT_nt_node_ni_inact] = new_dbsc_int64(curEntry->ni_inact, context);
    columns[VT_nt_node_ni_inact_reload] = new_dbsc_int64(curEntry->ni_inact_reload, context);
    columns[VT_nt_node_ni_txrate] = new_dbsc_int64(curEntry->ni_txrate, context);
//    columns[VT_nt_node_ni_psq] =  /* Unsupported type */
//    columns[VT_nt_node_ni_stats] =  /* Unsupported type */
    columns[VT_nt_node_ni_wdsvap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ni_wdsvap, context);
    columns[VT_nt_node_ni_rctls] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ni_rctls, context);
    columns[VT_nt_node_ni_quiet_ie_set] = new_dbsc_int64(curEntry->ni_quiet_ie_set, context);
//    columns[VT_nt_node_ni_quiet_ie] =  /* Unsupported type */
    columns[VT_nt_node_ni_uapsd] = new_dbsc_int64(curEntry->ni_uapsd, context);
    columns[VT_nt_node_ni_drv_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ni_drv_data, context);
//    columns[VT_nt_node_ni_spare] =  /* Unsupported type */

    return 0;
}
void
vtab_ieee80211_node_lock(void)
{
    sx_slock(&nt_node_lock);
}

void
vtab_ieee80211_node_unlock(void)
{
    sx_sunlock(&nt_node_lock);
}

void
vtab_ieee80211_node_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ieee80211_node *prc = LIST_FIRST(&nt_node);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_nt_node_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_nt_node_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ieee80211_node digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ieee80211_nodevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_nt_node_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ieee80211_node_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ieee80211_nodevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ieee80211_nodevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ieee80211_node_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ieee80211_node digest mismatch: UPDATE failed\n");
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
static sqlite3_module ieee80211_nodevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ieee80211_nodevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ieee80211_nodevtabRowid,
    /* xUpdate     */ ieee80211_nodevtabUpdate,
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
sqlite3_ieee80211_nodevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ieee80211_nodevtabModule,
        pAux);
}
void vtab_ieee80211_node_serialize(sqlite3 *real_db, struct timespec when) {
    struct ieee80211_node *entry = LIST_FIRST(&nt_node);

    const char *create_stmt =
        "CREATE TABLE all_ieee80211_nodes (ni_refcnt INTEGER, ni_flags INTEGER, ni_associd INTEGER, ni_vlan INTEGER, ni_txpower INTEGER, ni_authmode INTEGER, ni_ath_flags INTEGER, ni_ath_defkeyix INTEGER, ni_jointime INTEGER, ni_rxfragstamp INTEGER, ni_avgrssi INTEGER, ni_noise INTEGER, ni_mimo_chains INTEGER, ni_intval INTEGER, ni_capinfo INTEGER, ni_esslen INTEGER, ni_fhdwell INTEGER, ni_fhindex INTEGER, ni_erp INTEGER, ni_timoff INTEGER, ni_dtim_period INTEGER, ni_dtim_count INTEGER, ni_meshidlen INTEGER, ni_mlstate INTEGER, ni_mllid INTEGER, ni_mlpid INTEGER, ni_mlrcnt INTEGER, ni_mltval INTEGER, ni_mlhcnt INTEGER, ni_htcap INTEGER, ni_htparam INTEGER, ni_htctlchan INTEGER, ni_ht2ndchan INTEGER, ni_htopmode INTEGER, ni_htstbc INTEGER, ni_chw INTEGER, ni_vhtcap INTEGER, ni_vht_basicmcs INTEGER, ni_vht_pad2 INTEGER, ni_vht_chan1 INTEGER, ni_vht_chan2 INTEGER, ni_vht_chanwidth INTEGER, ni_vht_pad1 INTEGER, ni_inact INTEGER, ni_inact_reload INTEGER, ni_txrate INTEGER, ni_quiet_ie_set INTEGER, ni_uapsd INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ieee80211_nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_refcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_associd);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_vlan);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_txpower);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_authmode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_ath_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_ath_defkeyix);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_jointime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_rxfragstamp);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_avgrssi);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_noise);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_mimo_chains);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_intval);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_capinfo);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_esslen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_fhdwell);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_fhindex);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_erp);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_timoff);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_dtim_period);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_dtim_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_meshidlen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_mlstate);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_mllid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_mlpid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_mlrcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_mltval);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_mlhcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_htcap);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_htparam);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_htctlchan);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_ht2ndchan);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_htopmode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_htstbc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_chw);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_vhtcap);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_vht_basicmcs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_vht_pad2);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_vht_chan1);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_vht_chan2);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_vht_chanwidth);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_vht_pad1);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_inact);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_inact_reload);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_txrate);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_quiet_ie_set);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ni_uapsd);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

