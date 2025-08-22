#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_tmp_pkt_queue_tval = 0,
    VT_tmp_pkt_queue_direction = 1,
    VT_tmp_pkt_queue_ipver = 2,
    VT_tmp_pkt_queue_lport = 3,
    VT_tmp_pkt_queue_fport = 4,
    VT_tmp_pkt_queue_laddr = 5,
    VT_tmp_pkt_queue_faddr = 6,
    VT_tmp_pkt_queue_snd_cwnd = 7,
    VT_tmp_pkt_queue_snd_wnd = 8,
    VT_tmp_pkt_queue_rcv_wnd = 9,
    VT_tmp_pkt_queue_t_flags2 = 10,
    VT_tmp_pkt_queue_snd_ssthresh = 11,
    VT_tmp_pkt_queue_conn_state = 12,
    VT_tmp_pkt_queue_mss = 13,
    VT_tmp_pkt_queue_srtt = 14,
    VT_tmp_pkt_queue_sack_enabled = 15,
    VT_tmp_pkt_queue_snd_scale = 16,
    VT_tmp_pkt_queue_rcv_scale = 17,
    VT_tmp_pkt_queue_t_flags = 18,
    VT_tmp_pkt_queue_rto = 19,
    VT_tmp_pkt_queue_snd_buf_hiwater = 20,
    VT_tmp_pkt_queue_snd_buf_cc = 21,
    VT_tmp_pkt_queue_rcv_buf_hiwater = 22,
    VT_tmp_pkt_queue_rcv_buf_cc = 23,
    VT_tmp_pkt_queue_sent_inflight_bytes = 24,
    VT_tmp_pkt_queue_t_segqlen = 25,
    VT_tmp_pkt_queue_flowid = 26,
    VT_tmp_pkt_queue_flowtype = 27,
    VT_tmp_pkt_queue_nodes = 28,
    VT_tmp_pkt_queue_NUM_COLUMNS
};

static int
copy_columns(struct tmp_pkt_queue *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_tmp_pkt_queue_tval] =  TODO: Handle other types
    columns[VT_tmp_pkt_queue_direction] = new_osdb_int64(static_cast<int64_t>(curEntry->direction), context); // TODO: need better enum representation 
    columns[VT_tmp_pkt_queue_ipver] = new_osdb_int64(curEntry->ipver, context);
    columns[VT_tmp_pkt_queue_lport] = new_osdb_int64(curEntry->lport, context);
    columns[VT_tmp_pkt_queue_fport] = new_osdb_int64(curEntry->fport, context);
//    columns[VT_tmp_pkt_queue_laddr] =  TODO: Handle other types
//    columns[VT_tmp_pkt_queue_faddr] =  TODO: Handle other types
    columns[VT_tmp_pkt_queue_snd_cwnd] = new_osdb_int64(curEntry->snd_cwnd, context);
    columns[VT_tmp_pkt_queue_snd_wnd] = new_osdb_int64(curEntry->snd_wnd, context);
    columns[VT_tmp_pkt_queue_rcv_wnd] = new_osdb_int64(curEntry->rcv_wnd, context);
    columns[VT_tmp_pkt_queue_t_flags2] = new_osdb_int64(curEntry->t_flags2, context);
    columns[VT_tmp_pkt_queue_snd_ssthresh] = new_osdb_int64(curEntry->snd_ssthresh, context);
    columns[VT_tmp_pkt_queue_conn_state] = new_osdb_int64(curEntry->conn_state, context);
    columns[VT_tmp_pkt_queue_mss] = new_osdb_int64(curEntry->mss, context);
    columns[VT_tmp_pkt_queue_srtt] = new_osdb_int64(curEntry->srtt, context);
    columns[VT_tmp_pkt_queue_sack_enabled] = new_osdb_int64(curEntry->sack_enabled, context);
    columns[VT_tmp_pkt_queue_snd_scale] = new_osdb_int64(curEntry->snd_scale, context);
    columns[VT_tmp_pkt_queue_rcv_scale] = new_osdb_int64(curEntry->rcv_scale, context);
    columns[VT_tmp_pkt_queue_t_flags] = new_osdb_int64(curEntry->t_flags, context);
    columns[VT_tmp_pkt_queue_rto] = new_osdb_int64(curEntry->rto, context);
    columns[VT_tmp_pkt_queue_snd_buf_hiwater] = new_osdb_int64(curEntry->snd_buf_hiwater, context);
    columns[VT_tmp_pkt_queue_snd_buf_cc] = new_osdb_int64(curEntry->snd_buf_cc, context);
    columns[VT_tmp_pkt_queue_rcv_buf_hiwater] = new_osdb_int64(curEntry->rcv_buf_hiwater, context);
    columns[VT_tmp_pkt_queue_rcv_buf_cc] = new_osdb_int64(curEntry->rcv_buf_cc, context);
    columns[VT_tmp_pkt_queue_sent_inflight_bytes] = new_osdb_int64(curEntry->sent_inflight_bytes, context);
    columns[VT_tmp_pkt_queue_t_segqlen] = new_osdb_int64(curEntry->t_segqlen, context);
    columns[VT_tmp_pkt_queue_flowid] = new_osdb_int64(curEntry->flowid, context);
    columns[VT_tmp_pkt_queue_flowtype] = new_osdb_int64(curEntry->flowtype, context);
//    columns[VT_tmp_pkt_queue_nodes] =  TODO: Handle other types

    return 0;
}
void
vtab_pkthead_lock(void)
{
    sx_slock(&tmp_pkt_queue_lock);
}

void
vtab_pkthead_unlock(void)
{
    sx_sunlock(&tmp_pkt_queue_lock);
}

void
vtab_pkthead_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pkthead *prc = LIST_FIRST(&tmp_pkt_queue);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_tmp_pkt_queue_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_tmp_pkt_queue_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pkthead digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_pkthead_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_tmp_pkt_queue_PID];
    *pRowid = pid_value->int64_value;
    printf("pkthead_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_pkthead_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_pkthead_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pkthead_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pkthead digest mismatch: UPDATE failed\n");
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
static sqlite3_module pktheadvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pktheadvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pktheadvtabRowid,
    /* xUpdate     */ pktheadvtabUpdate,
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
sqlite3_pktheadvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pktheadvtabModule,
        pAux);
}
