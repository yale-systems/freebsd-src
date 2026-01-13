#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_tmp_queue_sinfo_stream = 0,
    VT_tmp_queue_sinfo_flags = 1,
    VT_tmp_queue_sinfo_ppid = 2,
    VT_tmp_queue_sinfo_context = 3,
    VT_tmp_queue_sinfo_timetolive = 4,
    VT_tmp_queue_sinfo_tsn = 5,
    VT_tmp_queue_sinfo_cumtsn = 6,
    VT_tmp_queue_sinfo_assoc_id = 7,
    VT_tmp_queue_mid = 8,
    VT_tmp_queue_length = 9,
    VT_tmp_queue_held_length = 10,
    VT_tmp_queue_top_fsn = 11,
    VT_tmp_queue_fsn_included = 12,
    VT_tmp_queue_whoFrom = 13,
    VT_tmp_queue_data = 14,
    VT_tmp_queue_tail_mbuf = 15,
    VT_tmp_queue_aux_data = 16,
    VT_tmp_queue_stcb = 17,
    VT_tmp_queue_next = 18,
    VT_tmp_queue_next_instrm = 19,
    VT_tmp_queue_reasm = 20,
    VT_tmp_queue_port_from = 21,
    VT_tmp_queue_spec_flags = 22,
    VT_tmp_queue_do_not_ref_stcb = 23,
    VT_tmp_queue_end_added = 24,
    VT_tmp_queue_pdapi_aborted = 25,
    VT_tmp_queue_pdapi_started = 26,
    VT_tmp_queue_some_taken = 27,
    VT_tmp_queue_last_frag_seen = 28,
    VT_tmp_queue_first_frag_seen = 29,
    VT_tmp_queue_on_read_q = 30,
    VT_tmp_queue_on_strm_q = 31,
    VT_tmp_queue_NUM_COLUMNS
};

static int
copy_columns(struct tmp_queue *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_tmp_queue_sinfo_stream] = new_osdb_int64(curEntry->sinfo_stream, context);
    columns[VT_tmp_queue_sinfo_flags] = new_osdb_int64(curEntry->sinfo_flags, context);
    columns[VT_tmp_queue_sinfo_ppid] = new_osdb_int64(curEntry->sinfo_ppid, context);
    columns[VT_tmp_queue_sinfo_context] = new_osdb_int64(curEntry->sinfo_context, context);
    columns[VT_tmp_queue_sinfo_timetolive] = new_osdb_int64(curEntry->sinfo_timetolive, context);
    columns[VT_tmp_queue_sinfo_tsn] = new_osdb_int64(curEntry->sinfo_tsn, context);
    columns[VT_tmp_queue_sinfo_cumtsn] = new_osdb_int64(curEntry->sinfo_cumtsn, context);
    columns[VT_tmp_queue_sinfo_assoc_id] = new_osdb_int64(curEntry->sinfo_assoc_id, context);
    columns[VT_tmp_queue_mid] = new_osdb_int64(curEntry->mid, context);
    columns[VT_tmp_queue_length] = new_osdb_int64(curEntry->length, context);
    columns[VT_tmp_queue_held_length] = new_osdb_int64(curEntry->held_length, context);
    columns[VT_tmp_queue_top_fsn] = new_osdb_int64(curEntry->top_fsn, context);
    columns[VT_tmp_queue_fsn_included] = new_osdb_int64(curEntry->fsn_included, context);
//    columns[VT_tmp_queue_whoFrom] =  TODO: Handle other types
//    columns[VT_tmp_queue_data] =  TODO: Handle other types
//    columns[VT_tmp_queue_tail_mbuf] =  TODO: Handle other types
//    columns[VT_tmp_queue_aux_data] =  TODO: Handle other types
//    columns[VT_tmp_queue_stcb] =  TODO: Handle other types
//    columns[VT_tmp_queue_next] =  TODO: Handle other types
//    columns[VT_tmp_queue_next_instrm] =  TODO: Handle other types
//    columns[VT_tmp_queue_reasm] =  TODO: Handle other types
    columns[VT_tmp_queue_port_from] = new_osdb_int64(curEntry->port_from, context);
    columns[VT_tmp_queue_spec_flags] = new_osdb_int64(curEntry->spec_flags, context);
    columns[VT_tmp_queue_do_not_ref_stcb] = new_osdb_int64(curEntry->do_not_ref_stcb, context);
    columns[VT_tmp_queue_end_added] = new_osdb_int64(curEntry->end_added, context);
    columns[VT_tmp_queue_pdapi_aborted] = new_osdb_int64(curEntry->pdapi_aborted, context);
    columns[VT_tmp_queue_pdapi_started] = new_osdb_int64(curEntry->pdapi_started, context);
    columns[VT_tmp_queue_some_taken] = new_osdb_int64(curEntry->some_taken, context);
    columns[VT_tmp_queue_last_frag_seen] = new_osdb_int64(curEntry->last_frag_seen, context);
    columns[VT_tmp_queue_first_frag_seen] = new_osdb_int64(curEntry->first_frag_seen, context);
    columns[VT_tmp_queue_on_read_q] = new_osdb_int64(curEntry->on_read_q, context);
    columns[VT_tmp_queue_on_strm_q] = new_osdb_int64(curEntry->on_strm_q, context);

    return 0;
}
void
vtab_sctp_readhead_lock(void)
{
    sx_slock(&tmp_queue_lock);
}

void
vtab_sctp_readhead_unlock(void)
{
    sx_sunlock(&tmp_queue_lock);
}

void
vtab_sctp_readhead_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct sctp_readhead *prc = LIST_FIRST(&tmp_queue);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_tmp_queue_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_tmp_queue_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("sctp_readhead digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_sctp_readhead_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_tmp_queue_PID];
    *pRowid = pid_value->int64_value;
    printf("sctp_readhead_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_sctp_readhead_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_sctp_readhead_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_sctp_readhead_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("sctp_readhead digest mismatch: UPDATE failed\n");
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
static sqlite3_module sctp_readheadvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ sctp_readheadvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ sctp_readheadvtabRowid,
    /* xUpdate     */ sctp_readheadvtabUpdate,
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
sqlite3_sctp_readheadvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &sctp_readheadvtabModule,
        pAux);
}
