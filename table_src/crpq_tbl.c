#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_crpq_crp_next = 0,
    VT_crpq_crp_task = 1,
    VT_crpq_crp_session = 2,
    VT_crpq_crp_olen = 3,
    VT_crpq_crp_etype = 4,
    VT_crpq_crp_flags = 5,
    VT_crpq_crp_op = 6,
    VT_crpq_crp_buf = 7,
    VT_crpq_crp_obuf = 8,
    VT_crpq_crp_aad = 9,
    VT_crpq_crp_aad_start = 10,
    VT_crpq_crp_aad_length = 11,
    VT_crpq_crp_esn = 12,
    VT_crpq_crp_iv_start = 13,
    VT_crpq_crp_payload_start = 14,
    VT_crpq_crp_payload_output_start = 15,
    VT_crpq_crp_payload_length = 16,
    VT_crpq_crp_digest_start = 17,
    VT_crpq_crp_iv = 18,
    VT_crpq_crp_cipher_key = 19,
    VT_crpq_crp_auth_key = 20,
    VT_crpq_crp_opaque = 21,
    VT_crpq_crp_callback = 22,
    VT_crpq_crp_tstamp = 23,
    VT_crpq_crp_seq = 24,
    VT_crpq_crp_retw_id = 25,
    VT_crpq_NUM_COLUMNS
};

static int
copy_columns(struct crpq *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_crpq_crp_next] =  TODO: Handle other types
//    columns[VT_crpq_crp_task] =  TODO: Handle other types
//    columns[VT_crpq_crp_session] =  TODO: Handle other types
    columns[VT_crpq_crp_olen] = new_osdb_int64(curEntry->crp_olen, context);
    columns[VT_crpq_crp_etype] = new_osdb_int64(curEntry->crp_etype, context);
    columns[VT_crpq_crp_flags] = new_osdb_int64(curEntry->crp_flags, context);
    columns[VT_crpq_crp_op] = new_osdb_int64(curEntry->crp_op, context);
//    columns[VT_crpq_crp_buf] =  TODO: Handle other types
//    columns[VT_crpq_crp_obuf] =  TODO: Handle other types
//    columns[VT_crpq_crp_aad] =  TODO: Handle other types
    columns[VT_crpq_crp_aad_start] = new_osdb_int64(curEntry->crp_aad_start, context);
    columns[VT_crpq_crp_aad_length] = new_osdb_int64(curEntry->crp_aad_length, context);
//    columns[VT_crpq_crp_esn] =  TODO: Handle other types
    columns[VT_crpq_crp_iv_start] = new_osdb_int64(curEntry->crp_iv_start, context);
    columns[VT_crpq_crp_payload_start] = new_osdb_int64(curEntry->crp_payload_start, context);
    columns[VT_crpq_crp_payload_output_start] = new_osdb_int64(curEntry->crp_payload_output_start, context);
    columns[VT_crpq_crp_payload_length] = new_osdb_int64(curEntry->crp_payload_length, context);
    columns[VT_crpq_crp_digest_start] = new_osdb_int64(curEntry->crp_digest_start, context);
//    columns[VT_crpq_crp_iv] =  TODO: Handle other types
//    columns[VT_crpq_crp_cipher_key] =  TODO: Handle other types
//    columns[VT_crpq_crp_auth_key] =  TODO: Handle other types
//    columns[VT_crpq_crp_opaque] =  TODO: Handle other types
//    columns[VT_crpq_crp_callback] =  TODO: Handle other types
//    columns[VT_crpq_crp_tstamp] =  TODO: Handle other types
    columns[VT_crpq_crp_seq] = new_osdb_int64(curEntry->crp_seq, context);
    columns[VT_crpq_crp_retw_id] = new_osdb_int64(curEntry->crp_retw_id, context);

    return 0;
}
void
vtab_cryptopq_lock(void)
{
    sx_slock(&crpq_lock);
}

void
vtab_cryptopq_unlock(void)
{
    sx_sunlock(&crpq_lock);
}

void
vtab_cryptopq_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cryptopq *prc = LIST_FIRST(&crpq);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_crpq_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_crpq_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cryptopq digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_cryptopq_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_crpq_PID];
    *pRowid = pid_value->int64_value;
    printf("cryptopq_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_cryptopq_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_cryptopq_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cryptopq_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cryptopq digest mismatch: UPDATE failed\n");
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
static sqlite3_module cryptopqvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cryptopqvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cryptopqvtabRowid,
    /* xUpdate     */ cryptopqvtabUpdate,
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
sqlite3_cryptopqvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cryptopqvtabModule,
        pAux);
}
