#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cryptop.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cryptop.h"

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
copy_columns(struct cryptop *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_crpq_crp_next] =  /* Unsupported type */
//    columns[VT_crpq_crp_task] =  /* Unsupported type */
    columns[VT_crpq_crp_session] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->crp_session, context);
    columns[VT_crpq_crp_olen] = new_dbsc_int64(curEntry->crp_olen, context);
    columns[VT_crpq_crp_etype] = new_dbsc_int64(curEntry->crp_etype, context);
    columns[VT_crpq_crp_flags] = new_dbsc_int64(curEntry->crp_flags, context);
    columns[VT_crpq_crp_op] = new_dbsc_int64(curEntry->crp_op, context);
//    columns[VT_crpq_crp_buf] =  /* Unsupported type */
//    columns[VT_crpq_crp_obuf] =  /* Unsupported type */
    columns[VT_crpq_crp_aad] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->crp_aad, context);
    columns[VT_crpq_crp_aad_start] = new_dbsc_int64(curEntry->crp_aad_start, context);
    columns[VT_crpq_crp_aad_length] = new_dbsc_int64(curEntry->crp_aad_length, context);
//    columns[VT_crpq_crp_esn] =  /* Unsupported type */
    columns[VT_crpq_crp_iv_start] = new_dbsc_int64(curEntry->crp_iv_start, context);
    columns[VT_crpq_crp_payload_start] = new_dbsc_int64(curEntry->crp_payload_start, context);
    columns[VT_crpq_crp_payload_output_start] = new_dbsc_int64(curEntry->crp_payload_output_start, context);
    columns[VT_crpq_crp_payload_length] = new_dbsc_int64(curEntry->crp_payload_length, context);
    columns[VT_crpq_crp_digest_start] = new_dbsc_int64(curEntry->crp_digest_start, context);
//    columns[VT_crpq_crp_iv] =  /* Unsupported type */
    columns[VT_crpq_crp_cipher_key] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->crp_cipher_key, context);
    columns[VT_crpq_crp_auth_key] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->crp_auth_key, context);
    columns[VT_crpq_crp_opaque] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->crp_opaque, context);
    columns[VT_crpq_crp_callback] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->crp_callback, context);
//    columns[VT_crpq_crp_tstamp] =  /* Unsupported type */
    columns[VT_crpq_crp_seq] = new_dbsc_int64(curEntry->crp_seq, context);
    columns[VT_crpq_crp_retw_id] = new_dbsc_int64(curEntry->crp_retw_id, context);

    return 0;
}
void
vtab_cryptop_lock(void)
{
    sx_slock(&crpq_lock);
}

void
vtab_cryptop_unlock(void)
{
    sx_sunlock(&crpq_lock);
}

void
vtab_cryptop_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cryptop *prc = LIST_FIRST(&crpq);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_crpq_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_crpq_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cryptop digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cryptopvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_crpq_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cryptop_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cryptopvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cryptopvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cryptop_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cryptop digest mismatch: UPDATE failed\n");
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
static sqlite3_module cryptopvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cryptopvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cryptopvtabRowid,
    /* xUpdate     */ cryptopvtabUpdate,
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
sqlite3_cryptopvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cryptopvtabModule,
        pAux);
}
void vtab_cryptop_serialize(sqlite3 *real_db, struct timespec when) {
    struct cryptop *entry = LIST_FIRST(&crpq);

    const char *create_stmt =
        "CREATE TABLE all_cryptops (crp_olen INTEGER, crp_etype INTEGER, crp_flags INTEGER, crp_op INTEGER, crp_aad_start INTEGER, crp_aad_length INTEGER, crp_iv_start INTEGER, crp_payload_start INTEGER, crp_payload_output_start INTEGER, crp_payload_length INTEGER, crp_digest_start INTEGER, crp_seq INTEGER, crp_retw_id INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cryptops VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_olen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_etype);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_op);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_aad_start);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_aad_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_iv_start);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_payload_start);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_payload_output_start);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_payload_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_digest_start);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_seq);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crp_retw_id);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

