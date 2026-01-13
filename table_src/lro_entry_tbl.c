#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/lro_entry.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_lro_entry.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_lro_active_next = 0,
    VT_lro_active_hash_next = 1,
    VT_lro_active_m_head = 2,
    VT_lro_active_m_tail = 3,
    VT_lro_active_m_last_mbuf = 4,
    VT_lro_active_outer = 5,
    VT_lro_active_inner = 6,
    VT_lro_active_next_seq = 7,
    VT_lro_active_ack_seq = 8,
    VT_lro_active_tsval = 9,
    VT_lro_active_tsecr = 10,
    VT_lro_active_compressed = 11,
    VT_lro_active_uncompressed = 12,
    VT_lro_active_window = 13,
    VT_lro_active_flags = 14,
    VT_lro_active_timestamp = 15,
    VT_lro_active_needs_merge = 16,
    VT_lro_active_reserved = 17,
    VT_lro_active_alloc_time = 18,
    VT_lro_active_NUM_COLUMNS
};

static int
copy_columns(struct lro_entry *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_lro_active_next] =  /* Unsupported type */
//    columns[VT_lro_active_hash_next] =  /* Unsupported type */
    columns[VT_lro_active_m_head] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->m_head, context);
    columns[VT_lro_active_m_tail] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->m_tail, context);
    columns[VT_lro_active_m_last_mbuf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->m_last_mbuf, context);
//    columns[VT_lro_active_outer] =  /* Unsupported type */
//    columns[VT_lro_active_inner] =  /* Unsupported type */
    columns[VT_lro_active_next_seq] = new_dbsc_int64(curEntry->next_seq, context);
    columns[VT_lro_active_ack_seq] = new_dbsc_int64(curEntry->ack_seq, context);
    columns[VT_lro_active_tsval] = new_dbsc_int64(curEntry->tsval, context);
    columns[VT_lro_active_tsecr] = new_dbsc_int64(curEntry->tsecr, context);
    columns[VT_lro_active_compressed] = new_dbsc_int64(curEntry->compressed, context);
    columns[VT_lro_active_uncompressed] = new_dbsc_int64(curEntry->uncompressed, context);
    columns[VT_lro_active_window] = new_dbsc_int64(curEntry->window, context);
    columns[VT_lro_active_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_lro_active_timestamp] = new_dbsc_int64(curEntry->timestamp, context);
    columns[VT_lro_active_needs_merge] = new_dbsc_int64(curEntry->needs_merge, context);
    columns[VT_lro_active_reserved] = new_dbsc_int64(curEntry->reserved, context);
//    columns[VT_lro_active_alloc_time] =  /* Unsupported type */

    return 0;
}
void
vtab_lro_entry_lock(void)
{
    sx_slock(&lro_active_lock);
}

void
vtab_lro_entry_unlock(void)
{
    sx_sunlock(&lro_active_lock);
}

void
vtab_lro_entry_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct lro_entry *prc = LIST_FIRST(&lro_active);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_lro_active_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_lro_active_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("lro_entry digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
lro_entryvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_lro_active_p_pid];
    *pRowid = pid_value->int64_value;
    printf("lro_entry_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
lro_entryvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
lro_entryvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_lro_entry_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("lro_entry digest mismatch: UPDATE failed\n");
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
static sqlite3_module lro_entryvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ lro_entryvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ lro_entryvtabRowid,
    /* xUpdate     */ lro_entryvtabUpdate,
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
sqlite3_lro_entryvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &lro_entryvtabModule,
        pAux);
}
void vtab_lro_entry_serialize(sqlite3 *real_db, struct timespec when) {
    struct lro_entry *entry = LIST_FIRST(&lro_active);

    const char *create_stmt =
        "CREATE TABLE all_lro_entrys (next_seq INTEGER, ack_seq INTEGER, tsval INTEGER, tsecr INTEGER, compressed INTEGER, uncompressed INTEGER, window INTEGER, flags INTEGER, timestamp INTEGER, needs_merge INTEGER, reserved INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_lro_entrys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->next_seq);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ack_seq);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tsval);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tsecr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->compressed);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uncompressed);
           sqlite3_bind_int64(stmt, bindIndex++, entry->window);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->timestamp);
           sqlite3_bind_int64(stmt, bindIndex++, entry->needs_merge);
           sqlite3_bind_int64(stmt, bindIndex++, entry->reserved);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

