#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ath_tid.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ath_tid.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_axq_tidq_tid_q = 0,
    VT_axq_tidq_an = 1,
    VT_axq_tidq_tid = 2,
    VT_axq_tidq_ac = 3,
    VT_axq_tidq_hwq_depth = 4,
    VT_axq_tidq_axq_depth = 5,
    VT_axq_tidq_filtq = 6,
    VT_axq_tidq_axq_qelem = 7,
    VT_axq_tidq_sched = 8,
    VT_axq_tidq_paused = 9,
    VT_axq_tidq_addba_tx_pending = 10,
    VT_axq_tidq_bar_wait = 11,
    VT_axq_tidq_bar_tx = 12,
    VT_axq_tidq_isfiltered = 13,
    VT_axq_tidq_cleanup_inprogress = 14,
    VT_axq_tidq_incomp = 15,
    VT_axq_tidq_tx_buf = 16,
    VT_axq_tidq_baw_head = 17,
    VT_axq_tidq_baw_tail = 18,
    VT_axq_tidq_NUM_COLUMNS
};

static int
copy_columns(struct ath_tid *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_axq_tidq_tid_q] =  /* Unsupported type */
    columns[VT_axq_tidq_an] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->an, context);
    columns[VT_axq_tidq_tid] = new_dbsc_int64(curEntry->tid, context);
    columns[VT_axq_tidq_ac] = new_dbsc_int64(curEntry->ac, context);
    columns[VT_axq_tidq_hwq_depth] = new_dbsc_int64(curEntry->hwq_depth, context);
    columns[VT_axq_tidq_axq_depth] = new_dbsc_int64(curEntry->axq_depth, context);
//    columns[VT_axq_tidq_filtq] =  /* Unsupported type */
//    columns[VT_axq_tidq_axq_qelem] =  /* Unsupported type */
    columns[VT_axq_tidq_sched] = new_dbsc_int64(curEntry->sched, context);
    columns[VT_axq_tidq_paused] = new_dbsc_int64(curEntry->paused, context);
    columns[VT_axq_tidq_addba_tx_pending] = new_dbsc_int64(curEntry->addba_tx_pending, context);
    columns[VT_axq_tidq_bar_wait] = new_dbsc_int64(curEntry->bar_wait, context);
    columns[VT_axq_tidq_bar_tx] = new_dbsc_int64(curEntry->bar_tx, context);
    columns[VT_axq_tidq_isfiltered] = new_dbsc_int64(curEntry->isfiltered, context);
    columns[VT_axq_tidq_cleanup_inprogress] = new_dbsc_int64(curEntry->cleanup_inprogress, context);
    columns[VT_axq_tidq_incomp] = new_dbsc_int64(curEntry->incomp, context);
//    columns[VT_axq_tidq_tx_buf] =  /* Unsupported type */
    columns[VT_axq_tidq_baw_head] = new_dbsc_int64(curEntry->baw_head, context);
    columns[VT_axq_tidq_baw_tail] = new_dbsc_int64(curEntry->baw_tail, context);

    return 0;
}
void
vtab_ath_tid_lock(void)
{
    sx_slock(&axq_tidq_lock);
}

void
vtab_ath_tid_unlock(void)
{
    sx_sunlock(&axq_tidq_lock);
}

void
vtab_ath_tid_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ath_tid *prc = LIST_FIRST(&axq_tidq);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_axq_tidq_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_axq_tidq_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ath_tid digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ath_tidvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_axq_tidq_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ath_tid_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ath_tidvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ath_tidvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ath_tid_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ath_tid digest mismatch: UPDATE failed\n");
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
static sqlite3_module ath_tidvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ath_tidvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ath_tidvtabRowid,
    /* xUpdate     */ ath_tidvtabUpdate,
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
sqlite3_ath_tidvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ath_tidvtabModule,
        pAux);
}
void vtab_ath_tid_serialize(sqlite3 *real_db, struct timespec when) {
    struct ath_tid *entry = LIST_FIRST(&axq_tidq);

    const char *create_stmt =
        "CREATE TABLE all_ath_tids (tid INTEGER, ac INTEGER, hwq_depth INTEGER, axq_depth INTEGER, sched INTEGER, paused INTEGER, addba_tx_pending INTEGER, bar_wait INTEGER, bar_tx INTEGER, isfiltered INTEGER, cleanup_inprogress INTEGER, incomp INTEGER, baw_head INTEGER, baw_tail INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ath_tids VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->tid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ac);
           sqlite3_bind_int64(stmt, bindIndex++, entry->hwq_depth);
           sqlite3_bind_int64(stmt, bindIndex++, entry->axq_depth);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sched);
           sqlite3_bind_int64(stmt, bindIndex++, entry->paused);
           sqlite3_bind_int64(stmt, bindIndex++, entry->addba_tx_pending);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bar_wait);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bar_tx);
           sqlite3_bind_int64(stmt, bindIndex++, entry->isfiltered);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cleanup_inprogress);
           sqlite3_bind_int64(stmt, bindIndex++, entry->incomp);
           sqlite3_bind_int64(stmt, bindIndex++, entry->baw_head);
           sqlite3_bind_int64(stmt, bindIndex++, entry->baw_tail);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

