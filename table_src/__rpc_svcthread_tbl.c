#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/__rpc_svcthread.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab___rpc_svcthread.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sg_idlethreads_st_lock = 0,
    VT_sg_idlethreads_st_pool = 1,
    VT_sg_idlethreads_st_xprt = 2,
    VT_sg_idlethreads_st_reqs = 3,
    VT_sg_idlethreads_st_cond = 4,
    VT_sg_idlethreads_st_ilink = 5,
    VT_sg_idlethreads_st_alink = 6,
    VT_sg_idlethreads_st_p2 = 7,
    VT_sg_idlethreads_st_p3 = 8,
    VT_sg_idlethreads_NUM_COLUMNS
};

static int
copy_columns(struct __rpc_svcthread *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_sg_idlethreads_st_lock] =  /* Unsupported type */
    columns[VT_sg_idlethreads_st_pool] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->st_pool, context);
    columns[VT_sg_idlethreads_st_xprt] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->st_xprt, context);
//    columns[VT_sg_idlethreads_st_reqs] =  /* Unsupported type */
//    columns[VT_sg_idlethreads_st_cond] =  /* Unsupported type */
//    columns[VT_sg_idlethreads_st_ilink] =  /* Unsupported type */
//    columns[VT_sg_idlethreads_st_alink] =  /* Unsupported type */
    columns[VT_sg_idlethreads_st_p2] = new_dbsc_int64(curEntry->st_p2, context);
    columns[VT_sg_idlethreads_st_p3] = new_dbsc_int64(curEntry->st_p3, context);

    return 0;
}
void
vtab___rpc_svcthread_lock(void)
{
    sx_slock(&sg_idlethreads_lock);
}

void
vtab___rpc_svcthread_unlock(void)
{
    sx_sunlock(&sg_idlethreads_lock);
}

void
vtab___rpc_svcthread_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct __rpc_svcthread *prc = LIST_FIRST(&sg_idlethreads);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sg_idlethreads_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sg_idlethreads_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("__rpc_svcthread digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
__rpc_svcthreadvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sg_idlethreads_p_pid];
    *pRowid = pid_value->int64_value;
    printf("__rpc_svcthread_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
__rpc_svcthreadvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
__rpc_svcthreadvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab___rpc_svcthread_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("__rpc_svcthread digest mismatch: UPDATE failed\n");
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
static sqlite3_module __rpc_svcthreadvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ __rpc_svcthreadvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ __rpc_svcthreadvtabRowid,
    /* xUpdate     */ __rpc_svcthreadvtabUpdate,
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
sqlite3___rpc_svcthreadvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &__rpc_svcthreadvtabModule,
        pAux);
}
void vtab___rpc_svcthread_serialize(sqlite3 *real_db, struct timespec when) {
    struct __rpc_svcthread *entry = LIST_FIRST(&sg_idlethreads);

    const char *create_stmt =
        "CREATE TABLE all___rpc_svcthreads (st_p2 INTEGER, st_p3 INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all___rpc_svcthreads VALUES (?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->st_p2);
           sqlite3_bind_int64(stmt, bindIndex++, entry->st_p3);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

