#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/napi_struct.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_napi_struct.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_napi_head_entry = 0,
    VT_napi_head_rx_list = 1,
    VT_napi_head_dev = 2,
    VT_napi_head_poll = 3,
    VT_napi_head_budget = 4,
    VT_napi_head_rx_count = 5,
    VT_napi_head_state = 6,
    VT_napi_head_napi_task = 7,
    VT_napi_head_NUM_COLUMNS
};

static int
copy_columns(struct napi_struct *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_napi_head_entry] =  /* Unsupported type */
//    columns[VT_napi_head_rx_list] =  /* Unsupported type */
    columns[VT_napi_head_dev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->dev, context);
    columns[VT_napi_head_poll] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->poll, context);
    columns[VT_napi_head_budget] = new_dbsc_int64(curEntry->budget, context);
    columns[VT_napi_head_rx_count] = new_dbsc_int64(curEntry->rx_count, context);
    columns[VT_napi_head_state] = new_dbsc_int64(curEntry->state, context);
//    columns[VT_napi_head_napi_task] =  /* Unsupported type */

    return 0;
}
void
vtab_napi_struct_lock(void)
{
    sx_slock(&napi_head_lock);
}

void
vtab_napi_struct_unlock(void)
{
    sx_sunlock(&napi_head_lock);
}

void
vtab_napi_struct_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct napi_struct *prc = LIST_FIRST(&napi_head);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_napi_head_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_napi_head_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("napi_struct digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
napi_structvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_napi_head_p_pid];
    *pRowid = pid_value->int64_value;
    printf("napi_struct_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
napi_structvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
napi_structvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_napi_struct_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("napi_struct digest mismatch: UPDATE failed\n");
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
static sqlite3_module napi_structvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ napi_structvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ napi_structvtabRowid,
    /* xUpdate     */ napi_structvtabUpdate,
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
sqlite3_napi_structvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &napi_structvtabModule,
        pAux);
}
void vtab_napi_struct_serialize(sqlite3 *real_db, struct timespec when) {
    struct napi_struct *entry = LIST_FIRST(&napi_head);

    const char *create_stmt =
        "CREATE TABLE all_napi_structs (budget INTEGER, rx_count INTEGER, state INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_napi_structs VALUES (?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->budget);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rx_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->state);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

