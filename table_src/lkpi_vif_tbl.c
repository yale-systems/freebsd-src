#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/lkpi_vif.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_lkpi_vif.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_lvif_head_lvif_entry = 0,
    VT_lvif_head_iv_vap = 1,
    VT_lvif_head_mtx = 2,
    VT_lvif_head_wdev = 3,
    VT_lvif_head_iv_newstate = 4,
    VT_lvif_head_iv_update_bss = 5,
    VT_lvif_head_lsta_head = 6,
    VT_lvif_head_lvif_bss = 7,
    VT_lvif_head_lvif_bss_synched = 8,
    VT_lvif_head_added_to_drv = 9,
    VT_lvif_head_hw_queue_stopped = 10,
    VT_lvif_head_vif = 11,
    VT_lvif_head_NUM_COLUMNS
};

static int
copy_columns(struct lkpi_vif *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_lvif_head_lvif_entry] =  /* Unsupported type */
//    columns[VT_lvif_head_iv_vap] =  /* Unsupported type */
//    columns[VT_lvif_head_mtx] =  /* Unsupported type */
//    columns[VT_lvif_head_wdev] =  /* Unsupported type */
    columns[VT_lvif_head_iv_newstate] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_newstate, context);
    columns[VT_lvif_head_iv_update_bss] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->iv_update_bss, context);
//    columns[VT_lvif_head_lsta_head] =  /* Unsupported type */
    columns[VT_lvif_head_lvif_bss] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lvif_bss, context);
    columns[VT_lvif_head_lvif_bss_synched] = new_dbsc_int64(curEntry->lvif_bss_synched, context);
    columns[VT_lvif_head_added_to_drv] = new_dbsc_int64(curEntry->added_to_drv, context);
//    columns[VT_lvif_head_hw_queue_stopped] =  /* Unsupported type */
//    columns[VT_lvif_head_vif] =  /* Unsupported type */

    return 0;
}
void
vtab_lkpi_vif_lock(void)
{
    sx_slock(&lvif_head_lock);
}

void
vtab_lkpi_vif_unlock(void)
{
    sx_sunlock(&lvif_head_lock);
}

void
vtab_lkpi_vif_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct lkpi_vif *prc = LIST_FIRST(&lvif_head);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_lvif_head_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_lvif_head_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("lkpi_vif digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
lkpi_vifvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_lvif_head_p_pid];
    *pRowid = pid_value->int64_value;
    printf("lkpi_vif_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
lkpi_vifvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
lkpi_vifvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_lkpi_vif_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("lkpi_vif digest mismatch: UPDATE failed\n");
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
static sqlite3_module lkpi_vifvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ lkpi_vifvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ lkpi_vifvtabRowid,
    /* xUpdate     */ lkpi_vifvtabUpdate,
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
sqlite3_lkpi_vifvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &lkpi_vifvtabModule,
        pAux);
}
void vtab_lkpi_vif_serialize(sqlite3 *real_db, struct timespec when) {
    struct lkpi_vif *entry = LIST_FIRST(&lvif_head);

    const char *create_stmt =
        "CREATE TABLE all_lkpi_vifs (lvif_bss_synched INTEGER, added_to_drv INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_lkpi_vifs VALUES (?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->lvif_bss_synched);
           sqlite3_bind_int64(stmt, bindIndex++, entry->added_to_drv);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

