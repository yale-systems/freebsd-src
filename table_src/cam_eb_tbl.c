#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cam_eb.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cam_eb.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_xpt_busses_et_entries = 0,
    VT_xpt_busses_links = 1,
    VT_xpt_busses_path_id = 2,
    VT_xpt_busses_sim = 3,
    VT_xpt_busses_last_reset = 4,
    VT_xpt_busses_flags = 5,
    VT_xpt_busses_refcount = 6,
    VT_xpt_busses_generation = 7,
    VT_xpt_busses_parent_dev = 8,
    VT_xpt_busses_xport = 9,
    VT_xpt_busses_eb_mtx = 10,
    VT_xpt_busses_NUM_COLUMNS
};

static int
copy_columns(struct cam_eb *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_xpt_busses_et_entries] =  /* Unsupported type */
//    columns[VT_xpt_busses_links] =  /* Unsupported type */
    columns[VT_xpt_busses_path_id] = new_dbsc_int64(curEntry->path_id, context);
    columns[VT_xpt_busses_sim] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sim, context);
//    columns[VT_xpt_busses_last_reset] =  /* Unsupported type */
    columns[VT_xpt_busses_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_xpt_busses_refcount] = new_dbsc_int64(curEntry->refcount, context);
    columns[VT_xpt_busses_generation] = new_dbsc_int64(curEntry->generation, context);
    columns[VT_xpt_busses_parent_dev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->parent_dev, context);
    columns[VT_xpt_busses_xport] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xport, context);
//    columns[VT_xpt_busses_eb_mtx] =  /* Unsupported type */

    return 0;
}
void
vtab_cam_eb_lock(void)
{
    sx_slock(&xpt_busses_lock);
}

void
vtab_cam_eb_unlock(void)
{
    sx_sunlock(&xpt_busses_lock);
}

void
vtab_cam_eb_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cam_eb *prc = LIST_FIRST(&xpt_busses);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_xpt_busses_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_xpt_busses_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cam_eb digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cam_ebvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_xpt_busses_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cam_eb_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cam_ebvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cam_ebvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cam_eb_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cam_eb digest mismatch: UPDATE failed\n");
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
static sqlite3_module cam_ebvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cam_ebvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cam_ebvtabRowid,
    /* xUpdate     */ cam_ebvtabUpdate,
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
sqlite3_cam_ebvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cam_ebvtabModule,
        pAux);
}
void vtab_cam_eb_serialize(sqlite3 *real_db, struct timespec when) {
    struct cam_eb *entry = LIST_FIRST(&xpt_busses);

    const char *create_stmt =
        "CREATE TABLE all_cam_ebs (path_id INTEGER, flags INTEGER, refcount INTEGER, generation INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cam_ebs VALUES (?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->path_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->refcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->generation);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

