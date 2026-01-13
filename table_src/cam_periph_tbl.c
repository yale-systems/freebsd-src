#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cam_periph.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cam_periph.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_units_periph_start = 0,
    VT_units_periph_oninval = 1,
    VT_units_periph_dtor = 2,
    VT_units_periph_name = 3,
    VT_units_path = 4,
    VT_units_softc = 5,
    VT_units_sim = 6,
    VT_units_unit_number = 7,
    VT_units_type = 8,
    VT_units_flags = 9,
    VT_units_scheduled_priority = 10,
    VT_units_immediate_priority = 11,
    VT_units_periph_allocating = 12,
    VT_units_periph_allocated = 13,
    VT_units_refcount = 14,
    VT_units_ccb_list = 15,
    VT_units_periph_links = 16,
    VT_units_unit_links = 17,
    VT_units_deferred_callback = 18,
    VT_units_deferred_ac = 19,
    VT_units_periph_run_task = 20,
    VT_units_ccb_zone = 21,
    VT_units_periph_rootmount = 22,
    VT_units_NUM_COLUMNS
};

static int
copy_columns(struct cam_periph *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_units_periph_start] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->periph_start, context);
    columns[VT_units_periph_oninval] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->periph_oninval, context);
    columns[VT_units_periph_dtor] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->periph_dtor, context);
    columns[VT_units_periph_name] = new_dbsc_text(curEntry->periph_name, strlen(curEntry->periph_name) + 1, context);
    columns[VT_units_path] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->path, context);
    columns[VT_units_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->softc, context);
    columns[VT_units_sim] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sim, context);
    columns[VT_units_unit_number] = new_dbsc_int64(curEntry->unit_number, context);
    columns[VT_units_type] = new_dbsc_int64((int64_t)(curEntry->type), context); // TODO: need better enum representation 
    columns[VT_units_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_units_scheduled_priority] = new_dbsc_int64(curEntry->scheduled_priority, context);
    columns[VT_units_immediate_priority] = new_dbsc_int64(curEntry->immediate_priority, context);
    columns[VT_units_periph_allocating] = new_dbsc_int64(curEntry->periph_allocating, context);
    columns[VT_units_periph_allocated] = new_dbsc_int64(curEntry->periph_allocated, context);
    columns[VT_units_refcount] = new_dbsc_int64(curEntry->refcount, context);
//    columns[VT_units_ccb_list] =  /* Unsupported type */
//    columns[VT_units_periph_links] =  /* Unsupported type */
//    columns[VT_units_unit_links] =  /* Unsupported type */
    columns[VT_units_deferred_callback] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->deferred_callback, context);
    columns[VT_units_deferred_ac] = new_dbsc_int64((int64_t)(curEntry->deferred_ac), context); // TODO: need better enum representation 
//    columns[VT_units_periph_run_task] =  /* Unsupported type */
    columns[VT_units_ccb_zone] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ccb_zone, context);
//    columns[VT_units_periph_rootmount] =  /* Unsupported type */

    return 0;
}
void
vtab_cam_periph_lock(void)
{
    sx_slock(&units_lock);
}

void
vtab_cam_periph_unlock(void)
{
    sx_sunlock(&units_lock);
}

void
vtab_cam_periph_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cam_periph *prc = LIST_FIRST(&units);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_units_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_units_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cam_periph digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cam_periphvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_units_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cam_periph_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cam_periphvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cam_periphvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cam_periph_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cam_periph digest mismatch: UPDATE failed\n");
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
static sqlite3_module cam_periphvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cam_periphvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cam_periphvtabRowid,
    /* xUpdate     */ cam_periphvtabUpdate,
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
sqlite3_cam_periphvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cam_periphvtabModule,
        pAux);
}
void vtab_cam_periph_serialize(sqlite3 *real_db, struct timespec when) {
    struct cam_periph *entry = LIST_FIRST(&units);

    const char *create_stmt =
        "CREATE TABLE all_cam_periphs (periph_name TEXT, unit_number INTEGER, type INTEGER, flags INTEGER, scheduled_priority INTEGER, immediate_priority INTEGER, periph_allocating INTEGER, periph_allocated INTEGER, refcount INTEGER, deferred_ac INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cam_periphs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->periph_name, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->unit_number);
           sqlite3_bind_int64(stmt, bindIndex++, entry->type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->scheduled_priority);
           sqlite3_bind_int64(stmt, bindIndex++, entry->immediate_priority);
           sqlite3_bind_int64(stmt, bindIndex++, entry->periph_allocating);
           sqlite3_bind_int64(stmt, bindIndex++, entry->periph_allocated);
           sqlite3_bind_int64(stmt, bindIndex++, entry->refcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->deferred_ac);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

