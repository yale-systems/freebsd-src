#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ctl_backend_driver.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ctl_backend_driver.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_be_list_name = 0,
    VT_be_list_flags = 1,
    VT_be_list_init = 2,
    VT_be_list_shutdown = 3,
    VT_be_list_data_submit = 4,
    VT_be_list_config_read = 5,
    VT_be_list_config_write = 6,
    VT_be_list_ioctl = 7,
    VT_be_list_lun_info = 8,
    VT_be_list_lun_attr = 9,
    VT_be_list_links = 10,
    VT_be_list_NUM_COLUMNS
};

static int
copy_columns(struct ctl_backend_driver *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_be_list_name] =  /* Unsupported type */
    columns[VT_be_list_flags] = new_dbsc_int64((int64_t)(curEntry->flags), context); // TODO: need better enum representation 
    columns[VT_be_list_init] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->init, context);
    columns[VT_be_list_shutdown] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->shutdown, context);
    columns[VT_be_list_data_submit] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->data_submit, context);
    columns[VT_be_list_config_read] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->config_read, context);
    columns[VT_be_list_config_write] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->config_write, context);
    columns[VT_be_list_ioctl] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ioctl, context);
    columns[VT_be_list_lun_info] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lun_info, context);
    columns[VT_be_list_lun_attr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lun_attr, context);
//    columns[VT_be_list_links] =  /* Unsupported type */

    return 0;
}
void
vtab_ctl_backend_driver_lock(void)
{
    sx_slock(&be_list_lock);
}

void
vtab_ctl_backend_driver_unlock(void)
{
    sx_sunlock(&be_list_lock);
}

void
vtab_ctl_backend_driver_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ctl_backend_driver *prc = LIST_FIRST(&be_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_be_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_be_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ctl_backend_driver digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ctl_backend_drivervtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_be_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ctl_backend_driver_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ctl_backend_drivervtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ctl_backend_drivervtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ctl_backend_driver_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ctl_backend_driver digest mismatch: UPDATE failed\n");
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
static sqlite3_module ctl_backend_drivervtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ctl_backend_drivervtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ctl_backend_drivervtabRowid,
    /* xUpdate     */ ctl_backend_drivervtabUpdate,
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
sqlite3_ctl_backend_drivervtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ctl_backend_drivervtabModule,
        pAux);
}
void vtab_ctl_backend_driver_serialize(sqlite3 *real_db, struct timespec when) {
    struct ctl_backend_driver *entry = LIST_FIRST(&be_list);

    const char *create_stmt =
        "CREATE TABLE all_ctl_backend_drivers (flags INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ctl_backend_drivers VALUES (?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

