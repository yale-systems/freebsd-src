#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cdev.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cdev.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_d_devs_si_spare0 = 0,
    VT_d_devs_si_flags = 1,
    VT_d_devs_si_atime = 2,
    VT_d_devs_si_ctime = 3,
    VT_d_devs_si_mtime = 4,
    VT_d_devs_si_uid = 5,
    VT_d_devs_si_gid = 6,
    VT_d_devs_si_mode = 7,
    VT_d_devs_si_cred = 8,
    VT_d_devs_si_drv0 = 9,
    VT_d_devs_si_refcount = 10,
    VT_d_devs_si_list = 11,
    VT_d_devs_si_clone = 12,
    VT_d_devs_si_children = 13,
    VT_d_devs_si_siblings = 14,
    VT_d_devs_si_parent = 15,
    VT_d_devs_si_mountpt = 16,
    VT_d_devs_si_drv1 = 17,
    VT_d_devs_si_drv2 = 18,
    VT_d_devs_si_devsw = 19,
    VT_d_devs_si_iosize_max = 20,
    VT_d_devs_si_usecount = 21,
    VT_d_devs_si_threadcount = 22,
    VT_d_devs___si_u = 23,
    VT_d_devs_si_name = 24,
    VT_d_devs_NUM_COLUMNS
};

static int
copy_columns(struct cdev *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_d_devs_si_spare0] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->si_spare0, context);
    columns[VT_d_devs_si_flags] = new_dbsc_int64(curEntry->si_flags, context);
//    columns[VT_d_devs_si_atime] =  /* Unsupported type */
//    columns[VT_d_devs_si_ctime] =  /* Unsupported type */
//    columns[VT_d_devs_si_mtime] =  /* Unsupported type */
    columns[VT_d_devs_si_uid] = new_dbsc_int64(curEntry->si_uid, context);
    columns[VT_d_devs_si_gid] = new_dbsc_int64(curEntry->si_gid, context);
    columns[VT_d_devs_si_mode] = new_dbsc_int64(curEntry->si_mode, context);
    columns[VT_d_devs_si_cred] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->si_cred, context);
    columns[VT_d_devs_si_drv0] = new_dbsc_int64(curEntry->si_drv0, context);
    columns[VT_d_devs_si_refcount] = new_dbsc_int64(curEntry->si_refcount, context);
//    columns[VT_d_devs_si_list] =  /* Unsupported type */
//    columns[VT_d_devs_si_clone] =  /* Unsupported type */
//    columns[VT_d_devs_si_children] =  /* Unsupported type */
//    columns[VT_d_devs_si_siblings] =  /* Unsupported type */
    columns[VT_d_devs_si_parent] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->si_parent, context);
    columns[VT_d_devs_si_mountpt] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->si_mountpt, context);
    columns[VT_d_devs_si_drv1] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->si_drv1, context);
    columns[VT_d_devs_si_drv2] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->si_drv2, context);
    columns[VT_d_devs_si_devsw] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->si_devsw, context);
    columns[VT_d_devs_si_iosize_max] = new_dbsc_int64(curEntry->si_iosize_max, context);
    columns[VT_d_devs_si_usecount] = new_dbsc_int64(curEntry->si_usecount, context);
    columns[VT_d_devs_si_threadcount] = new_dbsc_int64(curEntry->si_threadcount, context);
//    columns[VT_d_devs___si_u] =  /* Unsupported type */
//    columns[VT_d_devs_si_name] =  /* Unsupported type */

    return 0;
}
void
vtab_cdev_lock(void)
{
    sx_slock(&d_devs_lock);
}

void
vtab_cdev_unlock(void)
{
    sx_sunlock(&d_devs_lock);
}

void
vtab_cdev_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cdev *prc = LIST_FIRST(&d_devs);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_d_devs_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_d_devs_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cdev digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cdevvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_d_devs_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cdev_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cdevvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cdevvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cdev_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cdev digest mismatch: UPDATE failed\n");
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
static sqlite3_module cdevvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cdevvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cdevvtabRowid,
    /* xUpdate     */ cdevvtabUpdate,
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
sqlite3_cdevvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cdevvtabModule,
        pAux);
}
void vtab_cdev_serialize(sqlite3 *real_db, struct timespec when) {
    struct cdev *entry = LIST_FIRST(&d_devs);

    const char *create_stmt =
        "CREATE TABLE all_cdevs (si_flags INTEGER, si_uid INTEGER, si_gid INTEGER, si_mode INTEGER, si_drv0 INTEGER, si_refcount INTEGER, si_iosize_max INTEGER, si_usecount INTEGER, si_threadcount INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cdevs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->si_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->si_uid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->si_gid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->si_mode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->si_drv0);
           sqlite3_bind_int64(stmt, bindIndex++, entry->si_refcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->si_iosize_max);
           sqlite3_bind_int64(stmt, bindIndex++, entry->si_usecount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->si_threadcount);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

