#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/task_struct.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_task_struct.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ts_head_task_thread = 0,
    VT_ts_head_mm = 1,
    VT_ts_head_task_fn = 2,
    VT_ts_head_task_data = 3,
    VT_ts_head_task_ret = 4,
    VT_ts_head_usage = 5,
    VT_ts_head_state = 6,
    VT_ts_head_kthread_flags = 7,
    VT_ts_head_pid = 8,
    VT_ts_head_comm = 9,
    VT_ts_head_bsd_ioctl_data = 10,
    VT_ts_head_bsd_ioctl_len = 11,
    VT_ts_head_parked = 12,
    VT_ts_head_exited = 13,
    VT_ts_head_rcu_entry = 14,
    VT_ts_head_rcu_recurse = 15,
    VT_ts_head_bsd_interrupt_value = 16,
    VT_ts_head_work = 17,
    VT_ts_head_group_leader = 18,
    VT_ts_head_rcu_section = 19,
    VT_ts_head_fpu_ctx_level = 20,
    VT_ts_head_NUM_COLUMNS
};

static int
copy_columns(struct task_struct *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_ts_head_task_thread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->task_thread, context);
    columns[VT_ts_head_mm] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->mm, context);
    columns[VT_ts_head_task_fn] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->task_fn, context);
    columns[VT_ts_head_task_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->task_data, context);
    columns[VT_ts_head_task_ret] = new_dbsc_int64(curEntry->task_ret, context);
//    columns[VT_ts_head_usage] =  /* Unsupported type */
//    columns[VT_ts_head_state] =  /* Unsupported type */
//    columns[VT_ts_head_kthread_flags] =  /* Unsupported type */
    columns[VT_ts_head_pid] = new_dbsc_int64(curEntry->pid, context);
    columns[VT_ts_head_comm] = new_dbsc_text(curEntry->comm, strlen(curEntry->comm) + 1, context);
    columns[VT_ts_head_bsd_ioctl_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bsd_ioctl_data, context);
    columns[VT_ts_head_bsd_ioctl_len] = new_dbsc_int64(curEntry->bsd_ioctl_len, context);
//    columns[VT_ts_head_parked] =  /* Unsupported type */
//    columns[VT_ts_head_exited] =  /* Unsupported type */
//    columns[VT_ts_head_rcu_entry] =  /* Unsupported type */
//    columns[VT_ts_head_rcu_recurse] =  /* Unsupported type */
    columns[VT_ts_head_bsd_interrupt_value] = new_dbsc_int64(curEntry->bsd_interrupt_value, context);
    columns[VT_ts_head_work] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->work, context);
    columns[VT_ts_head_group_leader] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->group_leader, context);
//    columns[VT_ts_head_rcu_section] =  /* Unsupported type */
    columns[VT_ts_head_fpu_ctx_level] = new_dbsc_int64(curEntry->fpu_ctx_level, context);

    return 0;
}
void
vtab_task_struct_lock(void)
{
    sx_slock(&ts_head_lock);
}

void
vtab_task_struct_unlock(void)
{
    sx_sunlock(&ts_head_lock);
}

void
vtab_task_struct_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct task_struct *prc = LIST_FIRST(&ts_head);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ts_head_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_ts_head_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("task_struct digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
task_structvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_ts_head_p_pid];
    *pRowid = pid_value->int64_value;
    printf("task_struct_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
task_structvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
task_structvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_task_struct_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("task_struct digest mismatch: UPDATE failed\n");
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
static sqlite3_module task_structvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ task_structvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ task_structvtabRowid,
    /* xUpdate     */ task_structvtabUpdate,
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
sqlite3_task_structvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &task_structvtabModule,
        pAux);
}
void vtab_task_struct_serialize(sqlite3 *real_db, struct timespec when) {
    struct task_struct *entry = LIST_FIRST(&ts_head);

    const char *create_stmt =
        "CREATE TABLE all_task_structs (task_ret INTEGER, pid INTEGER, comm TEXT, bsd_ioctl_len INTEGER, bsd_interrupt_value INTEGER, fpu_ctx_level INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_task_structs VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->task_ret);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pid);
           sqlite3_bind_text(stmt, bindIndex++, entry->comm, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bsd_ioctl_len);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bsd_interrupt_value);
           sqlite3_bind_int64(stmt, bindIndex++, entry->fpu_ctx_level);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

