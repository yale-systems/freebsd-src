#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ctl_be_block_lun.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ctl_be_block_lun.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_lun_list_cbe_lun = 0,
    VT_lun_list_params = 1,
    VT_lun_list_dev_path = 2,
    VT_lun_list_dev_type = 3,
    VT_lun_list_vn = 4,
    VT_lun_list_backend = 5,
    VT_lun_list_dispatch = 6,
    VT_lun_list_lun_flush = 7,
    VT_lun_list_unmap = 8,
    VT_lun_list_get_lba_status = 9,
    VT_lun_list_getattr = 10,
    VT_lun_list_size_blocks = 11,
    VT_lun_list_size_bytes = 12,
    VT_lun_list_softc = 13,
    VT_lun_list_disk_stats = 14,
    VT_lun_list_flags = 15,
    VT_lun_list_links = 16,
    VT_lun_list_io_taskqueue = 17,
    VT_lun_list_io_task = 18,
    VT_lun_list_num_threads = 19,
    VT_lun_list_input_queue = 20,
    VT_lun_list_config_read_queue = 21,
    VT_lun_list_config_write_queue = 22,
    VT_lun_list_datamove_queue = 23,
    VT_lun_list_io_lock = 24,
    VT_lun_list_queue_lock = 25,
    VT_lun_list_NUM_COLUMNS
};

static int
copy_columns(struct ctl_be_block_lun *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_lun_list_cbe_lun] =  /* Unsupported type */
//    columns[VT_lun_list_params] =  /* Unsupported type */
    columns[VT_lun_list_dev_path] = new_dbsc_text(curEntry->dev_path, strlen(curEntry->dev_path) + 1, context);
    columns[VT_lun_list_dev_type] = new_dbsc_int64((int64_t)(curEntry->dev_type), context); // TODO: need better enum representation 
    columns[VT_lun_list_vn] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vn, context);
//    columns[VT_lun_list_backend] =  /* Unsupported type */
    columns[VT_lun_list_dispatch] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->dispatch, context);
    columns[VT_lun_list_lun_flush] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lun_flush, context);
    columns[VT_lun_list_unmap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->unmap, context);
    columns[VT_lun_list_get_lba_status] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->get_lba_status, context);
    columns[VT_lun_list_getattr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->getattr, context);
    columns[VT_lun_list_size_blocks] = new_dbsc_int64(curEntry->size_blocks, context);
    columns[VT_lun_list_size_bytes] = new_dbsc_int64(curEntry->size_bytes, context);
    columns[VT_lun_list_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->softc, context);
    columns[VT_lun_list_disk_stats] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->disk_stats, context);
    columns[VT_lun_list_flags] = new_dbsc_int64((int64_t)(curEntry->flags), context); // TODO: need better enum representation 
//    columns[VT_lun_list_links] =  /* Unsupported type */
    columns[VT_lun_list_io_taskqueue] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->io_taskqueue, context);
//    columns[VT_lun_list_io_task] =  /* Unsupported type */
    columns[VT_lun_list_num_threads] = new_dbsc_int64(curEntry->num_threads, context);
//    columns[VT_lun_list_input_queue] =  /* Unsupported type */
//    columns[VT_lun_list_config_read_queue] =  /* Unsupported type */
//    columns[VT_lun_list_config_write_queue] =  /* Unsupported type */
//    columns[VT_lun_list_datamove_queue] =  /* Unsupported type */
//    columns[VT_lun_list_io_lock] =  /* Unsupported type */
//    columns[VT_lun_list_queue_lock] =  /* Unsupported type */

    return 0;
}
void
vtab_ctl_be_block_lun_lock(void)
{
    sx_slock(&lun_list_lock);
}

void
vtab_ctl_be_block_lun_unlock(void)
{
    sx_sunlock(&lun_list_lock);
}

void
vtab_ctl_be_block_lun_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ctl_be_block_lun *prc = LIST_FIRST(&lun_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_lun_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_lun_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ctl_be_block_lun digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ctl_be_block_lunvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_lun_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ctl_be_block_lun_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ctl_be_block_lunvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ctl_be_block_lunvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ctl_be_block_lun_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ctl_be_block_lun digest mismatch: UPDATE failed\n");
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
static sqlite3_module ctl_be_block_lunvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ctl_be_block_lunvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ctl_be_block_lunvtabRowid,
    /* xUpdate     */ ctl_be_block_lunvtabUpdate,
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
sqlite3_ctl_be_block_lunvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ctl_be_block_lunvtabModule,
        pAux);
}
void vtab_ctl_be_block_lun_serialize(sqlite3 *real_db, struct timespec when) {
    struct ctl_be_block_lun *entry = LIST_FIRST(&lun_list);

    const char *create_stmt =
        "CREATE TABLE all_ctl_be_block_luns (dev_path TEXT, dev_type INTEGER, size_blocks INTEGER, size_bytes INTEGER, flags INTEGER, num_threads INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ctl_be_block_luns VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->dev_path, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->dev_type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->size_blocks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->size_bytes);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->num_threads);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

