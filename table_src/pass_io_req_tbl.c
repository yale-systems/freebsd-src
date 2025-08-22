#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/pass_io_req.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_pass_io_req.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_done_queue_ccb = 0,
    VT_done_queue_alloced_ccb = 1,
    VT_done_queue_user_ccb_ptr = 2,
    VT_done_queue_user_periph_links = 3,
    VT_done_queue_user_periph_priv = 4,
    VT_done_queue_mapinfo = 5,
    VT_done_queue_flags = 6,
    VT_done_queue_data_flags = 7,
    VT_done_queue_num_user_segs = 8,
    VT_done_queue_user_segs = 9,
    VT_done_queue_num_kern_segs = 10,
    VT_done_queue_kern_segs = 11,
    VT_done_queue_user_segptr = 12,
    VT_done_queue_kern_segptr = 13,
    VT_done_queue_num_bufs = 14,
    VT_done_queue_dirs = 15,
    VT_done_queue_lengths = 16,
    VT_done_queue_user_bufs = 17,
    VT_done_queue_kern_bufs = 18,
    VT_done_queue_start_time = 19,
    VT_done_queue_links = 20,
    VT_done_queue_NUM_COLUMNS
};

static int
copy_columns(struct pass_io_req *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_done_queue_ccb] =  /* Unsupported type */
    columns[VT_done_queue_alloced_ccb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->alloced_ccb, context);
    columns[VT_done_queue_user_ccb_ptr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->user_ccb_ptr, context);
//    columns[VT_done_queue_user_periph_links] =  /* Unsupported type */
//    columns[VT_done_queue_user_periph_priv] =  /* Unsupported type */
//    columns[VT_done_queue_mapinfo] =  /* Unsupported type */
    columns[VT_done_queue_flags] = new_dbsc_int64((int64_t)(curEntry->flags), context); // TODO: need better enum representation 
    columns[VT_done_queue_data_flags] = new_dbsc_int64((int64_t)(curEntry->data_flags), context); // TODO: need better enum representation 
    columns[VT_done_queue_num_user_segs] = new_dbsc_int64(curEntry->num_user_segs, context);
//    columns[VT_done_queue_user_segs] =  /* Unsupported type */
    columns[VT_done_queue_num_kern_segs] = new_dbsc_int64(curEntry->num_kern_segs, context);
//    columns[VT_done_queue_kern_segs] =  /* Unsupported type */
    columns[VT_done_queue_user_segptr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->user_segptr, context);
    columns[VT_done_queue_kern_segptr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->kern_segptr, context);
    columns[VT_done_queue_num_bufs] = new_dbsc_int64(curEntry->num_bufs, context);
//    columns[VT_done_queue_dirs] =  /* Unsupported type */
//    columns[VT_done_queue_lengths] =  /* Unsupported type */
//    columns[VT_done_queue_user_bufs] =  /* Unsupported type */
//    columns[VT_done_queue_kern_bufs] =  /* Unsupported type */
//    columns[VT_done_queue_start_time] =  /* Unsupported type */
//    columns[VT_done_queue_links] =  /* Unsupported type */

    return 0;
}
void
vtab_pass_io_req_lock(void)
{
    sx_slock(&done_queue_lock);
}

void
vtab_pass_io_req_unlock(void)
{
    sx_sunlock(&done_queue_lock);
}

void
vtab_pass_io_req_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pass_io_req *prc = LIST_FIRST(&done_queue);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_done_queue_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_done_queue_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pass_io_req digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
pass_io_reqvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_done_queue_p_pid];
    *pRowid = pid_value->int64_value;
    printf("pass_io_req_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
pass_io_reqvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
pass_io_reqvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pass_io_req_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pass_io_req digest mismatch: UPDATE failed\n");
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
static sqlite3_module pass_io_reqvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pass_io_reqvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pass_io_reqvtabRowid,
    /* xUpdate     */ pass_io_reqvtabUpdate,
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
sqlite3_pass_io_reqvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pass_io_reqvtabModule,
        pAux);
}
void vtab_pass_io_req_serialize(sqlite3 *real_db, struct timespec when) {
    struct pass_io_req *entry = LIST_FIRST(&done_queue);

    const char *create_stmt =
        "CREATE TABLE all_pass_io_reqs (flags INTEGER, data_flags INTEGER, num_user_segs INTEGER, num_kern_segs INTEGER, num_bufs INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_pass_io_reqs VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->data_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->num_user_segs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->num_kern_segs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->num_bufs);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

