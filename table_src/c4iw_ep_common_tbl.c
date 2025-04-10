#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/c4iw_ep_common.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_c4iw_ep_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_req_list_entry = 0,
    VT_req_list_cm_id = 1,
    VT_req_list_qp = 2,
    VT_req_list_dev = 3,
    VT_req_list_state = 4,
    VT_req_list_kref = 5,
    VT_req_list_mutex = 6,
    VT_req_list_local_addr = 7,
    VT_req_list_remote_addr = 8,
    VT_req_list_wr_wait = 9,
    VT_req_list_flags = 10,
    VT_req_list_history = 11,
    VT_req_list_rpl_err = 12,
    VT_req_list_rpl_done = 13,
    VT_req_list_thread = 14,
    VT_req_list_so = 15,
    VT_req_list_ep_events = 16,
    VT_req_list_NUM_COLUMNS
};

static int
copy_columns(struct c4iw_ep_common *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_req_list_entry] =  /* Unsupported type */
    columns[VT_req_list_cm_id] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cm_id, context);
    columns[VT_req_list_qp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->qp, context);
    columns[VT_req_list_dev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->dev, context);
    columns[VT_req_list_state] = new_dbsc_int64((int64_t)(curEntry->state), context); // TODO: need better enum representation 
//    columns[VT_req_list_kref] =  /* Unsupported type */
//    columns[VT_req_list_mutex] =  /* Unsupported type */
//    columns[VT_req_list_local_addr] =  /* Unsupported type */
//    columns[VT_req_list_remote_addr] =  /* Unsupported type */
//    columns[VT_req_list_wr_wait] =  /* Unsupported type */
    columns[VT_req_list_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_req_list_history] = new_dbsc_int64(curEntry->history, context);
    columns[VT_req_list_rpl_err] = new_dbsc_int64(curEntry->rpl_err, context);
    columns[VT_req_list_rpl_done] = new_dbsc_int64(curEntry->rpl_done, context);
    columns[VT_req_list_thread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->thread, context);
    columns[VT_req_list_so] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->so, context);
    columns[VT_req_list_ep_events] = new_dbsc_int64(curEntry->ep_events, context);

    return 0;
}
void
vtab_c4iw_ep_common_lock(void)
{
    sx_slock(&req_list_lock);
}

void
vtab_c4iw_ep_common_unlock(void)
{
    sx_sunlock(&req_list_lock);
}

void
vtab_c4iw_ep_common_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct c4iw_ep_common *prc = LIST_FIRST(&req_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_req_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_req_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("c4iw_ep_common digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
c4iw_ep_commonvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_req_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("c4iw_ep_common_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
c4iw_ep_commonvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
c4iw_ep_commonvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_c4iw_ep_common_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("c4iw_ep_common digest mismatch: UPDATE failed\n");
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
static sqlite3_module c4iw_ep_commonvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ c4iw_ep_commonvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ c4iw_ep_commonvtabRowid,
    /* xUpdate     */ c4iw_ep_commonvtabUpdate,
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
sqlite3_c4iw_ep_commonvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &c4iw_ep_commonvtabModule,
        pAux);
}
void vtab_c4iw_ep_common_serialize(sqlite3 *real_db, struct timespec when) {
    struct c4iw_ep_common *entry = LIST_FIRST(&req_list);

    const char *create_stmt =
        "CREATE TABLE all_c4iw_ep_commons (state INTEGER, flags INTEGER, history INTEGER, rpl_err INTEGER, rpl_done INTEGER, ep_events INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_c4iw_ep_commons VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->history);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rpl_err);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rpl_done);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ep_events);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

