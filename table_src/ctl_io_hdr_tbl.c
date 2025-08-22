#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ctl_io_hdr.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ctl_io_hdr.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_blocked_queue_version = 0,
    VT_blocked_queue_io_type = 1,
    VT_blocked_queue_msg_type = 2,
    VT_blocked_queue_nexus = 3,
    VT_blocked_queue_iid_indx = 4,
    VT_blocked_queue_flags = 5,
    VT_blocked_queue_status = 6,
    VT_blocked_queue_port_status = 7,
    VT_blocked_queue_timeout = 8,
    VT_blocked_queue_retries = 9,
    VT_blocked_queue_start_time = 10,
    VT_blocked_queue_start_bt = 11,
    VT_blocked_queue_dma_start_bt = 12,
    VT_blocked_queue_dma_bt = 13,
    VT_blocked_queue_num_dmas = 14,
    VT_blocked_queue_remote_io = 15,
    VT_blocked_queue_blocker = 16,
    VT_blocked_queue_pool = 17,
    VT_blocked_queue_ctl_private = 18,
    VT_blocked_queue_blocked_queue = 19,
    VT_blocked_queue_links = 20,
    VT_blocked_queue_ooa_links = 21,
    VT_blocked_queue_blocked_links = 22,
    VT_blocked_queue_NUM_COLUMNS
};

static int
copy_columns(struct ctl_io_hdr *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_blocked_queue_version] = new_dbsc_int64(curEntry->version, context);
    columns[VT_blocked_queue_io_type] = new_dbsc_int64((int64_t)(curEntry->io_type), context); // TODO: need better enum representation 
    columns[VT_blocked_queue_msg_type] = new_dbsc_int64((int64_t)(curEntry->msg_type), context); // TODO: need better enum representation 
//    columns[VT_blocked_queue_nexus] =  /* Unsupported type */
    columns[VT_blocked_queue_iid_indx] = new_dbsc_int64(curEntry->iid_indx, context);
    columns[VT_blocked_queue_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_blocked_queue_status] = new_dbsc_int64(curEntry->status, context);
    columns[VT_blocked_queue_port_status] = new_dbsc_int64(curEntry->port_status, context);
    columns[VT_blocked_queue_timeout] = new_dbsc_int64(curEntry->timeout, context);
    columns[VT_blocked_queue_retries] = new_dbsc_int64(curEntry->retries, context);
    columns[VT_blocked_queue_start_time] = new_dbsc_int64(curEntry->start_time, context);
//    columns[VT_blocked_queue_start_bt] =  /* Unsupported type */
//    columns[VT_blocked_queue_dma_start_bt] =  /* Unsupported type */
//    columns[VT_blocked_queue_dma_bt] =  /* Unsupported type */
    columns[VT_blocked_queue_num_dmas] = new_dbsc_int64(curEntry->num_dmas, context);
    columns[VT_blocked_queue_remote_io] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->remote_io, context);
    columns[VT_blocked_queue_blocker] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->blocker, context);
    columns[VT_blocked_queue_pool] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pool, context);
//    columns[VT_blocked_queue_ctl_private] =  /* Unsupported type */
//    columns[VT_blocked_queue_blocked_queue] =  /* Unsupported type */
//    columns[VT_blocked_queue_links] =  /* Unsupported type */
//    columns[VT_blocked_queue_ooa_links] =  /* Unsupported type */
//    columns[VT_blocked_queue_blocked_links] =  /* Unsupported type */

    return 0;
}
void
vtab_ctl_io_hdr_lock(void)
{
    sx_slock(&blocked_queue_lock);
}

void
vtab_ctl_io_hdr_unlock(void)
{
    sx_sunlock(&blocked_queue_lock);
}

void
vtab_ctl_io_hdr_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ctl_io_hdr *prc = LIST_FIRST(&blocked_queue);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_blocked_queue_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_blocked_queue_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ctl_io_hdr digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ctl_io_hdrvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_blocked_queue_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ctl_io_hdr_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ctl_io_hdrvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ctl_io_hdrvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ctl_io_hdr_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ctl_io_hdr digest mismatch: UPDATE failed\n");
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
static sqlite3_module ctl_io_hdrvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ctl_io_hdrvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ctl_io_hdrvtabRowid,
    /* xUpdate     */ ctl_io_hdrvtabUpdate,
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
sqlite3_ctl_io_hdrvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ctl_io_hdrvtabModule,
        pAux);
}
void vtab_ctl_io_hdr_serialize(sqlite3 *real_db, struct timespec when) {
    struct ctl_io_hdr *entry = LIST_FIRST(&blocked_queue);

    const char *create_stmt =
        "CREATE TABLE all_ctl_io_hdrs (version INTEGER, io_type INTEGER, msg_type INTEGER, iid_indx INTEGER, flags INTEGER, status INTEGER, port_status INTEGER, timeout INTEGER, retries INTEGER, start_time INTEGER, num_dmas INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ctl_io_hdrs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->version);
           sqlite3_bind_int64(stmt, bindIndex++, entry->io_type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->msg_type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->iid_indx);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->status);
           sqlite3_bind_int64(stmt, bindIndex++, entry->port_status);
           sqlite3_bind_int64(stmt, bindIndex++, entry->timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->retries);
           sqlite3_bind_int64(stmt, bindIndex++, entry->start_time);
           sqlite3_bind_int64(stmt, bindIndex++, entry->num_dmas);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

