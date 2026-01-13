#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ccb_hdr.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ccb_hdr.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_queue_extra_head_pinfo = 0,
    VT_queue_extra_head_xpt_links = 1,
    VT_queue_extra_head_sim_links = 2,
    VT_queue_extra_head_periph_links = 3,
    VT_queue_extra_head_retry_count = 4,
    VT_queue_extra_head_alloc_flags = 5,
    VT_queue_extra_head_cbfcnp = 6,
    VT_queue_extra_head_func_code = 7,
    VT_queue_extra_head_status = 8,
    VT_queue_extra_head_path = 9,
    VT_queue_extra_head_path_id = 10,
    VT_queue_extra_head_target_id = 11,
    VT_queue_extra_head_target_lun = 12,
    VT_queue_extra_head_flags = 13,
    VT_queue_extra_head_xflags = 14,
    VT_queue_extra_head_periph_priv = 15,
    VT_queue_extra_head_sim_priv = 16,
    VT_queue_extra_head_qos = 17,
    VT_queue_extra_head_timeout = 18,
    VT_queue_extra_head_softtimeout = 19,
    VT_queue_extra_head_NUM_COLUMNS
};

static int
copy_columns(struct ccb_hdr *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_queue_extra_head_pinfo] =  /* Unsupported type */
//    columns[VT_queue_extra_head_xpt_links] =  /* Unsupported type */
//    columns[VT_queue_extra_head_sim_links] =  /* Unsupported type */
//    columns[VT_queue_extra_head_periph_links] =  /* Unsupported type */
    columns[VT_queue_extra_head_retry_count] = new_dbsc_int64(curEntry->retry_count, context);
    columns[VT_queue_extra_head_alloc_flags] = new_dbsc_int64(curEntry->alloc_flags, context);
    columns[VT_queue_extra_head_cbfcnp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cbfcnp, context);
    columns[VT_queue_extra_head_func_code] = new_dbsc_int64((int64_t)(curEntry->func_code), context); // TODO: need better enum representation 
    columns[VT_queue_extra_head_status] = new_dbsc_int64(curEntry->status, context);
    columns[VT_queue_extra_head_path] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->path, context);
    columns[VT_queue_extra_head_path_id] = new_dbsc_int64(curEntry->path_id, context);
    columns[VT_queue_extra_head_target_id] = new_dbsc_int64(curEntry->target_id, context);
    columns[VT_queue_extra_head_target_lun] = new_dbsc_int64(curEntry->target_lun, context);
    columns[VT_queue_extra_head_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_queue_extra_head_xflags] = new_dbsc_int64(curEntry->xflags, context);
//    columns[VT_queue_extra_head_periph_priv] =  /* Unsupported type */
//    columns[VT_queue_extra_head_sim_priv] =  /* Unsupported type */
//    columns[VT_queue_extra_head_qos] =  /* Unsupported type */
    columns[VT_queue_extra_head_timeout] = new_dbsc_int64(curEntry->timeout, context);
//    columns[VT_queue_extra_head_softtimeout] =  /* Unsupported type */

    return 0;
}
void
vtab_ccb_hdr_lock(void)
{
    sx_slock(&queue_extra_head_lock);
}

void
vtab_ccb_hdr_unlock(void)
{
    sx_sunlock(&queue_extra_head_lock);
}

void
vtab_ccb_hdr_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ccb_hdr *prc = LIST_FIRST(&queue_extra_head);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_queue_extra_head_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_queue_extra_head_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ccb_hdr digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ccb_hdrvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_queue_extra_head_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ccb_hdr_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ccb_hdrvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ccb_hdrvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ccb_hdr_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ccb_hdr digest mismatch: UPDATE failed\n");
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
static sqlite3_module ccb_hdrvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ccb_hdrvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ccb_hdrvtabRowid,
    /* xUpdate     */ ccb_hdrvtabUpdate,
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
sqlite3_ccb_hdrvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ccb_hdrvtabModule,
        pAux);
}
void vtab_ccb_hdr_serialize(sqlite3 *real_db, struct timespec when) {
    struct ccb_hdr *entry = LIST_FIRST(&queue_extra_head);

    const char *create_stmt =
        "CREATE TABLE all_ccb_hdrs (retry_count INTEGER, alloc_flags INTEGER, func_code INTEGER, status INTEGER, path_id INTEGER, target_id INTEGER, target_lun INTEGER, flags INTEGER, xflags INTEGER, timeout INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ccb_hdrs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->retry_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->alloc_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->func_code);
           sqlite3_bind_int64(stmt, bindIndex++, entry->status);
           sqlite3_bind_int64(stmt, bindIndex++, entry->path_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->target_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->target_lun);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xflags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->timeout);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

