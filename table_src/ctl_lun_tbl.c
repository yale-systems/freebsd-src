#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ctl_lun.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ctl_lun.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_lun_list_lun_lock = 0,
    VT_lun_list_lun = 1,
    VT_lun_list_flags = 2,
    VT_lun_list_error_list = 3,
    VT_lun_list_error_serial = 4,
    VT_lun_list_ctl_softc = 5,
    VT_lun_list_be_lun = 6,
    VT_lun_list_backend = 7,
    VT_lun_list_delay_info = 8,
    VT_lun_list_idle_time = 9,
    VT_lun_list_last_busy = 10,
    VT_lun_list_ooa_queue = 11,
    VT_lun_list_links = 12,
    VT_lun_list_pending_sense = 13,
    VT_lun_list_pending_ua = 14,
    VT_lun_list_ua_tpt_info = 15,
    VT_lun_list_lasttpt = 16,
    VT_lun_list_ie_asc = 17,
    VT_lun_list_ie_ascq = 18,
    VT_lun_list_ie_reported = 19,
    VT_lun_list_ie_reportcnt = 20,
    VT_lun_list_ie_callout = 21,
    VT_lun_list_mode_pages = 22,
    VT_lun_list_log_pages = 23,
    VT_lun_list_stats = 24,
    VT_lun_list_res_idx = 25,
    VT_lun_list_pr_generation = 26,
    VT_lun_list_pr_keys = 27,
    VT_lun_list_pr_key_count = 28,
    VT_lun_list_pr_res_idx = 29,
    VT_lun_list_pr_res_type = 30,
    VT_lun_list_prevent_count = 31,
    VT_lun_list_prevent = 32,
    VT_lun_list_write_buffer = 33,
    VT_lun_list_lun_devid = 34,
    VT_lun_list_tpc_lists = 35,
    VT_lun_list_NUM_COLUMNS
};

static int
copy_columns(struct ctl_lun *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_lun_list_lun_lock] =  /* Unsupported type */
    columns[VT_lun_list_lun] = new_dbsc_int64(curEntry->lun, context);
    columns[VT_lun_list_flags] = new_dbsc_int64((int64_t)(curEntry->flags), context); // TODO: need better enum representation 
//    columns[VT_lun_list_error_list] =  /* Unsupported type */
    columns[VT_lun_list_error_serial] = new_dbsc_int64(curEntry->error_serial, context);
    columns[VT_lun_list_ctl_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ctl_softc, context);
    columns[VT_lun_list_be_lun] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->be_lun, context);
    columns[VT_lun_list_backend] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->backend, context);
//    columns[VT_lun_list_delay_info] =  /* Unsupported type */
    columns[VT_lun_list_idle_time] = new_dbsc_int64(curEntry->idle_time, context);
    columns[VT_lun_list_last_busy] = new_dbsc_int64(curEntry->last_busy, context);
//    columns[VT_lun_list_ooa_queue] =  /* Unsupported type */
//    columns[VT_lun_list_links] =  /* Unsupported type */
    columns[VT_lun_list_pending_sense] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pending_sense, context);
    columns[VT_lun_list_pending_ua] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pending_ua, context);
//    columns[VT_lun_list_ua_tpt_info] =  /* Unsupported type */
    columns[VT_lun_list_lasttpt] = new_dbsc_int64(curEntry->lasttpt, context);
    columns[VT_lun_list_ie_asc] = new_dbsc_int64(curEntry->ie_asc, context);
    columns[VT_lun_list_ie_ascq] = new_dbsc_int64(curEntry->ie_ascq, context);
    columns[VT_lun_list_ie_reported] = new_dbsc_int64(curEntry->ie_reported, context);
    columns[VT_lun_list_ie_reportcnt] = new_dbsc_int64(curEntry->ie_reportcnt, context);
//    columns[VT_lun_list_ie_callout] =  /* Unsupported type */
//    columns[VT_lun_list_mode_pages] =  /* Unsupported type */
//    columns[VT_lun_list_log_pages] =  /* Unsupported type */
//    columns[VT_lun_list_stats] =  /* Unsupported type */
    columns[VT_lun_list_res_idx] = new_dbsc_int64(curEntry->res_idx, context);
    columns[VT_lun_list_pr_generation] = new_dbsc_int64(curEntry->pr_generation, context);
    columns[VT_lun_list_pr_keys] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pr_keys, context);
    columns[VT_lun_list_pr_key_count] = new_dbsc_int64(curEntry->pr_key_count, context);
    columns[VT_lun_list_pr_res_idx] = new_dbsc_int64(curEntry->pr_res_idx, context);
    columns[VT_lun_list_pr_res_type] = new_dbsc_int64(curEntry->pr_res_type, context);
    columns[VT_lun_list_prevent_count] = new_dbsc_int64(curEntry->prevent_count, context);
    columns[VT_lun_list_prevent] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->prevent, context);
    columns[VT_lun_list_write_buffer] = new_dbsc_text(curEntry->write_buffer, strlen(curEntry->write_buffer) + 1, context);
    columns[VT_lun_list_lun_devid] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lun_devid, context);
//    columns[VT_lun_list_tpc_lists] =  /* Unsupported type */

    return 0;
}
void
vtab_ctl_lun_lock(void)
{
    sx_slock(&lun_list_lock);
}

void
vtab_ctl_lun_unlock(void)
{
    sx_sunlock(&lun_list_lock);
}

void
vtab_ctl_lun_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ctl_lun *prc = LIST_FIRST(&lun_list);

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
    printf("ctl_lun digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ctl_lunvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_lun_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ctl_lun_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ctl_lunvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ctl_lunvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ctl_lun_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ctl_lun digest mismatch: UPDATE failed\n");
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
static sqlite3_module ctl_lunvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ctl_lunvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ctl_lunvtabRowid,
    /* xUpdate     */ ctl_lunvtabUpdate,
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
sqlite3_ctl_lunvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ctl_lunvtabModule,
        pAux);
}
void vtab_ctl_lun_serialize(sqlite3 *real_db, struct timespec when) {
    struct ctl_lun *entry = LIST_FIRST(&lun_list);

    const char *create_stmt =
        "CREATE TABLE all_ctl_luns (lun INTEGER, flags INTEGER, error_serial INTEGER, idle_time INTEGER, last_busy INTEGER, lasttpt INTEGER, ie_asc INTEGER, ie_ascq INTEGER, ie_reported INTEGER, ie_reportcnt INTEGER, res_idx INTEGER, pr_generation INTEGER, pr_key_count INTEGER, pr_res_idx INTEGER, pr_res_type INTEGER, prevent_count INTEGER, write_buffer TEXT)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ctl_luns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->lun);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->error_serial);
           sqlite3_bind_int64(stmt, bindIndex++, entry->idle_time);
           sqlite3_bind_int64(stmt, bindIndex++, entry->last_busy);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lasttpt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ie_asc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ie_ascq);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ie_reported);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ie_reportcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->res_idx);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_generation);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_key_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_res_idx);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_res_type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->prevent_count);
           sqlite3_bind_text(stmt, bindIndex++, entry->write_buffer, -1, SQLITE_TRANSIENT);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

