#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cfiscsi_session.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cfiscsi_session.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sessions_cs_next = 0,
    VT_sessions_cs_lock = 1,
    VT_sessions_cs_conn = 2,
    VT_sessions_cs_cmdsn = 3,
    VT_sessions_cs_statsn = 4,
    VT_sessions_cs_target_transfer_tag = 5,
    VT_sessions_cs_outstanding_ctl_pdus = 6,
    VT_sessions_cs_waiting_for_data_out = 7,
    VT_sessions_cs_target = 8,
    VT_sessions_cs_callout = 9,
    VT_sessions_cs_timeout = 10,
    VT_sessions_cs_maintenance_cv = 11,
    VT_sessions_cs_terminating = 12,
    VT_sessions_cs_terminating_tasks = 13,
    VT_sessions_cs_handoff_in_progress = 14,
    VT_sessions_cs_tasks_aborted = 15,
    VT_sessions_cs_max_burst_length = 16,
    VT_sessions_cs_first_burst_length = 17,
    VT_sessions_cs_immediate_data = 18,
    VT_sessions_cs_initiator_name = 19,
    VT_sessions_cs_initiator_addr = 20,
    VT_sessions_cs_initiator_alias = 21,
    VT_sessions_cs_initiator_isid = 22,
    VT_sessions_cs_initiator_id = 23,
    VT_sessions_cs_id = 24,
    VT_sessions_cs_ctl_initid = 25,
    VT_sessions_NUM_COLUMNS
};

static int
copy_columns(struct cfiscsi_session *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_sessions_cs_next] =  /* Unsupported type */
//    columns[VT_sessions_cs_lock] =  /* Unsupported type */
    columns[VT_sessions_cs_conn] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cs_conn, context);
    columns[VT_sessions_cs_cmdsn] = new_dbsc_int64(curEntry->cs_cmdsn, context);
    columns[VT_sessions_cs_statsn] = new_dbsc_int64(curEntry->cs_statsn, context);
    columns[VT_sessions_cs_target_transfer_tag] = new_dbsc_int64(curEntry->cs_target_transfer_tag, context);
    columns[VT_sessions_cs_outstanding_ctl_pdus] = new_dbsc_int64(curEntry->cs_outstanding_ctl_pdus, context);
//    columns[VT_sessions_cs_waiting_for_data_out] =  /* Unsupported type */
    columns[VT_sessions_cs_target] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cs_target, context);
//    columns[VT_sessions_cs_callout] =  /* Unsupported type */
    columns[VT_sessions_cs_timeout] = new_dbsc_int64(curEntry->cs_timeout, context);
//    columns[VT_sessions_cs_maintenance_cv] =  /* Unsupported type */
    columns[VT_sessions_cs_terminating] = new_dbsc_int64(curEntry->cs_terminating, context);
    columns[VT_sessions_cs_terminating_tasks] = new_dbsc_int64(curEntry->cs_terminating_tasks, context);
    columns[VT_sessions_cs_handoff_in_progress] = new_dbsc_int64(curEntry->cs_handoff_in_progress, context);
    columns[VT_sessions_cs_tasks_aborted] = new_dbsc_int64(curEntry->cs_tasks_aborted, context);
    columns[VT_sessions_cs_max_burst_length] = new_dbsc_int64(curEntry->cs_max_burst_length, context);
    columns[VT_sessions_cs_first_burst_length] = new_dbsc_int64(curEntry->cs_first_burst_length, context);
    columns[VT_sessions_cs_immediate_data] = new_dbsc_int64(curEntry->cs_immediate_data, context);
//    columns[VT_sessions_cs_initiator_name] =  /* Unsupported type */
//    columns[VT_sessions_cs_initiator_addr] =  /* Unsupported type */
//    columns[VT_sessions_cs_initiator_alias] =  /* Unsupported type */
//    columns[VT_sessions_cs_initiator_isid] =  /* Unsupported type */
//    columns[VT_sessions_cs_initiator_id] =  /* Unsupported type */
    columns[VT_sessions_cs_id] = new_dbsc_int64(curEntry->cs_id, context);
    columns[VT_sessions_cs_ctl_initid] = new_dbsc_int64(curEntry->cs_ctl_initid, context);

    return 0;
}
void
vtab_cfiscsi_session_lock(void)
{
    sx_slock(&sessions_lock);
}

void
vtab_cfiscsi_session_unlock(void)
{
    sx_sunlock(&sessions_lock);
}

void
vtab_cfiscsi_session_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cfiscsi_session *prc = LIST_FIRST(&sessions);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sessions_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sessions_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cfiscsi_session digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cfiscsi_sessionvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sessions_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cfiscsi_session_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cfiscsi_sessionvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cfiscsi_sessionvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cfiscsi_session_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cfiscsi_session digest mismatch: UPDATE failed\n");
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
static sqlite3_module cfiscsi_sessionvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cfiscsi_sessionvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cfiscsi_sessionvtabRowid,
    /* xUpdate     */ cfiscsi_sessionvtabUpdate,
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
sqlite3_cfiscsi_sessionvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cfiscsi_sessionvtabModule,
        pAux);
}
void vtab_cfiscsi_session_serialize(sqlite3 *real_db, struct timespec when) {
    struct cfiscsi_session *entry = LIST_FIRST(&sessions);

    const char *create_stmt =
        "CREATE TABLE all_cfiscsi_sessions (cs_cmdsn INTEGER, cs_statsn INTEGER, cs_target_transfer_tag INTEGER, cs_outstanding_ctl_pdus INTEGER, cs_timeout INTEGER, cs_terminating INTEGER, cs_terminating_tasks INTEGER, cs_handoff_in_progress INTEGER, cs_tasks_aborted INTEGER, cs_max_burst_length INTEGER, cs_first_burst_length INTEGER, cs_immediate_data INTEGER, cs_id INTEGER, cs_ctl_initid INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cfiscsi_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_cmdsn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_statsn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_target_transfer_tag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_outstanding_ctl_pdus);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_terminating);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_terminating_tasks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_handoff_in_progress);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_tasks_aborted);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_max_burst_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_first_burst_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_immediate_data);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cs_ctl_initid);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

