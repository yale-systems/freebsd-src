#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/iscsi_session.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_iscsi_session.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sc_sessions_is_next = 0,
    VT_sc_sessions_is_conn = 1,
    VT_sc_sessions_is_lock = 2,
    VT_sc_sessions_is_statsn = 3,
    VT_sc_sessions_is_cmdsn = 4,
    VT_sc_sessions_is_expcmdsn = 5,
    VT_sc_sessions_is_maxcmdsn = 6,
    VT_sc_sessions_is_initiator_task_tag = 7,
    VT_sc_sessions_is_protocol_level = 8,
    VT_sc_sessions_is_initial_r2t = 9,
    VT_sc_sessions_is_max_burst_length = 10,
    VT_sc_sessions_is_first_burst_length = 11,
    VT_sc_sessions_is_isid = 12,
    VT_sc_sessions_is_tsih = 13,
    VT_sc_sessions_is_immediate_data = 14,
    VT_sc_sessions_is_target_alias = 15,
    VT_sc_sessions_is_outstanding = 16,
    VT_sc_sessions_is_postponed = 17,
    VT_sc_sessions_is_callout = 18,
    VT_sc_sessions_is_timeout = 19,
    VT_sc_sessions_is_ping_timeout = 20,
    VT_sc_sessions_is_login_timeout = 21,
    VT_sc_sessions_is_waiting_for_iscsid = 22,
    VT_sc_sessions_is_login_phase = 23,
    VT_sc_sessions_is_terminating = 24,
    VT_sc_sessions_is_reconnecting = 25,
    VT_sc_sessions_is_connected = 26,
    VT_sc_sessions_is_devq = 27,
    VT_sc_sessions_is_sim = 28,
    VT_sc_sessions_is_path = 29,
    VT_sc_sessions_is_maintenance_cv = 30,
    VT_sc_sessions_is_softc = 31,
    VT_sc_sessions_is_id = 32,
    VT_sc_sessions_is_conf = 33,
    VT_sc_sessions_is_simq_frozen = 34,
    VT_sc_sessions_is_reason = 35,
    VT_sc_sessions_NUM_COLUMNS
};

static int
copy_columns(struct iscsi_session *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_sc_sessions_is_next] =  /* Unsupported type */
    columns[VT_sc_sessions_is_conn] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->is_conn, context);
//    columns[VT_sc_sessions_is_lock] =  /* Unsupported type */
    columns[VT_sc_sessions_is_statsn] = new_dbsc_int64(curEntry->is_statsn, context);
    columns[VT_sc_sessions_is_cmdsn] = new_dbsc_int64(curEntry->is_cmdsn, context);
    columns[VT_sc_sessions_is_expcmdsn] = new_dbsc_int64(curEntry->is_expcmdsn, context);
    columns[VT_sc_sessions_is_maxcmdsn] = new_dbsc_int64(curEntry->is_maxcmdsn, context);
    columns[VT_sc_sessions_is_initiator_task_tag] = new_dbsc_int64(curEntry->is_initiator_task_tag, context);
    columns[VT_sc_sessions_is_protocol_level] = new_dbsc_int64(curEntry->is_protocol_level, context);
    columns[VT_sc_sessions_is_initial_r2t] = new_dbsc_int64(curEntry->is_initial_r2t, context);
    columns[VT_sc_sessions_is_max_burst_length] = new_dbsc_int64(curEntry->is_max_burst_length, context);
    columns[VT_sc_sessions_is_first_burst_length] = new_dbsc_int64(curEntry->is_first_burst_length, context);
//    columns[VT_sc_sessions_is_isid] =  /* Unsupported type */
    columns[VT_sc_sessions_is_tsih] = new_dbsc_int64(curEntry->is_tsih, context);
    columns[VT_sc_sessions_is_immediate_data] = new_dbsc_int64(curEntry->is_immediate_data, context);
//    columns[VT_sc_sessions_is_target_alias] =  /* Unsupported type */
//    columns[VT_sc_sessions_is_outstanding] =  /* Unsupported type */
//    columns[VT_sc_sessions_is_postponed] =  /* Unsupported type */
//    columns[VT_sc_sessions_is_callout] =  /* Unsupported type */
    columns[VT_sc_sessions_is_timeout] = new_dbsc_int64(curEntry->is_timeout, context);
    columns[VT_sc_sessions_is_ping_timeout] = new_dbsc_int64(curEntry->is_ping_timeout, context);
    columns[VT_sc_sessions_is_login_timeout] = new_dbsc_int64(curEntry->is_login_timeout, context);
    columns[VT_sc_sessions_is_waiting_for_iscsid] = new_dbsc_int64(curEntry->is_waiting_for_iscsid, context);
    columns[VT_sc_sessions_is_login_phase] = new_dbsc_int64(curEntry->is_login_phase, context);
    columns[VT_sc_sessions_is_terminating] = new_dbsc_int64(curEntry->is_terminating, context);
    columns[VT_sc_sessions_is_reconnecting] = new_dbsc_int64(curEntry->is_reconnecting, context);
    columns[VT_sc_sessions_is_connected] = new_dbsc_int64(curEntry->is_connected, context);
    columns[VT_sc_sessions_is_devq] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->is_devq, context);
    columns[VT_sc_sessions_is_sim] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->is_sim, context);
    columns[VT_sc_sessions_is_path] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->is_path, context);
//    columns[VT_sc_sessions_is_maintenance_cv] =  /* Unsupported type */
    columns[VT_sc_sessions_is_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->is_softc, context);
    columns[VT_sc_sessions_is_id] = new_dbsc_int64(curEntry->is_id, context);
//    columns[VT_sc_sessions_is_conf] =  /* Unsupported type */
    columns[VT_sc_sessions_is_simq_frozen] = new_dbsc_int64(curEntry->is_simq_frozen, context);
//    columns[VT_sc_sessions_is_reason] =  /* Unsupported type */

    return 0;
}
void
vtab_iscsi_session_lock(void)
{
    sx_slock(&sc_sessions_lock);
}

void
vtab_iscsi_session_unlock(void)
{
    sx_sunlock(&sc_sessions_lock);
}

void
vtab_iscsi_session_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct iscsi_session *prc = LIST_FIRST(&sc_sessions);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sc_sessions_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sc_sessions_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("iscsi_session digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
iscsi_sessionvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sc_sessions_p_pid];
    *pRowid = pid_value->int64_value;
    printf("iscsi_session_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
iscsi_sessionvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
iscsi_sessionvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_iscsi_session_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("iscsi_session digest mismatch: UPDATE failed\n");
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
static sqlite3_module iscsi_sessionvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ iscsi_sessionvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ iscsi_sessionvtabRowid,
    /* xUpdate     */ iscsi_sessionvtabUpdate,
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
sqlite3_iscsi_sessionvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &iscsi_sessionvtabModule,
        pAux);
}
void vtab_iscsi_session_serialize(sqlite3 *real_db, struct timespec when) {
    struct iscsi_session *entry = LIST_FIRST(&sc_sessions);

    const char *create_stmt =
        "CREATE TABLE all_iscsi_sessions (is_statsn INTEGER, is_cmdsn INTEGER, is_expcmdsn INTEGER, is_maxcmdsn INTEGER, is_initiator_task_tag INTEGER, is_protocol_level INTEGER, is_initial_r2t INTEGER, is_max_burst_length INTEGER, is_first_burst_length INTEGER, is_tsih INTEGER, is_immediate_data INTEGER, is_timeout INTEGER, is_ping_timeout INTEGER, is_login_timeout INTEGER, is_waiting_for_iscsid INTEGER, is_login_phase INTEGER, is_terminating INTEGER, is_reconnecting INTEGER, is_connected INTEGER, is_id INTEGER, is_simq_frozen INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_iscsi_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_statsn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_cmdsn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_expcmdsn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_maxcmdsn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_initiator_task_tag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_protocol_level);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_initial_r2t);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_max_burst_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_first_burst_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_tsih);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_immediate_data);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_ping_timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_login_timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_waiting_for_iscsid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_login_phase);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_terminating);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_reconnecting);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_connected);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->is_simq_frozen);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

