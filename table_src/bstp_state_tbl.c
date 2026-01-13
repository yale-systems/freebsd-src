#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/bstp_state.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_bstp_state.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_bstp_list_bs_list = 0,
    VT_bstp_list_bs_running = 1,
    VT_bstp_list_bs_mtx = 2,
    VT_bstp_list_bs_bridge_pv = 3,
    VT_bstp_list_bs_root_pv = 4,
    VT_bstp_list_bs_root_port = 5,
    VT_bstp_list_bs_protover = 6,
    VT_bstp_list_bs_migration_delay = 7,
    VT_bstp_list_bs_edge_delay = 8,
    VT_bstp_list_bs_bridge_max_age = 9,
    VT_bstp_list_bs_bridge_fdelay = 10,
    VT_bstp_list_bs_bridge_htime = 11,
    VT_bstp_list_bs_root_msg_age = 12,
    VT_bstp_list_bs_root_max_age = 13,
    VT_bstp_list_bs_root_fdelay = 14,
    VT_bstp_list_bs_root_htime = 15,
    VT_bstp_list_bs_hold_time = 16,
    VT_bstp_list_bs_bridge_priority = 17,
    VT_bstp_list_bs_txholdcount = 18,
    VT_bstp_list_bs_allsynced = 19,
    VT_bstp_list_bs_bstpcallout = 20,
    VT_bstp_list_bs_link_timer = 21,
    VT_bstp_list_bs_last_tc_time = 22,
    VT_bstp_list_bs_bplist = 23,
    VT_bstp_list_bs_state_cb = 24,
    VT_bstp_list_bs_rtage_cb = 25,
    VT_bstp_list_bs_vnet = 26,
    VT_bstp_list_NUM_COLUMNS
};

static int
copy_columns(struct bstp_state *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_bstp_list_bs_list] =  /* Unsupported type */
    columns[VT_bstp_list_bs_running] = new_dbsc_int64(curEntry->bs_running, context);
//    columns[VT_bstp_list_bs_mtx] =  /* Unsupported type */
//    columns[VT_bstp_list_bs_bridge_pv] =  /* Unsupported type */
//    columns[VT_bstp_list_bs_root_pv] =  /* Unsupported type */
    columns[VT_bstp_list_bs_root_port] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bs_root_port, context);
    columns[VT_bstp_list_bs_protover] = new_dbsc_int64(curEntry->bs_protover, context);
    columns[VT_bstp_list_bs_migration_delay] = new_dbsc_int64(curEntry->bs_migration_delay, context);
    columns[VT_bstp_list_bs_edge_delay] = new_dbsc_int64(curEntry->bs_edge_delay, context);
    columns[VT_bstp_list_bs_bridge_max_age] = new_dbsc_int64(curEntry->bs_bridge_max_age, context);
    columns[VT_bstp_list_bs_bridge_fdelay] = new_dbsc_int64(curEntry->bs_bridge_fdelay, context);
    columns[VT_bstp_list_bs_bridge_htime] = new_dbsc_int64(curEntry->bs_bridge_htime, context);
    columns[VT_bstp_list_bs_root_msg_age] = new_dbsc_int64(curEntry->bs_root_msg_age, context);
    columns[VT_bstp_list_bs_root_max_age] = new_dbsc_int64(curEntry->bs_root_max_age, context);
    columns[VT_bstp_list_bs_root_fdelay] = new_dbsc_int64(curEntry->bs_root_fdelay, context);
    columns[VT_bstp_list_bs_root_htime] = new_dbsc_int64(curEntry->bs_root_htime, context);
    columns[VT_bstp_list_bs_hold_time] = new_dbsc_int64(curEntry->bs_hold_time, context);
    columns[VT_bstp_list_bs_bridge_priority] = new_dbsc_int64(curEntry->bs_bridge_priority, context);
    columns[VT_bstp_list_bs_txholdcount] = new_dbsc_int64(curEntry->bs_txholdcount, context);
    columns[VT_bstp_list_bs_allsynced] = new_dbsc_int64(curEntry->bs_allsynced, context);
//    columns[VT_bstp_list_bs_bstpcallout] =  /* Unsupported type */
//    columns[VT_bstp_list_bs_link_timer] =  /* Unsupported type */
//    columns[VT_bstp_list_bs_last_tc_time] =  /* Unsupported type */
//    columns[VT_bstp_list_bs_bplist] =  /* Unsupported type */
    columns[VT_bstp_list_bs_state_cb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bs_state_cb, context);
    columns[VT_bstp_list_bs_rtage_cb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bs_rtage_cb, context);
    columns[VT_bstp_list_bs_vnet] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bs_vnet, context);

    return 0;
}
void
vtab_bstp_state_lock(void)
{
    sx_slock(&bstp_list_lock);
}

void
vtab_bstp_state_unlock(void)
{
    sx_sunlock(&bstp_list_lock);
}

void
vtab_bstp_state_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct bstp_state *prc = LIST_FIRST(&bstp_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_bstp_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_bstp_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("bstp_state digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
bstp_statevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_bstp_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("bstp_state_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
bstp_statevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
bstp_statevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_bstp_state_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("bstp_state digest mismatch: UPDATE failed\n");
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
static sqlite3_module bstp_statevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ bstp_statevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ bstp_statevtabRowid,
    /* xUpdate     */ bstp_statevtabUpdate,
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
sqlite3_bstp_statevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &bstp_statevtabModule,
        pAux);
}
void vtab_bstp_state_serialize(sqlite3 *real_db, struct timespec when) {
    struct bstp_state *entry = LIST_FIRST(&bstp_list);

    const char *create_stmt =
        "CREATE TABLE all_bstp_states (bs_running INTEGER, bs_protover INTEGER, bs_migration_delay INTEGER, bs_edge_delay INTEGER, bs_bridge_max_age INTEGER, bs_bridge_fdelay INTEGER, bs_bridge_htime INTEGER, bs_root_msg_age INTEGER, bs_root_max_age INTEGER, bs_root_fdelay INTEGER, bs_root_htime INTEGER, bs_hold_time INTEGER, bs_bridge_priority INTEGER, bs_txholdcount INTEGER, bs_allsynced INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_bstp_states VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_running);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_protover);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_migration_delay);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_edge_delay);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_bridge_max_age);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_bridge_fdelay);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_bridge_htime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_root_msg_age);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_root_max_age);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_root_fdelay);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_root_htime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_hold_time);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_bridge_priority);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_txholdcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bs_allsynced);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

