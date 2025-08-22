#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/bstp_port.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_bstp_port.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_bs_bplist_bp_next = 0,
    VT_bs_bplist_bp_ifp = 1,
    VT_bs_bplist_bp_bs = 2,
    VT_bs_bplist_bp_active = 3,
    VT_bs_bplist_bp_protover = 4,
    VT_bs_bplist_bp_flags = 5,
    VT_bs_bplist_bp_path_cost = 6,
    VT_bs_bplist_bp_port_msg_age = 7,
    VT_bs_bplist_bp_port_max_age = 8,
    VT_bs_bplist_bp_port_fdelay = 9,
    VT_bs_bplist_bp_port_htime = 10,
    VT_bs_bplist_bp_desg_msg_age = 11,
    VT_bs_bplist_bp_desg_max_age = 12,
    VT_bs_bplist_bp_desg_fdelay = 13,
    VT_bs_bplist_bp_desg_htime = 14,
    VT_bs_bplist_bp_edge_delay_timer = 15,
    VT_bs_bplist_bp_forward_delay_timer = 16,
    VT_bs_bplist_bp_hello_timer = 17,
    VT_bs_bplist_bp_message_age_timer = 18,
    VT_bs_bplist_bp_migrate_delay_timer = 19,
    VT_bs_bplist_bp_recent_backup_timer = 20,
    VT_bs_bplist_bp_recent_root_timer = 21,
    VT_bs_bplist_bp_tc_timer = 22,
    VT_bs_bplist_bp_msg_cu = 23,
    VT_bs_bplist_bp_desg_pv = 24,
    VT_bs_bplist_bp_port_pv = 25,
    VT_bs_bplist_bp_port_id = 26,
    VT_bs_bplist_bp_state = 27,
    VT_bs_bplist_bp_tcstate = 28,
    VT_bs_bplist_bp_role = 29,
    VT_bs_bplist_bp_infois = 30,
    VT_bs_bplist_bp_tc_ack = 31,
    VT_bs_bplist_bp_tc_prop = 32,
    VT_bs_bplist_bp_fdbflush = 33,
    VT_bs_bplist_bp_priority = 34,
    VT_bs_bplist_bp_ptp_link = 35,
    VT_bs_bplist_bp_agree = 36,
    VT_bs_bplist_bp_agreed = 37,
    VT_bs_bplist_bp_sync = 38,
    VT_bs_bplist_bp_synced = 39,
    VT_bs_bplist_bp_proposing = 40,
    VT_bs_bplist_bp_proposed = 41,
    VT_bs_bplist_bp_operedge = 42,
    VT_bs_bplist_bp_reroot = 43,
    VT_bs_bplist_bp_rcvdtc = 44,
    VT_bs_bplist_bp_rcvdtca = 45,
    VT_bs_bplist_bp_rcvdtcn = 46,
    VT_bs_bplist_bp_forward_transitions = 47,
    VT_bs_bplist_bp_txcount = 48,
    VT_bs_bplist_bp_statetask = 49,
    VT_bs_bplist_bp_rtagetask = 50,
    VT_bs_bplist_bp_mediatask = 51,
    VT_bs_bplist_NUM_COLUMNS
};

static int
copy_columns(struct bstp_port *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_bs_bplist_bp_next] =  /* Unsupported type */
    columns[VT_bs_bplist_bp_ifp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bp_ifp, context);
    columns[VT_bs_bplist_bp_bs] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bp_bs, context);
    columns[VT_bs_bplist_bp_active] = new_dbsc_int64(curEntry->bp_active, context);
    columns[VT_bs_bplist_bp_protover] = new_dbsc_int64(curEntry->bp_protover, context);
    columns[VT_bs_bplist_bp_flags] = new_dbsc_int64(curEntry->bp_flags, context);
    columns[VT_bs_bplist_bp_path_cost] = new_dbsc_int64(curEntry->bp_path_cost, context);
    columns[VT_bs_bplist_bp_port_msg_age] = new_dbsc_int64(curEntry->bp_port_msg_age, context);
    columns[VT_bs_bplist_bp_port_max_age] = new_dbsc_int64(curEntry->bp_port_max_age, context);
    columns[VT_bs_bplist_bp_port_fdelay] = new_dbsc_int64(curEntry->bp_port_fdelay, context);
    columns[VT_bs_bplist_bp_port_htime] = new_dbsc_int64(curEntry->bp_port_htime, context);
    columns[VT_bs_bplist_bp_desg_msg_age] = new_dbsc_int64(curEntry->bp_desg_msg_age, context);
    columns[VT_bs_bplist_bp_desg_max_age] = new_dbsc_int64(curEntry->bp_desg_max_age, context);
    columns[VT_bs_bplist_bp_desg_fdelay] = new_dbsc_int64(curEntry->bp_desg_fdelay, context);
    columns[VT_bs_bplist_bp_desg_htime] = new_dbsc_int64(curEntry->bp_desg_htime, context);
//    columns[VT_bs_bplist_bp_edge_delay_timer] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_forward_delay_timer] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_hello_timer] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_message_age_timer] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_migrate_delay_timer] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_recent_backup_timer] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_recent_root_timer] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_tc_timer] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_msg_cu] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_desg_pv] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_port_pv] =  /* Unsupported type */
    columns[VT_bs_bplist_bp_port_id] = new_dbsc_int64(curEntry->bp_port_id, context);
    columns[VT_bs_bplist_bp_state] = new_dbsc_int64(curEntry->bp_state, context);
    columns[VT_bs_bplist_bp_tcstate] = new_dbsc_int64(curEntry->bp_tcstate, context);
    columns[VT_bs_bplist_bp_role] = new_dbsc_int64(curEntry->bp_role, context);
    columns[VT_bs_bplist_bp_infois] = new_dbsc_int64(curEntry->bp_infois, context);
    columns[VT_bs_bplist_bp_tc_ack] = new_dbsc_int64(curEntry->bp_tc_ack, context);
    columns[VT_bs_bplist_bp_tc_prop] = new_dbsc_int64(curEntry->bp_tc_prop, context);
    columns[VT_bs_bplist_bp_fdbflush] = new_dbsc_int64(curEntry->bp_fdbflush, context);
    columns[VT_bs_bplist_bp_priority] = new_dbsc_int64(curEntry->bp_priority, context);
    columns[VT_bs_bplist_bp_ptp_link] = new_dbsc_int64(curEntry->bp_ptp_link, context);
    columns[VT_bs_bplist_bp_agree] = new_dbsc_int64(curEntry->bp_agree, context);
    columns[VT_bs_bplist_bp_agreed] = new_dbsc_int64(curEntry->bp_agreed, context);
    columns[VT_bs_bplist_bp_sync] = new_dbsc_int64(curEntry->bp_sync, context);
    columns[VT_bs_bplist_bp_synced] = new_dbsc_int64(curEntry->bp_synced, context);
    columns[VT_bs_bplist_bp_proposing] = new_dbsc_int64(curEntry->bp_proposing, context);
    columns[VT_bs_bplist_bp_proposed] = new_dbsc_int64(curEntry->bp_proposed, context);
    columns[VT_bs_bplist_bp_operedge] = new_dbsc_int64(curEntry->bp_operedge, context);
    columns[VT_bs_bplist_bp_reroot] = new_dbsc_int64(curEntry->bp_reroot, context);
    columns[VT_bs_bplist_bp_rcvdtc] = new_dbsc_int64(curEntry->bp_rcvdtc, context);
    columns[VT_bs_bplist_bp_rcvdtca] = new_dbsc_int64(curEntry->bp_rcvdtca, context);
    columns[VT_bs_bplist_bp_rcvdtcn] = new_dbsc_int64(curEntry->bp_rcvdtcn, context);
    columns[VT_bs_bplist_bp_forward_transitions] = new_dbsc_int64(curEntry->bp_forward_transitions, context);
    columns[VT_bs_bplist_bp_txcount] = new_dbsc_int64(curEntry->bp_txcount, context);
//    columns[VT_bs_bplist_bp_statetask] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_rtagetask] =  /* Unsupported type */
//    columns[VT_bs_bplist_bp_mediatask] =  /* Unsupported type */

    return 0;
}
void
vtab_bstp_port_lock(void)
{
    sx_slock(&bs_bplist_lock);
}

void
vtab_bstp_port_unlock(void)
{
    sx_sunlock(&bs_bplist_lock);
}

void
vtab_bstp_port_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct bstp_port *prc = LIST_FIRST(&bs_bplist);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_bs_bplist_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_bs_bplist_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("bstp_port digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
bstp_portvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_bs_bplist_p_pid];
    *pRowid = pid_value->int64_value;
    printf("bstp_port_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
bstp_portvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
bstp_portvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_bstp_port_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("bstp_port digest mismatch: UPDATE failed\n");
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
static sqlite3_module bstp_portvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ bstp_portvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ bstp_portvtabRowid,
    /* xUpdate     */ bstp_portvtabUpdate,
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
sqlite3_bstp_portvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &bstp_portvtabModule,
        pAux);
}
void vtab_bstp_port_serialize(sqlite3 *real_db, struct timespec when) {
    struct bstp_port *entry = LIST_FIRST(&bs_bplist);

    const char *create_stmt =
        "CREATE TABLE all_bstp_ports (bp_active INTEGER, bp_protover INTEGER, bp_flags INTEGER, bp_path_cost INTEGER, bp_port_msg_age INTEGER, bp_port_max_age INTEGER, bp_port_fdelay INTEGER, bp_port_htime INTEGER, bp_desg_msg_age INTEGER, bp_desg_max_age INTEGER, bp_desg_fdelay INTEGER, bp_desg_htime INTEGER, bp_port_id INTEGER, bp_state INTEGER, bp_tcstate INTEGER, bp_role INTEGER, bp_infois INTEGER, bp_tc_ack INTEGER, bp_tc_prop INTEGER, bp_fdbflush INTEGER, bp_priority INTEGER, bp_ptp_link INTEGER, bp_agree INTEGER, bp_agreed INTEGER, bp_sync INTEGER, bp_synced INTEGER, bp_proposing INTEGER, bp_proposed INTEGER, bp_operedge INTEGER, bp_reroot INTEGER, bp_rcvdtc INTEGER, bp_rcvdtca INTEGER, bp_rcvdtcn INTEGER, bp_forward_transitions INTEGER, bp_txcount INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_bstp_ports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_active);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_protover);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_path_cost);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_port_msg_age);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_port_max_age);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_port_fdelay);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_port_htime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_desg_msg_age);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_desg_max_age);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_desg_fdelay);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_desg_htime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_port_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_tcstate);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_role);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_infois);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_tc_ack);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_tc_prop);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_fdbflush);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_priority);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_ptp_link);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_agree);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_agreed);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_sync);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_synced);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_proposing);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_proposed);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_operedge);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_reroot);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_rcvdtc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_rcvdtca);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_rcvdtcn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_forward_transitions);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bp_txcount);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

