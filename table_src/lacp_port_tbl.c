#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/lacp_port.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_lacp_port.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_la_ports_lp_dist_q = 0,
    VT_la_ports_lp_next = 1,
    VT_la_ports_lp_lsc = 2,
    VT_la_ports_lp_lagg = 3,
    VT_la_ports_lp_ifp = 4,
    VT_la_ports_lp_partner = 5,
    VT_la_ports_lp_actor = 6,
    VT_la_ports_lp_marker = 7,
    VT_la_ports_lp_last_lacpdu = 8,
    VT_la_ports_lp_last_lacpdu_rx = 9,
    VT_la_ports_lp_lacpdu_sent = 10,
    VT_la_ports_lp_mux_state = 11,
    VT_la_ports_lp_selected = 12,
    VT_la_ports_lp_flags = 13,
    VT_la_ports_lp_media = 14,
    VT_la_ports_lp_timer = 15,
    VT_la_ports_lp_ifma = 16,
    VT_la_ports_lp_aggregator = 17,
    VT_la_ports_NUM_COLUMNS
};

static int
copy_columns(struct lacp_port *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_la_ports_lp_dist_q] =  /* Unsupported type */
//    columns[VT_la_ports_lp_next] =  /* Unsupported type */
    columns[VT_la_ports_lp_lsc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lp_lsc, context);
    columns[VT_la_ports_lp_lagg] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lp_lagg, context);
    columns[VT_la_ports_lp_ifp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lp_ifp, context);
//    columns[VT_la_ports_lp_partner] =  /* Unsupported type */
//    columns[VT_la_ports_lp_actor] =  /* Unsupported type */
//    columns[VT_la_ports_lp_marker] =  /* Unsupported type */
//    columns[VT_la_ports_lp_last_lacpdu] =  /* Unsupported type */
//    columns[VT_la_ports_lp_last_lacpdu_rx] =  /* Unsupported type */
    columns[VT_la_ports_lp_lacpdu_sent] = new_dbsc_int64(curEntry->lp_lacpdu_sent, context);
    columns[VT_la_ports_lp_mux_state] = new_dbsc_int64((int64_t)(curEntry->lp_mux_state), context); // TODO: need better enum representation 
    columns[VT_la_ports_lp_selected] = new_dbsc_int64((int64_t)(curEntry->lp_selected), context); // TODO: need better enum representation 
    columns[VT_la_ports_lp_flags] = new_dbsc_int64(curEntry->lp_flags, context);
    columns[VT_la_ports_lp_media] = new_dbsc_int64(curEntry->lp_media, context);
//    columns[VT_la_ports_lp_timer] =  /* Unsupported type */
    columns[VT_la_ports_lp_ifma] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lp_ifma, context);
    columns[VT_la_ports_lp_aggregator] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lp_aggregator, context);

    return 0;
}
void
vtab_lacp_port_lock(void)
{
    sx_slock(&la_ports_lock);
}

void
vtab_lacp_port_unlock(void)
{
    sx_sunlock(&la_ports_lock);
}

void
vtab_lacp_port_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct lacp_port *prc = LIST_FIRST(&la_ports);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_la_ports_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_la_ports_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("lacp_port digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
lacp_portvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_la_ports_p_pid];
    *pRowid = pid_value->int64_value;
    printf("lacp_port_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
lacp_portvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
lacp_portvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_lacp_port_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("lacp_port digest mismatch: UPDATE failed\n");
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
static sqlite3_module lacp_portvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ lacp_portvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ lacp_portvtabRowid,
    /* xUpdate     */ lacp_portvtabUpdate,
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
sqlite3_lacp_portvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &lacp_portvtabModule,
        pAux);
}
void vtab_lacp_port_serialize(sqlite3 *real_db, struct timespec when) {
    struct lacp_port *entry = LIST_FIRST(&la_ports);

    const char *create_stmt =
        "CREATE TABLE all_lacp_ports (lp_lacpdu_sent INTEGER, lp_mux_state INTEGER, lp_selected INTEGER, lp_flags INTEGER, lp_media INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_lacp_ports VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->lp_lacpdu_sent);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lp_mux_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lp_selected);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lp_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lp_media);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

