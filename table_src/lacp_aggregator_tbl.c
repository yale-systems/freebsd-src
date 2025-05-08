#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/lacp_aggregator.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_lacp_aggregator.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_lsc_aggregators_la_q = 0,
    VT_lsc_aggregators_la_refcnt = 1,
    VT_lsc_aggregators_la_nports = 2,
    VT_lsc_aggregators_la_ports = 3,
    VT_lsc_aggregators_la_partner = 4,
    VT_lsc_aggregators_la_actor = 5,
    VT_lsc_aggregators_la_pending = 6,
    VT_lsc_aggregators_NUM_COLUMNS
};

static int
copy_columns(struct lacp_aggregator *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_lsc_aggregators_la_q] =  /* Unsupported type */
    columns[VT_lsc_aggregators_la_refcnt] = new_dbsc_int64(curEntry->la_refcnt, context);
    columns[VT_lsc_aggregators_la_nports] = new_dbsc_int64(curEntry->la_nports, context);
//    columns[VT_lsc_aggregators_la_ports] =  /* Unsupported type */
//    columns[VT_lsc_aggregators_la_partner] =  /* Unsupported type */
//    columns[VT_lsc_aggregators_la_actor] =  /* Unsupported type */
    columns[VT_lsc_aggregators_la_pending] = new_dbsc_int64(curEntry->la_pending, context);

    return 0;
}
void
vtab_lacp_aggregator_lock(void)
{
    sx_slock(&lsc_aggregators_lock);
}

void
vtab_lacp_aggregator_unlock(void)
{
    sx_sunlock(&lsc_aggregators_lock);
}

void
vtab_lacp_aggregator_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct lacp_aggregator *prc = LIST_FIRST(&lsc_aggregators);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_lsc_aggregators_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_lsc_aggregators_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("lacp_aggregator digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
lacp_aggregatorvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_lsc_aggregators_p_pid];
    *pRowid = pid_value->int64_value;
    printf("lacp_aggregator_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
lacp_aggregatorvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
lacp_aggregatorvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_lacp_aggregator_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("lacp_aggregator digest mismatch: UPDATE failed\n");
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
static sqlite3_module lacp_aggregatorvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ lacp_aggregatorvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ lacp_aggregatorvtabRowid,
    /* xUpdate     */ lacp_aggregatorvtabUpdate,
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
sqlite3_lacp_aggregatorvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &lacp_aggregatorvtabModule,
        pAux);
}
void vtab_lacp_aggregator_serialize(sqlite3 *real_db, struct timespec when) {
    struct lacp_aggregator *entry = LIST_FIRST(&lsc_aggregators);

    const char *create_stmt =
        "CREATE TABLE all_lacp_aggregators (la_refcnt INTEGER, la_nports INTEGER, la_pending INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_lacp_aggregators VALUES (?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->la_refcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->la_nports);
           sqlite3_bind_int64(stmt, bindIndex++, entry->la_pending);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

