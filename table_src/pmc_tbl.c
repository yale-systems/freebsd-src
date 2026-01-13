#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/pmc.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_pmc.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_po_pmcs_pm_targets = 0,
    VT_po_pmcs_pm_next = 1,
    VT_po_pmcs_pm_gv = 2,
    VT_po_pmcs_pm_sc = 3,
    VT_po_pmcs_pm_pcpu_state = 4,
    VT_po_pmcs_pm_cpustate = 5,
    VT_po_pmcs_pm_caps = 6,
    VT_po_pmcs_pm_event = 7,
    VT_po_pmcs_pm_flags = 8,
    VT_po_pmcs_pm_owner = 9,
    VT_po_pmcs_pm_runcount = 10,
    VT_po_pmcs_pm_state = 11,
    VT_po_pmcs_pm_id = 12,
    VT_po_pmcs_pm_class = 13,
    VT_po_pmcs_pm_md = 14,
    VT_po_pmcs_NUM_COLUMNS
};

static int
copy_columns(struct pmc *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_po_pmcs_pm_targets] =  /* Unsupported type */
//    columns[VT_po_pmcs_pm_next] =  /* Unsupported type */
//    columns[VT_po_pmcs_pm_gv] =  /* Unsupported type */
//    columns[VT_po_pmcs_pm_sc] =  /* Unsupported type */
    columns[VT_po_pmcs_pm_pcpu_state] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pm_pcpu_state, context);
//    columns[VT_po_pmcs_pm_cpustate] =  /* Unsupported type */
    columns[VT_po_pmcs_pm_caps] = new_dbsc_int64(curEntry->pm_caps, context);
    columns[VT_po_pmcs_pm_event] = new_dbsc_int64((int64_t)(curEntry->pm_event), context); // TODO: need better enum representation 
    columns[VT_po_pmcs_pm_flags] = new_dbsc_int64(curEntry->pm_flags, context);
    columns[VT_po_pmcs_pm_owner] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pm_owner, context);
    columns[VT_po_pmcs_pm_runcount] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pm_runcount, context);
    columns[VT_po_pmcs_pm_state] = new_dbsc_int64((int64_t)(curEntry->pm_state), context); // TODO: need better enum representation 
    columns[VT_po_pmcs_pm_id] = new_dbsc_int64(curEntry->pm_id, context);
    columns[VT_po_pmcs_pm_class] = new_dbsc_int64((int64_t)(curEntry->pm_class), context); // TODO: need better enum representation 
//    columns[VT_po_pmcs_pm_md] =  /* Unsupported type */

    return 0;
}
void
vtab_pmc_lock(void)
{
    sx_slock(&po_pmcs_lock);
}

void
vtab_pmc_unlock(void)
{
    sx_sunlock(&po_pmcs_lock);
}

void
vtab_pmc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pmc *prc = LIST_FIRST(&po_pmcs);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_po_pmcs_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_po_pmcs_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pmc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
pmcvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_po_pmcs_p_pid];
    *pRowid = pid_value->int64_value;
    printf("pmc_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
pmcvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
pmcvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pmc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pmc digest mismatch: UPDATE failed\n");
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
static sqlite3_module pmcvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pmcvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pmcvtabRowid,
    /* xUpdate     */ pmcvtabUpdate,
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
sqlite3_pmcvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pmcvtabModule,
        pAux);
}
void vtab_pmc_serialize(sqlite3 *real_db, struct timespec when) {
    struct pmc *entry = LIST_FIRST(&po_pmcs);

    const char *create_stmt =
        "CREATE TABLE all_pmcs (pm_caps INTEGER, pm_event INTEGER, pm_flags INTEGER, pm_state INTEGER, pm_id INTEGER, pm_class INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_pmcs VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->pm_caps);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pm_event);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pm_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pm_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pm_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pm_class);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

