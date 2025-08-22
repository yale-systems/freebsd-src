#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cfiscsi_target.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cfiscsi_target.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_targets_ct_next = 0,
    VT_targets_ct_softc = 1,
    VT_targets_ct_refcount = 2,
    VT_targets_ct_name = 3,
    VT_targets_ct_alias = 4,
    VT_targets_ct_tag = 5,
    VT_targets_ct_state = 6,
    VT_targets_ct_online = 7,
    VT_targets_ct_target_id = 8,
    VT_targets_ct_port = 9,
    VT_targets_NUM_COLUMNS
};

static int
copy_columns(struct cfiscsi_target *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_targets_ct_next] =  /* Unsupported type */
    columns[VT_targets_ct_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ct_softc, context);
    columns[VT_targets_ct_refcount] = new_dbsc_int64(curEntry->ct_refcount, context);
//    columns[VT_targets_ct_name] =  /* Unsupported type */
//    columns[VT_targets_ct_alias] =  /* Unsupported type */
    columns[VT_targets_ct_tag] = new_dbsc_int64(curEntry->ct_tag, context);
    columns[VT_targets_ct_state] = new_dbsc_int64(curEntry->ct_state, context);
    columns[VT_targets_ct_online] = new_dbsc_int64(curEntry->ct_online, context);
    columns[VT_targets_ct_target_id] = new_dbsc_int64(curEntry->ct_target_id, context);
//    columns[VT_targets_ct_port] =  /* Unsupported type */

    return 0;
}
void
vtab_cfiscsi_target_lock(void)
{
    sx_slock(&targets_lock);
}

void
vtab_cfiscsi_target_unlock(void)
{
    sx_sunlock(&targets_lock);
}

void
vtab_cfiscsi_target_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cfiscsi_target *prc = LIST_FIRST(&targets);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_targets_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_targets_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cfiscsi_target digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cfiscsi_targetvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_targets_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cfiscsi_target_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cfiscsi_targetvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cfiscsi_targetvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cfiscsi_target_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cfiscsi_target digest mismatch: UPDATE failed\n");
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
static sqlite3_module cfiscsi_targetvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cfiscsi_targetvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cfiscsi_targetvtabRowid,
    /* xUpdate     */ cfiscsi_targetvtabUpdate,
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
sqlite3_cfiscsi_targetvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cfiscsi_targetvtabModule,
        pAux);
}
void vtab_cfiscsi_target_serialize(sqlite3 *real_db, struct timespec when) {
    struct cfiscsi_target *entry = LIST_FIRST(&targets);

    const char *create_stmt =
        "CREATE TABLE all_cfiscsi_targets (ct_refcount INTEGER, ct_tag INTEGER, ct_state INTEGER, ct_online INTEGER, ct_target_id INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cfiscsi_targets VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->ct_refcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ct_tag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ct_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ct_online);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ct_target_id);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

