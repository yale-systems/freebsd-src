#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/prison.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_prison.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_allprison_pr_list = 0,
    VT_allprison_pr_id = 1,
    VT_allprison_pr_ref = 2,
    VT_allprison_pr_uref = 3,
    VT_allprison_pr_flags = 4,
    VT_allprison_pr_children = 5,
    VT_allprison_pr_proclist = 6,
    VT_allprison_pr_sibling = 7,
    VT_allprison_pr_parent = 8,
    VT_allprison_pr_mtx = 9,
    VT_allprison_pr_task = 10,
    VT_allprison_pr_osd = 11,
    VT_allprison_pr_cpuset = 12,
    VT_allprison_pr_vnet = 13,
    VT_allprison_pr_root = 14,
    VT_allprison_pr_addrs = 15,
    VT_allprison_pr_prison_racct = 16,
    VT_allprison_pr_sparep = 17,
    VT_allprison_pr_childcount = 18,
    VT_allprison_pr_childmax = 19,
    VT_allprison_pr_allow = 20,
    VT_allprison_pr_securelevel = 21,
    VT_allprison_pr_enforce_statfs = 22,
    VT_allprison_pr_devfs_rsnum = 23,
    VT_allprison_pr_state = 24,
    VT_allprison_pr_exportcnt = 25,
    VT_allprison_pr_spare = 26,
    VT_allprison_pr_osreldate = 27,
    VT_allprison_pr_hostid = 28,
    VT_allprison_pr_name = 29,
    VT_allprison_pr_path = 30,
    VT_allprison_pr_hostname = 31,
    VT_allprison_pr_domainname = 32,
    VT_allprison_pr_hostuuid = 33,
    VT_allprison_pr_osrelease = 34,
    VT_allprison_NUM_COLUMNS
};

static int
copy_columns(struct prison *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_allprison_pr_list] =  /* Unsupported type */
    columns[VT_allprison_pr_id] = new_dbsc_int64(curEntry->pr_id, context);
    columns[VT_allprison_pr_ref] = new_dbsc_int64(curEntry->pr_ref, context);
    columns[VT_allprison_pr_uref] = new_dbsc_int64(curEntry->pr_uref, context);
    columns[VT_allprison_pr_flags] = new_dbsc_int64(curEntry->pr_flags, context);
//    columns[VT_allprison_pr_children] =  /* Unsupported type */
//    columns[VT_allprison_pr_proclist] =  /* Unsupported type */
//    columns[VT_allprison_pr_sibling] =  /* Unsupported type */
    columns[VT_allprison_pr_parent] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pr_parent, context);
//    columns[VT_allprison_pr_mtx] =  /* Unsupported type */
//    columns[VT_allprison_pr_task] =  /* Unsupported type */
//    columns[VT_allprison_pr_osd] =  /* Unsupported type */
    columns[VT_allprison_pr_cpuset] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pr_cpuset, context);
    columns[VT_allprison_pr_vnet] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pr_vnet, context);
    columns[VT_allprison_pr_root] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pr_root, context);
//    columns[VT_allprison_pr_addrs] =  /* Unsupported type */
    columns[VT_allprison_pr_prison_racct] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pr_prison_racct, context);
//    columns[VT_allprison_pr_sparep] =  /* Unsupported type */
    columns[VT_allprison_pr_childcount] = new_dbsc_int64(curEntry->pr_childcount, context);
    columns[VT_allprison_pr_childmax] = new_dbsc_int64(curEntry->pr_childmax, context);
    columns[VT_allprison_pr_allow] = new_dbsc_int64(curEntry->pr_allow, context);
    columns[VT_allprison_pr_securelevel] = new_dbsc_int64(curEntry->pr_securelevel, context);
    columns[VT_allprison_pr_enforce_statfs] = new_dbsc_int64(curEntry->pr_enforce_statfs, context);
    columns[VT_allprison_pr_devfs_rsnum] = new_dbsc_int64(curEntry->pr_devfs_rsnum, context);
    columns[VT_allprison_pr_state] = new_dbsc_int64((int64_t)(curEntry->pr_state), context); // TODO: need better enum representation 
    columns[VT_allprison_pr_exportcnt] = new_dbsc_int64(curEntry->pr_exportcnt, context);
    columns[VT_allprison_pr_spare] = new_dbsc_int64(curEntry->pr_spare, context);
    columns[VT_allprison_pr_osreldate] = new_dbsc_int64(curEntry->pr_osreldate, context);
    columns[VT_allprison_pr_hostid] = new_dbsc_int64(curEntry->pr_hostid, context);
//    columns[VT_allprison_pr_name] =  /* Unsupported type */
//    columns[VT_allprison_pr_path] =  /* Unsupported type */
//    columns[VT_allprison_pr_hostname] =  /* Unsupported type */
//    columns[VT_allprison_pr_domainname] =  /* Unsupported type */
//    columns[VT_allprison_pr_hostuuid] =  /* Unsupported type */
//    columns[VT_allprison_pr_osrelease] =  /* Unsupported type */

    return 0;
}
void
vtab_prison_lock(void)
{
    sx_slock(&allprison_lock);
}

void
vtab_prison_unlock(void)
{
    sx_sunlock(&allprison_lock);
}

void
vtab_prison_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct prison *prc = LIST_FIRST(&allprison);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_allprison_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_allprison_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("prison digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
prisonvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_allprison_p_pid];
    *pRowid = pid_value->int64_value;
    printf("prison_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
prisonvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
prisonvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_prison_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("prison digest mismatch: UPDATE failed\n");
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
static sqlite3_module prisonvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ prisonvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ prisonvtabRowid,
    /* xUpdate     */ prisonvtabUpdate,
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
sqlite3_prisonvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &prisonvtabModule,
        pAux);
}
void vtab_prison_serialize(sqlite3 *real_db, struct timespec when) {
    struct prison *entry = LIST_FIRST(&allprison);

    const char *create_stmt =
        "CREATE TABLE all_prisons (pr_id INTEGER, pr_ref INTEGER, pr_uref INTEGER, pr_flags INTEGER, pr_childcount INTEGER, pr_childmax INTEGER, pr_allow INTEGER, pr_securelevel INTEGER, pr_enforce_statfs INTEGER, pr_devfs_rsnum INTEGER, pr_state INTEGER, pr_exportcnt INTEGER, pr_spare INTEGER, pr_osreldate INTEGER, pr_hostid INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_prisons VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_ref);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_uref);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_childcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_childmax);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_allow);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_securelevel);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_enforce_statfs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_devfs_rsnum);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_exportcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_spare);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_osreldate);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pr_hostid);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

