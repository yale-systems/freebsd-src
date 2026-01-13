#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/nd_prefix.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_nd_prefix.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_vnet_entry_nd_prefix_ndpr_ifp = 0,
    VT_vnet_entry_nd_prefix_ndpr_entry = 1,
    VT_vnet_entry_nd_prefix_ndpr_prefix = 2,
    VT_vnet_entry_nd_prefix_ndpr_mask = 3,
    VT_vnet_entry_nd_prefix_ndpr_vltime = 4,
    VT_vnet_entry_nd_prefix_ndpr_pltime = 5,
    VT_vnet_entry_nd_prefix_ndpr_expire = 6,
    VT_vnet_entry_nd_prefix_ndpr_preferred = 7,
    VT_vnet_entry_nd_prefix_ndpr_lastupdate = 8,
    VT_vnet_entry_nd_prefix_ndpr_flags = 9,
    VT_vnet_entry_nd_prefix_ndpr_stateflags = 10,
    VT_vnet_entry_nd_prefix_ndpr_advrtrs = 11,
    VT_vnet_entry_nd_prefix_ndpr_plen = 12,
    VT_vnet_entry_nd_prefix_ndpr_addrcnt = 13,
    VT_vnet_entry_nd_prefix_ndpr_refcnt = 14,
    VT_vnet_entry_nd_prefix_NUM_COLUMNS
};

static int
copy_columns(struct nd_prefix *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_vnet_entry_nd_prefix_ndpr_ifp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ndpr_ifp, context);
//    columns[VT_vnet_entry_nd_prefix_ndpr_entry] =  /* Unsupported type */
//    columns[VT_vnet_entry_nd_prefix_ndpr_prefix] =  /* Unsupported type */
//    columns[VT_vnet_entry_nd_prefix_ndpr_mask] =  /* Unsupported type */
    columns[VT_vnet_entry_nd_prefix_ndpr_vltime] = new_dbsc_int64(curEntry->ndpr_vltime, context);
    columns[VT_vnet_entry_nd_prefix_ndpr_pltime] = new_dbsc_int64(curEntry->ndpr_pltime, context);
    columns[VT_vnet_entry_nd_prefix_ndpr_expire] = new_dbsc_int64(curEntry->ndpr_expire, context);
    columns[VT_vnet_entry_nd_prefix_ndpr_preferred] = new_dbsc_int64(curEntry->ndpr_preferred, context);
    columns[VT_vnet_entry_nd_prefix_ndpr_lastupdate] = new_dbsc_int64(curEntry->ndpr_lastupdate, context);
//    columns[VT_vnet_entry_nd_prefix_ndpr_flags] =  /* Unsupported type */
    columns[VT_vnet_entry_nd_prefix_ndpr_stateflags] = new_dbsc_int64(curEntry->ndpr_stateflags, context);
//    columns[VT_vnet_entry_nd_prefix_ndpr_advrtrs] =  /* Unsupported type */
    columns[VT_vnet_entry_nd_prefix_ndpr_plen] = new_dbsc_int64(curEntry->ndpr_plen, context);
    columns[VT_vnet_entry_nd_prefix_ndpr_addrcnt] = new_dbsc_int64(curEntry->ndpr_addrcnt, context);
    columns[VT_vnet_entry_nd_prefix_ndpr_refcnt] = new_dbsc_int64(curEntry->ndpr_refcnt, context);

    return 0;
}
void
vtab_nd_prefix_lock(void)
{
    sx_slock(&vnet_entry_nd_prefix_lock);
}

void
vtab_nd_prefix_unlock(void)
{
    sx_sunlock(&vnet_entry_nd_prefix_lock);
}

void
vtab_nd_prefix_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct nd_prefix *prc = LIST_FIRST(&vnet_entry_nd_prefix);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_nd_prefix_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_vnet_entry_nd_prefix_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("nd_prefix digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
nd_prefixvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_vnet_entry_nd_prefix_p_pid];
    *pRowid = pid_value->int64_value;
    printf("nd_prefix_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
nd_prefixvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
nd_prefixvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_nd_prefix_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("nd_prefix digest mismatch: UPDATE failed\n");
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
static sqlite3_module nd_prefixvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ nd_prefixvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ nd_prefixvtabRowid,
    /* xUpdate     */ nd_prefixvtabUpdate,
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
sqlite3_nd_prefixvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &nd_prefixvtabModule,
        pAux);
}
void vtab_nd_prefix_serialize(sqlite3 *real_db, struct timespec when) {
    struct nd_prefix *entry = LIST_FIRST(&vnet_entry_nd_prefix);

    const char *create_stmt =
        "CREATE TABLE all_nd_prefixs (ndpr_vltime INTEGER, ndpr_pltime INTEGER, ndpr_expire INTEGER, ndpr_preferred INTEGER, ndpr_lastupdate INTEGER, ndpr_stateflags INTEGER, ndpr_plen INTEGER, ndpr_addrcnt INTEGER, ndpr_refcnt INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_nd_prefixs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->ndpr_vltime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ndpr_pltime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ndpr_expire);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ndpr_preferred);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ndpr_lastupdate);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ndpr_stateflags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ndpr_plen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ndpr_addrcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ndpr_refcnt);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

