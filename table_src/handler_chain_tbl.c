#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_handler_chain_pri = 0,
    VT_handler_chain_dir = 1,
    VT_handler_chain_proto = 2,
    VT_handler_chain_fingerprint = 3,
    VT_handler_chain_protohandler = 4,
    VT_handler_chain_link = 5,
    VT_handler_chain_NUM_COLUMNS
};

static int
copy_columns(struct handler_chain *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_handler_chain_pri] = new_osdb_int64(curEntry->pri, context);
    columns[VT_handler_chain_dir] = new_osdb_int64(curEntry->dir, context);
    columns[VT_handler_chain_proto] = new_osdb_int64(curEntry->proto, context);
//    columns[VT_handler_chain_fingerprint] =  TODO: Handle other types
//    columns[VT_handler_chain_protohandler] =  TODO: Handle other types
//    columns[VT_handler_chain_link] =  TODO: Handle other types

    return 0;
}
void
vtab_handler_chain_lock(void)
{
    sx_slock(&handler_chain_lock);
}

void
vtab_handler_chain_unlock(void)
{
    sx_sunlock(&handler_chain_lock);
}

void
vtab_handler_chain_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct handler_chain *prc = LIST_FIRST(&handler_chain);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_handler_chain_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_handler_chain_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("handler_chain digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_handler_chain_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_handler_chain_PID];
    *pRowid = pid_value->int64_value;
    printf("handler_chain_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_handler_chain_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_handler_chain_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_handler_chain_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("handler_chain digest mismatch: UPDATE failed\n");
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
static sqlite3_module handler_chainvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ handler_chainvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ handler_chainvtabRowid,
    /* xUpdate     */ handler_chainvtabUpdate,
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
sqlite3_handler_chainvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &handler_chainvtabModule,
        pAux);
}
