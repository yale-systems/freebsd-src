#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ng_typelist_version = 0,
    VT_ng_typelist_name = 1,
    VT_ng_typelist_mod_event = 2,
    VT_ng_typelist_constructor = 3,
    VT_ng_typelist_rcvmsg = 4,
    VT_ng_typelist_close = 5,
    VT_ng_typelist_shutdown = 6,
    VT_ng_typelist_newhook = 7,
    VT_ng_typelist_findhook = 8,
    VT_ng_typelist_connect = 9,
    VT_ng_typelist_rcvdata = 10,
    VT_ng_typelist_disconnect = 11,
    VT_ng_typelist_cmdlist = 12,
    VT_ng_typelist_types = 13,
    VT_ng_typelist_refs = 14,
    VT_ng_typelist_NUM_COLUMNS
};

static int
copy_columns(struct ng_typelist *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_ng_typelist_version] = new_osdb_int64(curEntry->version, context);
    columns[VT_ng_typelist_name] = new_osdb_text(curEntry->name, strlen(curEntry->name) + 1, context);
//    columns[VT_ng_typelist_mod_event] =  TODO: Handle other types
//    columns[VT_ng_typelist_constructor] =  TODO: Handle other types
//    columns[VT_ng_typelist_rcvmsg] =  TODO: Handle other types
//    columns[VT_ng_typelist_close] =  TODO: Handle other types
//    columns[VT_ng_typelist_shutdown] =  TODO: Handle other types
//    columns[VT_ng_typelist_newhook] =  TODO: Handle other types
//    columns[VT_ng_typelist_findhook] =  TODO: Handle other types
//    columns[VT_ng_typelist_connect] =  TODO: Handle other types
//    columns[VT_ng_typelist_rcvdata] =  TODO: Handle other types
//    columns[VT_ng_typelist_disconnect] =  TODO: Handle other types
//    columns[VT_ng_typelist_cmdlist] =  TODO: Handle other types
//    columns[VT_ng_typelist_types] =  TODO: Handle other types
    columns[VT_ng_typelist_refs] = new_osdb_int64(curEntry->refs, context);

    return 0;
}
void
vtab__lock(void)
{
    sx_slock(&ng_typelist_lock);
}

void
vtab__unlock(void)
{
    sx_sunlock(&ng_typelist_lock);
}

void
vtab__snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct  *prc = LIST_FIRST(&ng_typelist);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ng_typelist_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_ng_typelist_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf(" digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab__rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_ng_typelist_PID];
    *pRowid = pid_value->int64_value;
    printf("_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab__bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab__update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab__snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf(" digest mismatch: UPDATE failed\n");
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
static sqlite3_module vtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vtabRowid,
    /* xUpdate     */ vtabUpdate,
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
sqlite3_vtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vtabModule,
        pAux);
}
