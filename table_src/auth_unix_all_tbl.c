#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_auth_unix_all_au_link = 0,
    VT_auth_unix_all_au_alllink = 1,
    VT_auth_unix_all_au_refs = 2,
    VT_auth_unix_all_au_xcred = 3,
    VT_auth_unix_all_au_origcred = 4,
    VT_auth_unix_all_au_shcred = 5,
    VT_auth_unix_all_au_shfaults = 6,
    VT_auth_unix_all_au_marshed = 7,
    VT_auth_unix_all_au_mpos = 8,
    VT_auth_unix_all_au_auth = 9,
    VT_auth_unix_all_NUM_COLUMNS
};

static int
copy_columns(struct auth_unix_all *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_auth_unix_all_au_link] =  TODO: Handle other types
//    columns[VT_auth_unix_all_au_alllink] =  TODO: Handle other types
    columns[VT_auth_unix_all_au_refs] = new_osdb_int64(curEntry->au_refs, context);
//    columns[VT_auth_unix_all_au_xcred] =  TODO: Handle other types
//    columns[VT_auth_unix_all_au_origcred] =  TODO: Handle other types
//    columns[VT_auth_unix_all_au_shcred] =  TODO: Handle other types
    columns[VT_auth_unix_all_au_shfaults] = new_osdb_int64(curEntry->au_shfaults, context);
//    columns[VT_auth_unix_all_au_marshed] =  TODO: Handle other types
    columns[VT_auth_unix_all_au_mpos] = new_osdb_int64(curEntry->au_mpos, context);
//    columns[VT_auth_unix_all_au_auth] =  TODO: Handle other types

    return 0;
}
void
vtab_audata_list_lock(void)
{
    sx_slock(&auth_unix_all_lock);
}

void
vtab_audata_list_unlock(void)
{
    sx_sunlock(&auth_unix_all_lock);
}

void
vtab_audata_list_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct audata_list *prc = LIST_FIRST(&auth_unix_all);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_auth_unix_all_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_auth_unix_all_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("audata_list digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_audata_list_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_auth_unix_all_PID];
    *pRowid = pid_value->int64_value;
    printf("audata_list_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_audata_list_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_audata_list_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_audata_list_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("audata_list digest mismatch: UPDATE failed\n");
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
static sqlite3_module audata_listvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ audata_listvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ audata_listvtabRowid,
    /* xUpdate     */ audata_listvtabUpdate,
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
sqlite3_audata_listvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &audata_listvtabModule,
        pAux);
}
