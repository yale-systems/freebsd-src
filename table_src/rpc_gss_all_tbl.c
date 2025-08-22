#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_rpc_gss_all_gd_refs = 0,
    VT_rpc_gss_all_gd_lock = 1,
    VT_rpc_gss_all_gd_hash = 2,
    VT_rpc_gss_all_gd_auth = 3,
    VT_rpc_gss_all_gd_ucred = 4,
    VT_rpc_gss_all_gd_principal = 5,
    VT_rpc_gss_all_gd_clntprincipal = 6,
    VT_rpc_gss_all_gd_options = 7,
    VT_rpc_gss_all_gd_state = 8,
    VT_rpc_gss_all_gd_verf = 9,
    VT_rpc_gss_all_gd_clnt = 10,
    VT_rpc_gss_all_gd_mech = 11,
    VT_rpc_gss_all_gd_qop = 12,
    VT_rpc_gss_all_gd_ctx = 13,
    VT_rpc_gss_all_gd_cred = 14,
    VT_rpc_gss_all_gd_seq = 15,
    VT_rpc_gss_all_gd_win = 16,
    VT_rpc_gss_all_gd_reqs = 17,
    VT_rpc_gss_all_gd_link = 18,
    VT_rpc_gss_all_gd_alllink = 19,
    VT_rpc_gss_all_NUM_COLUMNS
};

static int
copy_columns(struct rpc_gss_all *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_rpc_gss_all_gd_refs] = new_osdb_int64(curEntry->gd_refs, context);
//    columns[VT_rpc_gss_all_gd_lock] =  TODO: Handle other types
    columns[VT_rpc_gss_all_gd_hash] = new_osdb_int64(curEntry->gd_hash, context);
//    columns[VT_rpc_gss_all_gd_auth] =  TODO: Handle other types
//    columns[VT_rpc_gss_all_gd_ucred] =  TODO: Handle other types
    columns[VT_rpc_gss_all_gd_principal] = new_osdb_text(curEntry->gd_principal, strlen(curEntry->gd_principal) + 1, context);
    columns[VT_rpc_gss_all_gd_clntprincipal] = new_osdb_text(curEntry->gd_clntprincipal, strlen(curEntry->gd_clntprincipal) + 1, context);
//    columns[VT_rpc_gss_all_gd_options] =  TODO: Handle other types
    columns[VT_rpc_gss_all_gd_state] = new_osdb_int64(static_cast<int64_t>(curEntry->gd_state), context); // TODO: need better enum representation 
//    columns[VT_rpc_gss_all_gd_verf] =  TODO: Handle other types
//    columns[VT_rpc_gss_all_gd_clnt] =  TODO: Handle other types
//    columns[VT_rpc_gss_all_gd_mech] =  TODO: Handle other types
    columns[VT_rpc_gss_all_gd_qop] = new_osdb_int64(curEntry->gd_qop, context);
//    columns[VT_rpc_gss_all_gd_ctx] =  TODO: Handle other types
//    columns[VT_rpc_gss_all_gd_cred] =  TODO: Handle other types
    columns[VT_rpc_gss_all_gd_seq] = new_osdb_int64(curEntry->gd_seq, context);
    columns[VT_rpc_gss_all_gd_win] = new_osdb_int64(curEntry->gd_win, context);
//    columns[VT_rpc_gss_all_gd_reqs] =  TODO: Handle other types
//    columns[VT_rpc_gss_all_gd_link] =  TODO: Handle other types
//    columns[VT_rpc_gss_all_gd_alllink] =  TODO: Handle other types

    return 0;
}
void
vtab_rpc_gss_data_list_lock(void)
{
    sx_slock(&rpc_gss_all_lock);
}

void
vtab_rpc_gss_data_list_unlock(void)
{
    sx_sunlock(&rpc_gss_all_lock);
}

void
vtab_rpc_gss_data_list_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct rpc_gss_data_list *prc = LIST_FIRST(&rpc_gss_all);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_rpc_gss_all_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_rpc_gss_all_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("rpc_gss_data_list digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_rpc_gss_data_list_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_rpc_gss_all_PID];
    *pRowid = pid_value->int64_value;
    printf("rpc_gss_data_list_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_rpc_gss_data_list_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_rpc_gss_data_list_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_rpc_gss_data_list_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("rpc_gss_data_list digest mismatch: UPDATE failed\n");
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
static sqlite3_module rpc_gss_data_listvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ rpc_gss_data_listvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ rpc_gss_data_listvtabRowid,
    /* xUpdate     */ rpc_gss_data_listvtabUpdate,
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
sqlite3_rpc_gss_data_listvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &rpc_gss_data_listvtabModule,
        pAux);
}
