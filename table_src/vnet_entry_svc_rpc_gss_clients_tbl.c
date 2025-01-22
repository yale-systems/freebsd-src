#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_vnet_entry_svc_rpc_gss_clients_cl_link = 0,
    VT_vnet_entry_svc_rpc_gss_clients_cl_alllink = 1,
    VT_vnet_entry_svc_rpc_gss_clients_cl_refs = 2,
    VT_vnet_entry_svc_rpc_gss_clients_cl_lock = 3,
    VT_vnet_entry_svc_rpc_gss_clients_cl_id = 4,
    VT_vnet_entry_svc_rpc_gss_clients_cl_expiration = 5,
    VT_vnet_entry_svc_rpc_gss_clients_cl_state = 6,
    VT_vnet_entry_svc_rpc_gss_clients_cl_locked = 7,
    VT_vnet_entry_svc_rpc_gss_clients_cl_ctx = 8,
    VT_vnet_entry_svc_rpc_gss_clients_cl_creds = 9,
    VT_vnet_entry_svc_rpc_gss_clients_cl_cname = 10,
    VT_vnet_entry_svc_rpc_gss_clients_cl_sname = 11,
    VT_vnet_entry_svc_rpc_gss_clients_cl_rawcred = 12,
    VT_vnet_entry_svc_rpc_gss_clients_cl_ucred = 13,
    VT_vnet_entry_svc_rpc_gss_clients_cl_cred = 14,
    VT_vnet_entry_svc_rpc_gss_clients_cl_rpcflavor = 15,
    VT_vnet_entry_svc_rpc_gss_clients_cl_done_callback = 16,
    VT_vnet_entry_svc_rpc_gss_clients_cl_cookie = 17,
    VT_vnet_entry_svc_rpc_gss_clients_cl_gid_storage = 18,
    VT_vnet_entry_svc_rpc_gss_clients_cl_mech = 19,
    VT_vnet_entry_svc_rpc_gss_clients_cl_qop = 20,
    VT_vnet_entry_svc_rpc_gss_clients_cl_seqlast = 21,
    VT_vnet_entry_svc_rpc_gss_clients_cl_seqmask = 22,
    VT_vnet_entry_svc_rpc_gss_clients_NUM_COLUMNS
};

static int
copy_columns(struct vnet_entry_svc_rpc_gss_clients *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_link] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_alllink] =  TODO: Handle other types
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_refs] = new_osdb_int64(curEntry->cl_refs, context);
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_lock] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_id] =  TODO: Handle other types
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_expiration] = new_osdb_int64(curEntry->cl_expiration, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_state] = new_osdb_int64(static_cast<int64_t>(curEntry->cl_state), context); // TODO: need better enum representation 
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_locked] = new_osdb_int64(curEntry->cl_locked, context);
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_ctx] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_creds] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_cname] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_sname] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_rawcred] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_ucred] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_cred] =  TODO: Handle other types
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_rpcflavor] = new_osdb_int64(curEntry->cl_rpcflavor, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_done_callback] = new_osdb_int64(curEntry->cl_done_callback, context);
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_cookie] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_gid_storage] =  TODO: Handle other types
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_mech] =  TODO: Handle other types
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_qop] = new_osdb_int64(curEntry->cl_qop, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_seqlast] = new_osdb_int64(curEntry->cl_seqlast, context);
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_seqmask] =  TODO: Handle other types

    return 0;
}
void
vtab_svc_rpc_gss_client_list_lock(void)
{
    sx_slock(&vnet_entry_svc_rpc_gss_clients_lock);
}

void
vtab_svc_rpc_gss_client_list_unlock(void)
{
    sx_sunlock(&vnet_entry_svc_rpc_gss_clients_lock);
}

void
vtab_svc_rpc_gss_client_list_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct svc_rpc_gss_client_list *prc = LIST_FIRST(&vnet_entry_svc_rpc_gss_clients);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_svc_rpc_gss_clients_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_vnet_entry_svc_rpc_gss_clients_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("svc_rpc_gss_client_list digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_svc_rpc_gss_client_list_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_vnet_entry_svc_rpc_gss_clients_PID];
    *pRowid = pid_value->int64_value;
    printf("svc_rpc_gss_client_list_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_svc_rpc_gss_client_list_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_svc_rpc_gss_client_list_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_svc_rpc_gss_client_list_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("svc_rpc_gss_client_list digest mismatch: UPDATE failed\n");
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
static sqlite3_module svc_rpc_gss_client_listvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ svc_rpc_gss_client_listvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ svc_rpc_gss_client_listvtabRowid,
    /* xUpdate     */ svc_rpc_gss_client_listvtabUpdate,
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
sqlite3_svc_rpc_gss_client_listvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &svc_rpc_gss_client_listvtabModule,
        pAux);
}
