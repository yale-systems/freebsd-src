#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/svc_rpc_gss_client.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_svc_rpc_gss_client.h"

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
copy_columns(struct svc_rpc_gss_client *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_link] =  /* Unsupported type */
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_alllink] =  /* Unsupported type */
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_refs] = new_dbsc_int64(curEntry->cl_refs, context);
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_lock] =  /* Unsupported type */
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_id] =  /* Unsupported type */
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_expiration] = new_dbsc_int64(curEntry->cl_expiration, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_state] = new_dbsc_int64((int64_t)(curEntry->cl_state), context); // TODO: need better enum representation 
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_locked] = new_dbsc_int64(curEntry->cl_locked, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_ctx] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cl_ctx, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_creds] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cl_creds, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_cname] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cl_cname, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_sname] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cl_sname, context);
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_rawcred] =  /* Unsupported type */
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_ucred] =  /* Unsupported type */
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_cred] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cl_cred, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_rpcflavor] = new_dbsc_int64(curEntry->cl_rpcflavor, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_done_callback] = new_dbsc_int64(curEntry->cl_done_callback, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_cookie] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cl_cookie, context);
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_gid_storage] =  /* Unsupported type */
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_mech] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cl_mech, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_qop] = new_dbsc_int64(curEntry->cl_qop, context);
    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_seqlast] = new_dbsc_int64(curEntry->cl_seqlast, context);
//    columns[VT_vnet_entry_svc_rpc_gss_clients_cl_seqmask] =  /* Unsupported type */

    return 0;
}
void
vtab_svc_rpc_gss_client_lock(void)
{
    sx_slock(&vnet_entry_svc_rpc_gss_clients_lock);
}

void
vtab_svc_rpc_gss_client_unlock(void)
{
    sx_sunlock(&vnet_entry_svc_rpc_gss_clients_lock);
}

void
vtab_svc_rpc_gss_client_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct svc_rpc_gss_client *prc = LIST_FIRST(&vnet_entry_svc_rpc_gss_clients);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_svc_rpc_gss_clients_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_vnet_entry_svc_rpc_gss_clients_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("svc_rpc_gss_client digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
svc_rpc_gss_clientvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_vnet_entry_svc_rpc_gss_clients_p_pid];
    *pRowid = pid_value->int64_value;
    printf("svc_rpc_gss_client_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
svc_rpc_gss_clientvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
svc_rpc_gss_clientvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_svc_rpc_gss_client_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("svc_rpc_gss_client digest mismatch: UPDATE failed\n");
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
static sqlite3_module svc_rpc_gss_clientvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ svc_rpc_gss_clientvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ svc_rpc_gss_clientvtabRowid,
    /* xUpdate     */ svc_rpc_gss_clientvtabUpdate,
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
sqlite3_svc_rpc_gss_clientvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &svc_rpc_gss_clientvtabModule,
        pAux);
}
void vtab_svc_rpc_gss_client_serialize(sqlite3 *real_db, struct timespec when) {
    struct svc_rpc_gss_client *entry = LIST_FIRST(&vnet_entry_svc_rpc_gss_clients);

    const char *create_stmt =
        "CREATE TABLE all_svc_rpc_gss_clients (cl_refs INTEGER, cl_expiration INTEGER, cl_state INTEGER, cl_locked INTEGER, cl_rpcflavor INTEGER, cl_done_callback INTEGER, cl_qop INTEGER, cl_seqlast INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_svc_rpc_gss_clients VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->cl_refs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cl_expiration);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cl_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cl_locked);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cl_rpcflavor);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cl_done_callback);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cl_qop);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cl_seqlast);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

