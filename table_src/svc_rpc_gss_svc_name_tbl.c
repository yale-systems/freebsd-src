#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/svc_rpc_gss_svc_name.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_svc_rpc_gss_svc_name.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_vnet_entry_svc_rpc_gss_svc_names_sn_link = 0,
    VT_vnet_entry_svc_rpc_gss_svc_names_sn_principal = 1,
    VT_vnet_entry_svc_rpc_gss_svc_names_sn_mech = 2,
    VT_vnet_entry_svc_rpc_gss_svc_names_sn_req_time = 3,
    VT_vnet_entry_svc_rpc_gss_svc_names_sn_cred = 4,
    VT_vnet_entry_svc_rpc_gss_svc_names_sn_program = 5,
    VT_vnet_entry_svc_rpc_gss_svc_names_sn_version = 6,
    VT_vnet_entry_svc_rpc_gss_svc_names_NUM_COLUMNS
};

static int
copy_columns(struct svc_rpc_gss_svc_name *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vnet_entry_svc_rpc_gss_svc_names_sn_link] =  /* Unsupported type */
    columns[VT_vnet_entry_svc_rpc_gss_svc_names_sn_principal] = new_dbsc_text(curEntry->sn_principal, strlen(curEntry->sn_principal) + 1, context);
    columns[VT_vnet_entry_svc_rpc_gss_svc_names_sn_mech] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sn_mech, context);
    columns[VT_vnet_entry_svc_rpc_gss_svc_names_sn_req_time] = new_dbsc_int64(curEntry->sn_req_time, context);
    columns[VT_vnet_entry_svc_rpc_gss_svc_names_sn_cred] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sn_cred, context);
    columns[VT_vnet_entry_svc_rpc_gss_svc_names_sn_program] = new_dbsc_int64(curEntry->sn_program, context);
    columns[VT_vnet_entry_svc_rpc_gss_svc_names_sn_version] = new_dbsc_int64(curEntry->sn_version, context);

    return 0;
}
void
vtab_svc_rpc_gss_svc_name_lock(void)
{
    sx_slock(&vnet_entry_svc_rpc_gss_svc_names_lock);
}

void
vtab_svc_rpc_gss_svc_name_unlock(void)
{
    sx_sunlock(&vnet_entry_svc_rpc_gss_svc_names_lock);
}

void
vtab_svc_rpc_gss_svc_name_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct svc_rpc_gss_svc_name *prc = LIST_FIRST(&vnet_entry_svc_rpc_gss_svc_names);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_svc_rpc_gss_svc_names_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_vnet_entry_svc_rpc_gss_svc_names_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("svc_rpc_gss_svc_name digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
svc_rpc_gss_svc_namevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_vnet_entry_svc_rpc_gss_svc_names_p_pid];
    *pRowid = pid_value->int64_value;
    printf("svc_rpc_gss_svc_name_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
svc_rpc_gss_svc_namevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
svc_rpc_gss_svc_namevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_svc_rpc_gss_svc_name_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("svc_rpc_gss_svc_name digest mismatch: UPDATE failed\n");
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
static sqlite3_module svc_rpc_gss_svc_namevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ svc_rpc_gss_svc_namevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ svc_rpc_gss_svc_namevtabRowid,
    /* xUpdate     */ svc_rpc_gss_svc_namevtabUpdate,
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
sqlite3_svc_rpc_gss_svc_namevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &svc_rpc_gss_svc_namevtabModule,
        pAux);
}
void vtab_svc_rpc_gss_svc_name_serialize(sqlite3 *real_db, struct timespec when) {
    struct svc_rpc_gss_svc_name *entry = LIST_FIRST(&vnet_entry_svc_rpc_gss_svc_names);

    const char *create_stmt =
        "CREATE TABLE all_svc_rpc_gss_svc_names (sn_principal TEXT, sn_req_time INTEGER, sn_program INTEGER, sn_version INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_svc_rpc_gss_svc_names VALUES (?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->sn_principal, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sn_req_time);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sn_program);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sn_version);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

