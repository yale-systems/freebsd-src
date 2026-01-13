#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_nlm_hosts_nh_lock = 0,
    VT_nlm_hosts_nh_refs = 1,
    VT_nlm_hosts_nh_link = 2,
    VT_nlm_hosts_nh_caller_name = 3,
    VT_nlm_hosts_nh_sysid = 4,
    VT_nlm_hosts_nh_sysid_string = 5,
    VT_nlm_hosts_nh_addr = 6,
    VT_nlm_hosts_nh_srvrpc = 7,
    VT_nlm_hosts_nh_clntrpc = 8,
    VT_nlm_hosts_nh_vers = 9,
    VT_nlm_hosts_nh_state = 10,
    VT_nlm_hosts_nh_monstate = 11,
    VT_nlm_hosts_nh_idle_timeout = 12,
    VT_nlm_hosts_nh_sysctl = 13,
    VT_nlm_hosts_nh_grantcookie = 14,
    VT_nlm_hosts_nh_pending = 15,
    VT_nlm_hosts_nh_granted = 16,
    VT_nlm_hosts_nh_finished = 17,
    VT_nlm_hosts_NUM_COLUMNS
};

static int
copy_columns(struct nlm_hosts *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_nlm_hosts_nh_lock] =  TODO: Handle other types
    columns[VT_nlm_hosts_nh_refs] = new_osdb_int64(curEntry->nh_refs, context);
//    columns[VT_nlm_hosts_nh_link] =  TODO: Handle other types
//    columns[VT_nlm_hosts_nh_caller_name] =  TODO: Handle other types
    columns[VT_nlm_hosts_nh_sysid] = new_osdb_int64(curEntry->nh_sysid, context);
//    columns[VT_nlm_hosts_nh_sysid_string] =  TODO: Handle other types
//    columns[VT_nlm_hosts_nh_addr] =  TODO: Handle other types
//    columns[VT_nlm_hosts_nh_srvrpc] =  TODO: Handle other types
//    columns[VT_nlm_hosts_nh_clntrpc] =  TODO: Handle other types
    columns[VT_nlm_hosts_nh_vers] = new_osdb_int64(curEntry->nh_vers, context);
    columns[VT_nlm_hosts_nh_state] = new_osdb_int64(curEntry->nh_state, context);
    columns[VT_nlm_hosts_nh_monstate] = new_osdb_int64(static_cast<int64_t>(curEntry->nh_monstate), context); // TODO: need better enum representation 
    columns[VT_nlm_hosts_nh_idle_timeout] = new_osdb_int64(curEntry->nh_idle_timeout, context);
//    columns[VT_nlm_hosts_nh_sysctl] =  TODO: Handle other types
    columns[VT_nlm_hosts_nh_grantcookie] = new_osdb_int64(curEntry->nh_grantcookie, context);
//    columns[VT_nlm_hosts_nh_pending] =  TODO: Handle other types
//    columns[VT_nlm_hosts_nh_granted] =  TODO: Handle other types
//    columns[VT_nlm_hosts_nh_finished] =  TODO: Handle other types

    return 0;
}
void
vtab_nlm_host_list_lock(void)
{
    sx_slock(&nlm_hosts_lock);
}

void
vtab_nlm_host_list_unlock(void)
{
    sx_sunlock(&nlm_hosts_lock);
}

void
vtab_nlm_host_list_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct nlm_host_list *prc = LIST_FIRST(&nlm_hosts);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_nlm_hosts_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_nlm_hosts_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("nlm_host_list digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_nlm_host_list_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_nlm_hosts_PID];
    *pRowid = pid_value->int64_value;
    printf("nlm_host_list_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_nlm_host_list_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_nlm_host_list_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_nlm_host_list_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("nlm_host_list digest mismatch: UPDATE failed\n");
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
static sqlite3_module nlm_host_listvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ nlm_host_listvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ nlm_host_listvtabRowid,
    /* xUpdate     */ nlm_host_listvtabUpdate,
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
sqlite3_nlm_host_listvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &nlm_host_listvtabModule,
        pAux);
}
