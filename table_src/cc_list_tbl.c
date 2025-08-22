#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_cc_list_name = 0,
    VT_cc_list_mod_init = 1,
    VT_cc_list_mod_destroy = 2,
    VT_cc_list_cc_data_sz = 3,
    VT_cc_list_cb_init = 4,
    VT_cc_list_cb_destroy = 5,
    VT_cc_list_conn_init = 6,
    VT_cc_list_ack_received = 7,
    VT_cc_list_cong_signal = 8,
    VT_cc_list_post_recovery = 9,
    VT_cc_list_after_idle = 10,
    VT_cc_list_ecnpkt_handler = 11,
    VT_cc_list_newround = 12,
    VT_cc_list_rttsample = 13,
    VT_cc_list_ctl_output = 14,
    VT_cc_list_entries = 15,
    VT_cc_list_cc_refcount = 16,
    VT_cc_list_flags = 17,
    VT_cc_list_NUM_COLUMNS
};

static int
copy_columns(struct cc_list *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_cc_list_name] =  TODO: Handle other types
//    columns[VT_cc_list_mod_init] =  TODO: Handle other types
//    columns[VT_cc_list_mod_destroy] =  TODO: Handle other types
//    columns[VT_cc_list_cc_data_sz] =  TODO: Handle other types
//    columns[VT_cc_list_cb_init] =  TODO: Handle other types
//    columns[VT_cc_list_cb_destroy] =  TODO: Handle other types
//    columns[VT_cc_list_conn_init] =  TODO: Handle other types
//    columns[VT_cc_list_ack_received] =  TODO: Handle other types
//    columns[VT_cc_list_cong_signal] =  TODO: Handle other types
//    columns[VT_cc_list_post_recovery] =  TODO: Handle other types
//    columns[VT_cc_list_after_idle] =  TODO: Handle other types
//    columns[VT_cc_list_ecnpkt_handler] =  TODO: Handle other types
//    columns[VT_cc_list_newround] =  TODO: Handle other types
//    columns[VT_cc_list_rttsample] =  TODO: Handle other types
//    columns[VT_cc_list_ctl_output] =  TODO: Handle other types
//    columns[VT_cc_list_entries] =  TODO: Handle other types
    columns[VT_cc_list_cc_refcount] = new_osdb_int64(curEntry->cc_refcount, context);
    columns[VT_cc_list_flags] = new_osdb_int64(curEntry->flags, context);

    return 0;
}
void
vtab_cc_head_lock(void)
{
    sx_slock(&cc_list_lock);
}

void
vtab_cc_head_unlock(void)
{
    sx_sunlock(&cc_list_lock);
}

void
vtab_cc_head_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cc_head *prc = LIST_FIRST(&cc_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_cc_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_cc_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cc_head digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_cc_head_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_cc_list_PID];
    *pRowid = pid_value->int64_value;
    printf("cc_head_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_cc_head_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_cc_head_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cc_head_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cc_head digest mismatch: UPDATE failed\n");
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
static sqlite3_module cc_headvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cc_headvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cc_headvtabRowid,
    /* xUpdate     */ cc_headvtabUpdate,
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
sqlite3_cc_headvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cc_headvtabModule,
        pAux);
}
