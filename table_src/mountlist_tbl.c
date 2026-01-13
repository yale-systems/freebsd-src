#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_mountlist_mnt_vfs_ops = 0,
    VT_mountlist_mnt_kern_flag = 1,
    VT_mountlist_mnt_flag = 2,
    VT_mountlist_mnt_pcpu = 3,
    VT_mountlist_mnt_rootvnode = 4,
    VT_mountlist_mnt_vnodecovered = 5,
    VT_mountlist_mnt_op = 6,
    VT_mountlist_mnt_vfc = 7,
    VT_mountlist_mnt_mtx = 8,
    VT_mountlist_mnt_gen = 9,
    VT_mountlist_mnt_list = 10,
    VT_mountlist_mnt_syncer = 11,
    VT_mountlist_mnt_ref = 12,
    VT_mountlist_mnt_nvnodelist = 13,
    VT_mountlist_mnt_nvnodelistsize = 14,
    VT_mountlist_mnt_writeopcount = 15,
    VT_mountlist_mnt_opt = 16,
    VT_mountlist_mnt_optnew = 17,
    VT_mountlist_mnt_stat = 18,
    VT_mountlist_mnt_cred = 19,
    VT_mountlist_mnt_data = 20,
    VT_mountlist_mnt_time = 21,
    VT_mountlist_mnt_iosize_max = 22,
    VT_mountlist_mnt_export = 23,
    VT_mountlist_mnt_label = 24,
    VT_mountlist_mnt_hashseed = 25,
    VT_mountlist_mnt_lockref = 26,
    VT_mountlist_mnt_secondary_writes = 27,
    VT_mountlist_mnt_secondary_accwrites = 28,
    VT_mountlist_mnt_susp_owner = 29,
    VT_mountlist_mnt_exjail = 30,
    VT_mountlist_mnt_gjprovider = 31,
    VT_mountlist_mnt_listmtx = 32,
    VT_mountlist_mnt_lazyvnodelist = 33,
    VT_mountlist_mnt_lazyvnodelistsize = 34,
    VT_mountlist_mnt_upper_pending = 35,
    VT_mountlist_mnt_explock = 36,
    VT_mountlist_mnt_uppers = 37,
    VT_mountlist_mnt_notify = 38,
    VT_mountlist_mnt_taskqueue_link = 39,
    VT_mountlist_mnt_taskqueue_flags = 40,
    VT_mountlist_mnt_unmount_retries = 41,
    VT_mountlist_NUM_COLUMNS
};

static int
copy_columns(struct mountlist *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_mountlist_mnt_vfs_ops] = new_osdb_int64(curEntry->mnt_vfs_ops, context);
    columns[VT_mountlist_mnt_kern_flag] = new_osdb_int64(curEntry->mnt_kern_flag, context);
    columns[VT_mountlist_mnt_flag] = new_osdb_int64(curEntry->mnt_flag, context);
//    columns[VT_mountlist_mnt_pcpu] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_rootvnode] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_vnodecovered] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_op] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_vfc] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_mtx] =  TODO: Handle other types
    columns[VT_mountlist_mnt_gen] = new_osdb_int64(curEntry->mnt_gen, context);
//    columns[VT_mountlist_mnt_list] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_syncer] =  TODO: Handle other types
    columns[VT_mountlist_mnt_ref] = new_osdb_int64(curEntry->mnt_ref, context);
//    columns[VT_mountlist_mnt_nvnodelist] =  TODO: Handle other types
    columns[VT_mountlist_mnt_nvnodelistsize] = new_osdb_int64(curEntry->mnt_nvnodelistsize, context);
    columns[VT_mountlist_mnt_writeopcount] = new_osdb_int64(curEntry->mnt_writeopcount, context);
//    columns[VT_mountlist_mnt_opt] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_optnew] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_stat] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_cred] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_data] =  TODO: Handle other types
    columns[VT_mountlist_mnt_time] = new_osdb_int64(curEntry->mnt_time, context);
    columns[VT_mountlist_mnt_iosize_max] = new_osdb_int64(curEntry->mnt_iosize_max, context);
//    columns[VT_mountlist_mnt_export] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_label] =  TODO: Handle other types
    columns[VT_mountlist_mnt_hashseed] = new_osdb_int64(curEntry->mnt_hashseed, context);
    columns[VT_mountlist_mnt_lockref] = new_osdb_int64(curEntry->mnt_lockref, context);
    columns[VT_mountlist_mnt_secondary_writes] = new_osdb_int64(curEntry->mnt_secondary_writes, context);
    columns[VT_mountlist_mnt_secondary_accwrites] = new_osdb_int64(curEntry->mnt_secondary_accwrites, context);
//    columns[VT_mountlist_mnt_susp_owner] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_exjail] =  TODO: Handle other types
    columns[VT_mountlist_mnt_gjprovider] = new_osdb_text(curEntry->mnt_gjprovider, strlen(curEntry->mnt_gjprovider) + 1, context);
//    columns[VT_mountlist_mnt_listmtx] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_lazyvnodelist] =  TODO: Handle other types
    columns[VT_mountlist_mnt_lazyvnodelistsize] = new_osdb_int64(curEntry->mnt_lazyvnodelistsize, context);
    columns[VT_mountlist_mnt_upper_pending] = new_osdb_int64(curEntry->mnt_upper_pending, context);
//    columns[VT_mountlist_mnt_explock] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_uppers] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_notify] =  TODO: Handle other types
//    columns[VT_mountlist_mnt_taskqueue_link] =  TODO: Handle other types
    columns[VT_mountlist_mnt_taskqueue_flags] = new_osdb_int64(curEntry->mnt_taskqueue_flags, context);
    columns[VT_mountlist_mnt_unmount_retries] = new_osdb_int64(curEntry->mnt_unmount_retries, context);

    return 0;
}
void
vtab_mntlist_lock(void)
{
    sx_slock(&mountlist_lock);
}

void
vtab_mntlist_unlock(void)
{
    sx_sunlock(&mountlist_lock);
}

void
vtab_mntlist_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct mntlist *prc = LIST_FIRST(&mountlist);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_mountlist_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_mountlist_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("mntlist digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_mntlist_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_mountlist_PID];
    *pRowid = pid_value->int64_value;
    printf("mntlist_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_mntlist_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_mntlist_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_mntlist_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("mntlist digest mismatch: UPDATE failed\n");
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
static sqlite3_module mntlistvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ mntlistvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ mntlistvtabRowid,
    /* xUpdate     */ mntlistvtabUpdate,
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
sqlite3_mntlistvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &mntlistvtabModule,
        pAux);
}
