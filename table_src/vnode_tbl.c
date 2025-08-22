#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_vnode.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_mnt_nvnodelist_v_type = 0,
    VT_mnt_nvnodelist_v_state = 1,
    VT_mnt_nvnodelist_v_irflag = 2,
    VT_mnt_nvnodelist_v_seqc = 3,
    VT_mnt_nvnodelist_v_nchash = 4,
    VT_mnt_nvnodelist_v_hash = 5,
    VT_mnt_nvnodelist_v_op = 6,
    VT_mnt_nvnodelist_v_data = 7,
    VT_mnt_nvnodelist_v_mount = 8,
    VT_mnt_nvnodelist_v_nmntvnodes = 9,
    VT_mnt_nvnodelist_ = 10,
    VT_mnt_nvnodelist_v_hashlist = 11,
    VT_mnt_nvnodelist_v_cache_src = 12,
    VT_mnt_nvnodelist_v_cache_dst = 13,
    VT_mnt_nvnodelist_v_cache_dd = 14,
    VT_mnt_nvnodelist_v_lock = 15,
    VT_mnt_nvnodelist_v_interlock = 16,
    VT_mnt_nvnodelist_v_vnlock = 17,
    VT_mnt_nvnodelist_v_vnodelist = 18,
    VT_mnt_nvnodelist_v_lazylist = 19,
    VT_mnt_nvnodelist_v_bufobj = 20,
    VT_mnt_nvnodelist_v_pollinfo = 21,
    VT_mnt_nvnodelist_v_label = 22,
    VT_mnt_nvnodelist_v_lockf = 23,
    VT_mnt_nvnodelist_v_rl = 24,
    VT_mnt_nvnodelist_v_holdcnt = 25,
    VT_mnt_nvnodelist_v_usecount = 26,
    VT_mnt_nvnodelist_v_iflag = 27,
    VT_mnt_nvnodelist_v_vflag = 28,
    VT_mnt_nvnodelist_v_mflag = 29,
    VT_mnt_nvnodelist_v_dbatchcpu = 30,
    VT_mnt_nvnodelist_v_writecount = 31,
    VT_mnt_nvnodelist_v_seqc_users = 32,
    VT_mnt_nvnodelist_NUM_COLUMNS
};

static int
copy_columns(struct vnode *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_mnt_nvnodelist_v_type] = new_dbsc_int64((int64_t)(curEntry->v_type), context); // TODO: need better enum representation 
    columns[VT_mnt_nvnodelist_v_state] = new_dbsc_int64((int64_t)(curEntry->v_state), context); // TODO: need better enum representation 
    columns[VT_mnt_nvnodelist_v_irflag] = new_dbsc_int64(curEntry->v_irflag, context);
    columns[VT_mnt_nvnodelist_v_seqc] = new_dbsc_int64(curEntry->v_seqc, context);
    columns[VT_mnt_nvnodelist_v_nchash] = new_dbsc_int64(curEntry->v_nchash, context);
    columns[VT_mnt_nvnodelist_v_hash] = new_dbsc_int64(curEntry->v_hash, context);
    columns[VT_mnt_nvnodelist_v_op] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_op, context);
    columns[VT_mnt_nvnodelist_v_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_data, context);
    columns[VT_mnt_nvnodelist_v_mount] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_mount, context);
//    columns[VT_mnt_nvnodelist_v_nmntvnodes] =  /* Unsupported type */
//    columns[VT_mnt_nvnodelist_] =  /* Unsupported type */
//    columns[VT_mnt_nvnodelist_v_hashlist] =  /* Unsupported type */
//    columns[VT_mnt_nvnodelist_v_cache_src] =  /* Unsupported type */
//    columns[VT_mnt_nvnodelist_v_cache_dst] =  /* Unsupported type */
    columns[VT_mnt_nvnodelist_v_cache_dd] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_cache_dd, context);
//    columns[VT_mnt_nvnodelist_v_lock] =  /* Unsupported type */
//    columns[VT_mnt_nvnodelist_v_interlock] =  /* Unsupported type */
    columns[VT_mnt_nvnodelist_v_vnlock] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_vnlock, context);
//    columns[VT_mnt_nvnodelist_v_vnodelist] =  /* Unsupported type */
//    columns[VT_mnt_nvnodelist_v_lazylist] =  /* Unsupported type */
//    columns[VT_mnt_nvnodelist_v_bufobj] =  /* Unsupported type */
    columns[VT_mnt_nvnodelist_v_pollinfo] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_pollinfo, context);
    columns[VT_mnt_nvnodelist_v_label] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_label, context);
    columns[VT_mnt_nvnodelist_v_lockf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_lockf, context);
//    columns[VT_mnt_nvnodelist_v_rl] =  /* Unsupported type */
    columns[VT_mnt_nvnodelist_v_holdcnt] = new_dbsc_int64(curEntry->v_holdcnt, context);
    columns[VT_mnt_nvnodelist_v_usecount] = new_dbsc_int64(curEntry->v_usecount, context);
    columns[VT_mnt_nvnodelist_v_iflag] = new_dbsc_int64(curEntry->v_iflag, context);
    columns[VT_mnt_nvnodelist_v_vflag] = new_dbsc_int64(curEntry->v_vflag, context);
    columns[VT_mnt_nvnodelist_v_mflag] = new_dbsc_int64(curEntry->v_mflag, context);
    columns[VT_mnt_nvnodelist_v_dbatchcpu] = new_dbsc_int64(curEntry->v_dbatchcpu, context);
    columns[VT_mnt_nvnodelist_v_writecount] = new_dbsc_int64(curEntry->v_writecount, context);
    columns[VT_mnt_nvnodelist_v_seqc_users] = new_dbsc_int64(curEntry->v_seqc_users, context);

    return 0;
}
void
vtab_vnode_lock(void)
{
    sx_slock(&mnt_nvnodelist_lock);
}

void
vtab_vnode_unlock(void)
{
    sx_sunlock(&mnt_nvnodelist_lock);
}

void
vtab_vnode_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct vnode *prc = LIST_FIRST(&mnt_nvnodelist);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_mnt_nvnodelist_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_mnt_nvnodelist_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("vnode digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vnodevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_mnt_nvnodelist_p_pid];
    *pRowid = pid_value->int64_value;
    printf("vnode_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vnodevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
vnodevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_vnode_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("vnode digest mismatch: UPDATE failed\n");
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
static sqlite3_module vnodevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vnodevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vnodevtabRowid,
    /* xUpdate     */ vnodevtabUpdate,
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
sqlite3_vnodevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vnodevtabModule,
        pAux);
}
void vtab_vnode_serialize(sqlite3 *real_db, struct timespec when) {
    struct vnode *entry = LIST_FIRST(&mnt_nvnodelist);

    const char *create_stmt =
        "CREATE TABLE all_vnodes (v_type INTEGER, v_state INTEGER, v_irflag INTEGER, v_seqc INTEGER, v_nchash INTEGER, v_hash INTEGER, v_holdcnt INTEGER, v_usecount INTEGER, v_iflag INTEGER, v_vflag INTEGER, v_mflag INTEGER, v_dbatchcpu INTEGER, v_writecount INTEGER, v_seqc_users INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_vnodes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_irflag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_seqc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_nchash);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_hash);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_holdcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_usecount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_iflag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_vflag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_mflag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_dbatchcpu);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_writecount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_seqc_users);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

