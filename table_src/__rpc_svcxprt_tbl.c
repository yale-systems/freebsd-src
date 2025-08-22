#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/__rpc_svcxprt.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab___rpc_svcxprt.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sg_xlist_xp_refs = 0,
    VT_sg_xlist_xp_lock = 1,
    VT_sg_xlist_xp_pool = 2,
    VT_sg_xlist_xp_group = 3,
    VT_sg_xlist_xp_link = 4,
    VT_sg_xlist_xp_alink = 5,
    VT_sg_xlist_xp_registered = 6,
    VT_sg_xlist_xp_active = 7,
    VT_sg_xlist_xp_thread = 8,
    VT_sg_xlist_xp_socket = 9,
    VT_sg_xlist_xp_ops = 10,
    VT_sg_xlist_xp_netid = 11,
    VT_sg_xlist_xp_ltaddr = 12,
    VT_sg_xlist_xp_rtaddr = 13,
    VT_sg_xlist_xp_p1 = 14,
    VT_sg_xlist_xp_p2 = 15,
    VT_sg_xlist_xp_p3 = 16,
    VT_sg_xlist_xp_type = 17,
    VT_sg_xlist_xp_idletimeout = 18,
    VT_sg_xlist_xp_lastactive = 19,
    VT_sg_xlist_xp_sockref = 20,
    VT_sg_xlist_xp_upcallset = 21,
    VT_sg_xlist_xp_snd_cnt = 22,
    VT_sg_xlist_xp_snt_cnt = 23,
    VT_sg_xlist_xp_dontrcv = 24,
    VT_sg_xlist_xp_tls = 25,
    VT_sg_xlist_xp_sslsec = 26,
    VT_sg_xlist_xp_sslusec = 27,
    VT_sg_xlist_xp_sslrefno = 28,
    VT_sg_xlist_xp_sslproc = 29,
    VT_sg_xlist_xp_ngrps = 30,
    VT_sg_xlist_xp_uid = 31,
    VT_sg_xlist_xp_gidp = 32,
    VT_sg_xlist_xp_doneddp = 33,
    VT_sg_xlist_NUM_COLUMNS
};

static int
copy_columns(struct __rpc_svcxprt *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_sg_xlist_xp_refs] = new_dbsc_int64(curEntry->xp_refs, context);
//    columns[VT_sg_xlist_xp_lock] =  /* Unsupported type */
    columns[VT_sg_xlist_xp_pool] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xp_pool, context);
    columns[VT_sg_xlist_xp_group] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xp_group, context);
//    columns[VT_sg_xlist_xp_link] =  /* Unsupported type */
//    columns[VT_sg_xlist_xp_alink] =  /* Unsupported type */
    columns[VT_sg_xlist_xp_registered] = new_dbsc_int64(curEntry->xp_registered, context);
    columns[VT_sg_xlist_xp_active] = new_dbsc_int64(curEntry->xp_active, context);
    columns[VT_sg_xlist_xp_thread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xp_thread, context);
    columns[VT_sg_xlist_xp_socket] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xp_socket, context);
    columns[VT_sg_xlist_xp_ops] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xp_ops, context);
    columns[VT_sg_xlist_xp_netid] = new_dbsc_text(curEntry->xp_netid, strlen(curEntry->xp_netid) + 1, context);
//    columns[VT_sg_xlist_xp_ltaddr] =  /* Unsupported type */
//    columns[VT_sg_xlist_xp_rtaddr] =  /* Unsupported type */
    columns[VT_sg_xlist_xp_p1] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xp_p1, context);
    columns[VT_sg_xlist_xp_p2] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xp_p2, context);
    columns[VT_sg_xlist_xp_p3] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xp_p3, context);
    columns[VT_sg_xlist_xp_type] = new_dbsc_int64(curEntry->xp_type, context);
    columns[VT_sg_xlist_xp_idletimeout] = new_dbsc_int64(curEntry->xp_idletimeout, context);
    columns[VT_sg_xlist_xp_lastactive] = new_dbsc_int64(curEntry->xp_lastactive, context);
    columns[VT_sg_xlist_xp_sockref] = new_dbsc_int64(curEntry->xp_sockref, context);
    columns[VT_sg_xlist_xp_upcallset] = new_dbsc_int64(curEntry->xp_upcallset, context);
    columns[VT_sg_xlist_xp_snd_cnt] = new_dbsc_int64(curEntry->xp_snd_cnt, context);
    columns[VT_sg_xlist_xp_snt_cnt] = new_dbsc_int64(curEntry->xp_snt_cnt, context);
    columns[VT_sg_xlist_xp_dontrcv] = new_dbsc_int64(curEntry->xp_dontrcv, context);
    columns[VT_sg_xlist_xp_tls] = new_dbsc_int64(curEntry->xp_tls, context);
    columns[VT_sg_xlist_xp_sslsec] = new_dbsc_int64(curEntry->xp_sslsec, context);
    columns[VT_sg_xlist_xp_sslusec] = new_dbsc_int64(curEntry->xp_sslusec, context);
    columns[VT_sg_xlist_xp_sslrefno] = new_dbsc_int64(curEntry->xp_sslrefno, context);
    columns[VT_sg_xlist_xp_sslproc] = new_dbsc_int64(curEntry->xp_sslproc, context);
    columns[VT_sg_xlist_xp_ngrps] = new_dbsc_int64(curEntry->xp_ngrps, context);
    columns[VT_sg_xlist_xp_uid] = new_dbsc_int64(curEntry->xp_uid, context);
    columns[VT_sg_xlist_xp_gidp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xp_gidp, context);
    columns[VT_sg_xlist_xp_doneddp] = new_dbsc_int64(curEntry->xp_doneddp, context);

    return 0;
}
void
vtab___rpc_svcxprt_lock(void)
{
    sx_slock(&sg_xlist_lock);
}

void
vtab___rpc_svcxprt_unlock(void)
{
    sx_sunlock(&sg_xlist_lock);
}

void
vtab___rpc_svcxprt_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct __rpc_svcxprt *prc = LIST_FIRST(&sg_xlist);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sg_xlist_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sg_xlist_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("__rpc_svcxprt digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
__rpc_svcxprtvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sg_xlist_p_pid];
    *pRowid = pid_value->int64_value;
    printf("__rpc_svcxprt_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
__rpc_svcxprtvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
__rpc_svcxprtvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab___rpc_svcxprt_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("__rpc_svcxprt digest mismatch: UPDATE failed\n");
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
static sqlite3_module __rpc_svcxprtvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ __rpc_svcxprtvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ __rpc_svcxprtvtabRowid,
    /* xUpdate     */ __rpc_svcxprtvtabUpdate,
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
sqlite3___rpc_svcxprtvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &__rpc_svcxprtvtabModule,
        pAux);
}
void vtab___rpc_svcxprt_serialize(sqlite3 *real_db, struct timespec when) {
    struct __rpc_svcxprt *entry = LIST_FIRST(&sg_xlist);

    const char *create_stmt =
        "CREATE TABLE all___rpc_svcxprts (xp_refs INTEGER, xp_registered INTEGER, xp_active INTEGER, xp_netid TEXT, xp_type INTEGER, xp_idletimeout INTEGER, xp_lastactive INTEGER, xp_sockref INTEGER, xp_upcallset INTEGER, xp_snd_cnt INTEGER, xp_snt_cnt INTEGER, xp_dontrcv INTEGER, xp_tls INTEGER, xp_sslsec INTEGER, xp_sslusec INTEGER, xp_sslrefno INTEGER, xp_sslproc INTEGER, xp_ngrps INTEGER, xp_uid INTEGER, xp_doneddp INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all___rpc_svcxprts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_refs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_registered);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_active);
           sqlite3_bind_text(stmt, bindIndex++, entry->xp_netid, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_idletimeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_lastactive);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_sockref);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_upcallset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_snd_cnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_snt_cnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_dontrcv);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_tls);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_sslsec);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_sslusec);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_sslrefno);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_sslproc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_ngrps);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_uid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->xp_doneddp);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

