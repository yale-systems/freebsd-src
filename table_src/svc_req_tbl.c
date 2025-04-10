#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/svc_req.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_svc_req.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_st_reqs_rq_link = 0,
    VT_st_reqs_rq_thread = 1,
    VT_st_reqs_rq_xid = 2,
    VT_st_reqs_rq_prog = 3,
    VT_st_reqs_rq_vers = 4,
    VT_st_reqs_rq_proc = 5,
    VT_st_reqs_rq_size = 6,
    VT_st_reqs_rq_args = 7,
    VT_st_reqs_rq_cred = 8,
    VT_st_reqs_rq_verf = 9,
    VT_st_reqs_rq_clntcred = 10,
    VT_st_reqs_rq_auth = 11,
    VT_st_reqs_rq_xprt = 12,
    VT_st_reqs_rq_addr = 13,
    VT_st_reqs_rq_p1 = 14,
    VT_st_reqs_rq_p2 = 15,
    VT_st_reqs_rq_p3 = 16,
    VT_st_reqs_rq_reply_seq = 17,
    VT_st_reqs_rq_credarea = 18,
    VT_st_reqs_NUM_COLUMNS
};

static int
copy_columns(struct svc_req *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_st_reqs_rq_link] =  /* Unsupported type */
    columns[VT_st_reqs_rq_thread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rq_thread, context);
    columns[VT_st_reqs_rq_xid] = new_dbsc_int64(curEntry->rq_xid, context);
    columns[VT_st_reqs_rq_prog] = new_dbsc_int64(curEntry->rq_prog, context);
    columns[VT_st_reqs_rq_vers] = new_dbsc_int64(curEntry->rq_vers, context);
    columns[VT_st_reqs_rq_proc] = new_dbsc_int64(curEntry->rq_proc, context);
    columns[VT_st_reqs_rq_size] = new_dbsc_int64(curEntry->rq_size, context);
    columns[VT_st_reqs_rq_args] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rq_args, context);
//    columns[VT_st_reqs_rq_cred] =  /* Unsupported type */
//    columns[VT_st_reqs_rq_verf] =  /* Unsupported type */
    columns[VT_st_reqs_rq_clntcred] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rq_clntcred, context);
//    columns[VT_st_reqs_rq_auth] =  /* Unsupported type */
    columns[VT_st_reqs_rq_xprt] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rq_xprt, context);
    columns[VT_st_reqs_rq_addr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rq_addr, context);
    columns[VT_st_reqs_rq_p1] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rq_p1, context);
    columns[VT_st_reqs_rq_p2] = new_dbsc_int64(curEntry->rq_p2, context);
    columns[VT_st_reqs_rq_p3] = new_dbsc_int64(curEntry->rq_p3, context);
    columns[VT_st_reqs_rq_reply_seq] = new_dbsc_int64(curEntry->rq_reply_seq, context);
//    columns[VT_st_reqs_rq_credarea] =  /* Unsupported type */

    return 0;
}
void
vtab_svc_req_lock(void)
{
    sx_slock(&st_reqs_lock);
}

void
vtab_svc_req_unlock(void)
{
    sx_sunlock(&st_reqs_lock);
}

void
vtab_svc_req_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct svc_req *prc = LIST_FIRST(&st_reqs);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_st_reqs_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_st_reqs_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("svc_req digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
svc_reqvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_st_reqs_p_pid];
    *pRowid = pid_value->int64_value;
    printf("svc_req_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
svc_reqvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
svc_reqvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_svc_req_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("svc_req digest mismatch: UPDATE failed\n");
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
static sqlite3_module svc_reqvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ svc_reqvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ svc_reqvtabRowid,
    /* xUpdate     */ svc_reqvtabUpdate,
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
sqlite3_svc_reqvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &svc_reqvtabModule,
        pAux);
}
void vtab_svc_req_serialize(sqlite3 *real_db, struct timespec when) {
    struct svc_req *entry = LIST_FIRST(&st_reqs);

    const char *create_stmt =
        "CREATE TABLE all_svc_reqs (rq_xid INTEGER, rq_prog INTEGER, rq_vers INTEGER, rq_proc INTEGER, rq_size INTEGER, rq_p2 INTEGER, rq_p3 INTEGER, rq_reply_seq INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_svc_reqs VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->rq_xid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rq_prog);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rq_vers);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rq_proc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rq_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rq_p2);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rq_p3);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rq_reply_seq);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

