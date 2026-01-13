#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/knote.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_knote.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_kl_list_kn_link = 0,
    VT_kl_list_kn_selnext = 1,
    VT_kl_list_kn_knlist = 2,
    VT_kl_list_kn_tqe = 3,
    VT_kl_list_kn_kq = 4,
    VT_kl_list_kn_kevent = 5,
    VT_kl_list_kn_hook = 6,
    VT_kl_list_kn_hookid = 7,
    VT_kl_list_kn_status = 8,
    VT_kl_list_kn_influx = 9,
    VT_kl_list_kn_sfflags = 10,
    VT_kl_list_kn_sdata = 11,
    VT_kl_list_kn_ptr = 12,
    VT_kl_list_kn_fop = 13,
    VT_kl_list_NUM_COLUMNS
};

static int
copy_columns(struct knote *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_kl_list_kn_link] =  /* Unsupported type */
//    columns[VT_kl_list_kn_selnext] =  /* Unsupported type */
    columns[VT_kl_list_kn_knlist] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->kn_knlist, context);
//    columns[VT_kl_list_kn_tqe] =  /* Unsupported type */
    columns[VT_kl_list_kn_kq] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->kn_kq, context);
//    columns[VT_kl_list_kn_kevent] =  /* Unsupported type */
    columns[VT_kl_list_kn_hook] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->kn_hook, context);
    columns[VT_kl_list_kn_hookid] = new_dbsc_int64(curEntry->kn_hookid, context);
    columns[VT_kl_list_kn_status] = new_dbsc_int64(curEntry->kn_status, context);
    columns[VT_kl_list_kn_influx] = new_dbsc_int64(curEntry->kn_influx, context);
    columns[VT_kl_list_kn_sfflags] = new_dbsc_int64(curEntry->kn_sfflags, context);
    columns[VT_kl_list_kn_sdata] = new_dbsc_int64(curEntry->kn_sdata, context);
//    columns[VT_kl_list_kn_ptr] =  /* Unsupported type */
    columns[VT_kl_list_kn_fop] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->kn_fop, context);

    return 0;
}
void
vtab_knote_lock(void)
{
    sx_slock(&kl_list_lock);
}

void
vtab_knote_unlock(void)
{
    sx_sunlock(&kl_list_lock);
}

void
vtab_knote_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct knote *prc = LIST_FIRST(&kl_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_kl_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_kl_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("knote digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
knotevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_kl_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("knote_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
knotevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
knotevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_knote_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("knote digest mismatch: UPDATE failed\n");
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
static sqlite3_module knotevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ knotevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ knotevtabRowid,
    /* xUpdate     */ knotevtabUpdate,
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
sqlite3_knotevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &knotevtabModule,
        pAux);
}
void vtab_knote_serialize(sqlite3 *real_db, struct timespec when) {
    struct knote *entry = LIST_FIRST(&kl_list);

    const char *create_stmt =
        "CREATE TABLE all_knotes (kn_hookid INTEGER, kn_status INTEGER, kn_influx INTEGER, kn_sfflags INTEGER, kn_sdata INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_knotes VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->kn_hookid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->kn_status);
           sqlite3_bind_int64(stmt, bindIndex++, entry->kn_influx);
           sqlite3_bind_int64(stmt, bindIndex++, entry->kn_sfflags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->kn_sdata);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

