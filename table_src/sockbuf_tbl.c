#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/sockbuf.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_sockbuf.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_uxdg_conns_sb_sel = 0,
    VT_uxdg_conns_sb_state = 1,
    VT_uxdg_conns_sb_flags = 2,
    VT_uxdg_conns_sb_acc = 3,
    VT_uxdg_conns_sb_ccc = 4,
    VT_uxdg_conns_sb_mbcnt = 5,
    VT_uxdg_conns_sb_ctl = 6,
    VT_uxdg_conns_sb_hiwat = 7,
    VT_uxdg_conns_sb_lowat = 8,
    VT_uxdg_conns_sb_mbmax = 9,
    VT_uxdg_conns_sb_timeo = 10,
    VT_uxdg_conns_sb_upcall = 11,
    VT_uxdg_conns_sb_upcallarg = 12,
    VT_uxdg_conns_sb_aiojobq = 13,
    VT_uxdg_conns_sb_aiotask = 14,
    VT_uxdg_conns_ = 15,
    VT_uxdg_conns_NUM_COLUMNS
};

static int
copy_columns(struct sockbuf *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_uxdg_conns_sb_sel] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sb_sel, context);
    columns[VT_uxdg_conns_sb_state] = new_dbsc_int64(curEntry->sb_state, context);
    columns[VT_uxdg_conns_sb_flags] = new_dbsc_int64(curEntry->sb_flags, context);
    columns[VT_uxdg_conns_sb_acc] = new_dbsc_int64(curEntry->sb_acc, context);
    columns[VT_uxdg_conns_sb_ccc] = new_dbsc_int64(curEntry->sb_ccc, context);
    columns[VT_uxdg_conns_sb_mbcnt] = new_dbsc_int64(curEntry->sb_mbcnt, context);
    columns[VT_uxdg_conns_sb_ctl] = new_dbsc_int64(curEntry->sb_ctl, context);
    columns[VT_uxdg_conns_sb_hiwat] = new_dbsc_int64(curEntry->sb_hiwat, context);
    columns[VT_uxdg_conns_sb_lowat] = new_dbsc_int64(curEntry->sb_lowat, context);
    columns[VT_uxdg_conns_sb_mbmax] = new_dbsc_int64(curEntry->sb_mbmax, context);
    columns[VT_uxdg_conns_sb_timeo] = new_dbsc_int64(curEntry->sb_timeo, context);
    columns[VT_uxdg_conns_sb_upcall] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sb_upcall, context);
    columns[VT_uxdg_conns_sb_upcallarg] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sb_upcallarg, context);
//    columns[VT_uxdg_conns_sb_aiojobq] =  /* Unsupported type */
//    columns[VT_uxdg_conns_sb_aiotask] =  /* Unsupported type */
//    columns[VT_uxdg_conns_] =  /* Unsupported type */

    return 0;
}
void
vtab_sockbuf_lock(void)
{
    sx_slock(&uxdg_conns_lock);
}

void
vtab_sockbuf_unlock(void)
{
    sx_sunlock(&uxdg_conns_lock);
}

void
vtab_sockbuf_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct sockbuf *prc = LIST_FIRST(&uxdg_conns);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_uxdg_conns_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_uxdg_conns_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("sockbuf digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
sockbufvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_uxdg_conns_p_pid];
    *pRowid = pid_value->int64_value;
    printf("sockbuf_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
sockbufvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
sockbufvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_sockbuf_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("sockbuf digest mismatch: UPDATE failed\n");
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
static sqlite3_module sockbufvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ sockbufvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ sockbufvtabRowid,
    /* xUpdate     */ sockbufvtabUpdate,
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
sqlite3_sockbufvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &sockbufvtabModule,
        pAux);
}
void vtab_sockbuf_serialize(sqlite3 *real_db, struct timespec when) {
    struct sockbuf *entry = LIST_FIRST(&uxdg_conns);

    const char *create_stmt =
        "CREATE TABLE all_sockbufs (sb_state INTEGER, sb_flags INTEGER, sb_acc INTEGER, sb_ccc INTEGER, sb_mbcnt INTEGER, sb_ctl INTEGER, sb_hiwat INTEGER, sb_lowat INTEGER, sb_mbmax INTEGER, sb_timeo INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_sockbufs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_acc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_ccc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_mbcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_ctl);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_hiwat);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_lowat);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_mbmax);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sb_timeo);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

