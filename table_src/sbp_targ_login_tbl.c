#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/sbp_targ_login.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_sbp_targ_login.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_logins_lstate = 0,
    VT_logins_fwdev = 1,
    VT_logins_loginres = 2,
    VT_logins_fifo_hi = 3,
    VT_logins_last_hi = 4,
    VT_logins_fifo_lo = 5,
    VT_logins_last_lo = 6,
    VT_logins_orbs = 7,
    VT_logins_link = 8,
    VT_logins_hold_sec = 9,
    VT_logins_id = 10,
    VT_logins_flags = 11,
    VT_logins_spd = 12,
    VT_logins_hold_callout = 13,
    VT_logins_NUM_COLUMNS
};

static int
copy_columns(struct sbp_targ_login *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_logins_lstate] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lstate, context);
    columns[VT_logins_fwdev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->fwdev, context);
//    columns[VT_logins_loginres] =  /* Unsupported type */
    columns[VT_logins_fifo_hi] = new_dbsc_int64(curEntry->fifo_hi, context);
    columns[VT_logins_last_hi] = new_dbsc_int64(curEntry->last_hi, context);
    columns[VT_logins_fifo_lo] = new_dbsc_int64(curEntry->fifo_lo, context);
    columns[VT_logins_last_lo] = new_dbsc_int64(curEntry->last_lo, context);
//    columns[VT_logins_orbs] =  /* Unsupported type */
//    columns[VT_logins_link] =  /* Unsupported type */
    columns[VT_logins_hold_sec] = new_dbsc_int64(curEntry->hold_sec, context);
    columns[VT_logins_id] = new_dbsc_int64(curEntry->id, context);
    columns[VT_logins_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_logins_spd] = new_dbsc_int64(curEntry->spd, context);
//    columns[VT_logins_hold_callout] =  /* Unsupported type */

    return 0;
}
void
vtab_sbp_targ_login_lock(void)
{
    sx_slock(&logins_lock);
}

void
vtab_sbp_targ_login_unlock(void)
{
    sx_sunlock(&logins_lock);
}

void
vtab_sbp_targ_login_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct sbp_targ_login *prc = LIST_FIRST(&logins);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_logins_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_logins_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("sbp_targ_login digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
sbp_targ_loginvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_logins_p_pid];
    *pRowid = pid_value->int64_value;
    printf("sbp_targ_login_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
sbp_targ_loginvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
sbp_targ_loginvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_sbp_targ_login_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("sbp_targ_login digest mismatch: UPDATE failed\n");
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
static sqlite3_module sbp_targ_loginvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ sbp_targ_loginvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ sbp_targ_loginvtabRowid,
    /* xUpdate     */ sbp_targ_loginvtabUpdate,
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
sqlite3_sbp_targ_loginvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &sbp_targ_loginvtabModule,
        pAux);
}
void vtab_sbp_targ_login_serialize(sqlite3 *real_db, struct timespec when) {
    struct sbp_targ_login *entry = LIST_FIRST(&logins);

    const char *create_stmt =
        "CREATE TABLE all_sbp_targ_logins (fifo_hi INTEGER, last_hi INTEGER, fifo_lo INTEGER, last_lo INTEGER, hold_sec INTEGER, id INTEGER, flags INTEGER, spd INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_sbp_targ_logins VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->fifo_hi);
           sqlite3_bind_int64(stmt, bindIndex++, entry->last_hi);
           sqlite3_bind_int64(stmt, bindIndex++, entry->fifo_lo);
           sqlite3_bind_int64(stmt, bindIndex++, entry->last_lo);
           sqlite3_bind_int64(stmt, bindIndex++, entry->hold_sec);
           sqlite3_bind_int64(stmt, bindIndex++, entry->id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->spd);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

