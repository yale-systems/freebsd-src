#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ctl_ha_dt_req.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ctl_ha_dt_req.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ha_dts_command = 0,
    VT_ha_dts_context = 1,
    VT_ha_dts_callback = 2,
    VT_ha_dts_ret = 3,
    VT_ha_dts_size = 4,
    VT_ha_dts_local = 5,
    VT_ha_dts_remote = 6,
    VT_ha_dts_links = 7,
    VT_ha_dts_NUM_COLUMNS
};

static int
copy_columns(struct ctl_ha_dt_req *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_ha_dts_command] = new_dbsc_int64((int64_t)(curEntry->command), context); // TODO: need better enum representation 
    columns[VT_ha_dts_context] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->context, context);
    columns[VT_ha_dts_callback] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->callback, context);
    columns[VT_ha_dts_ret] = new_dbsc_int64(curEntry->ret, context);
    columns[VT_ha_dts_size] = new_dbsc_int64(curEntry->size, context);
    columns[VT_ha_dts_local] = new_dbsc_text(curEntry->local, strlen(curEntry->local) + 1, context);
    columns[VT_ha_dts_remote] = new_dbsc_text(curEntry->remote, strlen(curEntry->remote) + 1, context);
//    columns[VT_ha_dts_links] =  /* Unsupported type */

    return 0;
}
void
vtab_ctl_ha_dt_req_lock(void)
{
    sx_slock(&ha_dts_lock);
}

void
vtab_ctl_ha_dt_req_unlock(void)
{
    sx_sunlock(&ha_dts_lock);
}

void
vtab_ctl_ha_dt_req_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ctl_ha_dt_req *prc = LIST_FIRST(&ha_dts);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ha_dts_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_ha_dts_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ctl_ha_dt_req digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ctl_ha_dt_reqvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_ha_dts_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ctl_ha_dt_req_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ctl_ha_dt_reqvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ctl_ha_dt_reqvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ctl_ha_dt_req_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ctl_ha_dt_req digest mismatch: UPDATE failed\n");
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
static sqlite3_module ctl_ha_dt_reqvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ctl_ha_dt_reqvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ctl_ha_dt_reqvtabRowid,
    /* xUpdate     */ ctl_ha_dt_reqvtabUpdate,
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
sqlite3_ctl_ha_dt_reqvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ctl_ha_dt_reqvtabModule,
        pAux);
}
void vtab_ctl_ha_dt_req_serialize(sqlite3 *real_db, struct timespec when) {
    struct ctl_ha_dt_req *entry = LIST_FIRST(&ha_dts);

    const char *create_stmt =
        "CREATE TABLE all_ctl_ha_dt_reqs (command INTEGER, ret INTEGER, size INTEGER, local TEXT, remote TEXT)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ctl_ha_dt_reqs VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->command);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ret);
           sqlite3_bind_int64(stmt, bindIndex++, entry->size);
           sqlite3_bind_text(stmt, bindIndex++, entry->local, -1, SQLITE_TRANSIENT);
           sqlite3_bind_text(stmt, bindIndex++, entry->remote, -1, SQLITE_TRANSIENT);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

