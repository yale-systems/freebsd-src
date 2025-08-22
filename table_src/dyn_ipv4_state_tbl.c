#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/dyn_ipv4_state.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_dyn_ipv4_state.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_vnet_entry_dyn_expired_ipv4_type = 0,
    VT_vnet_entry_dyn_expired_ipv4_proto = 1,
    VT_vnet_entry_dyn_expired_ipv4_kidx = 2,
    VT_vnet_entry_dyn_expired_ipv4_sport = 3,
    VT_vnet_entry_dyn_expired_ipv4_dport = 4,
    VT_vnet_entry_dyn_expired_ipv4_src = 5,
    VT_vnet_entry_dyn_expired_ipv4_dst = 6,
    VT_vnet_entry_dyn_expired_ipv4_ = 7,
    VT_vnet_entry_dyn_expired_ipv4_entry = 8,
    VT_vnet_entry_dyn_expired_ipv4_expired = 9,
    VT_vnet_entry_dyn_expired_ipv4_NUM_COLUMNS
};

static int
copy_columns(struct dyn_ipv4_state *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_vnet_entry_dyn_expired_ipv4_type] = new_dbsc_int64(curEntry->type, context);
    columns[VT_vnet_entry_dyn_expired_ipv4_proto] = new_dbsc_int64(curEntry->proto, context);
    columns[VT_vnet_entry_dyn_expired_ipv4_kidx] = new_dbsc_int64(curEntry->kidx, context);
    columns[VT_vnet_entry_dyn_expired_ipv4_sport] = new_dbsc_int64(curEntry->sport, context);
    columns[VT_vnet_entry_dyn_expired_ipv4_dport] = new_dbsc_int64(curEntry->dport, context);
    columns[VT_vnet_entry_dyn_expired_ipv4_src] = new_dbsc_int64(curEntry->src, context);
    columns[VT_vnet_entry_dyn_expired_ipv4_dst] = new_dbsc_int64(curEntry->dst, context);
//    columns[VT_vnet_entry_dyn_expired_ipv4_] =  /* Unsupported type */
//    columns[VT_vnet_entry_dyn_expired_ipv4_entry] =  /* Unsupported type */
//    columns[VT_vnet_entry_dyn_expired_ipv4_expired] =  /* Unsupported type */

    return 0;
}
void
vtab_dyn_ipv4_state_lock(void)
{
    sx_slock(&vnet_entry_dyn_expired_ipv4_lock);
}

void
vtab_dyn_ipv4_state_unlock(void)
{
    sx_sunlock(&vnet_entry_dyn_expired_ipv4_lock);
}

void
vtab_dyn_ipv4_state_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct dyn_ipv4_state *prc = LIST_FIRST(&vnet_entry_dyn_expired_ipv4);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_dyn_expired_ipv4_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_vnet_entry_dyn_expired_ipv4_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("dyn_ipv4_state digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
dyn_ipv4_statevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_vnet_entry_dyn_expired_ipv4_p_pid];
    *pRowid = pid_value->int64_value;
    printf("dyn_ipv4_state_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
dyn_ipv4_statevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
dyn_ipv4_statevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_dyn_ipv4_state_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("dyn_ipv4_state digest mismatch: UPDATE failed\n");
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
static sqlite3_module dyn_ipv4_statevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ dyn_ipv4_statevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ dyn_ipv4_statevtabRowid,
    /* xUpdate     */ dyn_ipv4_statevtabUpdate,
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
sqlite3_dyn_ipv4_statevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &dyn_ipv4_statevtabModule,
        pAux);
}
void vtab_dyn_ipv4_state_serialize(sqlite3 *real_db, struct timespec when) {
    struct dyn_ipv4_state *entry = LIST_FIRST(&vnet_entry_dyn_expired_ipv4);

    const char *create_stmt =
        "CREATE TABLE all_dyn_ipv4_states (type INTEGER, proto INTEGER, kidx INTEGER, sport INTEGER, dport INTEGER, src INTEGER, dst INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_dyn_ipv4_states VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->proto);
           sqlite3_bind_int64(stmt, bindIndex++, entry->kidx);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sport);
           sqlite3_bind_int64(stmt, bindIndex++, entry->dport);
           sqlite3_bind_int64(stmt, bindIndex++, entry->src);
           sqlite3_bind_int64(stmt, bindIndex++, entry->dst);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

