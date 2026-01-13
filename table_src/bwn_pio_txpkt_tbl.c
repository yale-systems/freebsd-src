#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/bwn_pio_txpkt.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_bwn_pio_txpkt.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_tq_pktlist_tp_queue = 0,
    VT_tq_pktlist_tp_ni = 1,
    VT_tq_pktlist_tp_m = 2,
    VT_tq_pktlist_tp_index = 3,
    VT_tq_pktlist_tp_list = 4,
    VT_tq_pktlist_NUM_COLUMNS
};

static int
copy_columns(struct bwn_pio_txpkt *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_tq_pktlist_tp_queue] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tp_queue, context);
    columns[VT_tq_pktlist_tp_ni] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tp_ni, context);
    columns[VT_tq_pktlist_tp_m] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tp_m, context);
    columns[VT_tq_pktlist_tp_index] = new_dbsc_int64(curEntry->tp_index, context);
//    columns[VT_tq_pktlist_tp_list] =  /* Unsupported type */

    return 0;
}
void
vtab_bwn_pio_txpkt_lock(void)
{
    sx_slock(&tq_pktlist_lock);
}

void
vtab_bwn_pio_txpkt_unlock(void)
{
    sx_sunlock(&tq_pktlist_lock);
}

void
vtab_bwn_pio_txpkt_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct bwn_pio_txpkt *prc = LIST_FIRST(&tq_pktlist);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_tq_pktlist_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_tq_pktlist_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("bwn_pio_txpkt digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
bwn_pio_txpktvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_tq_pktlist_p_pid];
    *pRowid = pid_value->int64_value;
    printf("bwn_pio_txpkt_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
bwn_pio_txpktvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
bwn_pio_txpktvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_bwn_pio_txpkt_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("bwn_pio_txpkt digest mismatch: UPDATE failed\n");
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
static sqlite3_module bwn_pio_txpktvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ bwn_pio_txpktvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ bwn_pio_txpktvtabRowid,
    /* xUpdate     */ bwn_pio_txpktvtabUpdate,
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
sqlite3_bwn_pio_txpktvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &bwn_pio_txpktvtabModule,
        pAux);
}
void vtab_bwn_pio_txpkt_serialize(sqlite3 *real_db, struct timespec when) {
    struct bwn_pio_txpkt *entry = LIST_FIRST(&tq_pktlist);

    const char *create_stmt =
        "CREATE TABLE all_bwn_pio_txpkts (tp_index INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_bwn_pio_txpkts VALUES (?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->tp_index);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

