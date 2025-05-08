#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/bwn_mac.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_bwn_mac.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sc_maclist_mac_sc = 0,
    VT_sc_maclist_mac_status = 1,
    VT_sc_maclist_mac_flags = 2,
    VT_sc_maclist_mac_res_irq = 3,
    VT_sc_maclist_mac_rid_irq = 4,
    VT_sc_maclist_mac_intrhand = 5,
    VT_sc_maclist_mac_noise = 6,
    VT_sc_maclist_mac_phy = 7,
    VT_sc_maclist_mac_stats = 8,
    VT_sc_maclist_mac_reason_intr = 9,
    VT_sc_maclist_mac_reason = 10,
    VT_sc_maclist_mac_intr_mask = 11,
    VT_sc_maclist_mac_suspended = 12,
    VT_sc_maclist_mac_fw = 13,
    VT_sc_maclist_mac_dmatype = 14,
    VT_sc_maclist_mac_method = 15,
    VT_sc_maclist_mac_ktp = 16,
    VT_sc_maclist_mac_max_nr_keys = 17,
    VT_sc_maclist_mac_key = 18,
    VT_sc_maclist_mac_task_state = 19,
    VT_sc_maclist_mac_intrtask = 20,
    VT_sc_maclist_mac_hwreset = 21,
    VT_sc_maclist_mac_txpower = 22,
    VT_sc_maclist_mac_list = 23,
    VT_sc_maclist_NUM_COLUMNS
};

static int
copy_columns(struct bwn_mac *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_sc_maclist_mac_sc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->mac_sc, context);
    columns[VT_sc_maclist_mac_status] = new_dbsc_int64(curEntry->mac_status, context);
    columns[VT_sc_maclist_mac_flags] = new_dbsc_int64(curEntry->mac_flags, context);
    columns[VT_sc_maclist_mac_res_irq] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->mac_res_irq, context);
    columns[VT_sc_maclist_mac_rid_irq] = new_dbsc_int64(curEntry->mac_rid_irq, context);
    columns[VT_sc_maclist_mac_intrhand] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->mac_intrhand, context);
//    columns[VT_sc_maclist_mac_noise] =  /* Unsupported type */
//    columns[VT_sc_maclist_mac_phy] =  /* Unsupported type */
//    columns[VT_sc_maclist_mac_stats] =  /* Unsupported type */
    columns[VT_sc_maclist_mac_reason_intr] = new_dbsc_int64(curEntry->mac_reason_intr, context);
//    columns[VT_sc_maclist_mac_reason] =  /* Unsupported type */
    columns[VT_sc_maclist_mac_intr_mask] = new_dbsc_int64(curEntry->mac_intr_mask, context);
    columns[VT_sc_maclist_mac_suspended] = new_dbsc_int64(curEntry->mac_suspended, context);
//    columns[VT_sc_maclist_mac_fw] =  /* Unsupported type */
    columns[VT_sc_maclist_mac_dmatype] = new_dbsc_int64(curEntry->mac_dmatype, context);
//    columns[VT_sc_maclist_mac_method] =  /* Unsupported type */
    columns[VT_sc_maclist_mac_ktp] = new_dbsc_int64(curEntry->mac_ktp, context);
    columns[VT_sc_maclist_mac_max_nr_keys] = new_dbsc_int64(curEntry->mac_max_nr_keys, context);
//    columns[VT_sc_maclist_mac_key] =  /* Unsupported type */
    columns[VT_sc_maclist_mac_task_state] = new_dbsc_int64(curEntry->mac_task_state, context);
//    columns[VT_sc_maclist_mac_intrtask] =  /* Unsupported type */
//    columns[VT_sc_maclist_mac_hwreset] =  /* Unsupported type */
//    columns[VT_sc_maclist_mac_txpower] =  /* Unsupported type */
//    columns[VT_sc_maclist_mac_list] =  /* Unsupported type */

    return 0;
}
void
vtab_bwn_mac_lock(void)
{
    sx_slock(&sc_maclist_lock);
}

void
vtab_bwn_mac_unlock(void)
{
    sx_sunlock(&sc_maclist_lock);
}

void
vtab_bwn_mac_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct bwn_mac *prc = LIST_FIRST(&sc_maclist);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sc_maclist_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sc_maclist_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("bwn_mac digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
bwn_macvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sc_maclist_p_pid];
    *pRowid = pid_value->int64_value;
    printf("bwn_mac_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
bwn_macvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
bwn_macvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_bwn_mac_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("bwn_mac digest mismatch: UPDATE failed\n");
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
static sqlite3_module bwn_macvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ bwn_macvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ bwn_macvtabRowid,
    /* xUpdate     */ bwn_macvtabUpdate,
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
sqlite3_bwn_macvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &bwn_macvtabModule,
        pAux);
}
void vtab_bwn_mac_serialize(sqlite3 *real_db, struct timespec when) {
    struct bwn_mac *entry = LIST_FIRST(&sc_maclist);

    const char *create_stmt =
        "CREATE TABLE all_bwn_macs (mac_status INTEGER, mac_flags INTEGER, mac_rid_irq INTEGER, mac_reason_intr INTEGER, mac_intr_mask INTEGER, mac_suspended INTEGER, mac_dmatype INTEGER, mac_ktp INTEGER, mac_max_nr_keys INTEGER, mac_task_state INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_bwn_macs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_status);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_rid_irq);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_reason_intr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_intr_mask);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_suspended);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_dmatype);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_ktp);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_max_nr_keys);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mac_task_state);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

