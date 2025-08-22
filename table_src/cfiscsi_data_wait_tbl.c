#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cfiscsi_data_wait.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cfiscsi_data_wait.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_cs_waiting_for_data_out_cdw_next = 0,
    VT_cs_waiting_for_data_out_cdw_ctl_io = 1,
    VT_cs_waiting_for_data_out_cdw_target_transfer_tag = 2,
    VT_cs_waiting_for_data_out_cdw_initiator_task_tag = 3,
    VT_cs_waiting_for_data_out_cdw_sg_index = 4,
    VT_cs_waiting_for_data_out_cdw_sg_addr = 5,
    VT_cs_waiting_for_data_out_cdw_sg_len = 6,
    VT_cs_waiting_for_data_out_cdw_r2t_end = 7,
    VT_cs_waiting_for_data_out_cdw_datasn = 8,
    VT_cs_waiting_for_data_out_cdw_icl_prv = 9,
    VT_cs_waiting_for_data_out_NUM_COLUMNS
};

static int
copy_columns(struct cfiscsi_data_wait *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_cs_waiting_for_data_out_cdw_next] =  /* Unsupported type */
    columns[VT_cs_waiting_for_data_out_cdw_ctl_io] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cdw_ctl_io, context);
    columns[VT_cs_waiting_for_data_out_cdw_target_transfer_tag] = new_dbsc_int64(curEntry->cdw_target_transfer_tag, context);
    columns[VT_cs_waiting_for_data_out_cdw_initiator_task_tag] = new_dbsc_int64(curEntry->cdw_initiator_task_tag, context);
    columns[VT_cs_waiting_for_data_out_cdw_sg_index] = new_dbsc_int64(curEntry->cdw_sg_index, context);
    columns[VT_cs_waiting_for_data_out_cdw_sg_addr] = new_dbsc_text(curEntry->cdw_sg_addr, strlen(curEntry->cdw_sg_addr) + 1, context);
    columns[VT_cs_waiting_for_data_out_cdw_sg_len] = new_dbsc_int64(curEntry->cdw_sg_len, context);
    columns[VT_cs_waiting_for_data_out_cdw_r2t_end] = new_dbsc_int64(curEntry->cdw_r2t_end, context);
    columns[VT_cs_waiting_for_data_out_cdw_datasn] = new_dbsc_int64(curEntry->cdw_datasn, context);
    columns[VT_cs_waiting_for_data_out_cdw_icl_prv] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cdw_icl_prv, context);

    return 0;
}
void
vtab_cfiscsi_data_wait_lock(void)
{
    sx_slock(&cs_waiting_for_data_out_lock);
}

void
vtab_cfiscsi_data_wait_unlock(void)
{
    sx_sunlock(&cs_waiting_for_data_out_lock);
}

void
vtab_cfiscsi_data_wait_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cfiscsi_data_wait *prc = LIST_FIRST(&cs_waiting_for_data_out);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_cs_waiting_for_data_out_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_cs_waiting_for_data_out_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cfiscsi_data_wait digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cfiscsi_data_waitvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_cs_waiting_for_data_out_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cfiscsi_data_wait_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cfiscsi_data_waitvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cfiscsi_data_waitvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cfiscsi_data_wait_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cfiscsi_data_wait digest mismatch: UPDATE failed\n");
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
static sqlite3_module cfiscsi_data_waitvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cfiscsi_data_waitvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cfiscsi_data_waitvtabRowid,
    /* xUpdate     */ cfiscsi_data_waitvtabUpdate,
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
sqlite3_cfiscsi_data_waitvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cfiscsi_data_waitvtabModule,
        pAux);
}
void vtab_cfiscsi_data_wait_serialize(sqlite3 *real_db, struct timespec when) {
    struct cfiscsi_data_wait *entry = LIST_FIRST(&cs_waiting_for_data_out);

    const char *create_stmt =
        "CREATE TABLE all_cfiscsi_data_waits (cdw_target_transfer_tag INTEGER, cdw_initiator_task_tag INTEGER, cdw_sg_index INTEGER, cdw_sg_addr TEXT, cdw_sg_len INTEGER, cdw_r2t_end INTEGER, cdw_datasn INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cfiscsi_data_waits VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->cdw_target_transfer_tag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cdw_initiator_task_tag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cdw_sg_index);
           sqlite3_bind_text(stmt, bindIndex++, entry->cdw_sg_addr, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cdw_sg_len);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cdw_r2t_end);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cdw_datasn);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

