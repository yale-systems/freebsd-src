#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/dn_fsk.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_dn_fsk.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_fsu_fs = 0,
    VT_fsu_fsk_next = 1,
    VT_fsu_fsk_mask = 2,
    VT_fsu_qht = 3,
    VT_fsu_sched = 4,
    VT_fsu_sch_chain = 5,
    VT_fsu_drain_bucket = 6,
    VT_fsu_w_q = 7,
    VT_fsu_max_th = 8,
    VT_fsu_min_th = 9,
    VT_fsu_max_p = 10,
    VT_fsu_c_1 = 11,
    VT_fsu_c_2 = 12,
    VT_fsu_c_3 = 13,
    VT_fsu_c_4 = 14,
    VT_fsu_w_q_lookup = 15,
    VT_fsu_lookup_depth = 16,
    VT_fsu_lookup_step = 17,
    VT_fsu_lookup_weight = 18,
    VT_fsu_avg_pkt_size = 19,
    VT_fsu_max_pkt_size = 20,
    VT_fsu_aqmfp = 21,
    VT_fsu_aqmcfg = 22,
    VT_fsu_NUM_COLUMNS
};

static int
copy_columns(struct dn_fsk *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_fsu_fs] =  /* Unsupported type */
//    columns[VT_fsu_fsk_next] =  /* Unsupported type */
//    columns[VT_fsu_fsk_mask] =  /* Unsupported type */
    columns[VT_fsu_qht] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->qht, context);
    columns[VT_fsu_sched] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sched, context);
//    columns[VT_fsu_sch_chain] =  /* Unsupported type */
    columns[VT_fsu_drain_bucket] = new_dbsc_int64(curEntry->drain_bucket, context);
    columns[VT_fsu_w_q] = new_dbsc_int64(curEntry->w_q, context);
    columns[VT_fsu_max_th] = new_dbsc_int64(curEntry->max_th, context);
    columns[VT_fsu_min_th] = new_dbsc_int64(curEntry->min_th, context);
    columns[VT_fsu_max_p] = new_dbsc_int64(curEntry->max_p, context);
    columns[VT_fsu_c_1] = new_dbsc_int64(curEntry->c_1, context);
    columns[VT_fsu_c_2] = new_dbsc_int64(curEntry->c_2, context);
    columns[VT_fsu_c_3] = new_dbsc_int64(curEntry->c_3, context);
    columns[VT_fsu_c_4] = new_dbsc_int64(curEntry->c_4, context);
    columns[VT_fsu_w_q_lookup] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->w_q_lookup, context);
    columns[VT_fsu_lookup_depth] = new_dbsc_int64(curEntry->lookup_depth, context);
    columns[VT_fsu_lookup_step] = new_dbsc_int64(curEntry->lookup_step, context);
    columns[VT_fsu_lookup_weight] = new_dbsc_int64(curEntry->lookup_weight, context);
    columns[VT_fsu_avg_pkt_size] = new_dbsc_int64(curEntry->avg_pkt_size, context);
    columns[VT_fsu_max_pkt_size] = new_dbsc_int64(curEntry->max_pkt_size, context);
    columns[VT_fsu_aqmfp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->aqmfp, context);
    columns[VT_fsu_aqmcfg] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->aqmcfg, context);

    return 0;
}
void
vtab_dn_fsk_lock(void)
{
    sx_slock(&fsu_lock);
}

void
vtab_dn_fsk_unlock(void)
{
    sx_sunlock(&fsu_lock);
}

void
vtab_dn_fsk_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct dn_fsk *prc = LIST_FIRST(&fsu);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_fsu_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_fsu_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("dn_fsk digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
dn_fskvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_fsu_p_pid];
    *pRowid = pid_value->int64_value;
    printf("dn_fsk_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
dn_fskvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
dn_fskvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_dn_fsk_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("dn_fsk digest mismatch: UPDATE failed\n");
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
static sqlite3_module dn_fskvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ dn_fskvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ dn_fskvtabRowid,
    /* xUpdate     */ dn_fskvtabUpdate,
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
sqlite3_dn_fskvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &dn_fskvtabModule,
        pAux);
}
void vtab_dn_fsk_serialize(sqlite3 *real_db, struct timespec when) {
    struct dn_fsk *entry = LIST_FIRST(&fsu);

    const char *create_stmt =
        "CREATE TABLE all_dn_fsks (drain_bucket INTEGER, w_q INTEGER, max_th INTEGER, min_th INTEGER, max_p INTEGER, c_1 INTEGER, c_2 INTEGER, c_3 INTEGER, c_4 INTEGER, lookup_depth INTEGER, lookup_step INTEGER, lookup_weight INTEGER, avg_pkt_size INTEGER, max_pkt_size INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_dn_fsks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->drain_bucket);
           sqlite3_bind_int64(stmt, bindIndex++, entry->w_q);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_th);
           sqlite3_bind_int64(stmt, bindIndex++, entry->min_th);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_p);
           sqlite3_bind_int64(stmt, bindIndex++, entry->c_1);
           sqlite3_bind_int64(stmt, bindIndex++, entry->c_2);
           sqlite3_bind_int64(stmt, bindIndex++, entry->c_3);
           sqlite3_bind_int64(stmt, bindIndex++, entry->c_4);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lookup_depth);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lookup_step);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lookup_weight);
           sqlite3_bind_int64(stmt, bindIndex++, entry->avg_pkt_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_pkt_size);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

