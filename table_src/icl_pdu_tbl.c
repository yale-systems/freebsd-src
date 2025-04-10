#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/icl_pdu.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_icl_pdu.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_is_postponed_ip_next = 0,
    VT_is_postponed_ip_conn = 1,
    VT_is_postponed_ip_bhs = 2,
    VT_is_postponed_ip_bhs_mbuf = 3,
    VT_is_postponed_ip_ahs_len = 4,
    VT_is_postponed_ip_ahs_mbuf = 5,
    VT_is_postponed_ip_data_len = 6,
    VT_is_postponed_ip_data_mbuf = 7,
    VT_is_postponed_ip_additional_pdus = 8,
    VT_is_postponed_ip_prv0 = 9,
    VT_is_postponed_ip_prv1 = 10,
    VT_is_postponed_NUM_COLUMNS
};

static int
copy_columns(struct icl_pdu *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_is_postponed_ip_next] =  /* Unsupported type */
    columns[VT_is_postponed_ip_conn] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ip_conn, context);
    columns[VT_is_postponed_ip_bhs] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ip_bhs, context);
    columns[VT_is_postponed_ip_bhs_mbuf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ip_bhs_mbuf, context);
    columns[VT_is_postponed_ip_ahs_len] = new_dbsc_int64(curEntry->ip_ahs_len, context);
    columns[VT_is_postponed_ip_ahs_mbuf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ip_ahs_mbuf, context);
    columns[VT_is_postponed_ip_data_len] = new_dbsc_int64(curEntry->ip_data_len, context);
    columns[VT_is_postponed_ip_data_mbuf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ip_data_mbuf, context);
    columns[VT_is_postponed_ip_additional_pdus] = new_dbsc_int64(curEntry->ip_additional_pdus, context);
    columns[VT_is_postponed_ip_prv0] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ip_prv0, context);
    columns[VT_is_postponed_ip_prv1] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ip_prv1, context);

    return 0;
}
void
vtab_icl_pdu_lock(void)
{
    sx_slock(&is_postponed_lock);
}

void
vtab_icl_pdu_unlock(void)
{
    sx_sunlock(&is_postponed_lock);
}

void
vtab_icl_pdu_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct icl_pdu *prc = LIST_FIRST(&is_postponed);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_is_postponed_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_is_postponed_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("icl_pdu digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
icl_pduvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_is_postponed_p_pid];
    *pRowid = pid_value->int64_value;
    printf("icl_pdu_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
icl_pduvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
icl_pduvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_icl_pdu_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("icl_pdu digest mismatch: UPDATE failed\n");
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
static sqlite3_module icl_pduvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ icl_pduvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ icl_pduvtabRowid,
    /* xUpdate     */ icl_pduvtabUpdate,
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
sqlite3_icl_pduvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &icl_pduvtabModule,
        pAux);
}
void vtab_icl_pdu_serialize(sqlite3 *real_db, struct timespec when) {
    struct icl_pdu *entry = LIST_FIRST(&is_postponed);

    const char *create_stmt =
        "CREATE TABLE all_icl_pdus (ip_ahs_len INTEGER, ip_data_len INTEGER, ip_additional_pdus INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_icl_pdus VALUES (?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->ip_ahs_len);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ip_data_len);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ip_additional_pdus);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

