#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/hv_storvsc_request.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_hv_storvsc_request.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_hs_free_list_link = 0,
    VT_hs_free_list_vstor_packet = 1,
    VT_hs_free_list_prp_cnt = 2,
    VT_hs_free_list_prp_list = 3,
    VT_hs_free_list_sense_data = 4,
    VT_hs_free_list_sense_info_len = 5,
    VT_hs_free_list_retries = 6,
    VT_hs_free_list_ccb = 7,
    VT_hs_free_list_softc = 8,
    VT_hs_free_list_callout = 9,
    VT_hs_free_list_synch_sema = 10,
    VT_hs_free_list_bounce_sgl = 11,
    VT_hs_free_list_bounce_sgl_count = 12,
    VT_hs_free_list_not_aligned_seg_bits = 13,
    VT_hs_free_list_data_dmap = 14,
    VT_hs_free_list_NUM_COLUMNS
};

static int
copy_columns(struct hv_storvsc_request *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_hs_free_list_link] =  /* Unsupported type */
//    columns[VT_hs_free_list_vstor_packet] =  /* Unsupported type */
    columns[VT_hs_free_list_prp_cnt] = new_dbsc_int64(curEntry->prp_cnt, context);
//    columns[VT_hs_free_list_prp_list] =  /* Unsupported type */
    columns[VT_hs_free_list_sense_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sense_data, context);
    columns[VT_hs_free_list_sense_info_len] = new_dbsc_int64(curEntry->sense_info_len, context);
    columns[VT_hs_free_list_retries] = new_dbsc_int64(curEntry->retries, context);
    columns[VT_hs_free_list_ccb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ccb, context);
    columns[VT_hs_free_list_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->softc, context);
//    columns[VT_hs_free_list_callout] =  /* Unsupported type */
//    columns[VT_hs_free_list_synch_sema] =  /* Unsupported type */
    columns[VT_hs_free_list_bounce_sgl] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bounce_sgl, context);
    columns[VT_hs_free_list_bounce_sgl_count] = new_dbsc_int64(curEntry->bounce_sgl_count, context);
    columns[VT_hs_free_list_not_aligned_seg_bits] = new_dbsc_int64(curEntry->not_aligned_seg_bits, context);
    columns[VT_hs_free_list_data_dmap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->data_dmap, context);

    return 0;
}
void
vtab_hv_storvsc_request_lock(void)
{
    sx_slock(&hs_free_list_lock);
}

void
vtab_hv_storvsc_request_unlock(void)
{
    sx_sunlock(&hs_free_list_lock);
}

void
vtab_hv_storvsc_request_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct hv_storvsc_request *prc = LIST_FIRST(&hs_free_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_hs_free_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_hs_free_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("hv_storvsc_request digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
hv_storvsc_requestvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_hs_free_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("hv_storvsc_request_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
hv_storvsc_requestvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
hv_storvsc_requestvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_hv_storvsc_request_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("hv_storvsc_request digest mismatch: UPDATE failed\n");
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
static sqlite3_module hv_storvsc_requestvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ hv_storvsc_requestvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ hv_storvsc_requestvtabRowid,
    /* xUpdate     */ hv_storvsc_requestvtabUpdate,
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
sqlite3_hv_storvsc_requestvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &hv_storvsc_requestvtabModule,
        pAux);
}
void vtab_hv_storvsc_request_serialize(sqlite3 *real_db, struct timespec when) {
    struct hv_storvsc_request *entry = LIST_FIRST(&hs_free_list);

    const char *create_stmt =
        "CREATE TABLE all_hv_storvsc_requests (prp_cnt INTEGER, sense_info_len INTEGER, retries INTEGER, bounce_sgl_count INTEGER, not_aligned_seg_bits INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_hv_storvsc_requests VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->prp_cnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sense_info_len);
           sqlite3_bind_int64(stmt, bindIndex++, entry->retries);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bounce_sgl_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->not_aligned_seg_bits);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

