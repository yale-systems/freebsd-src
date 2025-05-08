#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ath_buf.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ath_buf.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_axq_q_bf_list = 0,
    VT_axq_q_bf_next = 1,
    VT_axq_q_bf_nseg = 2,
    VT_axq_q_bf_rxstatus = 3,
    VT_axq_q_bf_flags = 4,
    VT_axq_q_bf_descid = 5,
    VT_axq_q_bf_desc = 6,
    VT_axq_q_bf_status = 7,
    VT_axq_q_bf_daddr = 8,
    VT_axq_q_bf_dmamap = 9,
    VT_axq_q_bf_m = 10,
    VT_axq_q_bf_node = 11,
    VT_axq_q_bf_lastds = 12,
    VT_axq_q_bf_last = 13,
    VT_axq_q_bf_mapsize = 14,
    VT_axq_q_bf_segs = 15,
    VT_axq_q_bf_nextfraglen = 16,
    VT_axq_q_bf_comp = 17,
    VT_axq_q_bf_state = 18,
    VT_axq_q_NUM_COLUMNS
};

static int
copy_columns(struct ath_buf *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_axq_q_bf_list] =  /* Unsupported type */
    columns[VT_axq_q_bf_next] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bf_next, context);
    columns[VT_axq_q_bf_nseg] = new_dbsc_int64(curEntry->bf_nseg, context);
    columns[VT_axq_q_bf_rxstatus] = new_dbsc_int64((int64_t)(curEntry->bf_rxstatus), context); // TODO: need better enum representation 
    columns[VT_axq_q_bf_flags] = new_dbsc_int64(curEntry->bf_flags, context);
    columns[VT_axq_q_bf_descid] = new_dbsc_int64(curEntry->bf_descid, context);
    columns[VT_axq_q_bf_desc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bf_desc, context);
//    columns[VT_axq_q_bf_status] =  /* Unsupported type */
    columns[VT_axq_q_bf_daddr] = new_dbsc_int64(curEntry->bf_daddr, context);
    columns[VT_axq_q_bf_dmamap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bf_dmamap, context);
    columns[VT_axq_q_bf_m] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bf_m, context);
    columns[VT_axq_q_bf_node] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bf_node, context);
    columns[VT_axq_q_bf_lastds] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bf_lastds, context);
    columns[VT_axq_q_bf_last] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bf_last, context);
    columns[VT_axq_q_bf_mapsize] = new_dbsc_int64(curEntry->bf_mapsize, context);
//    columns[VT_axq_q_bf_segs] =  /* Unsupported type */
    columns[VT_axq_q_bf_nextfraglen] = new_dbsc_int64(curEntry->bf_nextfraglen, context);
    columns[VT_axq_q_bf_comp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bf_comp, context);
//    columns[VT_axq_q_bf_state] =  /* Unsupported type */

    return 0;
}
void
vtab_ath_buf_lock(void)
{
    sx_slock(&axq_q_lock);
}

void
vtab_ath_buf_unlock(void)
{
    sx_sunlock(&axq_q_lock);
}

void
vtab_ath_buf_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ath_buf *prc = LIST_FIRST(&axq_q);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_axq_q_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_axq_q_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ath_buf digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ath_bufvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_axq_q_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ath_buf_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ath_bufvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ath_bufvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ath_buf_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ath_buf digest mismatch: UPDATE failed\n");
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
static sqlite3_module ath_bufvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ath_bufvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ath_bufvtabRowid,
    /* xUpdate     */ ath_bufvtabUpdate,
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
sqlite3_ath_bufvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ath_bufvtabModule,
        pAux);
}
void vtab_ath_buf_serialize(sqlite3 *real_db, struct timespec when) {
    struct ath_buf *entry = LIST_FIRST(&axq_q);

    const char *create_stmt =
        "CREATE TABLE all_ath_bufs (bf_nseg INTEGER, bf_rxstatus INTEGER, bf_flags INTEGER, bf_descid INTEGER, bf_daddr INTEGER, bf_mapsize INTEGER, bf_nextfraglen INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ath_bufs VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->bf_nseg);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bf_rxstatus);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bf_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bf_descid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bf_daddr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bf_mapsize);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bf_nextfraglen);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

