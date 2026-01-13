#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sq_bf_list = 0,
    VT_sq_bf_next = 1,
    VT_sq_bf_nseg = 2,
    VT_sq_bf_rxstatus = 3,
    VT_sq_bf_flags = 4,
    VT_sq_bf_descid = 5,
    VT_sq_bf_desc = 6,
    VT_sq_bf_status = 7,
    VT_sq_bf_daddr = 8,
    VT_sq_bf_dmamap = 9,
    VT_sq_bf_m = 10,
    VT_sq_bf_node = 11,
    VT_sq_bf_lastds = 12,
    VT_sq_bf_last = 13,
    VT_sq_bf_mapsize = 14,
    VT_sq_bf_segs = 15,
    VT_sq_bf_nextfraglen = 16,
    VT_sq_bf_comp = 17,
    VT_sq_bf_state = 18,
    VT_sq_NUM_COLUMNS
};

static int
copy_columns(struct sq *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_sq_bf_list] =  TODO: Handle other types
//    columns[VT_sq_bf_next] =  TODO: Handle other types
    columns[VT_sq_bf_nseg] = new_osdb_int64(curEntry->bf_nseg, context);
    columns[VT_sq_bf_rxstatus] = new_osdb_int64(static_cast<int64_t>(curEntry->bf_rxstatus), context); // TODO: need better enum representation 
    columns[VT_sq_bf_flags] = new_osdb_int64(curEntry->bf_flags, context);
    columns[VT_sq_bf_descid] = new_osdb_int64(curEntry->bf_descid, context);
//    columns[VT_sq_bf_desc] =  TODO: Handle other types
//    columns[VT_sq_bf_status] =  TODO: Handle other types
    columns[VT_sq_bf_daddr] = new_osdb_int64(curEntry->bf_daddr, context);
//    columns[VT_sq_bf_dmamap] =  TODO: Handle other types
//    columns[VT_sq_bf_m] =  TODO: Handle other types
//    columns[VT_sq_bf_node] =  TODO: Handle other types
//    columns[VT_sq_bf_lastds] =  TODO: Handle other types
//    columns[VT_sq_bf_last] =  TODO: Handle other types
    columns[VT_sq_bf_mapsize] = new_osdb_int64(curEntry->bf_mapsize, context);
//    columns[VT_sq_bf_segs] =  TODO: Handle other types
    columns[VT_sq_bf_nextfraglen] = new_osdb_int64(curEntry->bf_nextfraglen, context);
//    columns[VT_sq_bf_comp] =  TODO: Handle other types
//    columns[VT_sq_bf_state] =  TODO: Handle other types

    return 0;
}
void
vtab_axq_q_f_s_lock(void)
{
    sx_slock(&sq_lock);
}

void
vtab_axq_q_f_s_unlock(void)
{
    sx_sunlock(&sq_lock);
}

void
vtab_axq_q_f_s_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct axq_q_f_s *prc = LIST_FIRST(&sq);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sq_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_sq_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("axq_q_f_s digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_axq_q_f_s_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_sq_PID];
    *pRowid = pid_value->int64_value;
    printf("axq_q_f_s_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_axq_q_f_s_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_axq_q_f_s_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_axq_q_f_s_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("axq_q_f_s digest mismatch: UPDATE failed\n");
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
static sqlite3_module axq_q_f_svtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ axq_q_f_svtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ axq_q_f_svtabRowid,
    /* xUpdate     */ axq_q_f_svtabUpdate,
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
sqlite3_axq_q_f_svtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &axq_q_f_svtabModule,
        pAux);
}
