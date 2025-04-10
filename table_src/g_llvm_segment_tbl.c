#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/g_llvm_segment.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_g_llvm_segment.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_lv_segs_sg_next = 0,
    VT_lv_segs_sg_start = 1,
    VT_lv_segs_sg_end = 2,
    VT_lv_segs_sg_count = 3,
    VT_lv_segs_sg_pvname = 4,
    VT_lv_segs_sg_pv = 5,
    VT_lv_segs_sg_pvstart = 6,
    VT_lv_segs_sg_pvoffset = 7,
    VT_lv_segs_NUM_COLUMNS
};

static int
copy_columns(struct g_llvm_segment *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_lv_segs_sg_next] =  /* Unsupported type */
    columns[VT_lv_segs_sg_start] = new_dbsc_int64(curEntry->sg_start, context);
    columns[VT_lv_segs_sg_end] = new_dbsc_int64(curEntry->sg_end, context);
    columns[VT_lv_segs_sg_count] = new_dbsc_int64(curEntry->sg_count, context);
//    columns[VT_lv_segs_sg_pvname] =  /* Unsupported type */
    columns[VT_lv_segs_sg_pv] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sg_pv, context);
    columns[VT_lv_segs_sg_pvstart] = new_dbsc_int64(curEntry->sg_pvstart, context);
    columns[VT_lv_segs_sg_pvoffset] = new_dbsc_int64(curEntry->sg_pvoffset, context);

    return 0;
}
void
vtab_g_llvm_segment_lock(void)
{
    sx_slock(&lv_segs_lock);
}

void
vtab_g_llvm_segment_unlock(void)
{
    sx_sunlock(&lv_segs_lock);
}

void
vtab_g_llvm_segment_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct g_llvm_segment *prc = LIST_FIRST(&lv_segs);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_lv_segs_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_lv_segs_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("g_llvm_segment digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
g_llvm_segmentvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_lv_segs_p_pid];
    *pRowid = pid_value->int64_value;
    printf("g_llvm_segment_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
g_llvm_segmentvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
g_llvm_segmentvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_g_llvm_segment_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("g_llvm_segment digest mismatch: UPDATE failed\n");
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
static sqlite3_module g_llvm_segmentvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ g_llvm_segmentvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ g_llvm_segmentvtabRowid,
    /* xUpdate     */ g_llvm_segmentvtabUpdate,
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
sqlite3_g_llvm_segmentvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &g_llvm_segmentvtabModule,
        pAux);
}
void vtab_g_llvm_segment_serialize(sqlite3 *real_db, struct timespec when) {
    struct g_llvm_segment *entry = LIST_FIRST(&lv_segs);

    const char *create_stmt =
        "CREATE TABLE all_g_llvm_segments (sg_start INTEGER, sg_end INTEGER, sg_count INTEGER, sg_pvstart INTEGER, sg_pvoffset INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_g_llvm_segments VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->sg_start);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sg_end);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sg_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sg_pvstart);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sg_pvoffset);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

