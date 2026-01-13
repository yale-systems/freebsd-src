#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_free_pages_plinks = 0,
    VT_free_pages_listq = 1,
    VT_free_pages_object = 2,
    VT_free_pages_pindex = 3,
    VT_free_pages_phys_addr = 4,
    VT_free_pages_md = 5,
    VT_free_pages_ref_count = 6,
    VT_free_pages_busy_lock = 7,
    VT_free_pages_a = 8,
    VT_free_pages_order = 9,
    VT_free_pages_pool = 10,
    VT_free_pages_flags = 11,
    VT_free_pages_oflags = 12,
    VT_free_pages_psind = 13,
    VT_free_pages_segind = 14,
    VT_free_pages_valid = 15,
    VT_free_pages_dirty = 16,
    VT_free_pages_NUM_COLUMNS
};

static int
copy_columns(struct free_pages *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_free_pages_plinks] =  TODO: Handle other types
//    columns[VT_free_pages_listq] =  TODO: Handle other types
//    columns[VT_free_pages_object] =  TODO: Handle other types
    columns[VT_free_pages_pindex] = new_osdb_int64(curEntry->pindex, context);
    columns[VT_free_pages_phys_addr] = new_osdb_int64(curEntry->phys_addr, context);
//    columns[VT_free_pages_md] =  TODO: Handle other types
    columns[VT_free_pages_ref_count] = new_osdb_int64(curEntry->ref_count, context);
    columns[VT_free_pages_busy_lock] = new_osdb_int64(curEntry->busy_lock, context);
//    columns[VT_free_pages_a] =  TODO: Handle other types
    columns[VT_free_pages_order] = new_osdb_int64(curEntry->order, context);
    columns[VT_free_pages_pool] = new_osdb_int64(curEntry->pool, context);
    columns[VT_free_pages_flags] = new_osdb_int64(curEntry->flags, context);
    columns[VT_free_pages_oflags] = new_osdb_int64(curEntry->oflags, context);
    columns[VT_free_pages_psind] = new_osdb_int64(curEntry->psind, context);
    columns[VT_free_pages_segind] = new_osdb_int64(curEntry->segind, context);
    columns[VT_free_pages_valid] = new_osdb_int64(curEntry->valid, context);
    columns[VT_free_pages_dirty] = new_osdb_int64(curEntry->dirty, context);

    return 0;
}
void
vtab__lock(void)
{
    sx_slock(&free_pages_lock);
}

void
vtab__unlock(void)
{
    sx_sunlock(&free_pages_lock);
}

void
vtab__snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct  *prc = LIST_FIRST(&free_pages);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_free_pages_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_free_pages_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf(" digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab__rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_free_pages_PID];
    *pRowid = pid_value->int64_value;
    printf("_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab__bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab__update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab__snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf(" digest mismatch: UPDATE failed\n");
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
static sqlite3_module vtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vtabRowid,
    /* xUpdate     */ vtabUpdate,
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
sqlite3_vtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vtabModule,
        pAux);
}
