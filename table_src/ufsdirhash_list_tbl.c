#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ufsdirhash_list_dh_lock = 0,
    VT_ufsdirhash_list_dh_refcount = 1,
    VT_ufsdirhash_list_dh_hash = 2,
    VT_ufsdirhash_list_dh_narrays = 3,
    VT_ufsdirhash_list_dh_hlen = 4,
    VT_ufsdirhash_list_dh_hused = 5,
    VT_ufsdirhash_list_dh_memreq = 6,
    VT_ufsdirhash_list_dh_blkfree = 7,
    VT_ufsdirhash_list_dh_nblk = 8,
    VT_ufsdirhash_list_dh_dirblks = 9,
    VT_ufsdirhash_list_dh_firstfree = 10,
    VT_ufsdirhash_list_dh_seqoff = 11,
    VT_ufsdirhash_list_dh_score = 12,
    VT_ufsdirhash_list_dh_onlist = 13,
    VT_ufsdirhash_list_dh_lastused = 14,
    VT_ufsdirhash_list_dh_list = 15,
    VT_ufsdirhash_list_NUM_COLUMNS
};

static int
copy_columns(struct ufsdirhash_list *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_ufsdirhash_list_dh_lock] =  TODO: Handle other types
    columns[VT_ufsdirhash_list_dh_refcount] = new_osdb_int64(curEntry->dh_refcount, context);
//    columns[VT_ufsdirhash_list_dh_hash] =  TODO: Handle other types
    columns[VT_ufsdirhash_list_dh_narrays] = new_osdb_int64(curEntry->dh_narrays, context);
    columns[VT_ufsdirhash_list_dh_hlen] = new_osdb_int64(curEntry->dh_hlen, context);
    columns[VT_ufsdirhash_list_dh_hused] = new_osdb_int64(curEntry->dh_hused, context);
    columns[VT_ufsdirhash_list_dh_memreq] = new_osdb_int64(curEntry->dh_memreq, context);
    columns[VT_ufsdirhash_list_dh_blkfree] = new_osdb_text(curEntry->dh_blkfree, strlen(curEntry->dh_blkfree) + 1, context);
    columns[VT_ufsdirhash_list_dh_nblk] = new_osdb_int64(curEntry->dh_nblk, context);
    columns[VT_ufsdirhash_list_dh_dirblks] = new_osdb_int64(curEntry->dh_dirblks, context);
//    columns[VT_ufsdirhash_list_dh_firstfree] =  TODO: Handle other types
    columns[VT_ufsdirhash_list_dh_seqoff] = new_osdb_int64(curEntry->dh_seqoff, context);
    columns[VT_ufsdirhash_list_dh_score] = new_osdb_int64(curEntry->dh_score, context);
    columns[VT_ufsdirhash_list_dh_onlist] = new_osdb_int64(curEntry->dh_onlist, context);
    columns[VT_ufsdirhash_list_dh_lastused] = new_osdb_int64(curEntry->dh_lastused, context);
//    columns[VT_ufsdirhash_list_dh_list] =  TODO: Handle other types

    return 0;
}
void
vtab__lock(void)
{
    sx_slock(&ufsdirhash_list_lock);
}

void
vtab__unlock(void)
{
    sx_sunlock(&ufsdirhash_list_lock);
}

void
vtab__snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct  *prc = LIST_FIRST(&ufsdirhash_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ufsdirhash_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_ufsdirhash_list_NUM_COLUMNS);
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
    osdb_value *pid_value = pCur->row->columns[VT_ufsdirhash_list_PID];
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
