#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_workq_pfrkt_kts = 0,
    VT_workq_pfrkt_tree = 1,
    VT_workq_pfrkt_workq = 2,
    VT_workq_pfrkt_ip4 = 3,
    VT_workq_pfrkt_ip6 = 4,
    VT_workq_pfrkt_shadow = 5,
    VT_workq_pfrkt_root = 6,
    VT_workq_pfrkt_rs = 7,
    VT_workq_pfrkt_larg = 8,
    VT_workq_pfrkt_nflags = 9,
    VT_workq_NUM_COLUMNS
};

static int
copy_columns(struct workq *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_workq_pfrkt_kts] =  TODO: Handle other types
//    columns[VT_workq_pfrkt_tree] =  TODO: Handle other types
//    columns[VT_workq_pfrkt_workq] =  TODO: Handle other types
//    columns[VT_workq_pfrkt_ip4] =  TODO: Handle other types
//    columns[VT_workq_pfrkt_ip6] =  TODO: Handle other types
//    columns[VT_workq_pfrkt_shadow] =  TODO: Handle other types
//    columns[VT_workq_pfrkt_root] =  TODO: Handle other types
//    columns[VT_workq_pfrkt_rs] =  TODO: Handle other types
    columns[VT_workq_pfrkt_larg] = new_osdb_int64(curEntry->pfrkt_larg, context);
    columns[VT_workq_pfrkt_nflags] = new_osdb_int64(curEntry->pfrkt_nflags, context);

    return 0;
}
void
vtab_pfr_ktableworkq_lock(void)
{
    sx_slock(&workq_lock);
}

void
vtab_pfr_ktableworkq_unlock(void)
{
    sx_sunlock(&workq_lock);
}

void
vtab_pfr_ktableworkq_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pfr_ktableworkq *prc = LIST_FIRST(&workq);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_workq_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_workq_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pfr_ktableworkq digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_pfr_ktableworkq_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_workq_PID];
    *pRowid = pid_value->int64_value;
    printf("pfr_ktableworkq_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_pfr_ktableworkq_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_pfr_ktableworkq_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pfr_ktableworkq_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pfr_ktableworkq digest mismatch: UPDATE failed\n");
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
static sqlite3_module pfr_ktableworkqvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pfr_ktableworkqvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pfr_ktableworkqvtabRowid,
    /* xUpdate     */ pfr_ktableworkqvtabUpdate,
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
sqlite3_pfr_ktableworkqvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pfr_ktableworkqvtabModule,
        pAux);
}
