#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_vnet_entry_pf_fragqueue_fr_key = 0,
    VT_vnet_entry_pf_fragqueue_fr_firstoff = 1,
    VT_vnet_entry_pf_fragqueue_fr_entries = 2,
    VT_vnet_entry_pf_fragqueue_fr_entry = 3,
    VT_vnet_entry_pf_fragqueue_frag_next = 4,
    VT_vnet_entry_pf_fragqueue_fr_timeout = 5,
    VT_vnet_entry_pf_fragqueue_fr_maxlen = 6,
    VT_vnet_entry_pf_fragqueue_fr_holes = 7,
    VT_vnet_entry_pf_fragqueue_fr_queue = 8,
    VT_vnet_entry_pf_fragqueue_NUM_COLUMNS
};

static int
copy_columns(struct vnet_entry_pf_fragqueue *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vnet_entry_pf_fragqueue_fr_key] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_fragqueue_fr_firstoff] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_fragqueue_fr_entries] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_fragqueue_fr_entry] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_fragqueue_frag_next] =  TODO: Handle other types
    columns[VT_vnet_entry_pf_fragqueue_fr_timeout] = new_osdb_int64(curEntry->fr_timeout, context);
    columns[VT_vnet_entry_pf_fragqueue_fr_maxlen] = new_osdb_int64(curEntry->fr_maxlen, context);
    columns[VT_vnet_entry_pf_fragqueue_fr_holes] = new_osdb_int64(curEntry->fr_holes, context);
//    columns[VT_vnet_entry_pf_fragqueue_fr_queue] =  TODO: Handle other types

    return 0;
}
void
vtab_pf_fragqueue_lock(void)
{
    sx_slock(&vnet_entry_pf_fragqueue_lock);
}

void
vtab_pf_fragqueue_unlock(void)
{
    sx_sunlock(&vnet_entry_pf_fragqueue_lock);
}

void
vtab_pf_fragqueue_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pf_fragqueue *prc = LIST_FIRST(&vnet_entry_pf_fragqueue);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_pf_fragqueue_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_vnet_entry_pf_fragqueue_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pf_fragqueue digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_pf_fragqueue_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_vnet_entry_pf_fragqueue_PID];
    *pRowid = pid_value->int64_value;
    printf("pf_fragqueue_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_pf_fragqueue_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_pf_fragqueue_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pf_fragqueue_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pf_fragqueue digest mismatch: UPDATE failed\n");
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
static sqlite3_module pf_fragqueuevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pf_fragqueuevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pf_fragqueuevtabRowid,
    /* xUpdate     */ pf_fragqueuevtabUpdate,
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
sqlite3_pf_fragqueuevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pf_fragqueuevtabModule,
        pAux);
}
