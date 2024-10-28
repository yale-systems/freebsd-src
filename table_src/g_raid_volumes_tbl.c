#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_g_raid_volumes_v_softc = 0,
    VT_g_raid_volumes_v_provider = 1,
    VT_g_raid_volumes_v_subdisks = 2,
    VT_g_raid_volumes_v_md_data = 3,
    VT_g_raid_volumes_v_tr = 4,
    VT_g_raid_volumes_v_name = 5,
    VT_g_raid_volumes_v_state = 6,
    VT_g_raid_volumes_v_raid_level = 7,
    VT_g_raid_volumes_v_raid_level_qualifier = 8,
    VT_g_raid_volumes_v_disks_count = 9,
    VT_g_raid_volumes_v_mdf_pdisks = 10,
    VT_g_raid_volumes_v_mdf_polynomial = 11,
    VT_g_raid_volumes_v_mdf_method = 12,
    VT_g_raid_volumes_v_strip_size = 13,
    VT_g_raid_volumes_v_rotate_parity = 14,
    VT_g_raid_volumes_v_sectorsize = 15,
    VT_g_raid_volumes_v_mediasize = 16,
    VT_g_raid_volumes_v_inflight = 17,
    VT_g_raid_volumes_v_locked = 18,
    VT_g_raid_volumes_v_locks = 19,
    VT_g_raid_volumes_v_pending_lock = 20,
    VT_g_raid_volumes_v_dirty = 21,
    VT_g_raid_volumes_v_last_done = 22,
    VT_g_raid_volumes_v_last_write = 23,
    VT_g_raid_volumes_v_writes = 24,
    VT_g_raid_volumes_v_rootmount = 25,
    VT_g_raid_volumes_v_starting = 26,
    VT_g_raid_volumes_v_stopping = 27,
    VT_g_raid_volumes_v_provider_open = 28,
    VT_g_raid_volumes_v_global_id = 29,
    VT_g_raid_volumes_v_read_only = 30,
    VT_g_raid_volumes_v_next = 31,
    VT_g_raid_volumes_v_global_next = 32,
    VT_g_raid_volumes_NUM_COLUMNS
};

static int
copy_columns(struct g_raid_volumes *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_g_raid_volumes_v_softc] =  TODO: Handle other types
//    columns[VT_g_raid_volumes_v_provider] =  TODO: Handle other types
//    columns[VT_g_raid_volumes_v_subdisks] =  TODO: Handle other types
//    columns[VT_g_raid_volumes_v_md_data] =  TODO: Handle other types
//    columns[VT_g_raid_volumes_v_tr] =  TODO: Handle other types
//    columns[VT_g_raid_volumes_v_name] =  TODO: Handle other types
    columns[VT_g_raid_volumes_v_state] = new_osdb_int64(curEntry->v_state, context);
    columns[VT_g_raid_volumes_v_raid_level] = new_osdb_int64(curEntry->v_raid_level, context);
    columns[VT_g_raid_volumes_v_raid_level_qualifier] = new_osdb_int64(curEntry->v_raid_level_qualifier, context);
    columns[VT_g_raid_volumes_v_disks_count] = new_osdb_int64(curEntry->v_disks_count, context);
    columns[VT_g_raid_volumes_v_mdf_pdisks] = new_osdb_int64(curEntry->v_mdf_pdisks, context);
    columns[VT_g_raid_volumes_v_mdf_polynomial] = new_osdb_int64(curEntry->v_mdf_polynomial, context);
    columns[VT_g_raid_volumes_v_mdf_method] = new_osdb_int64(curEntry->v_mdf_method, context);
    columns[VT_g_raid_volumes_v_strip_size] = new_osdb_int64(curEntry->v_strip_size, context);
    columns[VT_g_raid_volumes_v_rotate_parity] = new_osdb_int64(curEntry->v_rotate_parity, context);
    columns[VT_g_raid_volumes_v_sectorsize] = new_osdb_int64(curEntry->v_sectorsize, context);
    columns[VT_g_raid_volumes_v_mediasize] = new_osdb_int64(curEntry->v_mediasize, context);
//    columns[VT_g_raid_volumes_v_inflight] =  TODO: Handle other types
//    columns[VT_g_raid_volumes_v_locked] =  TODO: Handle other types
//    columns[VT_g_raid_volumes_v_locks] =  TODO: Handle other types
    columns[VT_g_raid_volumes_v_pending_lock] = new_osdb_int64(curEntry->v_pending_lock, context);
    columns[VT_g_raid_volumes_v_dirty] = new_osdb_int64(curEntry->v_dirty, context);
//    columns[VT_g_raid_volumes_v_last_done] =  TODO: Handle other types
    columns[VT_g_raid_volumes_v_last_write] = new_osdb_int64(curEntry->v_last_write, context);
    columns[VT_g_raid_volumes_v_writes] = new_osdb_int64(curEntry->v_writes, context);
//    columns[VT_g_raid_volumes_v_rootmount] =  TODO: Handle other types
    columns[VT_g_raid_volumes_v_starting] = new_osdb_int64(curEntry->v_starting, context);
    columns[VT_g_raid_volumes_v_stopping] = new_osdb_int64(curEntry->v_stopping, context);
    columns[VT_g_raid_volumes_v_provider_open] = new_osdb_int64(curEntry->v_provider_open, context);
    columns[VT_g_raid_volumes_v_global_id] = new_osdb_int64(curEntry->v_global_id, context);
    columns[VT_g_raid_volumes_v_read_only] = new_osdb_int64(curEntry->v_read_only, context);
//    columns[VT_g_raid_volumes_v_next] =  TODO: Handle other types
//    columns[VT_g_raid_volumes_v_global_next] =  TODO: Handle other types

    return 0;
}
void
vtab__lock(void)
{
    sx_slock(&g_raid_volumes_lock);
}

void
vtab__unlock(void)
{
    sx_sunlock(&g_raid_volumes_lock);
}

void
vtab__snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct  *prc = LIST_FIRST(&g_raid_volumes);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_g_raid_volumes_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_g_raid_volumes_NUM_COLUMNS);
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
    osdb_value *pid_value = pCur->row->columns[VT_g_raid_volumes_PID];
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
