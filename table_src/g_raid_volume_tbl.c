#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/g_raid_volume.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_g_raid_volume.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sc_volumes_v_softc = 0,
    VT_sc_volumes_v_provider = 1,
    VT_sc_volumes_v_subdisks = 2,
    VT_sc_volumes_v_md_data = 3,
    VT_sc_volumes_v_tr = 4,
    VT_sc_volumes_v_name = 5,
    VT_sc_volumes_v_state = 6,
    VT_sc_volumes_v_raid_level = 7,
    VT_sc_volumes_v_raid_level_qualifier = 8,
    VT_sc_volumes_v_disks_count = 9,
    VT_sc_volumes_v_mdf_pdisks = 10,
    VT_sc_volumes_v_mdf_polynomial = 11,
    VT_sc_volumes_v_mdf_method = 12,
    VT_sc_volumes_v_strip_size = 13,
    VT_sc_volumes_v_rotate_parity = 14,
    VT_sc_volumes_v_sectorsize = 15,
    VT_sc_volumes_v_mediasize = 16,
    VT_sc_volumes_v_inflight = 17,
    VT_sc_volumes_v_locked = 18,
    VT_sc_volumes_v_locks = 19,
    VT_sc_volumes_v_pending_lock = 20,
    VT_sc_volumes_v_dirty = 21,
    VT_sc_volumes_v_last_done = 22,
    VT_sc_volumes_v_last_write = 23,
    VT_sc_volumes_v_writes = 24,
    VT_sc_volumes_v_rootmount = 25,
    VT_sc_volumes_v_starting = 26,
    VT_sc_volumes_v_stopping = 27,
    VT_sc_volumes_v_provider_open = 28,
    VT_sc_volumes_v_global_id = 29,
    VT_sc_volumes_v_read_only = 30,
    VT_sc_volumes_v_next = 31,
    VT_sc_volumes_v_global_next = 32,
    VT_sc_volumes_NUM_COLUMNS
};

static int
copy_columns(struct g_raid_volume *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_sc_volumes_v_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_softc, context);
    columns[VT_sc_volumes_v_provider] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_provider, context);
//    columns[VT_sc_volumes_v_subdisks] =  /* Unsupported type */
    columns[VT_sc_volumes_v_md_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_md_data, context);
    columns[VT_sc_volumes_v_tr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_tr, context);
//    columns[VT_sc_volumes_v_name] =  /* Unsupported type */
    columns[VT_sc_volumes_v_state] = new_dbsc_int64(curEntry->v_state, context);
    columns[VT_sc_volumes_v_raid_level] = new_dbsc_int64(curEntry->v_raid_level, context);
    columns[VT_sc_volumes_v_raid_level_qualifier] = new_dbsc_int64(curEntry->v_raid_level_qualifier, context);
    columns[VT_sc_volumes_v_disks_count] = new_dbsc_int64(curEntry->v_disks_count, context);
    columns[VT_sc_volumes_v_mdf_pdisks] = new_dbsc_int64(curEntry->v_mdf_pdisks, context);
    columns[VT_sc_volumes_v_mdf_polynomial] = new_dbsc_int64(curEntry->v_mdf_polynomial, context);
    columns[VT_sc_volumes_v_mdf_method] = new_dbsc_int64(curEntry->v_mdf_method, context);
    columns[VT_sc_volumes_v_strip_size] = new_dbsc_int64(curEntry->v_strip_size, context);
    columns[VT_sc_volumes_v_rotate_parity] = new_dbsc_int64(curEntry->v_rotate_parity, context);
    columns[VT_sc_volumes_v_sectorsize] = new_dbsc_int64(curEntry->v_sectorsize, context);
    columns[VT_sc_volumes_v_mediasize] = new_dbsc_int64(curEntry->v_mediasize, context);
//    columns[VT_sc_volumes_v_inflight] =  /* Unsupported type */
//    columns[VT_sc_volumes_v_locked] =  /* Unsupported type */
//    columns[VT_sc_volumes_v_locks] =  /* Unsupported type */
    columns[VT_sc_volumes_v_pending_lock] = new_dbsc_int64(curEntry->v_pending_lock, context);
    columns[VT_sc_volumes_v_dirty] = new_dbsc_int64(curEntry->v_dirty, context);
//    columns[VT_sc_volumes_v_last_done] =  /* Unsupported type */
    columns[VT_sc_volumes_v_last_write] = new_dbsc_int64(curEntry->v_last_write, context);
    columns[VT_sc_volumes_v_writes] = new_dbsc_int64(curEntry->v_writes, context);
    columns[VT_sc_volumes_v_rootmount] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->v_rootmount, context);
    columns[VT_sc_volumes_v_starting] = new_dbsc_int64(curEntry->v_starting, context);
    columns[VT_sc_volumes_v_stopping] = new_dbsc_int64(curEntry->v_stopping, context);
    columns[VT_sc_volumes_v_provider_open] = new_dbsc_int64(curEntry->v_provider_open, context);
    columns[VT_sc_volumes_v_global_id] = new_dbsc_int64(curEntry->v_global_id, context);
    columns[VT_sc_volumes_v_read_only] = new_dbsc_int64(curEntry->v_read_only, context);
//    columns[VT_sc_volumes_v_next] =  /* Unsupported type */
//    columns[VT_sc_volumes_v_global_next] =  /* Unsupported type */

    return 0;
}
void
vtab_g_raid_volume_lock(void)
{
    sx_slock(&sc_volumes_lock);
}

void
vtab_g_raid_volume_unlock(void)
{
    sx_sunlock(&sc_volumes_lock);
}

void
vtab_g_raid_volume_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct g_raid_volume *prc = LIST_FIRST(&sc_volumes);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sc_volumes_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sc_volumes_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("g_raid_volume digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
g_raid_volumevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sc_volumes_p_pid];
    *pRowid = pid_value->int64_value;
    printf("g_raid_volume_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
g_raid_volumevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
g_raid_volumevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_g_raid_volume_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("g_raid_volume digest mismatch: UPDATE failed\n");
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
static sqlite3_module g_raid_volumevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ g_raid_volumevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ g_raid_volumevtabRowid,
    /* xUpdate     */ g_raid_volumevtabUpdate,
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
sqlite3_g_raid_volumevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &g_raid_volumevtabModule,
        pAux);
}
void vtab_g_raid_volume_serialize(sqlite3 *real_db, struct timespec when) {
    struct g_raid_volume *entry = LIST_FIRST(&sc_volumes);

    const char *create_stmt =
        "CREATE TABLE all_g_raid_volumes (v_state INTEGER, v_raid_level INTEGER, v_raid_level_qualifier INTEGER, v_disks_count INTEGER, v_mdf_pdisks INTEGER, v_mdf_polynomial INTEGER, v_mdf_method INTEGER, v_strip_size INTEGER, v_rotate_parity INTEGER, v_sectorsize INTEGER, v_mediasize INTEGER, v_pending_lock INTEGER, v_dirty INTEGER, v_last_write INTEGER, v_writes INTEGER, v_starting INTEGER, v_stopping INTEGER, v_provider_open INTEGER, v_global_id INTEGER, v_read_only INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_g_raid_volumes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_raid_level);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_raid_level_qualifier);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_disks_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_mdf_pdisks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_mdf_polynomial);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_mdf_method);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_strip_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_rotate_parity);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_sectorsize);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_mediasize);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_pending_lock);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_dirty);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_last_write);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_writes);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_starting);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_stopping);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_provider_open);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_global_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->v_read_only);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

