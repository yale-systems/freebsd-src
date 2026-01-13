#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/g_mirror_disk.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_g_mirror_disk.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sc_disks_d_id = 0,
    VT_sc_disks_d_consumer = 1,
    VT_sc_disks_d_softc = 2,
    VT_sc_disks_d_state = 3,
    VT_sc_disks_d_priority = 4,
    VT_sc_disks_load = 5,
    VT_sc_disks_d_last_offset = 6,
    VT_sc_disks_d_flags = 7,
    VT_sc_disks_d_genid = 8,
    VT_sc_disks_d_sync = 9,
    VT_sc_disks_d_next = 10,
    VT_sc_disks_d_init_ndisks = 11,
    VT_sc_disks_d_init_slice = 12,
    VT_sc_disks_d_init_balance = 13,
    VT_sc_disks_d_rotation_rate = 14,
    VT_sc_disks_d_init_mediasize = 15,
    VT_sc_disks_NUM_COLUMNS
};

static int
copy_columns(struct g_mirror_disk *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_sc_disks_d_id] = new_dbsc_int64(curEntry->d_id, context);
    columns[VT_sc_disks_d_consumer] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->d_consumer, context);
    columns[VT_sc_disks_d_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->d_softc, context);
    columns[VT_sc_disks_d_state] = new_dbsc_int64(curEntry->d_state, context);
    columns[VT_sc_disks_d_priority] = new_dbsc_int64(curEntry->d_priority, context);
    columns[VT_sc_disks_load] = new_dbsc_int64(curEntry->load, context);
    columns[VT_sc_disks_d_last_offset] = new_dbsc_int64(curEntry->d_last_offset, context);
    columns[VT_sc_disks_d_flags] = new_dbsc_int64(curEntry->d_flags, context);
    columns[VT_sc_disks_d_genid] = new_dbsc_int64(curEntry->d_genid, context);
//    columns[VT_sc_disks_d_sync] =  /* Unsupported type */
//    columns[VT_sc_disks_d_next] =  /* Unsupported type */
    columns[VT_sc_disks_d_init_ndisks] = new_dbsc_int64(curEntry->d_init_ndisks, context);
    columns[VT_sc_disks_d_init_slice] = new_dbsc_int64(curEntry->d_init_slice, context);
    columns[VT_sc_disks_d_init_balance] = new_dbsc_int64(curEntry->d_init_balance, context);
    columns[VT_sc_disks_d_rotation_rate] = new_dbsc_int64(curEntry->d_rotation_rate, context);
    columns[VT_sc_disks_d_init_mediasize] = new_dbsc_int64(curEntry->d_init_mediasize, context);

    return 0;
}
void
vtab_g_mirror_disk_lock(void)
{
    sx_slock(&sc_disks_lock);
}

void
vtab_g_mirror_disk_unlock(void)
{
    sx_sunlock(&sc_disks_lock);
}

void
vtab_g_mirror_disk_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct g_mirror_disk *prc = LIST_FIRST(&sc_disks);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sc_disks_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sc_disks_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("g_mirror_disk digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
g_mirror_diskvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sc_disks_p_pid];
    *pRowid = pid_value->int64_value;
    printf("g_mirror_disk_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
g_mirror_diskvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
g_mirror_diskvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_g_mirror_disk_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("g_mirror_disk digest mismatch: UPDATE failed\n");
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
static sqlite3_module g_mirror_diskvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ g_mirror_diskvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ g_mirror_diskvtabRowid,
    /* xUpdate     */ g_mirror_diskvtabUpdate,
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
sqlite3_g_mirror_diskvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &g_mirror_diskvtabModule,
        pAux);
}
void vtab_g_mirror_disk_serialize(sqlite3 *real_db, struct timespec when) {
    struct g_mirror_disk *entry = LIST_FIRST(&sc_disks);

    const char *create_stmt =
        "CREATE TABLE all_g_mirror_disks (d_id INTEGER, d_state INTEGER, d_priority INTEGER, load INTEGER, d_last_offset INTEGER, d_flags INTEGER, d_genid INTEGER, d_init_ndisks INTEGER, d_init_slice INTEGER, d_init_balance INTEGER, d_rotation_rate INTEGER, d_init_mediasize INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_g_mirror_disks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_priority);
           sqlite3_bind_int64(stmt, bindIndex++, entry->load);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_last_offset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_genid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_init_ndisks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_init_slice);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_init_balance);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_rotation_rate);
           sqlite3_bind_int64(stmt, bindIndex++, entry->d_init_mediasize);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

