#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/gv_volume.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_gv_volume.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_volumes_name = 0,
    VT_volumes_size = 1,
    VT_volumes_plexcount = 2,
    VT_volumes_state = 3,
    VT_volumes_flags = 4,
    VT_volumes_plexes = 5,
    VT_volumes_volume = 6,
    VT_volumes_provider = 7,
    VT_volumes_wqueue = 8,
    VT_volumes_last_read_plex = 9,
    VT_volumes_vinumconf = 10,
    VT_volumes_NUM_COLUMNS
};

static int
copy_columns(struct gv_volume *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_volumes_name] =  /* Unsupported type */
    columns[VT_volumes_size] = new_dbsc_int64(curEntry->size, context);
    columns[VT_volumes_plexcount] = new_dbsc_int64(curEntry->plexcount, context);
    columns[VT_volumes_state] = new_dbsc_int64(curEntry->state, context);
    columns[VT_volumes_flags] = new_dbsc_int64(curEntry->flags, context);
//    columns[VT_volumes_plexes] =  /* Unsupported type */
//    columns[VT_volumes_volume] =  /* Unsupported type */
    columns[VT_volumes_provider] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->provider, context);
    columns[VT_volumes_wqueue] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->wqueue, context);
    columns[VT_volumes_last_read_plex] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->last_read_plex, context);
    columns[VT_volumes_vinumconf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vinumconf, context);

    return 0;
}
void
vtab_gv_volume_lock(void)
{
    sx_slock(&volumes_lock);
}

void
vtab_gv_volume_unlock(void)
{
    sx_sunlock(&volumes_lock);
}

void
vtab_gv_volume_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct gv_volume *prc = LIST_FIRST(&volumes);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_volumes_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_volumes_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("gv_volume digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
gv_volumevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_volumes_p_pid];
    *pRowid = pid_value->int64_value;
    printf("gv_volume_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
gv_volumevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
gv_volumevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_gv_volume_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("gv_volume digest mismatch: UPDATE failed\n");
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
static sqlite3_module gv_volumevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ gv_volumevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ gv_volumevtabRowid,
    /* xUpdate     */ gv_volumevtabUpdate,
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
sqlite3_gv_volumevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &gv_volumevtabModule,
        pAux);
}
void vtab_gv_volume_serialize(sqlite3 *real_db, struct timespec when) {
    struct gv_volume *entry = LIST_FIRST(&volumes);

    const char *create_stmt =
        "CREATE TABLE all_gv_volumes (size INTEGER, plexcount INTEGER, state INTEGER, flags INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_gv_volumes VALUES (?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->plexcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

