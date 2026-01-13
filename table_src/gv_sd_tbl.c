#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/gv_sd.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_gv_sd.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_subdisks_name = 0,
    VT_subdisks_size = 1,
    VT_subdisks_drive_offset = 2,
    VT_subdisks_plex_offset = 3,
    VT_subdisks_state = 4,
    VT_subdisks_initialized = 5,
    VT_subdisks_init_size = 6,
    VT_subdisks_init_error = 7,
    VT_subdisks_flags = 8,
    VT_subdisks_drive = 9,
    VT_subdisks_plex = 10,
    VT_subdisks_drive_sc = 11,
    VT_subdisks_plex_sc = 12,
    VT_subdisks_from_drive = 13,
    VT_subdisks_in_plex = 14,
    VT_subdisks_sd = 15,
    VT_subdisks_vinumconf = 16,
    VT_subdisks_NUM_COLUMNS
};

static int
copy_columns(struct gv_sd *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_subdisks_name] =  /* Unsupported type */
    columns[VT_subdisks_size] = new_dbsc_int64(curEntry->size, context);
    columns[VT_subdisks_drive_offset] = new_dbsc_int64(curEntry->drive_offset, context);
    columns[VT_subdisks_plex_offset] = new_dbsc_int64(curEntry->plex_offset, context);
    columns[VT_subdisks_state] = new_dbsc_int64(curEntry->state, context);
    columns[VT_subdisks_initialized] = new_dbsc_int64(curEntry->initialized, context);
    columns[VT_subdisks_init_size] = new_dbsc_int64(curEntry->init_size, context);
    columns[VT_subdisks_init_error] = new_dbsc_int64(curEntry->init_error, context);
    columns[VT_subdisks_flags] = new_dbsc_int64(curEntry->flags, context);
//    columns[VT_subdisks_drive] =  /* Unsupported type */
//    columns[VT_subdisks_plex] =  /* Unsupported type */
    columns[VT_subdisks_drive_sc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->drive_sc, context);
    columns[VT_subdisks_plex_sc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->plex_sc, context);
//    columns[VT_subdisks_from_drive] =  /* Unsupported type */
//    columns[VT_subdisks_in_plex] =  /* Unsupported type */
//    columns[VT_subdisks_sd] =  /* Unsupported type */
    columns[VT_subdisks_vinumconf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vinumconf, context);

    return 0;
}
void
vtab_gv_sd_lock(void)
{
    sx_slock(&subdisks_lock);
}

void
vtab_gv_sd_unlock(void)
{
    sx_sunlock(&subdisks_lock);
}

void
vtab_gv_sd_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct gv_sd *prc = LIST_FIRST(&subdisks);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_subdisks_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_subdisks_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("gv_sd digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
gv_sdvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_subdisks_p_pid];
    *pRowid = pid_value->int64_value;
    printf("gv_sd_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
gv_sdvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
gv_sdvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_gv_sd_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("gv_sd digest mismatch: UPDATE failed\n");
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
static sqlite3_module gv_sdvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ gv_sdvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ gv_sdvtabRowid,
    /* xUpdate     */ gv_sdvtabUpdate,
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
sqlite3_gv_sdvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &gv_sdvtabModule,
        pAux);
}
void vtab_gv_sd_serialize(sqlite3 *real_db, struct timespec when) {
    struct gv_sd *entry = LIST_FIRST(&subdisks);

    const char *create_stmt =
        "CREATE TABLE all_gv_sds (size INTEGER, drive_offset INTEGER, plex_offset INTEGER, state INTEGER, initialized INTEGER, init_size INTEGER, init_error INTEGER, flags INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_gv_sds VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->drive_offset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->plex_offset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->initialized);
           sqlite3_bind_int64(stmt, bindIndex++, entry->init_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->init_error);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

