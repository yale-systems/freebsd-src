#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/gv_drive.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_gv_drive.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_drives_name = 0,
    VT_drives_device = 1,
    VT_drives_state = 2,
    VT_drives_size = 3,
    VT_drives_avail = 4,
    VT_drives_sdcount = 5,
    VT_drives_flags = 6,
    VT_drives_hdr = 7,
    VT_drives_consumer = 8,
    VT_drives_active = 9,
    VT_drives_freelist_entries = 10,
    VT_drives_freelist = 11,
    VT_drives_subdisks = 12,
    VT_drives_drive = 13,
    VT_drives_vinumconf = 14,
    VT_drives_NUM_COLUMNS
};

static int
copy_columns(struct gv_drive *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_drives_name] =  /* Unsupported type */
//    columns[VT_drives_device] =  /* Unsupported type */
    columns[VT_drives_state] = new_dbsc_int64(curEntry->state, context);
    columns[VT_drives_size] = new_dbsc_int64(curEntry->size, context);
    columns[VT_drives_avail] = new_dbsc_int64(curEntry->avail, context);
    columns[VT_drives_sdcount] = new_dbsc_int64(curEntry->sdcount, context);
    columns[VT_drives_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_drives_hdr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->hdr, context);
    columns[VT_drives_consumer] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->consumer, context);
    columns[VT_drives_active] = new_dbsc_int64(curEntry->active, context);
    columns[VT_drives_freelist_entries] = new_dbsc_int64(curEntry->freelist_entries, context);
//    columns[VT_drives_freelist] =  /* Unsupported type */
//    columns[VT_drives_subdisks] =  /* Unsupported type */
//    columns[VT_drives_drive] =  /* Unsupported type */
    columns[VT_drives_vinumconf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vinumconf, context);

    return 0;
}
void
vtab_gv_drive_lock(void)
{
    sx_slock(&drives_lock);
}

void
vtab_gv_drive_unlock(void)
{
    sx_sunlock(&drives_lock);
}

void
vtab_gv_drive_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct gv_drive *prc = LIST_FIRST(&drives);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_drives_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_drives_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("gv_drive digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
gv_drivevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_drives_p_pid];
    *pRowid = pid_value->int64_value;
    printf("gv_drive_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
gv_drivevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
gv_drivevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_gv_drive_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("gv_drive digest mismatch: UPDATE failed\n");
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
static sqlite3_module gv_drivevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ gv_drivevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ gv_drivevtabRowid,
    /* xUpdate     */ gv_drivevtabUpdate,
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
sqlite3_gv_drivevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &gv_drivevtabModule,
        pAux);
}
void vtab_gv_drive_serialize(sqlite3 *real_db, struct timespec when) {
    struct gv_drive *entry = LIST_FIRST(&drives);

    const char *create_stmt =
        "CREATE TABLE all_gv_drives (state INTEGER, size INTEGER, avail INTEGER, sdcount INTEGER, flags INTEGER, active INTEGER, freelist_entries INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_gv_drives VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->avail);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sdcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->active);
           sqlite3_bind_int64(stmt, bindIndex++, entry->freelist_entries);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

