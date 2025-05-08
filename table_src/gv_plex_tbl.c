#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/gv_plex.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_gv_plex.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_plexes_name = 0,
    VT_plexes_size = 1,
    VT_plexes_state = 2,
    VT_plexes_org = 3,
    VT_plexes_stripesize = 4,
    VT_plexes_volume = 5,
    VT_plexes_vol_sc = 6,
    VT_plexes_sddetached = 7,
    VT_plexes_sdcount = 8,
    VT_plexes_sddown = 9,
    VT_plexes_flags = 10,
    VT_plexes_synced = 11,
    VT_plexes_packets = 12,
    VT_plexes_subdisks = 13,
    VT_plexes_in_volume = 14,
    VT_plexes_plex = 15,
    VT_plexes_bqueue = 16,
    VT_plexes_wqueue = 17,
    VT_plexes_rqueue = 18,
    VT_plexes_vinumconf = 19,
    VT_plexes_NUM_COLUMNS
};

static int
copy_columns(struct gv_plex *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_plexes_name] =  /* Unsupported type */
    columns[VT_plexes_size] = new_dbsc_int64(curEntry->size, context);
    columns[VT_plexes_state] = new_dbsc_int64(curEntry->state, context);
    columns[VT_plexes_org] = new_dbsc_int64(curEntry->org, context);
    columns[VT_plexes_stripesize] = new_dbsc_int64(curEntry->stripesize, context);
//    columns[VT_plexes_volume] =  /* Unsupported type */
    columns[VT_plexes_vol_sc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vol_sc, context);
    columns[VT_plexes_sddetached] = new_dbsc_int64(curEntry->sddetached, context);
    columns[VT_plexes_sdcount] = new_dbsc_int64(curEntry->sdcount, context);
    columns[VT_plexes_sddown] = new_dbsc_int64(curEntry->sddown, context);
    columns[VT_plexes_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_plexes_synced] = new_dbsc_int64(curEntry->synced, context);
//    columns[VT_plexes_packets] =  /* Unsupported type */
//    columns[VT_plexes_subdisks] =  /* Unsupported type */
//    columns[VT_plexes_in_volume] =  /* Unsupported type */
//    columns[VT_plexes_plex] =  /* Unsupported type */
    columns[VT_plexes_bqueue] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bqueue, context);
    columns[VT_plexes_wqueue] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->wqueue, context);
    columns[VT_plexes_rqueue] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rqueue, context);
    columns[VT_plexes_vinumconf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vinumconf, context);

    return 0;
}
void
vtab_gv_plex_lock(void)
{
    sx_slock(&plexes_lock);
}

void
vtab_gv_plex_unlock(void)
{
    sx_sunlock(&plexes_lock);
}

void
vtab_gv_plex_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct gv_plex *prc = LIST_FIRST(&plexes);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_plexes_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_plexes_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("gv_plex digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
gv_plexvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_plexes_p_pid];
    *pRowid = pid_value->int64_value;
    printf("gv_plex_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
gv_plexvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
gv_plexvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_gv_plex_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("gv_plex digest mismatch: UPDATE failed\n");
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
static sqlite3_module gv_plexvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ gv_plexvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ gv_plexvtabRowid,
    /* xUpdate     */ gv_plexvtabUpdate,
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
sqlite3_gv_plexvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &gv_plexvtabModule,
        pAux);
}
void vtab_gv_plex_serialize(sqlite3 *real_db, struct timespec when) {
    struct gv_plex *entry = LIST_FIRST(&plexes);

    const char *create_stmt =
        "CREATE TABLE all_gv_plexs (size INTEGER, state INTEGER, org INTEGER, stripesize INTEGER, sddetached INTEGER, sdcount INTEGER, sddown INTEGER, flags INTEGER, synced INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_gv_plexs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->org);
           sqlite3_bind_int64(stmt, bindIndex++, entry->stripesize);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sddetached);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sdcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sddown);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->synced);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

