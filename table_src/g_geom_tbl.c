#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/g_geom.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_g_geom.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_geom_name = 0,
    VT_geom_class = 1,
    VT_geom_geom = 2,
    VT_geom_consumer = 3,
    VT_geom_provider = 4,
    VT_geom_geoms = 5,
    VT_geom_rank = 6,
    VT_geom_start = 7,
    VT_geom_spoiled = 8,
    VT_geom_attrchanged = 9,
    VT_geom_dumpconf = 10,
    VT_geom_access = 11,
    VT_geom_orphan = 12,
    VT_geom_ioctl = 13,
    VT_geom_providergone = 14,
    VT_geom_resize = 15,
    VT_geom_spare0 = 16,
    VT_geom_spare1 = 17,
    VT_geom_softc = 18,
    VT_geom_flags = 19,
    VT_geom_NUM_COLUMNS
};

static int
copy_columns(struct g_geom *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_geom_name] = new_dbsc_text(curEntry->name, strlen(curEntry->name) + 1, context);
    columns[VT_geom_class] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->class, context);
//    columns[VT_geom_geom] =  /* Unsupported type */
//    columns[VT_geom_consumer] =  /* Unsupported type */
//    columns[VT_geom_provider] =  /* Unsupported type */
//    columns[VT_geom_geoms] =  /* Unsupported type */
    columns[VT_geom_rank] = new_dbsc_int64(curEntry->rank, context);
    columns[VT_geom_start] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->start, context);
    columns[VT_geom_spoiled] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->spoiled, context);
    columns[VT_geom_attrchanged] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->attrchanged, context);
    columns[VT_geom_dumpconf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->dumpconf, context);
    columns[VT_geom_access] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->access, context);
    columns[VT_geom_orphan] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->orphan, context);
    columns[VT_geom_ioctl] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ioctl, context);
    columns[VT_geom_providergone] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->providergone, context);
    columns[VT_geom_resize] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->resize, context);
    columns[VT_geom_spare0] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->spare0, context);
    columns[VT_geom_spare1] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->spare1, context);
    columns[VT_geom_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->softc, context);
    columns[VT_geom_flags] = new_dbsc_int64(curEntry->flags, context);

    return 0;
}
void
vtab_g_geom_lock(void)
{
    sx_slock(&geom_lock);
}

void
vtab_g_geom_unlock(void)
{
    sx_sunlock(&geom_lock);
}

void
vtab_g_geom_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct g_geom *prc = LIST_FIRST(&geom);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_geom_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_geom_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("g_geom digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
g_geomvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_geom_p_pid];
    *pRowid = pid_value->int64_value;
    printf("g_geom_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
g_geomvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
g_geomvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_g_geom_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("g_geom digest mismatch: UPDATE failed\n");
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
static sqlite3_module g_geomvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ g_geomvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ g_geomvtabRowid,
    /* xUpdate     */ g_geomvtabUpdate,
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
sqlite3_g_geomvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &g_geomvtabModule,
        pAux);
}
void vtab_g_geom_serialize(sqlite3 *real_db, struct timespec when) {
    struct g_geom *entry = LIST_FIRST(&geom);

    const char *create_stmt =
        "CREATE TABLE all_g_geoms (name TEXT, rank INTEGER, flags INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_g_geoms VALUES (?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->name, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rank);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

