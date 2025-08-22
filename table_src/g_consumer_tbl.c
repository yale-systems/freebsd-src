#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/g_consumer.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_g_consumer.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_consumers_geom = 0,
    VT_consumers_consumer = 1,
    VT_consumers_provider = 2,
    VT_consumers_consumers = 3,
    VT_consumers_acr = 4,
    VT_consumers_acw = 5,
    VT_consumers_ace = 6,
    VT_consumers_flags = 7,
    VT_consumers_stat = 8,
    VT_consumers_nstart = 9,
    VT_consumers_nend = 10,
    VT_consumers_private = 11,
    VT_consumers_index = 12,
    VT_consumers_NUM_COLUMNS
};

static int
copy_columns(struct g_consumer *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_consumers_geom] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->geom, context);
//    columns[VT_consumers_consumer] =  /* Unsupported type */
    columns[VT_consumers_provider] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->provider, context);
//    columns[VT_consumers_consumers] =  /* Unsupported type */
    columns[VT_consumers_acr] = new_dbsc_int64(curEntry->acr, context);
    columns[VT_consumers_acw] = new_dbsc_int64(curEntry->acw, context);
    columns[VT_consumers_ace] = new_dbsc_int64(curEntry->ace, context);
    columns[VT_consumers_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_consumers_stat] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->stat, context);
    columns[VT_consumers_nstart] = new_dbsc_int64(curEntry->nstart, context);
    columns[VT_consumers_nend] = new_dbsc_int64(curEntry->nend, context);
    columns[VT_consumers_private] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->private, context);
    columns[VT_consumers_index] = new_dbsc_int64(curEntry->index, context);

    return 0;
}
void
vtab_g_consumer_lock(void)
{
    sx_slock(&consumers_lock);
}

void
vtab_g_consumer_unlock(void)
{
    sx_sunlock(&consumers_lock);
}

void
vtab_g_consumer_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct g_consumer *prc = LIST_FIRST(&consumers);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_consumers_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_consumers_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("g_consumer digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
g_consumervtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_consumers_p_pid];
    *pRowid = pid_value->int64_value;
    printf("g_consumer_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
g_consumervtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
g_consumervtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_g_consumer_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("g_consumer digest mismatch: UPDATE failed\n");
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
static sqlite3_module g_consumervtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ g_consumervtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ g_consumervtabRowid,
    /* xUpdate     */ g_consumervtabUpdate,
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
sqlite3_g_consumervtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &g_consumervtabModule,
        pAux);
}
void vtab_g_consumer_serialize(sqlite3 *real_db, struct timespec when) {
    struct g_consumer *entry = LIST_FIRST(&consumers);

    const char *create_stmt =
        "CREATE TABLE all_g_consumers (acr INTEGER, acw INTEGER, ace INTEGER, flags INTEGER, nstart INTEGER, nend INTEGER, index INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_g_consumers VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->acr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->acw);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ace);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->nstart);
           sqlite3_bind_int64(stmt, bindIndex++, entry->nend);
           sqlite3_bind_int64(stmt, bindIndex++, entry->index);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

