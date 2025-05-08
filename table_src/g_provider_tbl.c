#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/g_provider.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_g_provider.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_provider_name = 0,
    VT_provider_provider = 1,
    VT_provider_geom = 2,
    VT_provider_consumers = 3,
    VT_provider_acr = 4,
    VT_provider_acw = 5,
    VT_provider_ace = 6,
    VT_provider_error = 7,
    VT_provider_orphan = 8,
    VT_provider_mediasize = 9,
    VT_provider_sectorsize = 10,
    VT_provider_stripesize = 11,
    VT_provider_stripeoffset = 12,
    VT_provider_stat = 13,
    VT_provider_spare1 = 14,
    VT_provider_spare2 = 15,
    VT_provider_flags = 16,
    VT_provider_aliases = 17,
    VT_provider_private = 18,
    VT_provider_index = 19,
    VT_provider_NUM_COLUMNS
};

static int
copy_columns(struct g_provider *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_provider_name] = new_dbsc_text(curEntry->name, strlen(curEntry->name) + 1, context);
//    columns[VT_provider_provider] =  /* Unsupported type */
    columns[VT_provider_geom] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->geom, context);
//    columns[VT_provider_consumers] =  /* Unsupported type */
    columns[VT_provider_acr] = new_dbsc_int64(curEntry->acr, context);
    columns[VT_provider_acw] = new_dbsc_int64(curEntry->acw, context);
    columns[VT_provider_ace] = new_dbsc_int64(curEntry->ace, context);
    columns[VT_provider_error] = new_dbsc_int64(curEntry->error, context);
//    columns[VT_provider_orphan] =  /* Unsupported type */
    columns[VT_provider_mediasize] = new_dbsc_int64(curEntry->mediasize, context);
    columns[VT_provider_sectorsize] = new_dbsc_int64(curEntry->sectorsize, context);
    columns[VT_provider_stripesize] = new_dbsc_int64(curEntry->stripesize, context);
    columns[VT_provider_stripeoffset] = new_dbsc_int64(curEntry->stripeoffset, context);
    columns[VT_provider_stat] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->stat, context);
    columns[VT_provider_spare1] = new_dbsc_int64(curEntry->spare1, context);
    columns[VT_provider_spare2] = new_dbsc_int64(curEntry->spare2, context);
    columns[VT_provider_flags] = new_dbsc_int64(curEntry->flags, context);
//    columns[VT_provider_aliases] =  /* Unsupported type */
    columns[VT_provider_private] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->private, context);
    columns[VT_provider_index] = new_dbsc_int64(curEntry->index, context);

    return 0;
}
void
vtab_g_provider_lock(void)
{
    sx_slock(&provider_lock);
}

void
vtab_g_provider_unlock(void)
{
    sx_sunlock(&provider_lock);
}

void
vtab_g_provider_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct g_provider *prc = LIST_FIRST(&provider);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_provider_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_provider_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("g_provider digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
g_providervtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_provider_p_pid];
    *pRowid = pid_value->int64_value;
    printf("g_provider_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
g_providervtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
g_providervtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_g_provider_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("g_provider digest mismatch: UPDATE failed\n");
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
static sqlite3_module g_providervtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ g_providervtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ g_providervtabRowid,
    /* xUpdate     */ g_providervtabUpdate,
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
sqlite3_g_providervtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &g_providervtabModule,
        pAux);
}
void vtab_g_provider_serialize(sqlite3 *real_db, struct timespec when) {
    struct g_provider *entry = LIST_FIRST(&provider);

    const char *create_stmt =
        "CREATE TABLE all_g_providers (name TEXT, acr INTEGER, acw INTEGER, ace INTEGER, error INTEGER, mediasize INTEGER, sectorsize INTEGER, stripesize INTEGER, stripeoffset INTEGER, spare1 INTEGER, spare2 INTEGER, flags INTEGER, index INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_g_providers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->name, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->acr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->acw);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ace);
           sqlite3_bind_int64(stmt, bindIndex++, entry->error);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mediasize);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sectorsize);
           sqlite3_bind_int64(stmt, bindIndex++, entry->stripesize);
           sqlite3_bind_int64(stmt, bindIndex++, entry->stripeoffset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->spare1);
           sqlite3_bind_int64(stmt, bindIndex++, entry->spare2);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->index);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

