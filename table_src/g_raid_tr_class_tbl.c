#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/g_raid_tr_class.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_g_raid_tr_class.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_g_raid_tr_classes_name = 0,
    VT_g_raid_tr_classes_methods = 1,
    VT_g_raid_tr_classes_size = 2,
    VT_g_raid_tr_classes_baseclasses = 3,
    VT_g_raid_tr_classes_refs = 4,
    VT_g_raid_tr_classes_ops = 5,
    VT_g_raid_tr_classes_trc_enable = 6,
    VT_g_raid_tr_classes_trc_priority = 7,
    VT_g_raid_tr_classes_trc_accept_unmapped = 8,
    VT_g_raid_tr_classes_trc_list = 9,
    VT_g_raid_tr_classes_NUM_COLUMNS
};

static int
copy_columns(struct g_raid_tr_class *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_g_raid_tr_classes_name] = new_dbsc_text(curEntry->name, strlen(curEntry->name) + 1, context);
    columns[VT_g_raid_tr_classes_methods] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->methods, context);
    columns[VT_g_raid_tr_classes_size] = new_dbsc_int64(curEntry->size, context);
    columns[VT_g_raid_tr_classes_baseclasses] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->baseclasses, context);
    columns[VT_g_raid_tr_classes_refs] = new_dbsc_int64(curEntry->refs, context);
    columns[VT_g_raid_tr_classes_ops] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ops, context);
    columns[VT_g_raid_tr_classes_trc_enable] = new_dbsc_int64(curEntry->trc_enable, context);
    columns[VT_g_raid_tr_classes_trc_priority] = new_dbsc_int64(curEntry->trc_priority, context);
    columns[VT_g_raid_tr_classes_trc_accept_unmapped] = new_dbsc_int64(curEntry->trc_accept_unmapped, context);
//    columns[VT_g_raid_tr_classes_trc_list] =  /* Unsupported type */

    return 0;
}
void
vtab_g_raid_tr_class_lock(void)
{
    sx_slock(&g_raid_tr_classes_lock);
}

void
vtab_g_raid_tr_class_unlock(void)
{
    sx_sunlock(&g_raid_tr_classes_lock);
}

void
vtab_g_raid_tr_class_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct g_raid_tr_class *prc = LIST_FIRST(&g_raid_tr_classes);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_g_raid_tr_classes_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_g_raid_tr_classes_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("g_raid_tr_class digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
g_raid_tr_classvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_g_raid_tr_classes_p_pid];
    *pRowid = pid_value->int64_value;
    printf("g_raid_tr_class_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
g_raid_tr_classvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
g_raid_tr_classvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_g_raid_tr_class_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("g_raid_tr_class digest mismatch: UPDATE failed\n");
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
static sqlite3_module g_raid_tr_classvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ g_raid_tr_classvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ g_raid_tr_classvtabRowid,
    /* xUpdate     */ g_raid_tr_classvtabUpdate,
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
sqlite3_g_raid_tr_classvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &g_raid_tr_classvtabModule,
        pAux);
}
void vtab_g_raid_tr_class_serialize(sqlite3 *real_db, struct timespec when) {
    struct g_raid_tr_class *entry = LIST_FIRST(&g_raid_tr_classes);

    const char *create_stmt =
        "CREATE TABLE all_g_raid_tr_classs (name TEXT, size INTEGER, refs INTEGER, trc_enable INTEGER, trc_priority INTEGER, trc_accept_unmapped INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_g_raid_tr_classs VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->name, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->refs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->trc_enable);
           sqlite3_bind_int64(stmt, bindIndex++, entry->trc_priority);
           sqlite3_bind_int64(stmt, bindIndex++, entry->trc_accept_unmapped);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

