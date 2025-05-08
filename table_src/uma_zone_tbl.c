#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/uma_zone.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_uma_zone.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_uk_zones_uz_flags = 0,
    VT_uk_zones_uz_size = 1,
    VT_uk_zones_uz_ctor = 2,
    VT_uk_zones_uz_dtor = 3,
    VT_uk_zones_uz_smr = 4,
    VT_uk_zones_uz_max_items = 5,
    VT_uk_zones_uz_bucket_max = 6,
    VT_uk_zones_uz_bucket_size = 7,
    VT_uk_zones_uz_bucket_size_max = 8,
    VT_uk_zones_uz_sleepers = 9,
    VT_uk_zones_uz_xdomain = 10,
    VT_uk_zones_uz_keg = 11,
    VT_uk_zones_uz_import = 12,
    VT_uk_zones_uz_release = 13,
    VT_uk_zones_uz_arg = 14,
    VT_uk_zones_uz_init = 15,
    VT_uk_zones_uz_fini = 16,
    VT_uk_zones_uz_items = 17,
    VT_uk_zones_uz_sleeps = 18,
    VT_uk_zones_uz_link = 19,
    VT_uk_zones_uz_allocs = 20,
    VT_uk_zones_uz_frees = 21,
    VT_uk_zones_uz_fails = 22,
    VT_uk_zones_uz_name = 23,
    VT_uk_zones_uz_ctlname = 24,
    VT_uk_zones_uz_namecnt = 25,
    VT_uk_zones_uz_bucket_size_min = 26,
    VT_uk_zones_uz_reclaimers = 27,
    VT_uk_zones_uz_oid = 28,
    VT_uk_zones_uz_warning = 29,
    VT_uk_zones_uz_ratecheck = 30,
    VT_uk_zones_uz_maxaction = 31,
    VT_uk_zones_uz_cross_lock = 32,
    VT_uk_zones_uz_cpu = 33,
    VT_uk_zones_NUM_COLUMNS
};

static int
copy_columns(struct uma_zone *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_uk_zones_uz_flags] = new_dbsc_int64(curEntry->uz_flags, context);
    columns[VT_uk_zones_uz_size] = new_dbsc_int64(curEntry->uz_size, context);
    columns[VT_uk_zones_uz_ctor] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_ctor, context);
    columns[VT_uk_zones_uz_dtor] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_dtor, context);
    columns[VT_uk_zones_uz_smr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_smr, context);
    columns[VT_uk_zones_uz_max_items] = new_dbsc_int64(curEntry->uz_max_items, context);
    columns[VT_uk_zones_uz_bucket_max] = new_dbsc_int64(curEntry->uz_bucket_max, context);
    columns[VT_uk_zones_uz_bucket_size] = new_dbsc_int64(curEntry->uz_bucket_size, context);
    columns[VT_uk_zones_uz_bucket_size_max] = new_dbsc_int64(curEntry->uz_bucket_size_max, context);
    columns[VT_uk_zones_uz_sleepers] = new_dbsc_int64(curEntry->uz_sleepers, context);
    columns[VT_uk_zones_uz_xdomain] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_xdomain, context);
    columns[VT_uk_zones_uz_keg] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_keg, context);
    columns[VT_uk_zones_uz_import] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_import, context);
    columns[VT_uk_zones_uz_release] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_release, context);
    columns[VT_uk_zones_uz_arg] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_arg, context);
    columns[VT_uk_zones_uz_init] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_init, context);
    columns[VT_uk_zones_uz_fini] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_fini, context);
    columns[VT_uk_zones_uz_items] = new_dbsc_int64(curEntry->uz_items, context);
    columns[VT_uk_zones_uz_sleeps] = new_dbsc_int64(curEntry->uz_sleeps, context);
//    columns[VT_uk_zones_uz_link] =  /* Unsupported type */
    columns[VT_uk_zones_uz_allocs] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_allocs, context);
    columns[VT_uk_zones_uz_frees] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_frees, context);
    columns[VT_uk_zones_uz_fails] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_fails, context);
    columns[VT_uk_zones_uz_name] = new_dbsc_text(curEntry->uz_name, strlen(curEntry->uz_name) + 1, context);
    columns[VT_uk_zones_uz_ctlname] = new_dbsc_text(curEntry->uz_ctlname, strlen(curEntry->uz_ctlname) + 1, context);
    columns[VT_uk_zones_uz_namecnt] = new_dbsc_int64(curEntry->uz_namecnt, context);
    columns[VT_uk_zones_uz_bucket_size_min] = new_dbsc_int64(curEntry->uz_bucket_size_min, context);
    columns[VT_uk_zones_uz_reclaimers] = new_dbsc_int64(curEntry->uz_reclaimers, context);
    columns[VT_uk_zones_uz_oid] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->uz_oid, context);
    columns[VT_uk_zones_uz_warning] = new_dbsc_text(curEntry->uz_warning, strlen(curEntry->uz_warning) + 1, context);
//    columns[VT_uk_zones_uz_ratecheck] =  /* Unsupported type */
//    columns[VT_uk_zones_uz_maxaction] =  /* Unsupported type */
//    columns[VT_uk_zones_uz_cross_lock] =  /* Unsupported type */
//    columns[VT_uk_zones_uz_cpu] =  /* Unsupported type */

    return 0;
}
void
vtab_uma_zone_lock(void)
{
    sx_slock(&uk_zones_lock);
}

void
vtab_uma_zone_unlock(void)
{
    sx_sunlock(&uk_zones_lock);
}

void
vtab_uma_zone_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct uma_zone *prc = LIST_FIRST(&uk_zones);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_uk_zones_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_uk_zones_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("uma_zone digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
uma_zonevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_uk_zones_p_pid];
    *pRowid = pid_value->int64_value;
    printf("uma_zone_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
uma_zonevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
uma_zonevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_uma_zone_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("uma_zone digest mismatch: UPDATE failed\n");
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
static sqlite3_module uma_zonevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ uma_zonevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ uma_zonevtabRowid,
    /* xUpdate     */ uma_zonevtabUpdate,
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
sqlite3_uma_zonevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &uma_zonevtabModule,
        pAux);
}
void vtab_uma_zone_serialize(sqlite3 *real_db, struct timespec when) {
    struct uma_zone *entry = LIST_FIRST(&uk_zones);

    const char *create_stmt =
        "CREATE TABLE all_uma_zones (uz_flags INTEGER, uz_size INTEGER, uz_max_items INTEGER, uz_bucket_max INTEGER, uz_bucket_size INTEGER, uz_bucket_size_max INTEGER, uz_sleepers INTEGER, uz_items INTEGER, uz_sleeps INTEGER, uz_name TEXT, uz_ctlname TEXT, uz_namecnt INTEGER, uz_bucket_size_min INTEGER, uz_reclaimers INTEGER, uz_warning TEXT)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_uma_zones VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_max_items);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_bucket_max);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_bucket_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_bucket_size_max);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_sleepers);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_items);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_sleeps);
           sqlite3_bind_text(stmt, bindIndex++, entry->uz_name, -1, SQLITE_TRANSIENT);
           sqlite3_bind_text(stmt, bindIndex++, entry->uz_ctlname, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_namecnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_bucket_size_min);
           sqlite3_bind_int64(stmt, bindIndex++, entry->uz_reclaimers);
           sqlite3_bind_text(stmt, bindIndex++, entry->uz_warning, -1, SQLITE_TRANSIENT);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

