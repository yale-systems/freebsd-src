#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/vm_page.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_vm_page.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sgp_pglist_plinks = 0,
    VT_sgp_pglist_listq = 1,
    VT_sgp_pglist_object = 2,
    VT_sgp_pglist_pindex = 3,
    VT_sgp_pglist_phys_addr = 4,
    VT_sgp_pglist_md = 5,
    VT_sgp_pglist_ref_count = 6,
    VT_sgp_pglist_busy_lock = 7,
    VT_sgp_pglist_a = 8,
    VT_sgp_pglist_order = 9,
    VT_sgp_pglist_pool = 10,
    VT_sgp_pglist_flags = 11,
    VT_sgp_pglist_oflags = 12,
    VT_sgp_pglist_psind = 13,
    VT_sgp_pglist_segind = 14,
    VT_sgp_pglist_valid = 15,
    VT_sgp_pglist_dirty = 16,
    VT_sgp_pglist_NUM_COLUMNS
};

static int
copy_columns(struct vm_page *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_sgp_pglist_plinks] =  /* Unsupported type */
//    columns[VT_sgp_pglist_listq] =  /* Unsupported type */
    columns[VT_sgp_pglist_object] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->object, context);
    columns[VT_sgp_pglist_pindex] = new_dbsc_int64(curEntry->pindex, context);
    columns[VT_sgp_pglist_phys_addr] = new_dbsc_int64(curEntry->phys_addr, context);
//    columns[VT_sgp_pglist_md] =  /* Unsupported type */
    columns[VT_sgp_pglist_ref_count] = new_dbsc_int64(curEntry->ref_count, context);
    columns[VT_sgp_pglist_busy_lock] = new_dbsc_int64(curEntry->busy_lock, context);
//    columns[VT_sgp_pglist_a] =  /* Unsupported type */
    columns[VT_sgp_pglist_order] = new_dbsc_int64(curEntry->order, context);
    columns[VT_sgp_pglist_pool] = new_dbsc_int64(curEntry->pool, context);
    columns[VT_sgp_pglist_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_sgp_pglist_oflags] = new_dbsc_int64(curEntry->oflags, context);
    columns[VT_sgp_pglist_psind] = new_dbsc_int64(curEntry->psind, context);
    columns[VT_sgp_pglist_segind] = new_dbsc_int64(curEntry->segind, context);
    columns[VT_sgp_pglist_valid] = new_dbsc_int64(curEntry->valid, context);
    columns[VT_sgp_pglist_dirty] = new_dbsc_int64(curEntry->dirty, context);

    return 0;
}
void
vtab_vm_page_lock(void)
{
    sx_slock(&sgp_pglist_lock);
}

void
vtab_vm_page_unlock(void)
{
    sx_sunlock(&sgp_pglist_lock);
}

void
vtab_vm_page_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct vm_page *prc = LIST_FIRST(&sgp_pglist);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sgp_pglist_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sgp_pglist_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("vm_page digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vm_pagevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sgp_pglist_p_pid];
    *pRowid = pid_value->int64_value;
    printf("vm_page_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vm_pagevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
vm_pagevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_vm_page_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("vm_page digest mismatch: UPDATE failed\n");
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
static sqlite3_module vm_pagevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vm_pagevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vm_pagevtabRowid,
    /* xUpdate     */ vm_pagevtabUpdate,
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
sqlite3_vm_pagevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vm_pagevtabModule,
        pAux);
}
void vtab_vm_page_serialize(sqlite3 *real_db, struct timespec when) {
    struct vm_page *entry = LIST_FIRST(&sgp_pglist);

    const char *create_stmt =
        "CREATE TABLE all_vm_pages (pindex INTEGER, phys_addr INTEGER, ref_count INTEGER, busy_lock INTEGER, order INTEGER, pool INTEGER, flags INTEGER, oflags INTEGER, psind INTEGER, segind INTEGER, valid INTEGER, dirty INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_vm_pages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->pindex);
           sqlite3_bind_int64(stmt, bindIndex++, entry->phys_addr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ref_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->busy_lock);
           sqlite3_bind_int64(stmt, bindIndex++, entry->order);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pool);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->oflags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->psind);
           sqlite3_bind_int64(stmt, bindIndex++, entry->segind);
           sqlite3_bind_int64(stmt, bindIndex++, entry->valid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->dirty);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

