#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/vm_object.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_vm_object.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_vm_object_list_lock = 0,
    VT_vm_object_list_object_list = 1,
    VT_vm_object_list_shadow_head = 2,
    VT_vm_object_list_shadow_list = 3,
    VT_vm_object_list_memq = 4,
    VT_vm_object_list_rtree = 5,
    VT_vm_object_list_size = 6,
    VT_vm_object_list_domain = 7,
    VT_vm_object_list_generation = 8,
    VT_vm_object_list_cleangeneration = 9,
    VT_vm_object_list_ref_count = 10,
    VT_vm_object_list_shadow_count = 11,
    VT_vm_object_list_memattr = 12,
    VT_vm_object_list_type = 13,
    VT_vm_object_list_flags = 14,
    VT_vm_object_list_pg_color = 15,
    VT_vm_object_list_paging_in_progress = 16,
    VT_vm_object_list_busy = 17,
    VT_vm_object_list_resident_page_count = 18,
    VT_vm_object_list_backing_object = 19,
    VT_vm_object_list_backing_object_offset = 20,
    VT_vm_object_list_pager_object_list = 21,
    VT_vm_object_list_rvq = 22,
    VT_vm_object_list_handle = 23,
    VT_vm_object_list_un_pager = 24,
    VT_vm_object_list_cred = 25,
    VT_vm_object_list_charge = 26,
    VT_vm_object_list_umtx_data = 27,
    VT_vm_object_list_NUM_COLUMNS
};

static int
copy_columns(struct vm_object *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vm_object_list_lock] =  /* Unsupported type */
//    columns[VT_vm_object_list_object_list] =  /* Unsupported type */
//    columns[VT_vm_object_list_shadow_head] =  /* Unsupported type */
//    columns[VT_vm_object_list_shadow_list] =  /* Unsupported type */
//    columns[VT_vm_object_list_memq] =  /* Unsupported type */
//    columns[VT_vm_object_list_rtree] =  /* Unsupported type */
    columns[VT_vm_object_list_size] = new_dbsc_int64(curEntry->size, context);
//    columns[VT_vm_object_list_domain] =  /* Unsupported type */
    columns[VT_vm_object_list_generation] = new_dbsc_int64(curEntry->generation, context);
    columns[VT_vm_object_list_cleangeneration] = new_dbsc_int64(curEntry->cleangeneration, context);
    columns[VT_vm_object_list_ref_count] = new_dbsc_int64(curEntry->ref_count, context);
    columns[VT_vm_object_list_shadow_count] = new_dbsc_int64(curEntry->shadow_count, context);
    columns[VT_vm_object_list_memattr] = new_dbsc_int64(curEntry->memattr, context);
    columns[VT_vm_object_list_type] = new_dbsc_int64(curEntry->type, context);
    columns[VT_vm_object_list_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_vm_object_list_pg_color] = new_dbsc_int64(curEntry->pg_color, context);
//    columns[VT_vm_object_list_paging_in_progress] =  /* Unsupported type */
//    columns[VT_vm_object_list_busy] =  /* Unsupported type */
    columns[VT_vm_object_list_resident_page_count] = new_dbsc_int64(curEntry->resident_page_count, context);
    columns[VT_vm_object_list_backing_object] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->backing_object, context);
    columns[VT_vm_object_list_backing_object_offset] = new_dbsc_int64(curEntry->backing_object_offset, context);
//    columns[VT_vm_object_list_pager_object_list] =  /* Unsupported type */
//    columns[VT_vm_object_list_rvq] =  /* Unsupported type */
    columns[VT_vm_object_list_handle] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->handle, context);
//    columns[VT_vm_object_list_un_pager] =  /* Unsupported type */
    columns[VT_vm_object_list_cred] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cred, context);
    columns[VT_vm_object_list_charge] = new_dbsc_int64(curEntry->charge, context);
    columns[VT_vm_object_list_umtx_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->umtx_data, context);

    return 0;
}
void
vtab_vm_object_lock(void)
{
    sx_slock(&vm_object_list_lock);
}

void
vtab_vm_object_unlock(void)
{
    sx_sunlock(&vm_object_list_lock);
}

void
vtab_vm_object_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct vm_object *prc = LIST_FIRST(&vm_object_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vm_object_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_vm_object_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("vm_object digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vm_objectvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_vm_object_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("vm_object_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vm_objectvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
vm_objectvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_vm_object_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("vm_object digest mismatch: UPDATE failed\n");
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
static sqlite3_module vm_objectvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vm_objectvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vm_objectvtabRowid,
    /* xUpdate     */ vm_objectvtabUpdate,
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
sqlite3_vm_objectvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vm_objectvtabModule,
        pAux);
}
void vtab_vm_object_serialize(sqlite3 *real_db, struct timespec when) {
    struct vm_object *entry = LIST_FIRST(&vm_object_list);

    const char *create_stmt =
        "CREATE TABLE all_vm_objects (size INTEGER, generation INTEGER, cleangeneration INTEGER, ref_count INTEGER, shadow_count INTEGER, memattr INTEGER, type INTEGER, flags INTEGER, pg_color INTEGER, resident_page_count INTEGER, backing_object_offset INTEGER, charge INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_vm_objects VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->generation);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cleangeneration);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ref_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->shadow_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->memattr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pg_color);
           sqlite3_bind_int64(stmt, bindIndex++, entry->resident_page_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->backing_object_offset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->charge);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

