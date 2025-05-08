#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

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
copy_columns(struct vm_object_list *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vm_object_list_lock] =  TODO: Handle other types
//    columns[VT_vm_object_list_object_list] =  TODO: Handle other types
//    columns[VT_vm_object_list_shadow_head] =  TODO: Handle other types
//    columns[VT_vm_object_list_shadow_list] =  TODO: Handle other types
//    columns[VT_vm_object_list_memq] =  TODO: Handle other types
//    columns[VT_vm_object_list_rtree] =  TODO: Handle other types
    columns[VT_vm_object_list_size] = new_osdb_int64(curEntry->size, context);
//    columns[VT_vm_object_list_domain] =  TODO: Handle other types
    columns[VT_vm_object_list_generation] = new_osdb_int64(curEntry->generation, context);
    columns[VT_vm_object_list_cleangeneration] = new_osdb_int64(curEntry->cleangeneration, context);
    columns[VT_vm_object_list_ref_count] = new_osdb_int64(curEntry->ref_count, context);
    columns[VT_vm_object_list_shadow_count] = new_osdb_int64(curEntry->shadow_count, context);
    columns[VT_vm_object_list_memattr] = new_osdb_int64(curEntry->memattr, context);
    columns[VT_vm_object_list_type] = new_osdb_int64(curEntry->type, context);
    columns[VT_vm_object_list_flags] = new_osdb_int64(curEntry->flags, context);
    columns[VT_vm_object_list_pg_color] = new_osdb_int64(curEntry->pg_color, context);
//    columns[VT_vm_object_list_paging_in_progress] =  TODO: Handle other types
//    columns[VT_vm_object_list_busy] =  TODO: Handle other types
    columns[VT_vm_object_list_resident_page_count] = new_osdb_int64(curEntry->resident_page_count, context);
//    columns[VT_vm_object_list_backing_object] =  TODO: Handle other types
    columns[VT_vm_object_list_backing_object_offset] = new_osdb_int64(curEntry->backing_object_offset, context);
//    columns[VT_vm_object_list_pager_object_list] =  TODO: Handle other types
//    columns[VT_vm_object_list_rvq] =  TODO: Handle other types
//    columns[VT_vm_object_list_handle] =  TODO: Handle other types
//    columns[VT_vm_object_list_un_pager] =  TODO: Handle other types
//    columns[VT_vm_object_list_cred] =  TODO: Handle other types
    columns[VT_vm_object_list_charge] = new_osdb_int64(curEntry->charge, context);
//    columns[VT_vm_object_list_umtx_data] =  TODO: Handle other types

    return 0;
}
void
vtab_object_q_lock(void)
{
    sx_slock(&vm_object_list_lock);
}

void
vtab_object_q_unlock(void)
{
    sx_sunlock(&vm_object_list_lock);
}

void
vtab_object_q_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct object_q *prc = LIST_FIRST(&vm_object_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vm_object_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_vm_object_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("object_q digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_object_q_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_vm_object_list_PID];
    *pRowid = pid_value->int64_value;
    printf("object_q_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_object_q_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_object_q_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_object_q_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("object_q digest mismatch: UPDATE failed\n");
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
static sqlite3_module object_qvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ object_qvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ object_qvtabRowid,
    /* xUpdate     */ object_qvtabUpdate,
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
sqlite3_object_qvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &object_qvtabModule,
        pAux);
}
