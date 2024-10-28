#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_g_classes_name = 0,
    VT_g_classes_version = 1,
    VT_g_classes_spare0 = 2,
    VT_g_classes_taste = 3,
    VT_g_classes_ctlreq = 4,
    VT_g_classes_init = 5,
    VT_g_classes_fini = 6,
    VT_g_classes_destroy_geom = 7,
    VT_g_classes_start = 8,
    VT_g_classes_spoiled = 9,
    VT_g_classes_attrchanged = 10,
    VT_g_classes_dumpconf = 11,
    VT_g_classes_access = 12,
    VT_g_classes_orphan = 13,
    VT_g_classes_ioctl = 14,
    VT_g_classes_providergone = 15,
    VT_g_classes_resize = 16,
    VT_g_classes_spare1 = 17,
    VT_g_classes_spare2 = 18,
    VT_g_classes_class = 19,
    VT_g_classes_geom = 20,
    VT_g_classes_NUM_COLUMNS
};

static int
copy_columns(struct g_classes *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_g_classes_name] = new_osdb_text(curEntry->name, strlen(curEntry->name) + 1, context);
    columns[VT_g_classes_version] = new_osdb_int64(curEntry->version, context);
    columns[VT_g_classes_spare0] = new_osdb_int64(curEntry->spare0, context);
//    columns[VT_g_classes_taste] =  TODO: Handle other types
//    columns[VT_g_classes_ctlreq] =  TODO: Handle other types
//    columns[VT_g_classes_init] =  TODO: Handle other types
//    columns[VT_g_classes_fini] =  TODO: Handle other types
//    columns[VT_g_classes_destroy_geom] =  TODO: Handle other types
//    columns[VT_g_classes_start] =  TODO: Handle other types
//    columns[VT_g_classes_spoiled] =  TODO: Handle other types
//    columns[VT_g_classes_attrchanged] =  TODO: Handle other types
//    columns[VT_g_classes_dumpconf] =  TODO: Handle other types
//    columns[VT_g_classes_access] =  TODO: Handle other types
//    columns[VT_g_classes_orphan] =  TODO: Handle other types
//    columns[VT_g_classes_ioctl] =  TODO: Handle other types
//    columns[VT_g_classes_providergone] =  TODO: Handle other types
//    columns[VT_g_classes_resize] =  TODO: Handle other types
//    columns[VT_g_classes_spare1] =  TODO: Handle other types
//    columns[VT_g_classes_spare2] =  TODO: Handle other types
//    columns[VT_g_classes_class] =  TODO: Handle other types
//    columns[VT_g_classes_geom] =  TODO: Handle other types

    return 0;
}
void
vtab_class_list_head_lock(void)
{
    sx_slock(&g_classes_lock);
}

void
vtab_class_list_head_unlock(void)
{
    sx_sunlock(&g_classes_lock);
}

void
vtab_class_list_head_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct class_list_head *prc = LIST_FIRST(&g_classes);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_g_classes_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_g_classes_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("class_list_head digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_class_list_head_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_g_classes_PID];
    *pRowid = pid_value->int64_value;
    printf("class_list_head_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_class_list_head_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_class_list_head_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_class_list_head_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("class_list_head digest mismatch: UPDATE failed\n");
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
static sqlite3_module class_list_headvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ class_list_headvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ class_list_headvtabRowid,
    /* xUpdate     */ class_list_headvtabUpdate,
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
sqlite3_class_list_headvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &class_list_headvtabModule,
        pAux);
}
