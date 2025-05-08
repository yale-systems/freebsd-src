#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_queue_bio_cmd = 0,
    VT_queue_bio_flags = 1,
    VT_queue_bio_cflags = 2,
    VT_queue_bio_pflags = 3,
    VT_queue_bio_dev = 4,
    VT_queue_bio_disk = 5,
    VT_queue_bio_offset = 6,
    VT_queue_bio_bcount = 7,
    VT_queue_bio_data = 8,
    VT_queue_bio_ma = 9,
    VT_queue_bio_ma_offset = 10,
    VT_queue_bio_ma_n = 11,
    VT_queue_bio_error = 12,
    VT_queue_bio_resid = 13,
    VT_queue_bio_done = 14,
    VT_queue_bio_driver1 = 15,
    VT_queue_bio_driver2 = 16,
    VT_queue_bio_caller1 = 17,
    VT_queue_bio_caller2 = 18,
    VT_queue_bio_queue = 19,
    VT_queue_bio_attribute = 20,
    VT_queue_bio_zone = 21,
    VT_queue_bio_from = 22,
    VT_queue_bio_to = 23,
    VT_queue_bio_length = 24,
    VT_queue_bio_completed = 25,
    VT_queue_bio_children = 26,
    VT_queue_bio_inbed = 27,
    VT_queue_bio_parent = 28,
    VT_queue_bio_t0 = 29,
    VT_queue_bio_task = 30,
    VT_queue_bio_task_arg = 31,
    VT_queue_bio_spare1 = 32,
    VT_queue_bio_spare2 = 33,
    VT_queue_bio_track_bp = 34,
    VT_queue_bio_pblkno = 35,
    VT_queue_NUM_COLUMNS
};

static int
copy_columns(struct queue *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_queue_bio_cmd] = new_osdb_int64(curEntry->bio_cmd, context);
    columns[VT_queue_bio_flags] = new_osdb_int64(curEntry->bio_flags, context);
    columns[VT_queue_bio_cflags] = new_osdb_int64(curEntry->bio_cflags, context);
    columns[VT_queue_bio_pflags] = new_osdb_int64(curEntry->bio_pflags, context);
//    columns[VT_queue_bio_dev] =  TODO: Handle other types
//    columns[VT_queue_bio_disk] =  TODO: Handle other types
    columns[VT_queue_bio_offset] = new_osdb_int64(curEntry->bio_offset, context);
    columns[VT_queue_bio_bcount] = new_osdb_int64(curEntry->bio_bcount, context);
    columns[VT_queue_bio_data] = new_osdb_text(curEntry->bio_data, strlen(curEntry->bio_data) + 1, context);
//    columns[VT_queue_bio_ma] =  TODO: Handle other types
    columns[VT_queue_bio_ma_offset] = new_osdb_int64(curEntry->bio_ma_offset, context);
    columns[VT_queue_bio_ma_n] = new_osdb_int64(curEntry->bio_ma_n, context);
    columns[VT_queue_bio_error] = new_osdb_int64(curEntry->bio_error, context);
    columns[VT_queue_bio_resid] = new_osdb_int64(curEntry->bio_resid, context);
//    columns[VT_queue_bio_done] =  TODO: Handle other types
//    columns[VT_queue_bio_driver1] =  TODO: Handle other types
//    columns[VT_queue_bio_driver2] =  TODO: Handle other types
//    columns[VT_queue_bio_caller1] =  TODO: Handle other types
//    columns[VT_queue_bio_caller2] =  TODO: Handle other types
//    columns[VT_queue_bio_queue] =  TODO: Handle other types
    columns[VT_queue_bio_attribute] = new_osdb_text(curEntry->bio_attribute, strlen(curEntry->bio_attribute) + 1, context);
//    columns[VT_queue_bio_zone] =  TODO: Handle other types
//    columns[VT_queue_bio_from] =  TODO: Handle other types
//    columns[VT_queue_bio_to] =  TODO: Handle other types
    columns[VT_queue_bio_length] = new_osdb_int64(curEntry->bio_length, context);
    columns[VT_queue_bio_completed] = new_osdb_int64(curEntry->bio_completed, context);
    columns[VT_queue_bio_children] = new_osdb_int64(curEntry->bio_children, context);
    columns[VT_queue_bio_inbed] = new_osdb_int64(curEntry->bio_inbed, context);
//    columns[VT_queue_bio_parent] =  TODO: Handle other types
//    columns[VT_queue_bio_t0] =  TODO: Handle other types
//    columns[VT_queue_bio_task] =  TODO: Handle other types
//    columns[VT_queue_bio_task_arg] =  TODO: Handle other types
//    columns[VT_queue_bio_spare1] =  TODO: Handle other types
//    columns[VT_queue_bio_spare2] =  TODO: Handle other types
//    columns[VT_queue_bio_track_bp] =  TODO: Handle other types
    columns[VT_queue_bio_pblkno] = new_osdb_int64(curEntry->bio_pblkno, context);

    return 0;
}
void
vtab_bio_queue_lock(void)
{
    sx_slock(&queue_lock);
}

void
vtab_bio_queue_unlock(void)
{
    sx_sunlock(&queue_lock);
}

void
vtab_bio_queue_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct bio_queue *prc = LIST_FIRST(&queue);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_queue_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_queue_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("bio_queue digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_bio_queue_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_queue_PID];
    *pRowid = pid_value->int64_value;
    printf("bio_queue_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_bio_queue_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_bio_queue_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_bio_queue_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("bio_queue digest mismatch: UPDATE failed\n");
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
static sqlite3_module bio_queuevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ bio_queuevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ bio_queuevtabRowid,
    /* xUpdate     */ bio_queuevtabUpdate,
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
sqlite3_bio_queuevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &bio_queuevtabModule,
        pAux);
}
