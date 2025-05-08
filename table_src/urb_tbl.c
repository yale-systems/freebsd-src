#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/urb.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_urb.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_bsd_urb_list_bsd_urb_list = 0,
    VT_bsd_urb_list_cv_wait = 1,
    VT_bsd_urb_list_dev = 2,
    VT_bsd_urb_list_endpoint = 3,
    VT_bsd_urb_list_setup_packet = 4,
    VT_bsd_urb_list_bsd_data_ptr = 5,
    VT_bsd_urb_list_transfer_buffer = 6,
    VT_bsd_urb_list_context = 7,
    VT_bsd_urb_list_complete = 8,
    VT_bsd_urb_list_transfer_buffer_length = 9,
    VT_bsd_urb_list_bsd_length_rem = 10,
    VT_bsd_urb_list_actual_length = 11,
    VT_bsd_urb_list_timeout = 12,
    VT_bsd_urb_list_transfer_flags = 13,
    VT_bsd_urb_list_start_frame = 14,
    VT_bsd_urb_list_number_of_packets = 15,
    VT_bsd_urb_list_interval = 16,
    VT_bsd_urb_list_error_count = 17,
    VT_bsd_urb_list_status = 18,
    VT_bsd_urb_list_setup_dma = 19,
    VT_bsd_urb_list_transfer_dma = 20,
    VT_bsd_urb_list_bsd_isread = 21,
    VT_bsd_urb_list_kill_count = 22,
    VT_bsd_urb_list_iso_frame_desc = 23,
    VT_bsd_urb_list_NUM_COLUMNS
};

static int
copy_columns(struct urb *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_bsd_urb_list_bsd_urb_list] =  /* Unsupported type */
//    columns[VT_bsd_urb_list_cv_wait] =  /* Unsupported type */
    columns[VT_bsd_urb_list_dev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->dev, context);
    columns[VT_bsd_urb_list_endpoint] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->endpoint, context);
    columns[VT_bsd_urb_list_setup_packet] = new_dbsc_text(curEntry->setup_packet, strlen(curEntry->setup_packet) + 1, context);
    columns[VT_bsd_urb_list_bsd_data_ptr] = new_dbsc_text(curEntry->bsd_data_ptr, strlen(curEntry->bsd_data_ptr) + 1, context);
    columns[VT_bsd_urb_list_transfer_buffer] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->transfer_buffer, context);
    columns[VT_bsd_urb_list_context] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->context, context);
    columns[VT_bsd_urb_list_complete] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->complete, context);
    columns[VT_bsd_urb_list_transfer_buffer_length] = new_dbsc_int64(curEntry->transfer_buffer_length, context);
    columns[VT_bsd_urb_list_bsd_length_rem] = new_dbsc_int64(curEntry->bsd_length_rem, context);
    columns[VT_bsd_urb_list_actual_length] = new_dbsc_int64(curEntry->actual_length, context);
    columns[VT_bsd_urb_list_timeout] = new_dbsc_int64(curEntry->timeout, context);
    columns[VT_bsd_urb_list_transfer_flags] = new_dbsc_int64(curEntry->transfer_flags, context);
    columns[VT_bsd_urb_list_start_frame] = new_dbsc_int64(curEntry->start_frame, context);
    columns[VT_bsd_urb_list_number_of_packets] = new_dbsc_int64(curEntry->number_of_packets, context);
    columns[VT_bsd_urb_list_interval] = new_dbsc_int64(curEntry->interval, context);
    columns[VT_bsd_urb_list_error_count] = new_dbsc_int64(curEntry->error_count, context);
    columns[VT_bsd_urb_list_status] = new_dbsc_int64(curEntry->status, context);
    columns[VT_bsd_urb_list_setup_dma] = new_dbsc_int64(curEntry->setup_dma, context);
    columns[VT_bsd_urb_list_transfer_dma] = new_dbsc_int64(curEntry->transfer_dma, context);
    columns[VT_bsd_urb_list_bsd_isread] = new_dbsc_int64(curEntry->bsd_isread, context);
    columns[VT_bsd_urb_list_kill_count] = new_dbsc_int64(curEntry->kill_count, context);
//    columns[VT_bsd_urb_list_iso_frame_desc] =  /* Unsupported type */

    return 0;
}
void
vtab_urb_lock(void)
{
    sx_slock(&bsd_urb_list_lock);
}

void
vtab_urb_unlock(void)
{
    sx_sunlock(&bsd_urb_list_lock);
}

void
vtab_urb_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct urb *prc = LIST_FIRST(&bsd_urb_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_bsd_urb_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_bsd_urb_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("urb digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
urbvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_bsd_urb_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("urb_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
urbvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
urbvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_urb_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("urb digest mismatch: UPDATE failed\n");
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
static sqlite3_module urbvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ urbvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ urbvtabRowid,
    /* xUpdate     */ urbvtabUpdate,
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
sqlite3_urbvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &urbvtabModule,
        pAux);
}
void vtab_urb_serialize(sqlite3 *real_db, struct timespec when) {
    struct urb *entry = LIST_FIRST(&bsd_urb_list);

    const char *create_stmt =
        "CREATE TABLE all_urbs (setup_packet TEXT, bsd_data_ptr TEXT, transfer_buffer_length INTEGER, bsd_length_rem INTEGER, actual_length INTEGER, timeout INTEGER, transfer_flags INTEGER, start_frame INTEGER, number_of_packets INTEGER, interval INTEGER, error_count INTEGER, status INTEGER, setup_dma INTEGER, transfer_dma INTEGER, bsd_isread INTEGER, kill_count INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_urbs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->setup_packet, -1, SQLITE_TRANSIENT);
           sqlite3_bind_text(stmt, bindIndex++, entry->bsd_data_ptr, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->transfer_buffer_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bsd_length_rem);
           sqlite3_bind_int64(stmt, bindIndex++, entry->actual_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->transfer_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->start_frame);
           sqlite3_bind_int64(stmt, bindIndex++, entry->number_of_packets);
           sqlite3_bind_int64(stmt, bindIndex++, entry->interval);
           sqlite3_bind_int64(stmt, bindIndex++, entry->error_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->status);
           sqlite3_bind_int64(stmt, bindIndex++, entry->setup_dma);
           sqlite3_bind_int64(stmt, bindIndex++, entry->transfer_dma);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bsd_isread);
           sqlite3_bind_int64(stmt, bindIndex++, entry->kill_count);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

