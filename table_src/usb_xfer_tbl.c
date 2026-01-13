#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/usb_xfer.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_usb_xfer.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_head_timeout_handle = 0,
    VT_head_wait_entry = 1,
    VT_head_buf_fixup = 2,
    VT_head_wait_queue = 3,
    VT_head_dma_page_ptr = 4,
    VT_head_endpoint = 5,
    VT_head_xroot = 6,
    VT_head_qh_start = 7,
    VT_head_td_start = 8,
    VT_head_td_transfer_first = 9,
    VT_head_td_transfer_last = 10,
    VT_head_td_transfer_cache = 11,
    VT_head_priv_sc = 12,
    VT_head_priv_fifo = 13,
    VT_head_local_buffer = 14,
    VT_head_frlengths = 15,
    VT_head_frbuffers = 16,
    VT_head_callback = 17,
    VT_head_max_hc_frame_size = 18,
    VT_head_max_data_length = 19,
    VT_head_sumlen = 20,
    VT_head_actlen = 21,
    VT_head_timeout = 22,
    VT_head_max_frame_count = 23,
    VT_head_nframes = 24,
    VT_head_aframes = 25,
    VT_head_stream_id = 26,
    VT_head_max_packet_size = 27,
    VT_head_max_frame_size = 28,
    VT_head_qh_pos = 29,
    VT_head_isoc_time_complete = 30,
    VT_head_interval = 31,
    VT_head_address = 32,
    VT_head_endpointno = 33,
    VT_head_max_packet_count = 34,
    VT_head_usb_state = 35,
    VT_head_fps_shift = 36,
    VT_head_error = 37,
    VT_head_flags = 38,
    VT_head_flags_int = 39,
    VT_head_NUM_COLUMNS
};

static int
copy_columns(struct usb_xfer *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_head_timeout_handle] =  /* Unsupported type */
//    columns[VT_head_wait_entry] =  /* Unsupported type */
    columns[VT_head_buf_fixup] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->buf_fixup, context);
    columns[VT_head_wait_queue] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->wait_queue, context);
    columns[VT_head_dma_page_ptr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->dma_page_ptr, context);
    columns[VT_head_endpoint] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->endpoint, context);
    columns[VT_head_xroot] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->xroot, context);
//    columns[VT_head_qh_start] =  /* Unsupported type */
//    columns[VT_head_td_start] =  /* Unsupported type */
    columns[VT_head_td_transfer_first] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_transfer_first, context);
    columns[VT_head_td_transfer_last] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_transfer_last, context);
    columns[VT_head_td_transfer_cache] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_transfer_cache, context);
    columns[VT_head_priv_sc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->priv_sc, context);
    columns[VT_head_priv_fifo] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->priv_fifo, context);
    columns[VT_head_local_buffer] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->local_buffer, context);
    columns[VT_head_frlengths] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->frlengths, context);
    columns[VT_head_frbuffers] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->frbuffers, context);
    columns[VT_head_callback] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->callback, context);
    columns[VT_head_max_hc_frame_size] = new_dbsc_int64(curEntry->max_hc_frame_size, context);
    columns[VT_head_max_data_length] = new_dbsc_int64(curEntry->max_data_length, context);
    columns[VT_head_sumlen] = new_dbsc_int64(curEntry->sumlen, context);
    columns[VT_head_actlen] = new_dbsc_int64(curEntry->actlen, context);
    columns[VT_head_timeout] = new_dbsc_int64(curEntry->timeout, context);
    columns[VT_head_max_frame_count] = new_dbsc_int64(curEntry->max_frame_count, context);
    columns[VT_head_nframes] = new_dbsc_int64(curEntry->nframes, context);
    columns[VT_head_aframes] = new_dbsc_int64(curEntry->aframes, context);
    columns[VT_head_stream_id] = new_dbsc_int64(curEntry->stream_id, context);
    columns[VT_head_max_packet_size] = new_dbsc_int64(curEntry->max_packet_size, context);
    columns[VT_head_max_frame_size] = new_dbsc_int64(curEntry->max_frame_size, context);
    columns[VT_head_qh_pos] = new_dbsc_int64(curEntry->qh_pos, context);
    columns[VT_head_isoc_time_complete] = new_dbsc_int64(curEntry->isoc_time_complete, context);
    columns[VT_head_interval] = new_dbsc_int64(curEntry->interval, context);
    columns[VT_head_address] = new_dbsc_int64(curEntry->address, context);
    columns[VT_head_endpointno] = new_dbsc_int64(curEntry->endpointno, context);
    columns[VT_head_max_packet_count] = new_dbsc_int64(curEntry->max_packet_count, context);
    columns[VT_head_usb_state] = new_dbsc_int64(curEntry->usb_state, context);
    columns[VT_head_fps_shift] = new_dbsc_int64(curEntry->fps_shift, context);
    columns[VT_head_error] = new_dbsc_int64((int64_t)(curEntry->error), context); // TODO: need better enum representation 
//    columns[VT_head_flags] =  /* Unsupported type */
//    columns[VT_head_flags_int] =  /* Unsupported type */

    return 0;
}
void
vtab_usb_xfer_lock(void)
{
    sx_slock(&head_lock);
}

void
vtab_usb_xfer_unlock(void)
{
    sx_sunlock(&head_lock);
}

void
vtab_usb_xfer_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct usb_xfer *prc = LIST_FIRST(&head);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_head_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_head_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("usb_xfer digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
usb_xfervtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_head_p_pid];
    *pRowid = pid_value->int64_value;
    printf("usb_xfer_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
usb_xfervtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
usb_xfervtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_usb_xfer_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("usb_xfer digest mismatch: UPDATE failed\n");
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
static sqlite3_module usb_xfervtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ usb_xfervtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ usb_xfervtabRowid,
    /* xUpdate     */ usb_xfervtabUpdate,
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
sqlite3_usb_xfervtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &usb_xfervtabModule,
        pAux);
}
void vtab_usb_xfer_serialize(sqlite3 *real_db, struct timespec when) {
    struct usb_xfer *entry = LIST_FIRST(&head);

    const char *create_stmt =
        "CREATE TABLE all_usb_xfers (max_hc_frame_size INTEGER, max_data_length INTEGER, sumlen INTEGER, actlen INTEGER, timeout INTEGER, max_frame_count INTEGER, nframes INTEGER, aframes INTEGER, stream_id INTEGER, max_packet_size INTEGER, max_frame_size INTEGER, qh_pos INTEGER, isoc_time_complete INTEGER, interval INTEGER, address INTEGER, endpointno INTEGER, max_packet_count INTEGER, usb_state INTEGER, fps_shift INTEGER, error INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_usb_xfers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_hc_frame_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_data_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sumlen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->actlen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_frame_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->nframes);
           sqlite3_bind_int64(stmt, bindIndex++, entry->aframes);
           sqlite3_bind_int64(stmt, bindIndex++, entry->stream_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_packet_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_frame_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->qh_pos);
           sqlite3_bind_int64(stmt, bindIndex++, entry->isoc_time_complete);
           sqlite3_bind_int64(stmt, bindIndex++, entry->interval);
           sqlite3_bind_int64(stmt, bindIndex++, entry->address);
           sqlite3_bind_int64(stmt, bindIndex++, entry->endpointno);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_packet_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->usb_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->fps_shift);
           sqlite3_bind_int64(stmt, bindIndex++, entry->error);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

