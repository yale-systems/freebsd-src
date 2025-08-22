#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ahd_tailq_tags = 0,
    VT_ahd_tailq_bshs = 1,
    VT_ahd_tailq_buffer_dmat = 2,
    VT_ahd_tailq_scb_data = 3,
    VT_ahd_tailq_next_queued_hscb = 4,
    VT_ahd_tailq_next_queued_hscb_map = 5,
    VT_ahd_tailq_pending_scbs = 6,
    VT_ahd_tailq_timedout_scbs = 7,
    VT_ahd_tailq_dst_mode = 8,
    VT_ahd_tailq_src_mode = 9,
    VT_ahd_tailq_saved_dst_mode = 10,
    VT_ahd_tailq_saved_src_mode = 11,
    VT_ahd_tailq_platform_data = 12,
    VT_ahd_tailq_dev_softc = 13,
    VT_ahd_tailq_bus_intr = 14,
    VT_ahd_tailq_enabled_targets = 15,
    VT_ahd_tailq_black_hole = 16,
    VT_ahd_tailq_pending_device = 17,
    VT_ahd_tailq_reset_timer = 18,
    VT_ahd_tailq_stat_timer = 19,
    VT_ahd_tailq_cmdcmplt_bucket = 20,
    VT_ahd_tailq_cmdcmplt_counts = 21,
    VT_ahd_tailq_cmdcmplt_total = 22,
    VT_ahd_tailq_sysctl_ctx = 23,
    VT_ahd_tailq_sysctl_tree = 24,
    VT_ahd_tailq_summerr = 25,
    VT_ahd_tailq_chip = 26,
    VT_ahd_tailq_features = 27,
    VT_ahd_tailq_bugs = 28,
    VT_ahd_tailq_flags = 29,
    VT_ahd_tailq_seep_config = 30,
    VT_ahd_tailq_qoutfifo = 31,
    VT_ahd_tailq_qoutfifonext = 32,
    VT_ahd_tailq_qoutfifonext_valid_tag = 33,
    VT_ahd_tailq_qinfifonext = 34,
    VT_ahd_tailq_qinfifo = 35,
    VT_ahd_tailq_qfreeze_cnt = 36,
    VT_ahd_tailq_unpause = 37,
    VT_ahd_tailq_pause = 38,
    VT_ahd_tailq_critical_sections = 39,
    VT_ahd_tailq_num_critical_sections = 40,
    VT_ahd_tailq_overrun_buf = 41,
    VT_ahd_tailq_links = 42,
    VT_ahd_tailq_channel = 43,
    VT_ahd_tailq_our_id = 44,
    VT_ahd_tailq_targetcmds = 45,
    VT_ahd_tailq_tqinfifonext = 46,
    VT_ahd_tailq_hs_mailbox = 47,
    VT_ahd_tailq_send_msg_perror = 48,
    VT_ahd_tailq_msg_flags = 49,
    VT_ahd_tailq_msg_type = 50,
    VT_ahd_tailq_msgout_buf = 51,
    VT_ahd_tailq_msgin_buf = 52,
    VT_ahd_tailq_msgout_len = 53,
    VT_ahd_tailq_msgout_index = 54,
    VT_ahd_tailq_msgin_index = 55,
    VT_ahd_tailq_parent_dmat = 56,
    VT_ahd_tailq_shared_data_dmat = 57,
    VT_ahd_tailq_shared_data_map = 58,
    VT_ahd_tailq_suspend_state = 59,
    VT_ahd_tailq_enabled_luns = 60,
    VT_ahd_tailq_init_level = 61,
    VT_ahd_tailq_pci_cachesize = 62,
    VT_ahd_tailq_pcix_ptr = 63,
    VT_ahd_tailq_iocell_opts = 64,
    VT_ahd_tailq_stack_size = 65,
    VT_ahd_tailq_saved_stack = 66,
    VT_ahd_tailq_description = 67,
    VT_ahd_tailq_bus_description = 68,
    VT_ahd_tailq_name = 69,
    VT_ahd_tailq_unit = 70,
    VT_ahd_tailq_seltime = 71,
    VT_ahd_tailq_int_coalescing_timer = 72,
    VT_ahd_tailq_int_coalescing_maxcmds = 73,
    VT_ahd_tailq_int_coalescing_mincmds = 74,
    VT_ahd_tailq_int_coalescing_threshold = 75,
    VT_ahd_tailq_int_coalescing_stop_threshold = 76,
    VT_ahd_tailq_user_discenable = 77,
    VT_ahd_tailq_user_tagenable = 78,
    VT_ahd_tailq_NUM_COLUMNS
};

static int
copy_columns(struct ahd_tailq *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_ahd_tailq_tags] =  TODO: Handle other types
//    columns[VT_ahd_tailq_bshs] =  TODO: Handle other types
//    columns[VT_ahd_tailq_buffer_dmat] =  TODO: Handle other types
//    columns[VT_ahd_tailq_scb_data] =  TODO: Handle other types
//    columns[VT_ahd_tailq_next_queued_hscb] =  TODO: Handle other types
//    columns[VT_ahd_tailq_next_queued_hscb_map] =  TODO: Handle other types
//    columns[VT_ahd_tailq_pending_scbs] =  TODO: Handle other types
//    columns[VT_ahd_tailq_timedout_scbs] =  TODO: Handle other types
    columns[VT_ahd_tailq_dst_mode] = new_osdb_int64(static_cast<int64_t>(curEntry->dst_mode), context); // TODO: need better enum representation 
    columns[VT_ahd_tailq_src_mode] = new_osdb_int64(static_cast<int64_t>(curEntry->src_mode), context); // TODO: need better enum representation 
    columns[VT_ahd_tailq_saved_dst_mode] = new_osdb_int64(static_cast<int64_t>(curEntry->saved_dst_mode), context); // TODO: need better enum representation 
    columns[VT_ahd_tailq_saved_src_mode] = new_osdb_int64(static_cast<int64_t>(curEntry->saved_src_mode), context); // TODO: need better enum representation 
//    columns[VT_ahd_tailq_platform_data] =  TODO: Handle other types
//    columns[VT_ahd_tailq_dev_softc] =  TODO: Handle other types
//    columns[VT_ahd_tailq_bus_intr] =  TODO: Handle other types
//    columns[VT_ahd_tailq_enabled_targets] =  TODO: Handle other types
//    columns[VT_ahd_tailq_black_hole] =  TODO: Handle other types
//    columns[VT_ahd_tailq_pending_device] =  TODO: Handle other types
//    columns[VT_ahd_tailq_reset_timer] =  TODO: Handle other types
//    columns[VT_ahd_tailq_stat_timer] =  TODO: Handle other types
    columns[VT_ahd_tailq_cmdcmplt_bucket] = new_osdb_int64(curEntry->cmdcmplt_bucket, context);
//    columns[VT_ahd_tailq_cmdcmplt_counts] =  TODO: Handle other types
    columns[VT_ahd_tailq_cmdcmplt_total] = new_osdb_int64(curEntry->cmdcmplt_total, context);
//    columns[VT_ahd_tailq_sysctl_ctx] =  TODO: Handle other types
//    columns[VT_ahd_tailq_sysctl_tree] =  TODO: Handle other types
//    columns[VT_ahd_tailq_summerr] =  TODO: Handle other types
    columns[VT_ahd_tailq_chip] = new_osdb_int64(static_cast<int64_t>(curEntry->chip), context); // TODO: need better enum representation 
    columns[VT_ahd_tailq_features] = new_osdb_int64(static_cast<int64_t>(curEntry->features), context); // TODO: need better enum representation 
    columns[VT_ahd_tailq_bugs] = new_osdb_int64(static_cast<int64_t>(curEntry->bugs), context); // TODO: need better enum representation 
    columns[VT_ahd_tailq_flags] = new_osdb_int64(static_cast<int64_t>(curEntry->flags), context); // TODO: need better enum representation 
//    columns[VT_ahd_tailq_seep_config] =  TODO: Handle other types
//    columns[VT_ahd_tailq_qoutfifo] =  TODO: Handle other types
    columns[VT_ahd_tailq_qoutfifonext] = new_osdb_int64(curEntry->qoutfifonext, context);
    columns[VT_ahd_tailq_qoutfifonext_valid_tag] = new_osdb_int64(curEntry->qoutfifonext_valid_tag, context);
    columns[VT_ahd_tailq_qinfifonext] = new_osdb_int64(curEntry->qinfifonext, context);
//    columns[VT_ahd_tailq_qinfifo] =  TODO: Handle other types
    columns[VT_ahd_tailq_qfreeze_cnt] = new_osdb_int64(curEntry->qfreeze_cnt, context);
    columns[VT_ahd_tailq_unpause] = new_osdb_int64(curEntry->unpause, context);
    columns[VT_ahd_tailq_pause] = new_osdb_int64(curEntry->pause, context);
//    columns[VT_ahd_tailq_critical_sections] =  TODO: Handle other types
    columns[VT_ahd_tailq_num_critical_sections] = new_osdb_int64(curEntry->num_critical_sections, context);
    columns[VT_ahd_tailq_overrun_buf] = new_osdb_text(curEntry->overrun_buf, strlen(curEntry->overrun_buf) + 1, context);
//    columns[VT_ahd_tailq_links] =  TODO: Handle other types
    columns[VT_ahd_tailq_channel] = new_osdb_int64(curEntry->channel, context);
    columns[VT_ahd_tailq_our_id] = new_osdb_int64(curEntry->our_id, context);
//    columns[VT_ahd_tailq_targetcmds] =  TODO: Handle other types
    columns[VT_ahd_tailq_tqinfifonext] = new_osdb_int64(curEntry->tqinfifonext, context);
    columns[VT_ahd_tailq_hs_mailbox] = new_osdb_int64(curEntry->hs_mailbox, context);
    columns[VT_ahd_tailq_send_msg_perror] = new_osdb_int64(curEntry->send_msg_perror, context);
    columns[VT_ahd_tailq_msg_flags] = new_osdb_int64(static_cast<int64_t>(curEntry->msg_flags), context); // TODO: need better enum representation 
    columns[VT_ahd_tailq_msg_type] = new_osdb_int64(static_cast<int64_t>(curEntry->msg_type), context); // TODO: need better enum representation 
//    columns[VT_ahd_tailq_msgout_buf] =  TODO: Handle other types
//    columns[VT_ahd_tailq_msgin_buf] =  TODO: Handle other types
    columns[VT_ahd_tailq_msgout_len] = new_osdb_int64(curEntry->msgout_len, context);
    columns[VT_ahd_tailq_msgout_index] = new_osdb_int64(curEntry->msgout_index, context);
    columns[VT_ahd_tailq_msgin_index] = new_osdb_int64(curEntry->msgin_index, context);
//    columns[VT_ahd_tailq_parent_dmat] =  TODO: Handle other types
//    columns[VT_ahd_tailq_shared_data_dmat] =  TODO: Handle other types
//    columns[VT_ahd_tailq_shared_data_map] =  TODO: Handle other types
//    columns[VT_ahd_tailq_suspend_state] =  TODO: Handle other types
    columns[VT_ahd_tailq_enabled_luns] = new_osdb_int64(curEntry->enabled_luns, context);
    columns[VT_ahd_tailq_init_level] = new_osdb_int64(curEntry->init_level, context);
    columns[VT_ahd_tailq_pci_cachesize] = new_osdb_int64(curEntry->pci_cachesize, context);
    columns[VT_ahd_tailq_pcix_ptr] = new_osdb_int64(curEntry->pcix_ptr, context);
//    columns[VT_ahd_tailq_iocell_opts] =  TODO: Handle other types
    columns[VT_ahd_tailq_stack_size] = new_osdb_int64(curEntry->stack_size, context);
//    columns[VT_ahd_tailq_saved_stack] =  TODO: Handle other types
    columns[VT_ahd_tailq_description] = new_osdb_text(curEntry->description, strlen(curEntry->description) + 1, context);
    columns[VT_ahd_tailq_bus_description] = new_osdb_text(curEntry->bus_description, strlen(curEntry->bus_description) + 1, context);
    columns[VT_ahd_tailq_name] = new_osdb_text(curEntry->name, strlen(curEntry->name) + 1, context);
    columns[VT_ahd_tailq_unit] = new_osdb_int64(curEntry->unit, context);
    columns[VT_ahd_tailq_seltime] = new_osdb_int64(curEntry->seltime, context);
    columns[VT_ahd_tailq_int_coalescing_timer] = new_osdb_int64(curEntry->int_coalescing_timer, context);
    columns[VT_ahd_tailq_int_coalescing_maxcmds] = new_osdb_int64(curEntry->int_coalescing_maxcmds, context);
    columns[VT_ahd_tailq_int_coalescing_mincmds] = new_osdb_int64(curEntry->int_coalescing_mincmds, context);
    columns[VT_ahd_tailq_int_coalescing_threshold] = new_osdb_int64(curEntry->int_coalescing_threshold, context);
    columns[VT_ahd_tailq_int_coalescing_stop_threshold] = new_osdb_int64(curEntry->int_coalescing_stop_threshold, context);
    columns[VT_ahd_tailq_user_discenable] = new_osdb_int64(curEntry->user_discenable, context);
    columns[VT_ahd_tailq_user_tagenable] = new_osdb_int64(curEntry->user_tagenable, context);

    return 0;
}
void
vtab_ahd_softc_tailq_lock(void)
{
    sx_slock(&ahd_tailq_lock);
}

void
vtab_ahd_softc_tailq_unlock(void)
{
    sx_sunlock(&ahd_tailq_lock);
}

void
vtab_ahd_softc_tailq_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ahd_softc_tailq *prc = LIST_FIRST(&ahd_tailq);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ahd_tailq_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_ahd_tailq_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ahd_softc_tailq digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_ahd_softc_tailq_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_ahd_tailq_PID];
    *pRowid = pid_value->int64_value;
    printf("ahd_softc_tailq_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_ahd_softc_tailq_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_ahd_softc_tailq_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ahd_softc_tailq_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ahd_softc_tailq digest mismatch: UPDATE failed\n");
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
static sqlite3_module ahd_softc_tailqvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ahd_softc_tailqvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ahd_softc_tailqvtabRowid,
    /* xUpdate     */ ahd_softc_tailqvtabUpdate,
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
sqlite3_ahd_softc_tailqvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ahd_softc_tailqvtabModule,
        pAux);
}
