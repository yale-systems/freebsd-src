#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_mpt_tailq_dev = 0,
    VT_mpt_tailq_mpt_lock = 1,
    VT_mpt_tailq_mpt_locksetup = 2,
    VT_mpt_tailq_mpt_pers_mask = 3,
    VT_mpt_tailq_ = 4,
    VT_mpt_tailq_unit = 5,
    VT_mpt_tailq_ready = 6,
    VT_mpt_tailq_fw_uploaded = 7,
    VT_mpt_tailq_msi_enable = 8,
    VT_mpt_tailq_twildcard = 9,
    VT_mpt_tailq_tenabled = 10,
    VT_mpt_tailq_do_cfg_role = 11,
    VT_mpt_tailq_raid_enabled = 12,
    VT_mpt_tailq_raid_mwce_set = 13,
    VT_mpt_tailq_getreqwaiter = 14,
    VT_mpt_tailq_shutdwn_raid = 15,
    VT_mpt_tailq_shutdwn_recovery = 16,
    VT_mpt_tailq_outofbeer = 17,
    VT_mpt_tailq_disabled = 18,
    VT_mpt_tailq_is_spi = 19,
    VT_mpt_tailq_is_sas = 20,
    VT_mpt_tailq_is_fc = 21,
    VT_mpt_tailq_is_1078 = 22,
    VT_mpt_tailq_cfg_role = 23,
    VT_mpt_tailq_role = 24,
    VT_mpt_tailq_verbose = 25,
    VT_mpt_tailq_ioc_facts = 26,
    VT_mpt_tailq_port_facts = 27,
    VT_mpt_tailq_cfg = 28,
    VT_mpt_tailq_scinfo = 29,
    VT_mpt_tailq_ioc_page2 = 30,
    VT_mpt_tailq_ioc_page3 = 31,
    VT_mpt_tailq_raid_volumes = 32,
    VT_mpt_tailq_raid_disks = 33,
    VT_mpt_tailq_raid_max_volumes = 34,
    VT_mpt_tailq_raid_max_disks = 35,
    VT_mpt_tailq_raid_page0_len = 36,
    VT_mpt_tailq_raid_wakeup = 37,
    VT_mpt_tailq_raid_rescan = 38,
    VT_mpt_tailq_raid_resync_rate = 39,
    VT_mpt_tailq_raid_mwce_setting = 40,
    VT_mpt_tailq_raid_queue_depth = 41,
    VT_mpt_tailq_raid_nonopt_volumes = 42,
    VT_mpt_tailq_raid_thread = 43,
    VT_mpt_tailq_raid_timer = 44,
    VT_mpt_tailq_pci_irq = 45,
    VT_mpt_tailq_ih = 46,
    VT_mpt_tailq_pci_reg = 47,
    VT_mpt_tailq_pci_st = 48,
    VT_mpt_tailq_pci_sh = 49,
    VT_mpt_tailq_pci_pio_reg = 50,
    VT_mpt_tailq_pci_pio_st = 51,
    VT_mpt_tailq_pci_pio_sh = 52,
    VT_mpt_tailq_parent_dmat = 53,
    VT_mpt_tailq_reply_dmat = 54,
    VT_mpt_tailq_reply_dmap = 55,
    VT_mpt_tailq_reply = 56,
    VT_mpt_tailq_reply_phys = 57,
    VT_mpt_tailq_buffer_dmat = 58,
    VT_mpt_tailq_request_dmat = 59,
    VT_mpt_tailq_request_dmap = 60,
    VT_mpt_tailq_request = 61,
    VT_mpt_tailq_request_phys = 62,
    VT_mpt_tailq_max_seg_cnt = 63,
    VT_mpt_tailq_max_cam_seg_cnt = 64,
    VT_mpt_tailq_reset_cnt = 65,
    VT_mpt_tailq_request_pool = 66,
    VT_mpt_tailq_request_free_list = 67,
    VT_mpt_tailq_request_pending_list = 68,
    VT_mpt_tailq_request_timeout_list = 69,
    VT_mpt_tailq_sim = 70,
    VT_mpt_tailq_path = 71,
    VT_mpt_tailq_phydisk_sim = 72,
    VT_mpt_tailq_phydisk_path = 73,
    VT_mpt_tailq_recovery_thread = 74,
    VT_mpt_tailq_tmf_req = 75,
    VT_mpt_tailq_ack_frames = 76,
    VT_mpt_tailq_scsi_tgt_handler_id = 77,
    VT_mpt_tailq_tgt_cmd_ptrs = 78,
    VT_mpt_tailq_els_cmd_ptrs = 79,
    VT_mpt_tailq_trt_wildcard = 80,
    VT_mpt_tailq_trt = 81,
    VT_mpt_tailq_tgt_cmds_allocated = 82,
    VT_mpt_tailq_els_cmds_allocated = 83,
    VT_mpt_tailq_timeouts = 84,
    VT_mpt_tailq_success = 85,
    VT_mpt_tailq_sequence = 86,
    VT_mpt_tailq_pad3 = 87,
    VT_mpt_tailq_fw_image_size = 88,
    VT_mpt_tailq_fw_image = 89,
    VT_mpt_tailq_fw_dmat = 90,
    VT_mpt_tailq_fw_dmap = 91,
    VT_mpt_tailq_fw_phys = 92,
    VT_mpt_tailq_sas_portinfo = 93,
    VT_mpt_tailq_eh = 94,
    VT_mpt_tailq_cdev = 95,
    VT_mpt_tailq_links = 96,
    VT_mpt_tailq_NUM_COLUMNS
};

static int
copy_columns(struct mpt_tailq *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_mpt_tailq_dev] =  TODO: Handle other types
//    columns[VT_mpt_tailq_mpt_lock] =  TODO: Handle other types
    columns[VT_mpt_tailq_mpt_locksetup] = new_osdb_int64(curEntry->mpt_locksetup, context);
    columns[VT_mpt_tailq_mpt_pers_mask] = new_osdb_int64(curEntry->mpt_pers_mask, context);
    columns[VT_mpt_tailq_] = new_osdb_int64(curEntry->, context);
    columns[VT_mpt_tailq_unit] = new_osdb_int64(curEntry->unit, context);
    columns[VT_mpt_tailq_ready] = new_osdb_int64(curEntry->ready, context);
    columns[VT_mpt_tailq_fw_uploaded] = new_osdb_int64(curEntry->fw_uploaded, context);
    columns[VT_mpt_tailq_msi_enable] = new_osdb_int64(curEntry->msi_enable, context);
    columns[VT_mpt_tailq_twildcard] = new_osdb_int64(curEntry->twildcard, context);
    columns[VT_mpt_tailq_tenabled] = new_osdb_int64(curEntry->tenabled, context);
    columns[VT_mpt_tailq_do_cfg_role] = new_osdb_int64(curEntry->do_cfg_role, context);
    columns[VT_mpt_tailq_raid_enabled] = new_osdb_int64(curEntry->raid_enabled, context);
    columns[VT_mpt_tailq_raid_mwce_set] = new_osdb_int64(curEntry->raid_mwce_set, context);
    columns[VT_mpt_tailq_getreqwaiter] = new_osdb_int64(curEntry->getreqwaiter, context);
    columns[VT_mpt_tailq_shutdwn_raid] = new_osdb_int64(curEntry->shutdwn_raid, context);
    columns[VT_mpt_tailq_shutdwn_recovery] = new_osdb_int64(curEntry->shutdwn_recovery, context);
    columns[VT_mpt_tailq_outofbeer] = new_osdb_int64(curEntry->outofbeer, context);
    columns[VT_mpt_tailq_disabled] = new_osdb_int64(curEntry->disabled, context);
    columns[VT_mpt_tailq_is_spi] = new_osdb_int64(curEntry->is_spi, context);
    columns[VT_mpt_tailq_is_sas] = new_osdb_int64(curEntry->is_sas, context);
    columns[VT_mpt_tailq_is_fc] = new_osdb_int64(curEntry->is_fc, context);
    columns[VT_mpt_tailq_is_1078] = new_osdb_int64(curEntry->is_1078, context);
    columns[VT_mpt_tailq_cfg_role] = new_osdb_int64(curEntry->cfg_role, context);
    columns[VT_mpt_tailq_role] = new_osdb_int64(curEntry->role, context);
    columns[VT_mpt_tailq_verbose] = new_osdb_int64(curEntry->verbose, context);
//    columns[VT_mpt_tailq_ioc_facts] =  TODO: Handle other types
//    columns[VT_mpt_tailq_port_facts] =  TODO: Handle other types
//    columns[VT_mpt_tailq_cfg] =  TODO: Handle other types
//    columns[VT_mpt_tailq_scinfo] =  TODO: Handle other types
//    columns[VT_mpt_tailq_ioc_page2] =  TODO: Handle other types
//    columns[VT_mpt_tailq_ioc_page3] =  TODO: Handle other types
//    columns[VT_mpt_tailq_raid_volumes] =  TODO: Handle other types
//    columns[VT_mpt_tailq_raid_disks] =  TODO: Handle other types
    columns[VT_mpt_tailq_raid_max_volumes] = new_osdb_int64(curEntry->raid_max_volumes, context);
    columns[VT_mpt_tailq_raid_max_disks] = new_osdb_int64(curEntry->raid_max_disks, context);
    columns[VT_mpt_tailq_raid_page0_len] = new_osdb_int64(curEntry->raid_page0_len, context);
    columns[VT_mpt_tailq_raid_wakeup] = new_osdb_int64(curEntry->raid_wakeup, context);
    columns[VT_mpt_tailq_raid_rescan] = new_osdb_int64(curEntry->raid_rescan, context);
    columns[VT_mpt_tailq_raid_resync_rate] = new_osdb_int64(curEntry->raid_resync_rate, context);
    columns[VT_mpt_tailq_raid_mwce_setting] = new_osdb_int64(curEntry->raid_mwce_setting, context);
    columns[VT_mpt_tailq_raid_queue_depth] = new_osdb_int64(curEntry->raid_queue_depth, context);
    columns[VT_mpt_tailq_raid_nonopt_volumes] = new_osdb_int64(curEntry->raid_nonopt_volumes, context);
//    columns[VT_mpt_tailq_raid_thread] =  TODO: Handle other types
//    columns[VT_mpt_tailq_raid_timer] =  TODO: Handle other types
//    columns[VT_mpt_tailq_pci_irq] =  TODO: Handle other types
//    columns[VT_mpt_tailq_ih] =  TODO: Handle other types
//    columns[VT_mpt_tailq_pci_reg] =  TODO: Handle other types
//    columns[VT_mpt_tailq_pci_st] =  TODO: Handle other types
    columns[VT_mpt_tailq_pci_sh] = new_osdb_int64(curEntry->pci_sh, context);
//    columns[VT_mpt_tailq_pci_pio_reg] =  TODO: Handle other types
//    columns[VT_mpt_tailq_pci_pio_st] =  TODO: Handle other types
    columns[VT_mpt_tailq_pci_pio_sh] = new_osdb_int64(curEntry->pci_pio_sh, context);
//    columns[VT_mpt_tailq_parent_dmat] =  TODO: Handle other types
//    columns[VT_mpt_tailq_reply_dmat] =  TODO: Handle other types
//    columns[VT_mpt_tailq_reply_dmap] =  TODO: Handle other types
    columns[VT_mpt_tailq_reply] = new_osdb_text(curEntry->reply, strlen(curEntry->reply) + 1, context);
    columns[VT_mpt_tailq_reply_phys] = new_osdb_int64(curEntry->reply_phys, context);
//    columns[VT_mpt_tailq_buffer_dmat] =  TODO: Handle other types
//    columns[VT_mpt_tailq_request_dmat] =  TODO: Handle other types
//    columns[VT_mpt_tailq_request_dmap] =  TODO: Handle other types
    columns[VT_mpt_tailq_request] = new_osdb_text(curEntry->request, strlen(curEntry->request) + 1, context);
    columns[VT_mpt_tailq_request_phys] = new_osdb_int64(curEntry->request_phys, context);
    columns[VT_mpt_tailq_max_seg_cnt] = new_osdb_int64(curEntry->max_seg_cnt, context);
    columns[VT_mpt_tailq_max_cam_seg_cnt] = new_osdb_int64(curEntry->max_cam_seg_cnt, context);
    columns[VT_mpt_tailq_reset_cnt] = new_osdb_int64(curEntry->reset_cnt, context);
//    columns[VT_mpt_tailq_request_pool] =  TODO: Handle other types
//    columns[VT_mpt_tailq_request_free_list] =  TODO: Handle other types
//    columns[VT_mpt_tailq_request_pending_list] =  TODO: Handle other types
//    columns[VT_mpt_tailq_request_timeout_list] =  TODO: Handle other types
//    columns[VT_mpt_tailq_sim] =  TODO: Handle other types
//    columns[VT_mpt_tailq_path] =  TODO: Handle other types
//    columns[VT_mpt_tailq_phydisk_sim] =  TODO: Handle other types
//    columns[VT_mpt_tailq_phydisk_path] =  TODO: Handle other types
//    columns[VT_mpt_tailq_recovery_thread] =  TODO: Handle other types
//    columns[VT_mpt_tailq_tmf_req] =  TODO: Handle other types
//    columns[VT_mpt_tailq_ack_frames] =  TODO: Handle other types
    columns[VT_mpt_tailq_scsi_tgt_handler_id] = new_osdb_int64(curEntry->scsi_tgt_handler_id, context);
//    columns[VT_mpt_tailq_tgt_cmd_ptrs] =  TODO: Handle other types
//    columns[VT_mpt_tailq_els_cmd_ptrs] =  TODO: Handle other types
//    columns[VT_mpt_tailq_trt_wildcard] =  TODO: Handle other types
//    columns[VT_mpt_tailq_trt] =  TODO: Handle other types
    columns[VT_mpt_tailq_tgt_cmds_allocated] = new_osdb_int64(curEntry->tgt_cmds_allocated, context);
    columns[VT_mpt_tailq_els_cmds_allocated] = new_osdb_int64(curEntry->els_cmds_allocated, context);
    columns[VT_mpt_tailq_timeouts] = new_osdb_int64(curEntry->timeouts, context);
    columns[VT_mpt_tailq_success] = new_osdb_int64(curEntry->success, context);
    columns[VT_mpt_tailq_sequence] = new_osdb_int64(curEntry->sequence, context);
    columns[VT_mpt_tailq_pad3] = new_osdb_int64(curEntry->pad3, context);
    columns[VT_mpt_tailq_fw_image_size] = new_osdb_int64(curEntry->fw_image_size, context);
    columns[VT_mpt_tailq_fw_image] = new_osdb_text(curEntry->fw_image, strlen(curEntry->fw_image) + 1, context);
//    columns[VT_mpt_tailq_fw_dmat] =  TODO: Handle other types
//    columns[VT_mpt_tailq_fw_dmap] =  TODO: Handle other types
    columns[VT_mpt_tailq_fw_phys] = new_osdb_int64(curEntry->fw_phys, context);
//    columns[VT_mpt_tailq_sas_portinfo] =  TODO: Handle other types
//    columns[VT_mpt_tailq_eh] =  TODO: Handle other types
//    columns[VT_mpt_tailq_cdev] =  TODO: Handle other types
//    columns[VT_mpt_tailq_links] =  TODO: Handle other types

    return 0;
}
void
vtab__lock(void)
{
    sx_slock(&mpt_tailq_lock);
}

void
vtab__unlock(void)
{
    sx_sunlock(&mpt_tailq_lock);
}

void
vtab__snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct  *prc = LIST_FIRST(&mpt_tailq);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_mpt_tailq_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_mpt_tailq_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf(" digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab__rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_mpt_tailq_PID];
    *pRowid = pid_value->int64_value;
    printf("_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab__bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab__update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab__snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf(" digest mismatch: UPDATE failed\n");
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
static sqlite3_module vtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vtabRowid,
    /* xUpdate     */ vtabUpdate,
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
sqlite3_vtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vtabModule,
        pAux);
}
