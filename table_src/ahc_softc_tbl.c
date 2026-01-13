#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ahc_softc.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ahc_softc.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ahc_tailq_tag = 0,
    VT_ahc_tailq_bsh = 1,
    VT_ahc_tailq_buffer_dmat = 2,
    VT_ahc_tailq_scb_data = 3,
    VT_ahc_tailq_next_queued_scb = 4,
    VT_ahc_tailq_pending_scbs = 5,
    VT_ahc_tailq_timedout_scbs = 6,
    VT_ahc_tailq_untagged_queue_lock = 7,
    VT_ahc_tailq_untagged_queues = 8,
    VT_ahc_tailq_bus_softc = 9,
    VT_ahc_tailq_platform_data = 10,
    VT_ahc_tailq_dev_softc = 11,
    VT_ahc_tailq_bus_intr = 12,
    VT_ahc_tailq_bus_chip_init = 13,
    VT_ahc_tailq_bus_suspend = 14,
    VT_ahc_tailq_bus_resume = 15,
    VT_ahc_tailq_enabled_targets = 16,
    VT_ahc_tailq_black_hole = 17,
    VT_ahc_tailq_pending_device = 18,
    VT_ahc_tailq_chip = 19,
    VT_ahc_tailq_features = 20,
    VT_ahc_tailq_bugs = 21,
    VT_ahc_tailq_flags = 22,
    VT_ahc_tailq_seep_config = 23,
    VT_ahc_tailq_unpause = 24,
    VT_ahc_tailq_pause = 25,
    VT_ahc_tailq_qoutfifonext = 26,
    VT_ahc_tailq_qinfifonext = 27,
    VT_ahc_tailq_qoutfifo = 28,
    VT_ahc_tailq_qinfifo = 29,
    VT_ahc_tailq_critical_sections = 30,
    VT_ahc_tailq_num_critical_sections = 31,
    VT_ahc_tailq_links = 32,
    VT_ahc_tailq_channel = 33,
    VT_ahc_tailq_channel_b = 34,
    VT_ahc_tailq_our_id = 35,
    VT_ahc_tailq_our_id_b = 36,
    VT_ahc_tailq_unsolicited_ints = 37,
    VT_ahc_tailq_targetcmds = 38,
    VT_ahc_tailq_tqinfifonext = 39,
    VT_ahc_tailq_seqctl = 40,
    VT_ahc_tailq_send_msg_perror = 41,
    VT_ahc_tailq_msg_type = 42,
    VT_ahc_tailq_msgout_buf = 43,
    VT_ahc_tailq_msgin_buf = 44,
    VT_ahc_tailq_msgout_len = 45,
    VT_ahc_tailq_msgout_index = 46,
    VT_ahc_tailq_msgin_index = 47,
    VT_ahc_tailq_parent_dmat = 48,
    VT_ahc_tailq_shared_data_dmat = 49,
    VT_ahc_tailq_shared_data_dmamap = 50,
    VT_ahc_tailq_shared_data_busaddr = 51,
    VT_ahc_tailq_dma_bug_buf = 52,
    VT_ahc_tailq_enabled_luns = 53,
    VT_ahc_tailq_init_level = 54,
    VT_ahc_tailq_pci_cachesize = 55,
    VT_ahc_tailq_pci_target_perr_count = 56,
    VT_ahc_tailq_instruction_ram_size = 57,
    VT_ahc_tailq_description = 58,
    VT_ahc_tailq_name = 59,
    VT_ahc_tailq_unit = 60,
    VT_ahc_tailq_seltime = 61,
    VT_ahc_tailq_seltime_b = 62,
    VT_ahc_tailq_user_discenable = 63,
    VT_ahc_tailq_user_tagenable = 64,
    VT_ahc_tailq_NUM_COLUMNS
};

static int
copy_columns(struct ahc_softc *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_ahc_tailq_tag] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tag, context);
    columns[VT_ahc_tailq_bsh] = new_dbsc_int64(curEntry->bsh, context);
    columns[VT_ahc_tailq_buffer_dmat] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->buffer_dmat, context);
    columns[VT_ahc_tailq_scb_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->scb_data, context);
    columns[VT_ahc_tailq_next_queued_scb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->next_queued_scb, context);
//    columns[VT_ahc_tailq_pending_scbs] =  /* Unsupported type */
//    columns[VT_ahc_tailq_timedout_scbs] =  /* Unsupported type */
    columns[VT_ahc_tailq_untagged_queue_lock] = new_dbsc_int64(curEntry->untagged_queue_lock, context);
//    columns[VT_ahc_tailq_untagged_queues] =  /* Unsupported type */
//    columns[VT_ahc_tailq_bus_softc] =  /* Unsupported type */
    columns[VT_ahc_tailq_platform_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->platform_data, context);
    columns[VT_ahc_tailq_dev_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->dev_softc, context);
    columns[VT_ahc_tailq_bus_intr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bus_intr, context);
    columns[VT_ahc_tailq_bus_chip_init] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bus_chip_init, context);
    columns[VT_ahc_tailq_bus_suspend] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bus_suspend, context);
    columns[VT_ahc_tailq_bus_resume] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->bus_resume, context);
//    columns[VT_ahc_tailq_enabled_targets] =  /* Unsupported type */
    columns[VT_ahc_tailq_black_hole] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->black_hole, context);
    columns[VT_ahc_tailq_pending_device] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pending_device, context);
    columns[VT_ahc_tailq_chip] = new_dbsc_int64((int64_t)(curEntry->chip), context); // TODO: need better enum representation 
    columns[VT_ahc_tailq_features] = new_dbsc_int64((int64_t)(curEntry->features), context); // TODO: need better enum representation 
    columns[VT_ahc_tailq_bugs] = new_dbsc_int64((int64_t)(curEntry->bugs), context); // TODO: need better enum representation 
    columns[VT_ahc_tailq_flags] = new_dbsc_int64((int64_t)(curEntry->flags), context); // TODO: need better enum representation 
    columns[VT_ahc_tailq_seep_config] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->seep_config, context);
    columns[VT_ahc_tailq_unpause] = new_dbsc_int64(curEntry->unpause, context);
    columns[VT_ahc_tailq_pause] = new_dbsc_int64(curEntry->pause, context);
    columns[VT_ahc_tailq_qoutfifonext] = new_dbsc_int64(curEntry->qoutfifonext, context);
    columns[VT_ahc_tailq_qinfifonext] = new_dbsc_int64(curEntry->qinfifonext, context);
    columns[VT_ahc_tailq_qoutfifo] = new_dbsc_text(curEntry->qoutfifo, strlen(curEntry->qoutfifo) + 1, context);
    columns[VT_ahc_tailq_qinfifo] = new_dbsc_text(curEntry->qinfifo, strlen(curEntry->qinfifo) + 1, context);
    columns[VT_ahc_tailq_critical_sections] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->critical_sections, context);
    columns[VT_ahc_tailq_num_critical_sections] = new_dbsc_int64(curEntry->num_critical_sections, context);
//    columns[VT_ahc_tailq_links] =  /* Unsupported type */
    columns[VT_ahc_tailq_channel] = new_dbsc_int64(curEntry->channel, context);
    columns[VT_ahc_tailq_channel_b] = new_dbsc_int64(curEntry->channel_b, context);
    columns[VT_ahc_tailq_our_id] = new_dbsc_int64(curEntry->our_id, context);
    columns[VT_ahc_tailq_our_id_b] = new_dbsc_int64(curEntry->our_id_b, context);
    columns[VT_ahc_tailq_unsolicited_ints] = new_dbsc_int64(curEntry->unsolicited_ints, context);
    columns[VT_ahc_tailq_targetcmds] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->targetcmds, context);
    columns[VT_ahc_tailq_tqinfifonext] = new_dbsc_int64(curEntry->tqinfifonext, context);
    columns[VT_ahc_tailq_seqctl] = new_dbsc_int64(curEntry->seqctl, context);
    columns[VT_ahc_tailq_send_msg_perror] = new_dbsc_int64(curEntry->send_msg_perror, context);
    columns[VT_ahc_tailq_msg_type] = new_dbsc_int64((int64_t)(curEntry->msg_type), context); // TODO: need better enum representation 
//    columns[VT_ahc_tailq_msgout_buf] =  /* Unsupported type */
//    columns[VT_ahc_tailq_msgin_buf] =  /* Unsupported type */
    columns[VT_ahc_tailq_msgout_len] = new_dbsc_int64(curEntry->msgout_len, context);
    columns[VT_ahc_tailq_msgout_index] = new_dbsc_int64(curEntry->msgout_index, context);
    columns[VT_ahc_tailq_msgin_index] = new_dbsc_int64(curEntry->msgin_index, context);
    columns[VT_ahc_tailq_parent_dmat] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->parent_dmat, context);
    columns[VT_ahc_tailq_shared_data_dmat] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->shared_data_dmat, context);
    columns[VT_ahc_tailq_shared_data_dmamap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->shared_data_dmamap, context);
    columns[VT_ahc_tailq_shared_data_busaddr] = new_dbsc_int64(curEntry->shared_data_busaddr, context);
    columns[VT_ahc_tailq_dma_bug_buf] = new_dbsc_int64(curEntry->dma_bug_buf, context);
    columns[VT_ahc_tailq_enabled_luns] = new_dbsc_int64(curEntry->enabled_luns, context);
    columns[VT_ahc_tailq_init_level] = new_dbsc_int64(curEntry->init_level, context);
    columns[VT_ahc_tailq_pci_cachesize] = new_dbsc_int64(curEntry->pci_cachesize, context);
    columns[VT_ahc_tailq_pci_target_perr_count] = new_dbsc_int64(curEntry->pci_target_perr_count, context);
    columns[VT_ahc_tailq_instruction_ram_size] = new_dbsc_int64(curEntry->instruction_ram_size, context);
    columns[VT_ahc_tailq_description] = new_dbsc_text(curEntry->description, strlen(curEntry->description) + 1, context);
    columns[VT_ahc_tailq_name] = new_dbsc_text(curEntry->name, strlen(curEntry->name) + 1, context);
    columns[VT_ahc_tailq_unit] = new_dbsc_int64(curEntry->unit, context);
    columns[VT_ahc_tailq_seltime] = new_dbsc_int64(curEntry->seltime, context);
    columns[VT_ahc_tailq_seltime_b] = new_dbsc_int64(curEntry->seltime_b, context);
    columns[VT_ahc_tailq_user_discenable] = new_dbsc_int64(curEntry->user_discenable, context);
    columns[VT_ahc_tailq_user_tagenable] = new_dbsc_int64(curEntry->user_tagenable, context);

    return 0;
}
void
vtab_ahc_softc_lock(void)
{
    sx_slock(&ahc_tailq_lock);
}

void
vtab_ahc_softc_unlock(void)
{
    sx_sunlock(&ahc_tailq_lock);
}

void
vtab_ahc_softc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ahc_softc *prc = LIST_FIRST(&ahc_tailq);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ahc_tailq_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_ahc_tailq_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ahc_softc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ahc_softcvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_ahc_tailq_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ahc_softc_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ahc_softcvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ahc_softcvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ahc_softc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ahc_softc digest mismatch: UPDATE failed\n");
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
static sqlite3_module ahc_softcvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ahc_softcvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ahc_softcvtabRowid,
    /* xUpdate     */ ahc_softcvtabUpdate,
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
sqlite3_ahc_softcvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ahc_softcvtabModule,
        pAux);
}
void vtab_ahc_softc_serialize(sqlite3 *real_db, struct timespec when) {
    struct ahc_softc *entry = LIST_FIRST(&ahc_tailq);

    const char *create_stmt =
        "CREATE TABLE all_ahc_softcs (bsh INTEGER, untagged_queue_lock INTEGER, chip INTEGER, features INTEGER, bugs INTEGER, flags INTEGER, unpause INTEGER, pause INTEGER, qoutfifonext INTEGER, qinfifonext INTEGER, qoutfifo TEXT, qinfifo TEXT, num_critical_sections INTEGER, channel INTEGER, channel_b INTEGER, our_id INTEGER, our_id_b INTEGER, unsolicited_ints INTEGER, tqinfifonext INTEGER, seqctl INTEGER, send_msg_perror INTEGER, msg_type INTEGER, msgout_len INTEGER, msgout_index INTEGER, msgin_index INTEGER, shared_data_busaddr INTEGER, dma_bug_buf INTEGER, enabled_luns INTEGER, init_level INTEGER, pci_cachesize INTEGER, pci_target_perr_count INTEGER, instruction_ram_size INTEGER, description TEXT, name TEXT, unit INTEGER, seltime INTEGER, seltime_b INTEGER, user_discenable INTEGER, user_tagenable INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ahc_softcs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->bsh);
           sqlite3_bind_int64(stmt, bindIndex++, entry->untagged_queue_lock);
           sqlite3_bind_int64(stmt, bindIndex++, entry->chip);
           sqlite3_bind_int64(stmt, bindIndex++, entry->features);
           sqlite3_bind_int64(stmt, bindIndex++, entry->bugs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->unpause);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pause);
           sqlite3_bind_int64(stmt, bindIndex++, entry->qoutfifonext);
           sqlite3_bind_int64(stmt, bindIndex++, entry->qinfifonext);
           sqlite3_bind_text(stmt, bindIndex++, entry->qoutfifo, -1, SQLITE_TRANSIENT);
           sqlite3_bind_text(stmt, bindIndex++, entry->qinfifo, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->num_critical_sections);
           sqlite3_bind_int64(stmt, bindIndex++, entry->channel);
           sqlite3_bind_int64(stmt, bindIndex++, entry->channel_b);
           sqlite3_bind_int64(stmt, bindIndex++, entry->our_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->our_id_b);
           sqlite3_bind_int64(stmt, bindIndex++, entry->unsolicited_ints);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tqinfifonext);
           sqlite3_bind_int64(stmt, bindIndex++, entry->seqctl);
           sqlite3_bind_int64(stmt, bindIndex++, entry->send_msg_perror);
           sqlite3_bind_int64(stmt, bindIndex++, entry->msg_type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->msgout_len);
           sqlite3_bind_int64(stmt, bindIndex++, entry->msgout_index);
           sqlite3_bind_int64(stmt, bindIndex++, entry->msgin_index);
           sqlite3_bind_int64(stmt, bindIndex++, entry->shared_data_busaddr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->dma_bug_buf);
           sqlite3_bind_int64(stmt, bindIndex++, entry->enabled_luns);
           sqlite3_bind_int64(stmt, bindIndex++, entry->init_level);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pci_cachesize);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pci_target_perr_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->instruction_ram_size);
           sqlite3_bind_text(stmt, bindIndex++, entry->description, -1, SQLITE_TRANSIENT);
           sqlite3_bind_text(stmt, bindIndex++, entry->name, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->unit);
           sqlite3_bind_int64(stmt, bindIndex++, entry->seltime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->seltime_b);
           sqlite3_bind_int64(stmt, bindIndex++, entry->user_discenable);
           sqlite3_bind_int64(stmt, bindIndex++, entry->user_tagenable);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

