#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cam_ed.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cam_ed.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ed_entries_devq_entry = 0,
    VT_ed_entries_links = 1,
    VT_ed_entries_target = 2,
    VT_ed_entries_sim = 3,
    VT_ed_entries_lun_id = 4,
    VT_ed_entries_ccbq = 5,
    VT_ed_entries_asyncs = 6,
    VT_ed_entries_periphs = 7,
    VT_ed_entries_generation = 8,
    VT_ed_entries_quirk = 9,
    VT_ed_entries_maxtags = 10,
    VT_ed_entries_mintags = 11,
    VT_ed_entries_protocol = 12,
    VT_ed_entries_protocol_version = 13,
    VT_ed_entries_transport = 14,
    VT_ed_entries_transport_version = 15,
    VT_ed_entries_inq_data = 16,
    VT_ed_entries_supported_vpds = 17,
    VT_ed_entries_supported_vpds_len = 18,
    VT_ed_entries_device_id_len = 19,
    VT_ed_entries_device_id = 20,
    VT_ed_entries_ext_inq_len = 21,
    VT_ed_entries_ext_inq = 22,
    VT_ed_entries_physpath_len = 23,
    VT_ed_entries_physpath = 24,
    VT_ed_entries_rcap_len = 25,
    VT_ed_entries_rcap_buf = 26,
    VT_ed_entries_ident_data = 27,
    VT_ed_entries_mmc_ident_data = 28,
    VT_ed_entries_inq_flags = 29,
    VT_ed_entries_queue_flags = 30,
    VT_ed_entries_serial_num_len = 31,
    VT_ed_entries_serial_num = 32,
    VT_ed_entries_flags = 33,
    VT_ed_entries_tag_delay_count = 34,
    VT_ed_entries_tag_saved_openings = 35,
    VT_ed_entries_refcount = 36,
    VT_ed_entries_callout = 37,
    VT_ed_entries_highpowerq_entry = 38,
    VT_ed_entries_device_mtx = 39,
    VT_ed_entries_device_destroy_task = 40,
    VT_ed_entries_nvme_cdata = 41,
    VT_ed_entries_nvme_data = 42,
    VT_ed_entries_NUM_COLUMNS
};

static int
copy_columns(struct cam_ed *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_ed_entries_devq_entry] =  /* Unsupported type */
//    columns[VT_ed_entries_links] =  /* Unsupported type */
    columns[VT_ed_entries_target] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->target, context);
    columns[VT_ed_entries_sim] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sim, context);
    columns[VT_ed_entries_lun_id] = new_dbsc_int64(curEntry->lun_id, context);
//    columns[VT_ed_entries_ccbq] =  /* Unsupported type */
//    columns[VT_ed_entries_asyncs] =  /* Unsupported type */
//    columns[VT_ed_entries_periphs] =  /* Unsupported type */
    columns[VT_ed_entries_generation] = new_dbsc_int64(curEntry->generation, context);
    columns[VT_ed_entries_quirk] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->quirk, context);
    columns[VT_ed_entries_maxtags] = new_dbsc_int64(curEntry->maxtags, context);
    columns[VT_ed_entries_mintags] = new_dbsc_int64(curEntry->mintags, context);
    columns[VT_ed_entries_protocol] = new_dbsc_int64((int64_t)(curEntry->protocol), context); // TODO: need better enum representation 
    columns[VT_ed_entries_protocol_version] = new_dbsc_int64(curEntry->protocol_version, context);
    columns[VT_ed_entries_transport] = new_dbsc_int64((int64_t)(curEntry->transport), context); // TODO: need better enum representation 
    columns[VT_ed_entries_transport_version] = new_dbsc_int64(curEntry->transport_version, context);
//    columns[VT_ed_entries_inq_data] =  /* Unsupported type */
    columns[VT_ed_entries_supported_vpds] = new_dbsc_text(curEntry->supported_vpds, strlen(curEntry->supported_vpds) + 1, context);
    columns[VT_ed_entries_supported_vpds_len] = new_dbsc_int64(curEntry->supported_vpds_len, context);
    columns[VT_ed_entries_device_id_len] = new_dbsc_int64(curEntry->device_id_len, context);
    columns[VT_ed_entries_device_id] = new_dbsc_text(curEntry->device_id, strlen(curEntry->device_id) + 1, context);
    columns[VT_ed_entries_ext_inq_len] = new_dbsc_int64(curEntry->ext_inq_len, context);
    columns[VT_ed_entries_ext_inq] = new_dbsc_text(curEntry->ext_inq, strlen(curEntry->ext_inq) + 1, context);
    columns[VT_ed_entries_physpath_len] = new_dbsc_int64(curEntry->physpath_len, context);
    columns[VT_ed_entries_physpath] = new_dbsc_text(curEntry->physpath, strlen(curEntry->physpath) + 1, context);
    columns[VT_ed_entries_rcap_len] = new_dbsc_int64(curEntry->rcap_len, context);
    columns[VT_ed_entries_rcap_buf] = new_dbsc_text(curEntry->rcap_buf, strlen(curEntry->rcap_buf) + 1, context);
//    columns[VT_ed_entries_ident_data] =  /* Unsupported type */
//    columns[VT_ed_entries_mmc_ident_data] =  /* Unsupported type */
    columns[VT_ed_entries_inq_flags] = new_dbsc_int64(curEntry->inq_flags, context);
    columns[VT_ed_entries_queue_flags] = new_dbsc_int64(curEntry->queue_flags, context);
    columns[VT_ed_entries_serial_num_len] = new_dbsc_int64(curEntry->serial_num_len, context);
    columns[VT_ed_entries_serial_num] = new_dbsc_text(curEntry->serial_num, strlen(curEntry->serial_num) + 1, context);
    columns[VT_ed_entries_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_ed_entries_tag_delay_count] = new_dbsc_int64(curEntry->tag_delay_count, context);
    columns[VT_ed_entries_tag_saved_openings] = new_dbsc_int64(curEntry->tag_saved_openings, context);
    columns[VT_ed_entries_refcount] = new_dbsc_int64(curEntry->refcount, context);
//    columns[VT_ed_entries_callout] =  /* Unsupported type */
//    columns[VT_ed_entries_highpowerq_entry] =  /* Unsupported type */
//    columns[VT_ed_entries_device_mtx] =  /* Unsupported type */
//    columns[VT_ed_entries_device_destroy_task] =  /* Unsupported type */
    columns[VT_ed_entries_nvme_cdata] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->nvme_cdata, context);
    columns[VT_ed_entries_nvme_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->nvme_data, context);

    return 0;
}
void
vtab_cam_ed_lock(void)
{
    sx_slock(&ed_entries_lock);
}

void
vtab_cam_ed_unlock(void)
{
    sx_sunlock(&ed_entries_lock);
}

void
vtab_cam_ed_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cam_ed *prc = LIST_FIRST(&ed_entries);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ed_entries_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_ed_entries_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cam_ed digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cam_edvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_ed_entries_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cam_ed_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cam_edvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cam_edvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cam_ed_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cam_ed digest mismatch: UPDATE failed\n");
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
static sqlite3_module cam_edvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cam_edvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cam_edvtabRowid,
    /* xUpdate     */ cam_edvtabUpdate,
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
sqlite3_cam_edvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cam_edvtabModule,
        pAux);
}
void vtab_cam_ed_serialize(sqlite3 *real_db, struct timespec when) {
    struct cam_ed *entry = LIST_FIRST(&ed_entries);

    const char *create_stmt =
        "CREATE TABLE all_cam_eds (lun_id INTEGER, generation INTEGER, maxtags INTEGER, mintags INTEGER, protocol INTEGER, protocol_version INTEGER, transport INTEGER, transport_version INTEGER, supported_vpds TEXT, supported_vpds_len INTEGER, device_id_len INTEGER, device_id TEXT, ext_inq_len INTEGER, ext_inq TEXT, physpath_len INTEGER, physpath TEXT, rcap_len INTEGER, rcap_buf TEXT, inq_flags INTEGER, queue_flags INTEGER, serial_num_len INTEGER, serial_num TEXT, flags INTEGER, tag_delay_count INTEGER, tag_saved_openings INTEGER, refcount INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cam_eds VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->lun_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->generation);
           sqlite3_bind_int64(stmt, bindIndex++, entry->maxtags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mintags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->protocol);
           sqlite3_bind_int64(stmt, bindIndex++, entry->protocol_version);
           sqlite3_bind_int64(stmt, bindIndex++, entry->transport);
           sqlite3_bind_int64(stmt, bindIndex++, entry->transport_version);
           sqlite3_bind_text(stmt, bindIndex++, entry->supported_vpds, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->supported_vpds_len);
           sqlite3_bind_int64(stmt, bindIndex++, entry->device_id_len);
           sqlite3_bind_text(stmt, bindIndex++, entry->device_id, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ext_inq_len);
           sqlite3_bind_text(stmt, bindIndex++, entry->ext_inq, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->physpath_len);
           sqlite3_bind_text(stmt, bindIndex++, entry->physpath, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rcap_len);
           sqlite3_bind_text(stmt, bindIndex++, entry->rcap_buf, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->inq_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->queue_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->serial_num_len);
           sqlite3_bind_text(stmt, bindIndex++, entry->serial_num, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tag_delay_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tag_saved_openings);
           sqlite3_bind_int64(stmt, bindIndex++, entry->refcount);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

