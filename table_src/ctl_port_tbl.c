#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ctl_port.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ctl_port.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_port_list_ctl_softc = 0,
    VT_port_list_frontend = 1,
    VT_port_list_port_type = 2,
    VT_port_list_num_requested_ctl_io = 3,
    VT_port_list_port_name = 4,
    VT_port_list_physical_port = 5,
    VT_port_list_virtual_port = 6,
    VT_port_list_port_online = 7,
    VT_port_list_port_offline = 8,
    VT_port_list_port_info = 9,
    VT_port_list_onoff_arg = 10,
    VT_port_list_lun_enable = 11,
    VT_port_list_lun_disable = 12,
    VT_port_list_lun_map_size = 13,
    VT_port_list_lun_map = 14,
    VT_port_list_targ_lun_arg = 15,
    VT_port_list_fe_datamove = 16,
    VT_port_list_fe_done = 17,
    VT_port_list_targ_port = 18,
    VT_port_list_ctl_pool_ref = 19,
    VT_port_list_max_initiators = 20,
    VT_port_list_wwpn_iid = 21,
    VT_port_list_wwnn = 22,
    VT_port_list_wwpn = 23,
    VT_port_list_status = 24,
    VT_port_list_options = 25,
    VT_port_list_port_devid = 26,
    VT_port_list_target_devid = 27,
    VT_port_list_init_devid = 28,
    VT_port_list_stats = 29,
    VT_port_list_port_lock = 30,
    VT_port_list_fe_links = 31,
    VT_port_list_links = 32,
    VT_port_list_NUM_COLUMNS
};

static int
copy_columns(struct ctl_port *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_port_list_ctl_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ctl_softc, context);
    columns[VT_port_list_frontend] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->frontend, context);
    columns[VT_port_list_port_type] = new_dbsc_int64((int64_t)(curEntry->port_type), context); // TODO: need better enum representation 
    columns[VT_port_list_num_requested_ctl_io] = new_dbsc_int64(curEntry->num_requested_ctl_io, context);
    columns[VT_port_list_port_name] = new_dbsc_text(curEntry->port_name, strlen(curEntry->port_name) + 1, context);
    columns[VT_port_list_physical_port] = new_dbsc_int64(curEntry->physical_port, context);
    columns[VT_port_list_virtual_port] = new_dbsc_int64(curEntry->virtual_port, context);
    columns[VT_port_list_port_online] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->port_online, context);
    columns[VT_port_list_port_offline] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->port_offline, context);
    columns[VT_port_list_port_info] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->port_info, context);
    columns[VT_port_list_onoff_arg] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->onoff_arg, context);
    columns[VT_port_list_lun_enable] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lun_enable, context);
    columns[VT_port_list_lun_disable] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lun_disable, context);
    columns[VT_port_list_lun_map_size] = new_dbsc_int64(curEntry->lun_map_size, context);
    columns[VT_port_list_lun_map] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lun_map, context);
    columns[VT_port_list_targ_lun_arg] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->targ_lun_arg, context);
    columns[VT_port_list_fe_datamove] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->fe_datamove, context);
    columns[VT_port_list_fe_done] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->fe_done, context);
    columns[VT_port_list_targ_port] = new_dbsc_int64(curEntry->targ_port, context);
    columns[VT_port_list_ctl_pool_ref] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ctl_pool_ref, context);
    columns[VT_port_list_max_initiators] = new_dbsc_int64(curEntry->max_initiators, context);
    columns[VT_port_list_wwpn_iid] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->wwpn_iid, context);
    columns[VT_port_list_wwnn] = new_dbsc_int64(curEntry->wwnn, context);
    columns[VT_port_list_wwpn] = new_dbsc_int64(curEntry->wwpn, context);
    columns[VT_port_list_status] = new_dbsc_int64((int64_t)(curEntry->status), context); // TODO: need better enum representation 
    columns[VT_port_list_options] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->options, context);
    columns[VT_port_list_port_devid] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->port_devid, context);
    columns[VT_port_list_target_devid] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->target_devid, context);
    columns[VT_port_list_init_devid] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->init_devid, context);
//    columns[VT_port_list_stats] =  /* Unsupported type */
//    columns[VT_port_list_port_lock] =  /* Unsupported type */
//    columns[VT_port_list_fe_links] =  /* Unsupported type */
//    columns[VT_port_list_links] =  /* Unsupported type */

    return 0;
}
void
vtab_ctl_port_lock(void)
{
    sx_slock(&port_list_lock);
}

void
vtab_ctl_port_unlock(void)
{
    sx_sunlock(&port_list_lock);
}

void
vtab_ctl_port_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ctl_port *prc = LIST_FIRST(&port_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_port_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_port_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ctl_port digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ctl_portvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_port_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ctl_port_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ctl_portvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ctl_portvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ctl_port_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ctl_port digest mismatch: UPDATE failed\n");
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
static sqlite3_module ctl_portvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ctl_portvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ctl_portvtabRowid,
    /* xUpdate     */ ctl_portvtabUpdate,
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
sqlite3_ctl_portvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ctl_portvtabModule,
        pAux);
}
void vtab_ctl_port_serialize(sqlite3 *real_db, struct timespec when) {
    struct ctl_port *entry = LIST_FIRST(&port_list);

    const char *create_stmt =
        "CREATE TABLE all_ctl_ports (port_type INTEGER, num_requested_ctl_io INTEGER, port_name TEXT, physical_port INTEGER, virtual_port INTEGER, lun_map_size INTEGER, targ_port INTEGER, max_initiators INTEGER, wwnn INTEGER, wwpn INTEGER, status INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ctl_ports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->port_type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->num_requested_ctl_io);
           sqlite3_bind_text(stmt, bindIndex++, entry->port_name, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->physical_port);
           sqlite3_bind_int64(stmt, bindIndex++, entry->virtual_port);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lun_map_size);
           sqlite3_bind_int64(stmt, bindIndex++, entry->targ_port);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_initiators);
           sqlite3_bind_int64(stmt, bindIndex++, entry->wwnn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->wwpn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->status);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

