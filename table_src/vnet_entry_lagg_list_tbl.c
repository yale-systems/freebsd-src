#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_vnet_entry_lagg_list_sc_ifp = 0,
    VT_vnet_entry_lagg_list_sc_mtx = 1,
    VT_vnet_entry_lagg_list_sc_sx = 2,
    VT_vnet_entry_lagg_list_sc_proto = 3,
    VT_vnet_entry_lagg_list_sc_count = 4,
    VT_vnet_entry_lagg_list_sc_active = 5,
    VT_vnet_entry_lagg_list_sc_flapping = 6,
    VT_vnet_entry_lagg_list_sc_primary = 7,
    VT_vnet_entry_lagg_list_sc_media = 8,
    VT_vnet_entry_lagg_list_sc_psc = 9,
    VT_vnet_entry_lagg_list_sc_seq = 10,
    VT_vnet_entry_lagg_list_sc_stride = 11,
    VT_vnet_entry_lagg_list_sc_flags = 12,
    VT_vnet_entry_lagg_list_sc_destroying = 13,
    VT_vnet_entry_lagg_list_sc_ports = 14,
    VT_vnet_entry_lagg_list_sc_entries = 15,
    VT_vnet_entry_lagg_list_vlan_attach = 16,
    VT_vnet_entry_lagg_list_vlan_detach = 17,
    VT_vnet_entry_lagg_list_sc_callout = 18,
    VT_vnet_entry_lagg_list_sc_opts = 19,
    VT_vnet_entry_lagg_list_flowid_shift = 20,
    VT_vnet_entry_lagg_list_detached_counters = 21,
    VT_vnet_entry_lagg_list_sc_watchdog = 22,
    VT_vnet_entry_lagg_list_sc_bcast_addr = 23,
    VT_vnet_entry_lagg_list_NUM_COLUMNS
};

static int
copy_columns(struct vnet_entry_lagg_list *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vnet_entry_lagg_list_sc_ifp] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_sc_mtx] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_sc_sx] =  TODO: Handle other types
    columns[VT_vnet_entry_lagg_list_sc_proto] = new_osdb_int64(curEntry->sc_proto, context);
    columns[VT_vnet_entry_lagg_list_sc_count] = new_osdb_int64(curEntry->sc_count, context);
    columns[VT_vnet_entry_lagg_list_sc_active] = new_osdb_int64(curEntry->sc_active, context);
    columns[VT_vnet_entry_lagg_list_sc_flapping] = new_osdb_int64(curEntry->sc_flapping, context);
//    columns[VT_vnet_entry_lagg_list_sc_primary] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_sc_media] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_sc_psc] =  TODO: Handle other types
    columns[VT_vnet_entry_lagg_list_sc_seq] = new_osdb_int64(curEntry->sc_seq, context);
    columns[VT_vnet_entry_lagg_list_sc_stride] = new_osdb_int64(curEntry->sc_stride, context);
    columns[VT_vnet_entry_lagg_list_sc_flags] = new_osdb_int64(curEntry->sc_flags, context);
    columns[VT_vnet_entry_lagg_list_sc_destroying] = new_osdb_int64(curEntry->sc_destroying, context);
//    columns[VT_vnet_entry_lagg_list_sc_ports] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_sc_entries] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_vlan_attach] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_vlan_detach] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_sc_callout] =  TODO: Handle other types
    columns[VT_vnet_entry_lagg_list_sc_opts] = new_osdb_int64(curEntry->sc_opts, context);
    columns[VT_vnet_entry_lagg_list_flowid_shift] = new_osdb_int64(curEntry->flowid_shift, context);
//    columns[VT_vnet_entry_lagg_list_detached_counters] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_sc_watchdog] =  TODO: Handle other types
//    columns[VT_vnet_entry_lagg_list_sc_bcast_addr] =  TODO: Handle other types

    return 0;
}
void
vtab___trhead_lock(void)
{
    sx_slock(&vnet_entry_lagg_list_lock);
}

void
vtab___trhead_unlock(void)
{
    sx_sunlock(&vnet_entry_lagg_list_lock);
}

void
vtab___trhead_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct __trhead *prc = LIST_FIRST(&vnet_entry_lagg_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_lagg_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_vnet_entry_lagg_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("__trhead digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab___trhead_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_vnet_entry_lagg_list_PID];
    *pRowid = pid_value->int64_value;
    printf("__trhead_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab___trhead_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab___trhead_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab___trhead_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("__trhead digest mismatch: UPDATE failed\n");
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
static sqlite3_module __trheadvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ __trheadvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ __trheadvtabRowid,
    /* xUpdate     */ __trheadvtabUpdate,
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
sqlite3___trheadvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &__trheadvtabModule,
        pAux);
}
