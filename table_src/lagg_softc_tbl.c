#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/lagg_softc.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_lagg_softc.h"

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
copy_columns(struct lagg_softc *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_vnet_entry_lagg_list_sc_ifp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sc_ifp, context);
//    columns[VT_vnet_entry_lagg_list_sc_mtx] =  /* Unsupported type */
//    columns[VT_vnet_entry_lagg_list_sc_sx] =  /* Unsupported type */
    columns[VT_vnet_entry_lagg_list_sc_proto] = new_dbsc_int64(curEntry->sc_proto, context);
    columns[VT_vnet_entry_lagg_list_sc_count] = new_dbsc_int64(curEntry->sc_count, context);
    columns[VT_vnet_entry_lagg_list_sc_active] = new_dbsc_int64(curEntry->sc_active, context);
    columns[VT_vnet_entry_lagg_list_sc_flapping] = new_dbsc_int64(curEntry->sc_flapping, context);
    columns[VT_vnet_entry_lagg_list_sc_primary] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sc_primary, context);
//    columns[VT_vnet_entry_lagg_list_sc_media] =  /* Unsupported type */
    columns[VT_vnet_entry_lagg_list_sc_psc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sc_psc, context);
    columns[VT_vnet_entry_lagg_list_sc_seq] = new_dbsc_int64(curEntry->sc_seq, context);
    columns[VT_vnet_entry_lagg_list_sc_stride] = new_dbsc_int64(curEntry->sc_stride, context);
    columns[VT_vnet_entry_lagg_list_sc_flags] = new_dbsc_int64(curEntry->sc_flags, context);
    columns[VT_vnet_entry_lagg_list_sc_destroying] = new_dbsc_int64(curEntry->sc_destroying, context);
//    columns[VT_vnet_entry_lagg_list_sc_ports] =  /* Unsupported type */
//    columns[VT_vnet_entry_lagg_list_sc_entries] =  /* Unsupported type */
    columns[VT_vnet_entry_lagg_list_vlan_attach] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vlan_attach, context);
    columns[VT_vnet_entry_lagg_list_vlan_detach] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vlan_detach, context);
//    columns[VT_vnet_entry_lagg_list_sc_callout] =  /* Unsupported type */
    columns[VT_vnet_entry_lagg_list_sc_opts] = new_dbsc_int64(curEntry->sc_opts, context);
    columns[VT_vnet_entry_lagg_list_flowid_shift] = new_dbsc_int64(curEntry->flowid_shift, context);
//    columns[VT_vnet_entry_lagg_list_detached_counters] =  /* Unsupported type */
//    columns[VT_vnet_entry_lagg_list_sc_watchdog] =  /* Unsupported type */
//    columns[VT_vnet_entry_lagg_list_sc_bcast_addr] =  /* Unsupported type */

    return 0;
}
void
vtab_lagg_softc_lock(void)
{
    sx_slock(&vnet_entry_lagg_list_lock);
}

void
vtab_lagg_softc_unlock(void)
{
    sx_sunlock(&vnet_entry_lagg_list_lock);
}

void
vtab_lagg_softc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct lagg_softc *prc = LIST_FIRST(&vnet_entry_lagg_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_lagg_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_vnet_entry_lagg_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("lagg_softc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
lagg_softcvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_vnet_entry_lagg_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("lagg_softc_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
lagg_softcvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
lagg_softcvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_lagg_softc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("lagg_softc digest mismatch: UPDATE failed\n");
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
static sqlite3_module lagg_softcvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ lagg_softcvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ lagg_softcvtabRowid,
    /* xUpdate     */ lagg_softcvtabUpdate,
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
sqlite3_lagg_softcvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &lagg_softcvtabModule,
        pAux);
}
void vtab_lagg_softc_serialize(sqlite3 *real_db, struct timespec when) {
    struct lagg_softc *entry = LIST_FIRST(&vnet_entry_lagg_list);

    const char *create_stmt =
        "CREATE TABLE all_lagg_softcs (sc_proto INTEGER, sc_count INTEGER, sc_active INTEGER, sc_flapping INTEGER, sc_seq INTEGER, sc_stride INTEGER, sc_flags INTEGER, sc_destroying INTEGER, sc_opts INTEGER, flowid_shift INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_lagg_softcs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_proto);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_active);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_flapping);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_seq);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_stride);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_destroying);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_opts);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flowid_shift);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

