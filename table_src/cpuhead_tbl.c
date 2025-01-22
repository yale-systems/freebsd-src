#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_cpuhead_pc_curthread = 0,
    VT_cpuhead_pc_idlethread = 1,
    VT_cpuhead_pc_fpcurthread = 2,
    VT_cpuhead_pc_deadthread = 3,
    VT_cpuhead_pc_curpcb = 4,
    VT_cpuhead_pc_sched = 5,
    VT_cpuhead_pc_switchtime = 6,
    VT_cpuhead_pc_switchticks = 7,
    VT_cpuhead_pc_cpuid = 8,
    VT_cpuhead_pc_allcpu = 9,
    VT_cpuhead_pc_spinlocks = 10,
    VT_cpuhead_pc_cp_time = 11,
    VT_cpuhead_pc_device = 12,
    VT_cpuhead_pc_netisr = 13,
    VT_cpuhead_pc_vfs_freevnodes = 14,
    VT_cpuhead_pc_unused1 = 15,
    VT_cpuhead_pc_domain = 16,
    VT_cpuhead_pc_rm_queue = 17,
    VT_cpuhead_pc_dynamic = 18,
    VT_cpuhead_pc_early_dummy_counter = 19,
    VT_cpuhead_pc_zpcpu_offset = 20,
    VT_cpuhead_pc_acpi_id = 21,
    VT_cpuhead_pc_midr = 22,
    VT_cpuhead_pc_clock = 23,
    VT_cpuhead_pc_bp_harden = 24,
    VT_cpuhead_pc_ssbd = 25,
    VT_cpuhead_pc_curpmap = 26,
    VT_cpuhead_pc_curvmpmap = 27,
    VT_cpuhead_pc_mpidr = 28,
    VT_cpuhead_pc_bcast_tlbi_workaround = 29,
    VT_cpuhead___pad = 30,
    VT_cpuhead_NUM_COLUMNS
};

static int
copy_columns(struct cpuhead *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_cpuhead_pc_curthread] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_idlethread] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_fpcurthread] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_deadthread] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_curpcb] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_sched] =  TODO: Handle other types
    columns[VT_cpuhead_pc_switchtime] = new_osdb_int64(curEntry->pc_switchtime, context);
    columns[VT_cpuhead_pc_switchticks] = new_osdb_int64(curEntry->pc_switchticks, context);
    columns[VT_cpuhead_pc_cpuid] = new_osdb_int64(curEntry->pc_cpuid, context);
//    columns[VT_cpuhead_pc_allcpu] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_spinlocks] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_cp_time] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_device] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_netisr] =  TODO: Handle other types
    columns[VT_cpuhead_pc_vfs_freevnodes] = new_osdb_int64(curEntry->pc_vfs_freevnodes, context);
//    columns[VT_cpuhead_pc_unused1] =  TODO: Handle other types
    columns[VT_cpuhead_pc_domain] = new_osdb_int64(curEntry->pc_domain, context);
//    columns[VT_cpuhead_pc_rm_queue] =  TODO: Handle other types
    columns[VT_cpuhead_pc_dynamic] = new_osdb_int64(curEntry->pc_dynamic, context);
    columns[VT_cpuhead_pc_early_dummy_counter] = new_osdb_int64(curEntry->pc_early_dummy_counter, context);
    columns[VT_cpuhead_pc_zpcpu_offset] = new_osdb_int64(curEntry->pc_zpcpu_offset, context);
    columns[VT_cpuhead_pc_acpi_id] = new_osdb_int64(curEntry->pc_acpi_id, context);
    columns[VT_cpuhead_pc_midr] = new_osdb_int64(curEntry->pc_midr, context);
    columns[VT_cpuhead_pc_clock] = new_osdb_int64(curEntry->pc_clock, context);
//    columns[VT_cpuhead_pc_bp_harden] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_ssbd] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_curpmap] =  TODO: Handle other types
//    columns[VT_cpuhead_pc_curvmpmap] =  TODO: Handle other types
    columns[VT_cpuhead_pc_mpidr] = new_osdb_int64(curEntry->pc_mpidr, context);
    columns[VT_cpuhead_pc_bcast_tlbi_workaround] = new_osdb_int64(curEntry->pc_bcast_tlbi_workaround, context);
//    columns[VT_cpuhead___pad] =  TODO: Handle other types

    return 0;
}
void
vtab_cpuhead_lock(void)
{
    sx_slock(&cpuhead_lock);
}

void
vtab_cpuhead_unlock(void)
{
    sx_sunlock(&cpuhead_lock);
}

void
vtab_cpuhead_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cpuhead *prc = LIST_FIRST(&cpuhead);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_cpuhead_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_cpuhead_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cpuhead digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_cpuhead_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_cpuhead_PID];
    *pRowid = pid_value->int64_value;
    printf("cpuhead_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_cpuhead_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_cpuhead_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cpuhead_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cpuhead digest mismatch: UPDATE failed\n");
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
static sqlite3_module cpuheadvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cpuheadvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cpuheadvtabRowid,
    /* xUpdate     */ cpuheadvtabUpdate,
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
sqlite3_cpuheadvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cpuheadvtabModule,
        pAux);
}
