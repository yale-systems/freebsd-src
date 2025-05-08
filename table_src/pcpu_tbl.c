#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_pcpu.h"

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
copy_columns(struct pcpu *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_cpuhead_pc_curthread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_curthread, context);
    columns[VT_cpuhead_pc_idlethread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_idlethread, context);
    columns[VT_cpuhead_pc_fpcurthread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_fpcurthread, context);
    columns[VT_cpuhead_pc_deadthread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_deadthread, context);
    columns[VT_cpuhead_pc_curpcb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_curpcb, context);
    columns[VT_cpuhead_pc_sched] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_sched, context);
    columns[VT_cpuhead_pc_switchtime] = new_dbsc_int64(curEntry->pc_switchtime, context);
    columns[VT_cpuhead_pc_switchticks] = new_dbsc_int64(curEntry->pc_switchticks, context);
    columns[VT_cpuhead_pc_cpuid] = new_dbsc_int64(curEntry->pc_cpuid, context);
//    columns[VT_cpuhead_pc_allcpu] =  /* Unsupported type */
    columns[VT_cpuhead_pc_spinlocks] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_spinlocks, context);
//    columns[VT_cpuhead_pc_cp_time] =  /* Unsupported type */
    columns[VT_cpuhead_pc_device] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_device, context);
    columns[VT_cpuhead_pc_netisr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_netisr, context);
    columns[VT_cpuhead_pc_vfs_freevnodes] = new_dbsc_int64(curEntry->pc_vfs_freevnodes, context);
//    columns[VT_cpuhead_pc_unused1] =  /* Unsupported type */
    columns[VT_cpuhead_pc_domain] = new_dbsc_int64(curEntry->pc_domain, context);
//    columns[VT_cpuhead_pc_rm_queue] =  /* Unsupported type */
    columns[VT_cpuhead_pc_dynamic] = new_dbsc_int64(curEntry->pc_dynamic, context);
    columns[VT_cpuhead_pc_early_dummy_counter] = new_dbsc_int64(curEntry->pc_early_dummy_counter, context);
    columns[VT_cpuhead_pc_zpcpu_offset] = new_dbsc_int64(curEntry->pc_zpcpu_offset, context);
    columns[VT_cpuhead_pc_acpi_id] = new_dbsc_int64(curEntry->pc_acpi_id, context);
    columns[VT_cpuhead_pc_midr] = new_dbsc_int64(curEntry->pc_midr, context);
    columns[VT_cpuhead_pc_clock] = new_dbsc_int64(curEntry->pc_clock, context);
    columns[VT_cpuhead_pc_bp_harden] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_bp_harden, context);
    columns[VT_cpuhead_pc_ssbd] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_ssbd, context);
    columns[VT_cpuhead_pc_curpmap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_curpmap, context);
    columns[VT_cpuhead_pc_curvmpmap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->pc_curvmpmap, context);
    columns[VT_cpuhead_pc_mpidr] = new_dbsc_int64(curEntry->pc_mpidr, context);
    columns[VT_cpuhead_pc_bcast_tlbi_workaround] = new_dbsc_int64(curEntry->pc_bcast_tlbi_workaround, context);
//    columns[VT_cpuhead___pad] =  /* Unsupported type */

    return 0;
}
void
vtab_pcpu_lock(void)
{
    sx_slock(&cpuhead_lock);
}

void
vtab_pcpu_unlock(void)
{
    sx_sunlock(&cpuhead_lock);
}

void
vtab_pcpu_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pcpu *prc = LIST_FIRST(&cpuhead);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_cpuhead_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_cpuhead_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pcpu digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
pcpuvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_cpuhead_p_pid];
    *pRowid = pid_value->int64_value;
    printf("pcpu_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
pcpuvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
pcpuvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pcpu_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pcpu digest mismatch: UPDATE failed\n");
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
static sqlite3_module pcpuvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pcpuvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pcpuvtabRowid,
    /* xUpdate     */ pcpuvtabUpdate,
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
sqlite3_pcpuvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pcpuvtabModule,
        pAux);
}
void vtab_pcpu_serialize(sqlite3 *real_db, struct timespec when) {
    struct pcpu *entry = LIST_FIRST(&cpuhead);

    const char *create_stmt =
        "CREATE TABLE all_pcpus (pc_switchtime INTEGER, pc_switchticks INTEGER, pc_cpuid INTEGER, pc_vfs_freevnodes INTEGER, pc_domain INTEGER, pc_dynamic INTEGER, pc_early_dummy_counter INTEGER, pc_zpcpu_offset INTEGER, pc_acpi_id INTEGER, pc_midr INTEGER, pc_clock INTEGER, pc_mpidr INTEGER, pc_bcast_tlbi_workaround INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_pcpus VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_switchtime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_switchticks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_cpuid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_vfs_freevnodes);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_domain);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_dynamic);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_early_dummy_counter);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_zpcpu_offset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_acpi_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_midr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_clock);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_mpidr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pc_bcast_tlbi_workaround);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

