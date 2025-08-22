#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_proc.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_pr_proclist_p_list = 0,
    VT_pr_proclist_p_threads = 1,
    VT_pr_proclist_p_slock = 2,
    VT_pr_proclist_p_ucred = 3,
    VT_pr_proclist_p_fd = 4,
    VT_pr_proclist_p_fdtol = 5,
    VT_pr_proclist_p_pd = 6,
    VT_pr_proclist_p_stats = 7,
    VT_pr_proclist_p_limit = 8,
    VT_pr_proclist_p_limco = 9,
    VT_pr_proclist_p_sigacts = 10,
    VT_pr_proclist_p_flag = 11,
    VT_pr_proclist_p_flag2 = 12,
    VT_pr_proclist_p_state = 13,
    VT_pr_proclist_p_pid = 14,
    VT_pr_proclist_p_hash = 15,
    VT_pr_proclist_p_pglist = 16,
    VT_pr_proclist_p_pptr = 17,
    VT_pr_proclist_p_sibling = 18,
    VT_pr_proclist_p_children = 19,
    VT_pr_proclist_p_reaper = 20,
    VT_pr_proclist_p_reaplist = 21,
    VT_pr_proclist_p_reapsibling = 22,
    VT_pr_proclist_p_mtx = 23,
    VT_pr_proclist_p_statmtx = 24,
    VT_pr_proclist_p_itimmtx = 25,
    VT_pr_proclist_p_profmtx = 26,
    VT_pr_proclist_p_ksi = 27,
    VT_pr_proclist_p_sigqueue = 28,
    VT_pr_proclist_p_oppid = 29,
    VT_pr_proclist_p_vmspace = 30,
    VT_pr_proclist_p_swtick = 31,
    VT_pr_proclist_p_cowgen = 32,
    VT_pr_proclist_p_realtimer = 33,
    VT_pr_proclist_p_ru = 34,
    VT_pr_proclist_p_rux = 35,
    VT_pr_proclist_p_crux = 36,
    VT_pr_proclist_p_profthreads = 37,
    VT_pr_proclist_p_exitthreads = 38,
    VT_pr_proclist_p_traceflag = 39,
    VT_pr_proclist_p_ktrioparms = 40,
    VT_pr_proclist_p_textvp = 41,
    VT_pr_proclist_p_textdvp = 42,
    VT_pr_proclist_p_binname = 43,
    VT_pr_proclist_p_lock = 44,
    VT_pr_proclist_p_sigiolst = 45,
    VT_pr_proclist_p_sigparent = 46,
    VT_pr_proclist_p_sig = 47,
    VT_pr_proclist_p_ptevents = 48,
    VT_pr_proclist_p_aioinfo = 49,
    VT_pr_proclist_p_singlethread = 50,
    VT_pr_proclist_p_suspcount = 51,
    VT_pr_proclist_p_xthread = 52,
    VT_pr_proclist_p_boundary_count = 53,
    VT_pr_proclist_p_pendingcnt = 54,
    VT_pr_proclist_p_itimers = 55,
    VT_pr_proclist_p_procdesc = 56,
    VT_pr_proclist_p_treeflag = 57,
    VT_pr_proclist_p_pendingexits = 58,
    VT_pr_proclist_p_filemon = 59,
    VT_pr_proclist_p_pdeathsig = 60,
    VT_pr_proclist_p_magic = 61,
    VT_pr_proclist_p_osrel = 62,
    VT_pr_proclist_p_fctl0 = 63,
    VT_pr_proclist_p_comm = 64,
    VT_pr_proclist_p_sysent = 65,
    VT_pr_proclist_p_args = 66,
    VT_pr_proclist_p_cpulimit = 67,
    VT_pr_proclist_p_nice = 68,
    VT_pr_proclist_p_fibnum = 69,
    VT_pr_proclist_p_reapsubtree = 70,
    VT_pr_proclist_p_elf_flags = 71,
    VT_pr_proclist_p_elf_brandinfo = 72,
    VT_pr_proclist_p_umtx_min_timeout = 73,
    VT_pr_proclist_p_xexit = 74,
    VT_pr_proclist_p_xsig = 75,
    VT_pr_proclist_p_pgrp = 76,
    VT_pr_proclist_p_klist = 77,
    VT_pr_proclist_p_numthreads = 78,
    VT_pr_proclist_p_md = 79,
    VT_pr_proclist_p_itcallout = 80,
    VT_pr_proclist_p_acflag = 81,
    VT_pr_proclist_p_peers = 82,
    VT_pr_proclist_p_leader = 83,
    VT_pr_proclist_p_emuldata = 84,
    VT_pr_proclist_p_label = 85,
    VT_pr_proclist_p_ktr = 86,
    VT_pr_proclist_p_mqnotifier = 87,
    VT_pr_proclist_p_dtrace = 88,
    VT_pr_proclist_p_pwait = 89,
    VT_pr_proclist_p_prev_runtime = 90,
    VT_pr_proclist_p_racct = 91,
    VT_pr_proclist_p_throttled = 92,
    VT_pr_proclist_p_orphan = 93,
    VT_pr_proclist_p_orphans = 94,
    VT_pr_proclist_p_kqtim_stop = 95,
    VT_pr_proclist_p_jaillist = 96,
    VT_pr_proclist_NUM_COLUMNS
};

static int
copy_columns(struct proc *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_pr_proclist_p_list] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_threads] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_slock] =  /* Unsupported type */
    columns[VT_pr_proclist_p_ucred] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_ucred, context);
    columns[VT_pr_proclist_p_fd] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_fd, context);
    columns[VT_pr_proclist_p_fdtol] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_fdtol, context);
    columns[VT_pr_proclist_p_pd] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_pd, context);
    columns[VT_pr_proclist_p_stats] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_stats, context);
    columns[VT_pr_proclist_p_limit] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_limit, context);
//    columns[VT_pr_proclist_p_limco] =  /* Unsupported type */
    columns[VT_pr_proclist_p_sigacts] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_sigacts, context);
    columns[VT_pr_proclist_p_flag] = new_dbsc_int64(curEntry->p_flag, context);
    columns[VT_pr_proclist_p_flag2] = new_dbsc_int64(curEntry->p_flag2, context);
    columns[VT_pr_proclist_p_state] = new_dbsc_int64((int64_t)(curEntry->p_state), context); // TODO: need better enum representation 
    columns[VT_pr_proclist_p_pid] = new_dbsc_int64(curEntry->p_pid, context);
//    columns[VT_pr_proclist_p_hash] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_pglist] =  /* Unsupported type */
    columns[VT_pr_proclist_p_pptr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_pptr, context);
//    columns[VT_pr_proclist_p_sibling] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_children] =  /* Unsupported type */
    columns[VT_pr_proclist_p_reaper] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_reaper, context);
//    columns[VT_pr_proclist_p_reaplist] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_reapsibling] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_mtx] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_statmtx] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_itimmtx] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_profmtx] =  /* Unsupported type */
    columns[VT_pr_proclist_p_ksi] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_ksi, context);
//    columns[VT_pr_proclist_p_sigqueue] =  /* Unsupported type */
    columns[VT_pr_proclist_p_oppid] = new_dbsc_int64(curEntry->p_oppid, context);
    columns[VT_pr_proclist_p_vmspace] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_vmspace, context);
    columns[VT_pr_proclist_p_swtick] = new_dbsc_int64(curEntry->p_swtick, context);
    columns[VT_pr_proclist_p_cowgen] = new_dbsc_int64(curEntry->p_cowgen, context);
//    columns[VT_pr_proclist_p_realtimer] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_ru] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_rux] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_crux] =  /* Unsupported type */
    columns[VT_pr_proclist_p_profthreads] = new_dbsc_int64(curEntry->p_profthreads, context);
    columns[VT_pr_proclist_p_exitthreads] = new_dbsc_int64(curEntry->p_exitthreads, context);
    columns[VT_pr_proclist_p_traceflag] = new_dbsc_int64(curEntry->p_traceflag, context);
    columns[VT_pr_proclist_p_ktrioparms] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_ktrioparms, context);
    columns[VT_pr_proclist_p_textvp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_textvp, context);
    columns[VT_pr_proclist_p_textdvp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_textdvp, context);
    columns[VT_pr_proclist_p_binname] = new_dbsc_text(curEntry->p_binname, strlen(curEntry->p_binname) + 1, context);
    columns[VT_pr_proclist_p_lock] = new_dbsc_int64(curEntry->p_lock, context);
//    columns[VT_pr_proclist_p_sigiolst] =  /* Unsupported type */
    columns[VT_pr_proclist_p_sigparent] = new_dbsc_int64(curEntry->p_sigparent, context);
    columns[VT_pr_proclist_p_sig] = new_dbsc_int64(curEntry->p_sig, context);
    columns[VT_pr_proclist_p_ptevents] = new_dbsc_int64(curEntry->p_ptevents, context);
    columns[VT_pr_proclist_p_aioinfo] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_aioinfo, context);
    columns[VT_pr_proclist_p_singlethread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_singlethread, context);
    columns[VT_pr_proclist_p_suspcount] = new_dbsc_int64(curEntry->p_suspcount, context);
    columns[VT_pr_proclist_p_xthread] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_xthread, context);
    columns[VT_pr_proclist_p_boundary_count] = new_dbsc_int64(curEntry->p_boundary_count, context);
    columns[VT_pr_proclist_p_pendingcnt] = new_dbsc_int64(curEntry->p_pendingcnt, context);
    columns[VT_pr_proclist_p_itimers] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_itimers, context);
    columns[VT_pr_proclist_p_procdesc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_procdesc, context);
    columns[VT_pr_proclist_p_treeflag] = new_dbsc_int64(curEntry->p_treeflag, context);
    columns[VT_pr_proclist_p_pendingexits] = new_dbsc_int64(curEntry->p_pendingexits, context);
    columns[VT_pr_proclist_p_filemon] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_filemon, context);
    columns[VT_pr_proclist_p_pdeathsig] = new_dbsc_int64(curEntry->p_pdeathsig, context);
    columns[VT_pr_proclist_p_magic] = new_dbsc_int64(curEntry->p_magic, context);
    columns[VT_pr_proclist_p_osrel] = new_dbsc_int64(curEntry->p_osrel, context);
    columns[VT_pr_proclist_p_fctl0] = new_dbsc_int64(curEntry->p_fctl0, context);
//    columns[VT_pr_proclist_p_comm] =  /* Unsupported type */
    columns[VT_pr_proclist_p_sysent] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_sysent, context);
    columns[VT_pr_proclist_p_args] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_args, context);
    columns[VT_pr_proclist_p_cpulimit] = new_dbsc_int64(curEntry->p_cpulimit, context);
    columns[VT_pr_proclist_p_nice] = new_dbsc_int64(curEntry->p_nice, context);
    columns[VT_pr_proclist_p_fibnum] = new_dbsc_int64(curEntry->p_fibnum, context);
    columns[VT_pr_proclist_p_reapsubtree] = new_dbsc_int64(curEntry->p_reapsubtree, context);
    columns[VT_pr_proclist_p_elf_flags] = new_dbsc_int64(curEntry->p_elf_flags, context);
    columns[VT_pr_proclist_p_elf_brandinfo] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_elf_brandinfo, context);
    columns[VT_pr_proclist_p_umtx_min_timeout] = new_dbsc_int64(curEntry->p_umtx_min_timeout, context);
    columns[VT_pr_proclist_p_xexit] = new_dbsc_int64(curEntry->p_xexit, context);
    columns[VT_pr_proclist_p_xsig] = new_dbsc_int64(curEntry->p_xsig, context);
    columns[VT_pr_proclist_p_pgrp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_pgrp, context);
    columns[VT_pr_proclist_p_klist] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_klist, context);
    columns[VT_pr_proclist_p_numthreads] = new_dbsc_int64(curEntry->p_numthreads, context);
//    columns[VT_pr_proclist_p_md] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_itcallout] =  /* Unsupported type */
    columns[VT_pr_proclist_p_acflag] = new_dbsc_int64(curEntry->p_acflag, context);
    columns[VT_pr_proclist_p_peers] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_peers, context);
    columns[VT_pr_proclist_p_leader] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_leader, context);
    columns[VT_pr_proclist_p_emuldata] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_emuldata, context);
    columns[VT_pr_proclist_p_label] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_label, context);
//    columns[VT_pr_proclist_p_ktr] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_mqnotifier] =  /* Unsupported type */
    columns[VT_pr_proclist_p_dtrace] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_dtrace, context);
//    columns[VT_pr_proclist_p_pwait] =  /* Unsupported type */
    columns[VT_pr_proclist_p_prev_runtime] = new_dbsc_int64(curEntry->p_prev_runtime, context);
    columns[VT_pr_proclist_p_racct] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_racct, context);
    columns[VT_pr_proclist_p_throttled] = new_dbsc_int64(curEntry->p_throttled, context);
//    columns[VT_pr_proclist_p_orphan] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_orphans] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_kqtim_stop] =  /* Unsupported type */
//    columns[VT_pr_proclist_p_jaillist] =  /* Unsupported type */

    return 0;
}
void
vtab_proc_lock(void)
{
    sx_slock(&pr_proclist_lock);
}

void
vtab_proc_unlock(void)
{
    sx_sunlock(&pr_proclist_lock);
}

void
vtab_proc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct proc *prc = LIST_FIRST(&pr_proclist);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_pr_proclist_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_pr_proclist_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("proc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
procvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_pr_proclist_p_pid];
    *pRowid = pid_value->int64_value;
    printf("proc_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
procvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
procvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_proc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("proc digest mismatch: UPDATE failed\n");
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
static sqlite3_module procvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ procvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ procvtabRowid,
    /* xUpdate     */ procvtabUpdate,
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
sqlite3_procvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &procvtabModule,
        pAux);
}
void vtab_proc_serialize(sqlite3 *real_db, struct timespec when) {
    struct proc *entry = LIST_FIRST(&pr_proclist);

    const char *create_stmt =
        "CREATE TABLE all_procs (p_flag INTEGER, p_flag2 INTEGER, p_state INTEGER, p_pid INTEGER, p_oppid INTEGER, p_swtick INTEGER, p_cowgen INTEGER, p_profthreads INTEGER, p_exitthreads INTEGER, p_traceflag INTEGER, p_binname TEXT, p_lock INTEGER, p_sigparent INTEGER, p_sig INTEGER, p_ptevents INTEGER, p_suspcount INTEGER, p_boundary_count INTEGER, p_pendingcnt INTEGER, p_treeflag INTEGER, p_pendingexits INTEGER, p_pdeathsig INTEGER, p_magic INTEGER, p_osrel INTEGER, p_fctl0 INTEGER, p_cpulimit INTEGER, p_nice INTEGER, p_fibnum INTEGER, p_reapsubtree INTEGER, p_elf_flags INTEGER, p_umtx_min_timeout INTEGER, p_xexit INTEGER, p_xsig INTEGER, p_numthreads INTEGER, p_acflag INTEGER, p_prev_runtime INTEGER, p_throttled INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_procs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_flag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_flag2);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_pid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_oppid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_swtick);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_cowgen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_profthreads);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_exitthreads);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_traceflag);
           sqlite3_bind_text(stmt, bindIndex++, entry->p_binname, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_lock);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_sigparent);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_sig);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_ptevents);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_suspcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_boundary_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_pendingcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_treeflag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_pendingexits);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_pdeathsig);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_magic);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_osrel);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_fctl0);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_cpulimit);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_nice);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_fibnum);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_reapsubtree);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_elf_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_umtx_min_timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_xexit);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_xsig);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_numthreads);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_acflag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_prev_runtime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_throttled);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

