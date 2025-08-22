#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_allproc_p_list = 0,
    VT_allproc_p_threads = 1,
    VT_allproc_p_slock = 2,
    VT_allproc_p_ucred = 3,
    VT_allproc_p_fd = 4,
    VT_allproc_p_fdtol = 5,
    VT_allproc_p_pd = 6,
    VT_allproc_p_stats = 7,
    VT_allproc_p_limit = 8,
    VT_allproc_p_limco = 9,
    VT_allproc_p_sigacts = 10,
    VT_allproc_p_flag = 11,
    VT_allproc_p_flag2 = 12,
    VT_allproc_p_state = 13,
    VT_allproc_p_pid = 14,
    VT_allproc_p_hash = 15,
    VT_allproc_p_pglist = 16,
    VT_allproc_p_pptr = 17,
    VT_allproc_p_sibling = 18,
    VT_allproc_p_children = 19,
    VT_allproc_p_reaper = 20,
    VT_allproc_p_reaplist = 21,
    VT_allproc_p_reapsibling = 22,
    VT_allproc_p_mtx = 23,
    VT_allproc_p_statmtx = 24,
    VT_allproc_p_itimmtx = 25,
    VT_allproc_p_profmtx = 26,
    VT_allproc_p_ksi = 27,
    VT_allproc_p_sigqueue = 28,
    VT_allproc_p_oppid = 29,
    VT_allproc_p_vmspace = 30,
    VT_allproc_p_swtick = 31,
    VT_allproc_p_cowgen = 32,
    VT_allproc_p_realtimer = 33,
    VT_allproc_p_ru = 34,
    VT_allproc_p_rux = 35,
    VT_allproc_p_crux = 36,
    VT_allproc_p_profthreads = 37,
    VT_allproc_p_exitthreads = 38,
    VT_allproc_p_traceflag = 39,
    VT_allproc_p_ktrioparms = 40,
    VT_allproc_p_textvp = 41,
    VT_allproc_p_textdvp = 42,
    VT_allproc_p_binname = 43,
    VT_allproc_p_lock = 44,
    VT_allproc_p_sigiolst = 45,
    VT_allproc_p_sigparent = 46,
    VT_allproc_p_sig = 47,
    VT_allproc_p_ptevents = 48,
    VT_allproc_p_aioinfo = 49,
    VT_allproc_p_singlethread = 50,
    VT_allproc_p_suspcount = 51,
    VT_allproc_p_xthread = 52,
    VT_allproc_p_boundary_count = 53,
    VT_allproc_p_pendingcnt = 54,
    VT_allproc_p_itimers = 55,
    VT_allproc_p_procdesc = 56,
    VT_allproc_p_treeflag = 57,
    VT_allproc_p_pendingexits = 58,
    VT_allproc_p_filemon = 59,
    VT_allproc_p_pdeathsig = 60,
    VT_allproc_p_magic = 61,
    VT_allproc_p_osrel = 62,
    VT_allproc_p_fctl0 = 63,
    VT_allproc_p_comm = 64,
    VT_allproc_p_sysent = 65,
    VT_allproc_p_args = 66,
    VT_allproc_p_cpulimit = 67,
    VT_allproc_p_nice = 68,
    VT_allproc_p_fibnum = 69,
    VT_allproc_p_reapsubtree = 70,
    VT_allproc_p_elf_flags = 71,
    VT_allproc_p_elf_brandinfo = 72,
    VT_allproc_p_umtx_min_timeout = 73,
    VT_allproc_p_xexit = 74,
    VT_allproc_p_xsig = 75,
    VT_allproc_p_pgrp = 76,
    VT_allproc_p_klist = 77,
    VT_allproc_p_numthreads = 78,
    VT_allproc_p_md = 79,
    VT_allproc_p_itcallout = 80,
    VT_allproc_p_acflag = 81,
    VT_allproc_p_peers = 82,
    VT_allproc_p_leader = 83,
    VT_allproc_p_emuldata = 84,
    VT_allproc_p_label = 85,
    VT_allproc_p_ktr = 86,
    VT_allproc_p_mqnotifier = 87,
    VT_allproc_p_dtrace = 88,
    VT_allproc_p_pwait = 89,
    VT_allproc_p_prev_runtime = 90,
    VT_allproc_p_racct = 91,
    VT_allproc_p_throttled = 92,
    VT_allproc_p_orphan = 93,
    VT_allproc_p_orphans = 94,
    VT_allproc_p_kqtim_stop = 95,
    VT_allproc_p_jaillist = 96,
    VT_allproc_NUM_COLUMNS
};

static int
copy_columns(struct allproc *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_allproc_p_list] =  TODO: Handle other types
//    columns[VT_allproc_p_threads] =  TODO: Handle other types
//    columns[VT_allproc_p_slock] =  TODO: Handle other types
//    columns[VT_allproc_p_ucred] =  TODO: Handle other types
//    columns[VT_allproc_p_fd] =  TODO: Handle other types
//    columns[VT_allproc_p_fdtol] =  TODO: Handle other types
//    columns[VT_allproc_p_pd] =  TODO: Handle other types
//    columns[VT_allproc_p_stats] =  TODO: Handle other types
//    columns[VT_allproc_p_limit] =  TODO: Handle other types
//    columns[VT_allproc_p_limco] =  TODO: Handle other types
//    columns[VT_allproc_p_sigacts] =  TODO: Handle other types
    columns[VT_allproc_p_flag] = new_osdb_int64(curEntry->p_flag, context);
    columns[VT_allproc_p_flag2] = new_osdb_int64(curEntry->p_flag2, context);
    columns[VT_allproc_p_state] = new_osdb_int64(static_cast<int64_t>(curEntry->p_state), context); // TODO: need better enum representation 
    columns[VT_allproc_p_pid] = new_osdb_int64(curEntry->p_pid, context);
//    columns[VT_allproc_p_hash] =  TODO: Handle other types
//    columns[VT_allproc_p_pglist] =  TODO: Handle other types
//    columns[VT_allproc_p_pptr] =  TODO: Handle other types
//    columns[VT_allproc_p_sibling] =  TODO: Handle other types
//    columns[VT_allproc_p_children] =  TODO: Handle other types
//    columns[VT_allproc_p_reaper] =  TODO: Handle other types
//    columns[VT_allproc_p_reaplist] =  TODO: Handle other types
//    columns[VT_allproc_p_reapsibling] =  TODO: Handle other types
//    columns[VT_allproc_p_mtx] =  TODO: Handle other types
//    columns[VT_allproc_p_statmtx] =  TODO: Handle other types
//    columns[VT_allproc_p_itimmtx] =  TODO: Handle other types
//    columns[VT_allproc_p_profmtx] =  TODO: Handle other types
//    columns[VT_allproc_p_ksi] =  TODO: Handle other types
//    columns[VT_allproc_p_sigqueue] =  TODO: Handle other types
    columns[VT_allproc_p_oppid] = new_osdb_int64(curEntry->p_oppid, context);
//    columns[VT_allproc_p_vmspace] =  TODO: Handle other types
    columns[VT_allproc_p_swtick] = new_osdb_int64(curEntry->p_swtick, context);
    columns[VT_allproc_p_cowgen] = new_osdb_int64(curEntry->p_cowgen, context);
//    columns[VT_allproc_p_realtimer] =  TODO: Handle other types
//    columns[VT_allproc_p_ru] =  TODO: Handle other types
//    columns[VT_allproc_p_rux] =  TODO: Handle other types
//    columns[VT_allproc_p_crux] =  TODO: Handle other types
    columns[VT_allproc_p_profthreads] = new_osdb_int64(curEntry->p_profthreads, context);
    columns[VT_allproc_p_exitthreads] = new_osdb_int64(curEntry->p_exitthreads, context);
    columns[VT_allproc_p_traceflag] = new_osdb_int64(curEntry->p_traceflag, context);
//    columns[VT_allproc_p_ktrioparms] =  TODO: Handle other types
//    columns[VT_allproc_p_textvp] =  TODO: Handle other types
//    columns[VT_allproc_p_textdvp] =  TODO: Handle other types
    columns[VT_allproc_p_binname] = new_osdb_text(curEntry->p_binname, strlen(curEntry->p_binname) + 1, context);
    columns[VT_allproc_p_lock] = new_osdb_int64(curEntry->p_lock, context);
//    columns[VT_allproc_p_sigiolst] =  TODO: Handle other types
    columns[VT_allproc_p_sigparent] = new_osdb_int64(curEntry->p_sigparent, context);
    columns[VT_allproc_p_sig] = new_osdb_int64(curEntry->p_sig, context);
    columns[VT_allproc_p_ptevents] = new_osdb_int64(curEntry->p_ptevents, context);
//    columns[VT_allproc_p_aioinfo] =  TODO: Handle other types
//    columns[VT_allproc_p_singlethread] =  TODO: Handle other types
    columns[VT_allproc_p_suspcount] = new_osdb_int64(curEntry->p_suspcount, context);
//    columns[VT_allproc_p_xthread] =  TODO: Handle other types
    columns[VT_allproc_p_boundary_count] = new_osdb_int64(curEntry->p_boundary_count, context);
    columns[VT_allproc_p_pendingcnt] = new_osdb_int64(curEntry->p_pendingcnt, context);
//    columns[VT_allproc_p_itimers] =  TODO: Handle other types
//    columns[VT_allproc_p_procdesc] =  TODO: Handle other types
    columns[VT_allproc_p_treeflag] = new_osdb_int64(curEntry->p_treeflag, context);
    columns[VT_allproc_p_pendingexits] = new_osdb_int64(curEntry->p_pendingexits, context);
//    columns[VT_allproc_p_filemon] =  TODO: Handle other types
    columns[VT_allproc_p_pdeathsig] = new_osdb_int64(curEntry->p_pdeathsig, context);
    columns[VT_allproc_p_magic] = new_osdb_int64(curEntry->p_magic, context);
    columns[VT_allproc_p_osrel] = new_osdb_int64(curEntry->p_osrel, context);
    columns[VT_allproc_p_fctl0] = new_osdb_int64(curEntry->p_fctl0, context);
//    columns[VT_allproc_p_comm] =  TODO: Handle other types
//    columns[VT_allproc_p_sysent] =  TODO: Handle other types
//    columns[VT_allproc_p_args] =  TODO: Handle other types
    columns[VT_allproc_p_cpulimit] = new_osdb_int64(curEntry->p_cpulimit, context);
    columns[VT_allproc_p_nice] = new_osdb_int64(curEntry->p_nice, context);
    columns[VT_allproc_p_fibnum] = new_osdb_int64(curEntry->p_fibnum, context);
    columns[VT_allproc_p_reapsubtree] = new_osdb_int64(curEntry->p_reapsubtree, context);
    columns[VT_allproc_p_elf_flags] = new_osdb_int64(curEntry->p_elf_flags, context);
//    columns[VT_allproc_p_elf_brandinfo] =  TODO: Handle other types
    columns[VT_allproc_p_umtx_min_timeout] = new_osdb_int64(curEntry->p_umtx_min_timeout, context);
    columns[VT_allproc_p_xexit] = new_osdb_int64(curEntry->p_xexit, context);
    columns[VT_allproc_p_xsig] = new_osdb_int64(curEntry->p_xsig, context);
//    columns[VT_allproc_p_pgrp] =  TODO: Handle other types
//    columns[VT_allproc_p_klist] =  TODO: Handle other types
    columns[VT_allproc_p_numthreads] = new_osdb_int64(curEntry->p_numthreads, context);
//    columns[VT_allproc_p_md] =  TODO: Handle other types
//    columns[VT_allproc_p_itcallout] =  TODO: Handle other types
    columns[VT_allproc_p_acflag] = new_osdb_int64(curEntry->p_acflag, context);
//    columns[VT_allproc_p_peers] =  TODO: Handle other types
//    columns[VT_allproc_p_leader] =  TODO: Handle other types
//    columns[VT_allproc_p_emuldata] =  TODO: Handle other types
//    columns[VT_allproc_p_label] =  TODO: Handle other types
//    columns[VT_allproc_p_ktr] =  TODO: Handle other types
//    columns[VT_allproc_p_mqnotifier] =  TODO: Handle other types
//    columns[VT_allproc_p_dtrace] =  TODO: Handle other types
//    columns[VT_allproc_p_pwait] =  TODO: Handle other types
    columns[VT_allproc_p_prev_runtime] = new_osdb_int64(curEntry->p_prev_runtime, context);
//    columns[VT_allproc_p_racct] =  TODO: Handle other types
    columns[VT_allproc_p_throttled] = new_osdb_int64(curEntry->p_throttled, context);
//    columns[VT_allproc_p_orphan] =  TODO: Handle other types
//    columns[VT_allproc_p_orphans] =  TODO: Handle other types
//    columns[VT_allproc_p_kqtim_stop] =  TODO: Handle other types
//    columns[VT_allproc_p_jaillist] =  TODO: Handle other types

    return 0;
}
void
vtab_proclist_lock(void)
{
    sx_slock(&allproc_lock);
}

void
vtab_proclist_unlock(void)
{
    sx_sunlock(&allproc_lock);
}

void
vtab_proclist_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct proclist *prc = LIST_FIRST(&allproc);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_allproc_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_allproc_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("proclist digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_proclist_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_allproc_PID];
    *pRowid = pid_value->int64_value;
    printf("proclist_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_proclist_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_proclist_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_proclist_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("proclist digest mismatch: UPDATE failed\n");
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
static sqlite3_module proclistvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ proclistvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ proclistvtabRowid,
    /* xUpdate     */ proclistvtabUpdate,
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
sqlite3_proclistvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &proclistvtabModule,
        pAux);
}
