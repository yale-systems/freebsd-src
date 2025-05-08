#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/thread.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_thread.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_p_threads_td_lock = 0,
    VT_p_threads_td_proc = 1,
    VT_p_threads_td_plist = 2,
    VT_p_threads_td_runq = 3,
    VT_p_threads_ = 4,
    VT_p_threads_td_lockq = 5,
    VT_p_threads_td_hash = 6,
    VT_p_threads_td_cpuset = 7,
    VT_p_threads_td_domain = 8,
    VT_p_threads_td_sel = 9,
    VT_p_threads_td_sleepqueue = 10,
    VT_p_threads_td_turnstile = 11,
    VT_p_threads_td_rlqe = 12,
    VT_p_threads_td_umtxq = 13,
    VT_p_threads_td_tid = 14,
    VT_p_threads_td_sigqueue = 15,
    VT_p_threads_td_lend_user_pri = 16,
    VT_p_threads_td_allocdomain = 17,
    VT_p_threads_td_base_ithread_pri = 18,
    VT_p_threads_td_kmsan = 19,
    VT_p_threads_td_flags = 20,
    VT_p_threads_td_ast = 21,
    VT_p_threads_td_inhibitors = 22,
    VT_p_threads_td_pflags = 23,
    VT_p_threads_td_pflags2 = 24,
    VT_p_threads_td_dupfd = 25,
    VT_p_threads_td_sqqueue = 26,
    VT_p_threads_td_wchan = 27,
    VT_p_threads_td_wmesg = 28,
    VT_p_threads_td_owepreempt = 29,
    VT_p_threads_td_tsqueue = 30,
    VT_p_threads__td_pad0 = 31,
    VT_p_threads_td_locks = 32,
    VT_p_threads_td_rw_rlocks = 33,
    VT_p_threads_td_sx_slocks = 34,
    VT_p_threads_td_lk_slocks = 35,
    VT_p_threads_td_wantedlock = 36,
    VT_p_threads_td_blocked = 37,
    VT_p_threads_td_lockname = 38,
    VT_p_threads_td_contested = 39,
    VT_p_threads_td_sleeplocks = 40,
    VT_p_threads_td_intr_nesting_level = 41,
    VT_p_threads_td_pinned = 42,
    VT_p_threads_td_realucred = 43,
    VT_p_threads_td_ucred = 44,
    VT_p_threads_td_limit = 45,
    VT_p_threads_td_slptick = 46,
    VT_p_threads_td_blktick = 47,
    VT_p_threads_td_swvoltick = 48,
    VT_p_threads_td_swinvoltick = 49,
    VT_p_threads_td_cow = 50,
    VT_p_threads_td_ru = 51,
    VT_p_threads_td_rux = 52,
    VT_p_threads_td_incruntime = 53,
    VT_p_threads_td_runtime = 54,
    VT_p_threads_td_pticks = 55,
    VT_p_threads_td_sticks = 56,
    VT_p_threads_td_iticks = 57,
    VT_p_threads_td_uticks = 58,
    VT_p_threads_td_intrval = 59,
    VT_p_threads_td_oldsigmask = 60,
    VT_p_threads_td_generation = 61,
    VT_p_threads_td_sigstk = 62,
    VT_p_threads_td_xsig = 63,
    VT_p_threads_td_profil_addr = 64,
    VT_p_threads_td_profil_ticks = 65,
    VT_p_threads_td_name = 66,
    VT_p_threads_td_fpop = 67,
    VT_p_threads_td_dbgflags = 68,
    VT_p_threads_td_si = 69,
    VT_p_threads_td_ng_outbound = 70,
    VT_p_threads_td_osd = 71,
    VT_p_threads_td_map_def_user = 72,
    VT_p_threads_td_dbg_forked = 73,
    VT_p_threads_td_no_sleeping = 74,
    VT_p_threads_td_vp_reserved = 75,
    VT_p_threads_td_su = 76,
    VT_p_threads_td_sleeptimo = 77,
    VT_p_threads_td_rtcgen = 78,
    VT_p_threads_td_errno = 79,
    VT_p_threads_td_vslock_sz = 80,
    VT_p_threads_td_kcov_info = 81,
    VT_p_threads_td_ucredref = 82,
    VT_p_threads_td_sigmask = 83,
    VT_p_threads_td_rqindex = 84,
    VT_p_threads_td_base_pri = 85,
    VT_p_threads_td_priority = 86,
    VT_p_threads_td_pri_class = 87,
    VT_p_threads_td_user_pri = 88,
    VT_p_threads_td_base_user_pri = 89,
    VT_p_threads_td_rb_list = 90,
    VT_p_threads_td_rbp_list = 91,
    VT_p_threads_td_rb_inact = 92,
    VT_p_threads_td_sa = 93,
    VT_p_threads_td_sigblock_ptr = 94,
    VT_p_threads_td_sigblock_val = 95,
    VT_p_threads_td_pcb = 96,
    VT_p_threads_td_state = 97,
    VT_p_threads_td_uretoff = 98,
    VT_p_threads_td_cowgen = 99,
    VT_p_threads_td_slpcallout = 100,
    VT_p_threads_td_frame = 101,
    VT_p_threads_td_kstack = 102,
    VT_p_threads_td_kstack_pages = 103,
    VT_p_threads_td_kstack_domain = 104,
    VT_p_threads_td_critnest = 105,
    VT_p_threads_td_md = 106,
    VT_p_threads_td_ar = 107,
    VT_p_threads_td_lprof = 108,
    VT_p_threads_td_dtrace = 109,
    VT_p_threads_td_vnet = 110,
    VT_p_threads_td_vnet_lpush = 111,
    VT_p_threads_td_intr_frame = 112,
    VT_p_threads_td_rfppwait_p = 113,
    VT_p_threads_td_ma = 114,
    VT_p_threads_td_ma_cnt = 115,
    VT_p_threads_td_emuldata = 116,
    VT_p_threads_td_lastcpu = 117,
    VT_p_threads_td_oncpu = 118,
    VT_p_threads_td_lkpi_task = 119,
    VT_p_threads_td_pmcpend = 120,
    VT_p_threads_td_remotereq = 121,
    VT_p_threads_td_ktr_io_lim = 122,
    VT_p_threads_NUM_COLUMNS
};

static int
copy_columns(struct thread *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_p_threads_td_lock] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_lock, context);
    columns[VT_p_threads_td_proc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_proc, context);
//    columns[VT_p_threads_td_plist] =  /* Unsupported type */
//    columns[VT_p_threads_td_runq] =  /* Unsupported type */
//    columns[VT_p_threads_] =  /* Unsupported type */
//    columns[VT_p_threads_td_lockq] =  /* Unsupported type */
//    columns[VT_p_threads_td_hash] =  /* Unsupported type */
    columns[VT_p_threads_td_cpuset] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_cpuset, context);
//    columns[VT_p_threads_td_domain] =  /* Unsupported type */
    columns[VT_p_threads_td_sel] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_sel, context);
    columns[VT_p_threads_td_sleepqueue] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_sleepqueue, context);
    columns[VT_p_threads_td_turnstile] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_turnstile, context);
    columns[VT_p_threads_td_rlqe] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_rlqe, context);
    columns[VT_p_threads_td_umtxq] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_umtxq, context);
    columns[VT_p_threads_td_tid] = new_dbsc_int64(curEntry->td_tid, context);
//    columns[VT_p_threads_td_sigqueue] =  /* Unsupported type */
    columns[VT_p_threads_td_lend_user_pri] = new_dbsc_int64(curEntry->td_lend_user_pri, context);
    columns[VT_p_threads_td_allocdomain] = new_dbsc_int64(curEntry->td_allocdomain, context);
    columns[VT_p_threads_td_base_ithread_pri] = new_dbsc_int64(curEntry->td_base_ithread_pri, context);
    columns[VT_p_threads_td_kmsan] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_kmsan, context);
    columns[VT_p_threads_td_flags] = new_dbsc_int64(curEntry->td_flags, context);
    columns[VT_p_threads_td_ast] = new_dbsc_int64(curEntry->td_ast, context);
    columns[VT_p_threads_td_inhibitors] = new_dbsc_int64(curEntry->td_inhibitors, context);
    columns[VT_p_threads_td_pflags] = new_dbsc_int64(curEntry->td_pflags, context);
    columns[VT_p_threads_td_pflags2] = new_dbsc_int64(curEntry->td_pflags2, context);
    columns[VT_p_threads_td_dupfd] = new_dbsc_int64(curEntry->td_dupfd, context);
    columns[VT_p_threads_td_sqqueue] = new_dbsc_int64(curEntry->td_sqqueue, context);
    columns[VT_p_threads_td_wchan] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_wchan, context);
    columns[VT_p_threads_td_wmesg] = new_dbsc_text(curEntry->td_wmesg, strlen(curEntry->td_wmesg) + 1, context);
    columns[VT_p_threads_td_owepreempt] = new_dbsc_int64(curEntry->td_owepreempt, context);
    columns[VT_p_threads_td_tsqueue] = new_dbsc_int64(curEntry->td_tsqueue, context);
//    columns[VT_p_threads__td_pad0] =  /* Unsupported type */
    columns[VT_p_threads_td_locks] = new_dbsc_int64(curEntry->td_locks, context);
    columns[VT_p_threads_td_rw_rlocks] = new_dbsc_int64(curEntry->td_rw_rlocks, context);
    columns[VT_p_threads_td_sx_slocks] = new_dbsc_int64(curEntry->td_sx_slocks, context);
    columns[VT_p_threads_td_lk_slocks] = new_dbsc_int64(curEntry->td_lk_slocks, context);
    columns[VT_p_threads_td_wantedlock] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_wantedlock, context);
    columns[VT_p_threads_td_blocked] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_blocked, context);
    columns[VT_p_threads_td_lockname] = new_dbsc_text(curEntry->td_lockname, strlen(curEntry->td_lockname) + 1, context);
//    columns[VT_p_threads_td_contested] =  /* Unsupported type */
    columns[VT_p_threads_td_sleeplocks] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_sleeplocks, context);
    columns[VT_p_threads_td_intr_nesting_level] = new_dbsc_int64(curEntry->td_intr_nesting_level, context);
    columns[VT_p_threads_td_pinned] = new_dbsc_int64(curEntry->td_pinned, context);
    columns[VT_p_threads_td_realucred] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_realucred, context);
    columns[VT_p_threads_td_ucred] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_ucred, context);
    columns[VT_p_threads_td_limit] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_limit, context);
    columns[VT_p_threads_td_slptick] = new_dbsc_int64(curEntry->td_slptick, context);
    columns[VT_p_threads_td_blktick] = new_dbsc_int64(curEntry->td_blktick, context);
    columns[VT_p_threads_td_swvoltick] = new_dbsc_int64(curEntry->td_swvoltick, context);
    columns[VT_p_threads_td_swinvoltick] = new_dbsc_int64(curEntry->td_swinvoltick, context);
    columns[VT_p_threads_td_cow] = new_dbsc_int64(curEntry->td_cow, context);
//    columns[VT_p_threads_td_ru] =  /* Unsupported type */
//    columns[VT_p_threads_td_rux] =  /* Unsupported type */
    columns[VT_p_threads_td_incruntime] = new_dbsc_int64(curEntry->td_incruntime, context);
    columns[VT_p_threads_td_runtime] = new_dbsc_int64(curEntry->td_runtime, context);
    columns[VT_p_threads_td_pticks] = new_dbsc_int64(curEntry->td_pticks, context);
    columns[VT_p_threads_td_sticks] = new_dbsc_int64(curEntry->td_sticks, context);
    columns[VT_p_threads_td_iticks] = new_dbsc_int64(curEntry->td_iticks, context);
    columns[VT_p_threads_td_uticks] = new_dbsc_int64(curEntry->td_uticks, context);
    columns[VT_p_threads_td_intrval] = new_dbsc_int64(curEntry->td_intrval, context);
//    columns[VT_p_threads_td_oldsigmask] =  /* Unsupported type */
    columns[VT_p_threads_td_generation] = new_dbsc_int64(curEntry->td_generation, context);
//    columns[VT_p_threads_td_sigstk] =  /* Unsupported type */
    columns[VT_p_threads_td_xsig] = new_dbsc_int64(curEntry->td_xsig, context);
    columns[VT_p_threads_td_profil_addr] = new_dbsc_int64(curEntry->td_profil_addr, context);
    columns[VT_p_threads_td_profil_ticks] = new_dbsc_int64(curEntry->td_profil_ticks, context);
//    columns[VT_p_threads_td_name] =  /* Unsupported type */
    columns[VT_p_threads_td_fpop] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_fpop, context);
    columns[VT_p_threads_td_dbgflags] = new_dbsc_int64(curEntry->td_dbgflags, context);
//    columns[VT_p_threads_td_si] =  /* Unsupported type */
    columns[VT_p_threads_td_ng_outbound] = new_dbsc_int64(curEntry->td_ng_outbound, context);
//    columns[VT_p_threads_td_osd] =  /* Unsupported type */
    columns[VT_p_threads_td_map_def_user] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_map_def_user, context);
    columns[VT_p_threads_td_dbg_forked] = new_dbsc_int64(curEntry->td_dbg_forked, context);
    columns[VT_p_threads_td_no_sleeping] = new_dbsc_int64(curEntry->td_no_sleeping, context);
    columns[VT_p_threads_td_vp_reserved] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_vp_reserved, context);
    columns[VT_p_threads_td_su] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_su, context);
    columns[VT_p_threads_td_sleeptimo] = new_dbsc_int64(curEntry->td_sleeptimo, context);
    columns[VT_p_threads_td_rtcgen] = new_dbsc_int64(curEntry->td_rtcgen, context);
    columns[VT_p_threads_td_errno] = new_dbsc_int64(curEntry->td_errno, context);
    columns[VT_p_threads_td_vslock_sz] = new_dbsc_int64(curEntry->td_vslock_sz, context);
    columns[VT_p_threads_td_kcov_info] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_kcov_info, context);
    columns[VT_p_threads_td_ucredref] = new_dbsc_int64(curEntry->td_ucredref, context);
//    columns[VT_p_threads_td_sigmask] =  /* Unsupported type */
    columns[VT_p_threads_td_rqindex] = new_dbsc_int64(curEntry->td_rqindex, context);
    columns[VT_p_threads_td_base_pri] = new_dbsc_int64(curEntry->td_base_pri, context);
    columns[VT_p_threads_td_priority] = new_dbsc_int64(curEntry->td_priority, context);
    columns[VT_p_threads_td_pri_class] = new_dbsc_int64(curEntry->td_pri_class, context);
    columns[VT_p_threads_td_user_pri] = new_dbsc_int64(curEntry->td_user_pri, context);
    columns[VT_p_threads_td_base_user_pri] = new_dbsc_int64(curEntry->td_base_user_pri, context);
    columns[VT_p_threads_td_rb_list] = new_dbsc_int64(curEntry->td_rb_list, context);
    columns[VT_p_threads_td_rbp_list] = new_dbsc_int64(curEntry->td_rbp_list, context);
    columns[VT_p_threads_td_rb_inact] = new_dbsc_int64(curEntry->td_rb_inact, context);
//    columns[VT_p_threads_td_sa] =  /* Unsupported type */
    columns[VT_p_threads_td_sigblock_ptr] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_sigblock_ptr, context);
    columns[VT_p_threads_td_sigblock_val] = new_dbsc_int64(curEntry->td_sigblock_val, context);
    columns[VT_p_threads_td_pcb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_pcb, context);
    columns[VT_p_threads_td_state] = new_dbsc_int64((int64_t)(curEntry->td_state), context); // TODO: need better enum representation 
//    columns[VT_p_threads_td_uretoff] =  /* Unsupported type */
    columns[VT_p_threads_td_cowgen] = new_dbsc_int64(curEntry->td_cowgen, context);
//    columns[VT_p_threads_td_slpcallout] =  /* Unsupported type */
    columns[VT_p_threads_td_frame] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_frame, context);
    columns[VT_p_threads_td_kstack] = new_dbsc_int64(curEntry->td_kstack, context);
    columns[VT_p_threads_td_kstack_pages] = new_dbsc_int64(curEntry->td_kstack_pages, context);
    columns[VT_p_threads_td_kstack_domain] = new_dbsc_int64(curEntry->td_kstack_domain, context);
    columns[VT_p_threads_td_critnest] = new_dbsc_int64(curEntry->td_critnest, context);
//    columns[VT_p_threads_td_md] =  /* Unsupported type */
    columns[VT_p_threads_td_ar] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_ar, context);
//    columns[VT_p_threads_td_lprof] =  /* Unsupported type */
    columns[VT_p_threads_td_dtrace] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_dtrace, context);
    columns[VT_p_threads_td_vnet] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_vnet, context);
    columns[VT_p_threads_td_vnet_lpush] = new_dbsc_text(curEntry->td_vnet_lpush, strlen(curEntry->td_vnet_lpush) + 1, context);
    columns[VT_p_threads_td_intr_frame] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_intr_frame, context);
    columns[VT_p_threads_td_rfppwait_p] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_rfppwait_p, context);
    columns[VT_p_threads_td_ma] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_ma, context);
    columns[VT_p_threads_td_ma_cnt] = new_dbsc_int64(curEntry->td_ma_cnt, context);
    columns[VT_p_threads_td_emuldata] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_emuldata, context);
    columns[VT_p_threads_td_lastcpu] = new_dbsc_int64(curEntry->td_lastcpu, context);
    columns[VT_p_threads_td_oncpu] = new_dbsc_int64(curEntry->td_oncpu, context);
    columns[VT_p_threads_td_lkpi_task] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_lkpi_task, context);
    columns[VT_p_threads_td_pmcpend] = new_dbsc_int64(curEntry->td_pmcpend, context);
    columns[VT_p_threads_td_remotereq] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->td_remotereq, context);
    columns[VT_p_threads_td_ktr_io_lim] = new_dbsc_int64(curEntry->td_ktr_io_lim, context);

    return 0;
}
void
vtab_thread_lock(void)
{
    sx_slock(&p_threads_lock);
}

void
vtab_thread_unlock(void)
{
    sx_sunlock(&p_threads_lock);
}

void
vtab_thread_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct thread *prc = LIST_FIRST(&p_threads);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_p_threads_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_p_threads_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("thread digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
threadvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_p_threads_p_pid];
    *pRowid = pid_value->int64_value;
    printf("thread_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
threadvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
threadvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_thread_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("thread digest mismatch: UPDATE failed\n");
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
static sqlite3_module threadvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ threadvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ threadvtabRowid,
    /* xUpdate     */ threadvtabUpdate,
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
sqlite3_threadvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &threadvtabModule,
        pAux);
}
void vtab_thread_serialize(sqlite3 *real_db, struct timespec when) {
    struct thread *entry = LIST_FIRST(&p_threads);

    const char *create_stmt =
        "CREATE TABLE all_threads (td_tid INTEGER, td_lend_user_pri INTEGER, td_allocdomain INTEGER, td_base_ithread_pri INTEGER, td_flags INTEGER, td_ast INTEGER, td_inhibitors INTEGER, td_pflags INTEGER, td_pflags2 INTEGER, td_dupfd INTEGER, td_sqqueue INTEGER, td_wmesg TEXT, td_owepreempt INTEGER, td_tsqueue INTEGER, td_locks INTEGER, td_rw_rlocks INTEGER, td_sx_slocks INTEGER, td_lk_slocks INTEGER, td_lockname TEXT, td_intr_nesting_level INTEGER, td_pinned INTEGER, td_slptick INTEGER, td_blktick INTEGER, td_swvoltick INTEGER, td_swinvoltick INTEGER, td_cow INTEGER, td_incruntime INTEGER, td_runtime INTEGER, td_pticks INTEGER, td_sticks INTEGER, td_iticks INTEGER, td_uticks INTEGER, td_intrval INTEGER, td_generation INTEGER, td_xsig INTEGER, td_profil_addr INTEGER, td_profil_ticks INTEGER, td_dbgflags INTEGER, td_ng_outbound INTEGER, td_dbg_forked INTEGER, td_no_sleeping INTEGER, td_sleeptimo INTEGER, td_rtcgen INTEGER, td_errno INTEGER, td_vslock_sz INTEGER, td_ucredref INTEGER, td_rqindex INTEGER, td_base_pri INTEGER, td_priority INTEGER, td_pri_class INTEGER, td_user_pri INTEGER, td_base_user_pri INTEGER, td_rb_list INTEGER, td_rbp_list INTEGER, td_rb_inact INTEGER, td_sigblock_val INTEGER, td_state INTEGER, td_cowgen INTEGER, td_kstack INTEGER, td_kstack_pages INTEGER, td_kstack_domain INTEGER, td_critnest INTEGER, td_vnet_lpush TEXT, td_ma_cnt INTEGER, td_lastcpu INTEGER, td_oncpu INTEGER, td_pmcpend INTEGER, td_ktr_io_lim INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_tid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_lend_user_pri);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_allocdomain);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_base_ithread_pri);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_ast);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_inhibitors);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_pflags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_pflags2);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_dupfd);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_sqqueue);
           sqlite3_bind_text(stmt, bindIndex++, entry->td_wmesg, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_owepreempt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_tsqueue);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_locks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_rw_rlocks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_sx_slocks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_lk_slocks);
           sqlite3_bind_text(stmt, bindIndex++, entry->td_lockname, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_intr_nesting_level);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_pinned);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_slptick);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_blktick);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_swvoltick);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_swinvoltick);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_cow);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_incruntime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_runtime);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_pticks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_sticks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_iticks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_uticks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_intrval);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_generation);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_xsig);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_profil_addr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_profil_ticks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_dbgflags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_ng_outbound);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_dbg_forked);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_no_sleeping);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_sleeptimo);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_rtcgen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_errno);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_vslock_sz);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_ucredref);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_rqindex);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_base_pri);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_priority);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_pri_class);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_user_pri);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_base_user_pri);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_rb_list);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_rbp_list);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_rb_inact);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_sigblock_val);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_cowgen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_kstack);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_kstack_pages);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_kstack_domain);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_critnest);
           sqlite3_bind_text(stmt, bindIndex++, entry->td_vnet_lpush, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_ma_cnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_lastcpu);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_oncpu);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_pmcpend);
           sqlite3_bind_int64(stmt, bindIndex++, entry->td_ktr_io_lim);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

