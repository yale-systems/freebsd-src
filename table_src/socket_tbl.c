#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_socket.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sol_incomp_so_lock = 0,
    VT_sol_incomp_so_count = 1,
    VT_sol_incomp_so_rdsel = 2,
    VT_sol_incomp_so_wrsel = 3,
    VT_sol_incomp_so_options = 4,
    VT_sol_incomp_so_type = 5,
    VT_sol_incomp_so_state = 6,
    VT_sol_incomp_so_pcb = 7,
    VT_sol_incomp_so_vnet = 8,
    VT_sol_incomp_so_proto = 9,
    VT_sol_incomp_so_linger = 10,
    VT_sol_incomp_so_timeo = 11,
    VT_sol_incomp_so_error = 12,
    VT_sol_incomp_so_rerror = 13,
    VT_sol_incomp_so_sigio = 14,
    VT_sol_incomp_so_cred = 15,
    VT_sol_incomp_so_label = 16,
    VT_sol_incomp_so_gencnt = 17,
    VT_sol_incomp_so_emuldata = 18,
    VT_sol_incomp_so_dtor = 19,
    VT_sol_incomp_osd = 20,
    VT_sol_incomp_so_fibnum = 21,
    VT_sol_incomp_so_user_cookie = 22,
    VT_sol_incomp_so_ts_clock = 23,
    VT_sol_incomp_so_max_pacing_rate = 24,
    VT_sol_incomp_so_snd_sx = 25,
    VT_sol_incomp_so_snd_mtx = 26,
    VT_sol_incomp_so_rcv_sx = 27,
    VT_sol_incomp_so_rcv_mtx = 28,
    VT_sol_incomp_ = 29,
    VT_sol_incomp_NUM_COLUMNS
};

static int
copy_columns(struct socket *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_sol_incomp_so_lock] =  /* Unsupported type */
    columns[VT_sol_incomp_so_count] = new_dbsc_int64(curEntry->so_count, context);
//    columns[VT_sol_incomp_so_rdsel] =  /* Unsupported type */
//    columns[VT_sol_incomp_so_wrsel] =  /* Unsupported type */
    columns[VT_sol_incomp_so_options] = new_dbsc_int64(curEntry->so_options, context);
    columns[VT_sol_incomp_so_type] = new_dbsc_int64(curEntry->so_type, context);
    columns[VT_sol_incomp_so_state] = new_dbsc_int64(curEntry->so_state, context);
    columns[VT_sol_incomp_so_pcb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->so_pcb, context);
    columns[VT_sol_incomp_so_vnet] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->so_vnet, context);
    columns[VT_sol_incomp_so_proto] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->so_proto, context);
    columns[VT_sol_incomp_so_linger] = new_dbsc_int64(curEntry->so_linger, context);
    columns[VT_sol_incomp_so_timeo] = new_dbsc_int64(curEntry->so_timeo, context);
    columns[VT_sol_incomp_so_error] = new_dbsc_int64(curEntry->so_error, context);
    columns[VT_sol_incomp_so_rerror] = new_dbsc_int64(curEntry->so_rerror, context);
    columns[VT_sol_incomp_so_sigio] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->so_sigio, context);
    columns[VT_sol_incomp_so_cred] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->so_cred, context);
    columns[VT_sol_incomp_so_label] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->so_label, context);
    columns[VT_sol_incomp_so_gencnt] = new_dbsc_int64(curEntry->so_gencnt, context);
    columns[VT_sol_incomp_so_emuldata] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->so_emuldata, context);
    columns[VT_sol_incomp_so_dtor] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->so_dtor, context);
//    columns[VT_sol_incomp_osd] =  /* Unsupported type */
    columns[VT_sol_incomp_so_fibnum] = new_dbsc_int64(curEntry->so_fibnum, context);
    columns[VT_sol_incomp_so_user_cookie] = new_dbsc_int64(curEntry->so_user_cookie, context);
    columns[VT_sol_incomp_so_ts_clock] = new_dbsc_int64(curEntry->so_ts_clock, context);
    columns[VT_sol_incomp_so_max_pacing_rate] = new_dbsc_int64(curEntry->so_max_pacing_rate, context);
//    columns[VT_sol_incomp_so_snd_sx] =  /* Unsupported type */
//    columns[VT_sol_incomp_so_snd_mtx] =  /* Unsupported type */
//    columns[VT_sol_incomp_so_rcv_sx] =  /* Unsupported type */
//    columns[VT_sol_incomp_so_rcv_mtx] =  /* Unsupported type */
//    columns[VT_sol_incomp_] =  /* Unsupported type */

    return 0;
}
void
vtab_socket_lock(void)
{
    sx_slock(&sol_incomp_lock);
}

void
vtab_socket_unlock(void)
{
    sx_sunlock(&sol_incomp_lock);
}

void
vtab_socket_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct socket *prc = LIST_FIRST(&sol_incomp);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sol_incomp_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sol_incomp_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("socket digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
socketvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sol_incomp_p_pid];
    *pRowid = pid_value->int64_value;
    printf("socket_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
socketvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
socketvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_socket_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("socket digest mismatch: UPDATE failed\n");
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
static sqlite3_module socketvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ socketvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ socketvtabRowid,
    /* xUpdate     */ socketvtabUpdate,
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
sqlite3_socketvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &socketvtabModule,
        pAux);
}
void vtab_socket_serialize(sqlite3 *real_db, struct timespec when) {
    struct socket *entry = LIST_FIRST(&sol_incomp);

    const char *create_stmt =
        "CREATE TABLE all_sockets (so_count INTEGER, so_options INTEGER, so_type INTEGER, so_state INTEGER, so_linger INTEGER, so_timeo INTEGER, so_error INTEGER, so_rerror INTEGER, so_gencnt INTEGER, so_fibnum INTEGER, so_user_cookie INTEGER, so_ts_clock INTEGER, so_max_pacing_rate INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_sockets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_options);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_linger);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_timeo);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_error);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_rerror);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_gencnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_fibnum);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_user_cookie);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_ts_clock);
           sqlite3_bind_int64(stmt, bindIndex++, entry->so_max_pacing_rate);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

