#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/wg_peer.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_wg_peer.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sc_peers_p_entry = 0,
    VT_sc_peers_p_id = 1,
    VT_sc_peers_p_sc = 2,
    VT_sc_peers_p_remote = 3,
    VT_sc_peers_p_cookie = 4,
    VT_sc_peers_p_endpoint_lock = 5,
    VT_sc_peers_p_endpoint = 6,
    VT_sc_peers_p_stage_queue = 7,
    VT_sc_peers_p_encrypt_serial = 8,
    VT_sc_peers_p_decrypt_serial = 9,
    VT_sc_peers_p_enabled = 10,
    VT_sc_peers_p_need_another_keepalive = 11,
    VT_sc_peers_p_persistent_keepalive_interval = 12,
    VT_sc_peers_p_new_handshake = 13,
    VT_sc_peers_p_send_keepalive = 14,
    VT_sc_peers_p_retry_handshake = 15,
    VT_sc_peers_p_zero_key_material = 16,
    VT_sc_peers_p_persistent_keepalive = 17,
    VT_sc_peers_p_handshake_mtx = 18,
    VT_sc_peers_p_handshake_complete = 19,
    VT_sc_peers_p_handshake_retries = 20,
    VT_sc_peers_p_send = 21,
    VT_sc_peers_p_recv = 22,
    VT_sc_peers_p_tx_bytes = 23,
    VT_sc_peers_p_rx_bytes = 24,
    VT_sc_peers_p_aips = 25,
    VT_sc_peers_p_aips_num = 26,
    VT_sc_peers_NUM_COLUMNS
};

static int
copy_columns(struct wg_peer *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_sc_peers_p_entry] =  /* Unsupported type */
    columns[VT_sc_peers_p_id] = new_dbsc_int64(curEntry->p_id, context);
    columns[VT_sc_peers_p_sc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_sc, context);
    columns[VT_sc_peers_p_remote] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_remote, context);
//    columns[VT_sc_peers_p_cookie] =  /* Unsupported type */
//    columns[VT_sc_peers_p_endpoint_lock] =  /* Unsupported type */
//    columns[VT_sc_peers_p_endpoint] =  /* Unsupported type */
//    columns[VT_sc_peers_p_stage_queue] =  /* Unsupported type */
//    columns[VT_sc_peers_p_encrypt_serial] =  /* Unsupported type */
//    columns[VT_sc_peers_p_decrypt_serial] =  /* Unsupported type */
    columns[VT_sc_peers_p_enabled] = new_dbsc_int64(curEntry->p_enabled, context);
    columns[VT_sc_peers_p_need_another_keepalive] = new_dbsc_int64(curEntry->p_need_another_keepalive, context);
    columns[VT_sc_peers_p_persistent_keepalive_interval] = new_dbsc_int64(curEntry->p_persistent_keepalive_interval, context);
//    columns[VT_sc_peers_p_new_handshake] =  /* Unsupported type */
//    columns[VT_sc_peers_p_send_keepalive] =  /* Unsupported type */
//    columns[VT_sc_peers_p_retry_handshake] =  /* Unsupported type */
//    columns[VT_sc_peers_p_zero_key_material] =  /* Unsupported type */
//    columns[VT_sc_peers_p_persistent_keepalive] =  /* Unsupported type */
//    columns[VT_sc_peers_p_handshake_mtx] =  /* Unsupported type */
//    columns[VT_sc_peers_p_handshake_complete] =  /* Unsupported type */
    columns[VT_sc_peers_p_handshake_retries] = new_dbsc_int64(curEntry->p_handshake_retries, context);
//    columns[VT_sc_peers_p_send] =  /* Unsupported type */
//    columns[VT_sc_peers_p_recv] =  /* Unsupported type */
    columns[VT_sc_peers_p_tx_bytes] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_tx_bytes, context);
    columns[VT_sc_peers_p_rx_bytes] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->p_rx_bytes, context);
//    columns[VT_sc_peers_p_aips] =  /* Unsupported type */
    columns[VT_sc_peers_p_aips_num] = new_dbsc_int64(curEntry->p_aips_num, context);

    return 0;
}
void
vtab_wg_peer_lock(void)
{
    sx_slock(&sc_peers_lock);
}

void
vtab_wg_peer_unlock(void)
{
    sx_sunlock(&sc_peers_lock);
}

void
vtab_wg_peer_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct wg_peer *prc = LIST_FIRST(&sc_peers);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sc_peers_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sc_peers_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("wg_peer digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
wg_peervtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sc_peers_p_pid];
    *pRowid = pid_value->int64_value;
    printf("wg_peer_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
wg_peervtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
wg_peervtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_wg_peer_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("wg_peer digest mismatch: UPDATE failed\n");
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
static sqlite3_module wg_peervtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ wg_peervtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ wg_peervtabRowid,
    /* xUpdate     */ wg_peervtabUpdate,
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
sqlite3_wg_peervtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &wg_peervtabModule,
        pAux);
}
void vtab_wg_peer_serialize(sqlite3 *real_db, struct timespec when) {
    struct wg_peer *entry = LIST_FIRST(&sc_peers);

    const char *create_stmt =
        "CREATE TABLE all_wg_peers (p_id INTEGER, p_enabled INTEGER, p_need_another_keepalive INTEGER, p_persistent_keepalive_interval INTEGER, p_handshake_retries INTEGER, p_aips_num INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_wg_peers VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_enabled);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_need_another_keepalive);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_persistent_keepalive_interval);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_handshake_retries);
           sqlite3_bind_int64(stmt, bindIndex++, entry->p_aips_num);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

