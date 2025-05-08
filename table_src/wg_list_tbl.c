#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_wg_list_sc_entry = 0,
    VT_wg_list_sc_ifp = 1,
    VT_wg_list_sc_flags = 2,
    VT_wg_list_sc_ucred = 3,
    VT_wg_list_sc_socket = 4,
    VT_wg_list_sc_peers = 5,
    VT_wg_list_sc_peers_num = 6,
    VT_wg_list_sc_local = 7,
    VT_wg_list_sc_cookie = 8,
    VT_wg_list_sc_aip4 = 9,
    VT_wg_list_sc_aip6 = 10,
    VT_wg_list_sc_handshake = 11,
    VT_wg_list_sc_handshake_queue = 12,
    VT_wg_list_sc_encrypt = 13,
    VT_wg_list_sc_decrypt = 14,
    VT_wg_list_sc_encrypt_parallel = 15,
    VT_wg_list_sc_decrypt_parallel = 16,
    VT_wg_list_sc_encrypt_last_cpu = 17,
    VT_wg_list_sc_decrypt_last_cpu = 18,
    VT_wg_list_sc_lock = 19,
    VT_wg_list_NUM_COLUMNS
};

static int
copy_columns(struct wg_list *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_wg_list_sc_entry] =  TODO: Handle other types
//    columns[VT_wg_list_sc_ifp] =  TODO: Handle other types
    columns[VT_wg_list_sc_flags] = new_osdb_int64(curEntry->sc_flags, context);
//    columns[VT_wg_list_sc_ucred] =  TODO: Handle other types
//    columns[VT_wg_list_sc_socket] =  TODO: Handle other types
//    columns[VT_wg_list_sc_peers] =  TODO: Handle other types
    columns[VT_wg_list_sc_peers_num] = new_osdb_int64(curEntry->sc_peers_num, context);
//    columns[VT_wg_list_sc_local] =  TODO: Handle other types
//    columns[VT_wg_list_sc_cookie] =  TODO: Handle other types
//    columns[VT_wg_list_sc_aip4] =  TODO: Handle other types
//    columns[VT_wg_list_sc_aip6] =  TODO: Handle other types
//    columns[VT_wg_list_sc_handshake] =  TODO: Handle other types
//    columns[VT_wg_list_sc_handshake_queue] =  TODO: Handle other types
//    columns[VT_wg_list_sc_encrypt] =  TODO: Handle other types
//    columns[VT_wg_list_sc_decrypt] =  TODO: Handle other types
//    columns[VT_wg_list_sc_encrypt_parallel] =  TODO: Handle other types
//    columns[VT_wg_list_sc_decrypt_parallel] =  TODO: Handle other types
    columns[VT_wg_list_sc_encrypt_last_cpu] = new_osdb_int64(curEntry->sc_encrypt_last_cpu, context);
    columns[VT_wg_list_sc_decrypt_last_cpu] = new_osdb_int64(curEntry->sc_decrypt_last_cpu, context);
//    columns[VT_wg_list_sc_lock] =  TODO: Handle other types

    return 0;
}
void
vtab__lock(void)
{
    sx_slock(&wg_list_lock);
}

void
vtab__unlock(void)
{
    sx_sunlock(&wg_list_lock);
}

void
vtab__snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct  *prc = LIST_FIRST(&wg_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_wg_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_wg_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf(" digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab__rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_wg_list_PID];
    *pRowid = pid_value->int64_value;
    printf("_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab__bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab__update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab__snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf(" digest mismatch: UPDATE failed\n");
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
static sqlite3_module vtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vtabRowid,
    /* xUpdate     */ vtabUpdate,
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
sqlite3_vtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vtabModule,
        pAux);
}
