#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_cleanup_xp_refs = 0,
    VT_cleanup_xp_lock = 1,
    VT_cleanup_xp_pool = 2,
    VT_cleanup_xp_group = 3,
    VT_cleanup_xp_link = 4,
    VT_cleanup_xp_alink = 5,
    VT_cleanup_xp_registered = 6,
    VT_cleanup_xp_active = 7,
    VT_cleanup_xp_thread = 8,
    VT_cleanup_xp_socket = 9,
    VT_cleanup_xp_ops = 10,
    VT_cleanup_xp_netid = 11,
    VT_cleanup_xp_ltaddr = 12,
    VT_cleanup_xp_rtaddr = 13,
    VT_cleanup_xp_p1 = 14,
    VT_cleanup_xp_p2 = 15,
    VT_cleanup_xp_p3 = 16,
    VT_cleanup_xp_type = 17,
    VT_cleanup_xp_idletimeout = 18,
    VT_cleanup_xp_lastactive = 19,
    VT_cleanup_xp_sockref = 20,
    VT_cleanup_xp_upcallset = 21,
    VT_cleanup_xp_snd_cnt = 22,
    VT_cleanup_xp_snt_cnt = 23,
    VT_cleanup_xp_dontrcv = 24,
    VT_cleanup_xp_tls = 25,
    VT_cleanup_xp_sslsec = 26,
    VT_cleanup_xp_sslusec = 27,
    VT_cleanup_xp_sslrefno = 28,
    VT_cleanup_xp_sslproc = 29,
    VT_cleanup_xp_ngrps = 30,
    VT_cleanup_xp_uid = 31,
    VT_cleanup_xp_gidp = 32,
    VT_cleanup_xp_doneddp = 33,
    VT_cleanup_NUM_COLUMNS
};

static int
copy_columns(struct cleanup *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_cleanup_xp_refs] = new_osdb_int64(curEntry->xp_refs, context);
//    columns[VT_cleanup_xp_lock] =  TODO: Handle other types
//    columns[VT_cleanup_xp_pool] =  TODO: Handle other types
//    columns[VT_cleanup_xp_group] =  TODO: Handle other types
//    columns[VT_cleanup_xp_link] =  TODO: Handle other types
//    columns[VT_cleanup_xp_alink] =  TODO: Handle other types
    columns[VT_cleanup_xp_registered] = new_osdb_int64(curEntry->xp_registered, context);
    columns[VT_cleanup_xp_active] = new_osdb_int64(curEntry->xp_active, context);
//    columns[VT_cleanup_xp_thread] =  TODO: Handle other types
//    columns[VT_cleanup_xp_socket] =  TODO: Handle other types
//    columns[VT_cleanup_xp_ops] =  TODO: Handle other types
    columns[VT_cleanup_xp_netid] = new_osdb_text(curEntry->xp_netid, strlen(curEntry->xp_netid) + 1, context);
//    columns[VT_cleanup_xp_ltaddr] =  TODO: Handle other types
//    columns[VT_cleanup_xp_rtaddr] =  TODO: Handle other types
//    columns[VT_cleanup_xp_p1] =  TODO: Handle other types
//    columns[VT_cleanup_xp_p2] =  TODO: Handle other types
//    columns[VT_cleanup_xp_p3] =  TODO: Handle other types
    columns[VT_cleanup_xp_type] = new_osdb_int64(curEntry->xp_type, context);
    columns[VT_cleanup_xp_idletimeout] = new_osdb_int64(curEntry->xp_idletimeout, context);
    columns[VT_cleanup_xp_lastactive] = new_osdb_int64(curEntry->xp_lastactive, context);
    columns[VT_cleanup_xp_sockref] = new_osdb_int64(curEntry->xp_sockref, context);
    columns[VT_cleanup_xp_upcallset] = new_osdb_int64(curEntry->xp_upcallset, context);
    columns[VT_cleanup_xp_snd_cnt] = new_osdb_int64(curEntry->xp_snd_cnt, context);
    columns[VT_cleanup_xp_snt_cnt] = new_osdb_int64(curEntry->xp_snt_cnt, context);
    columns[VT_cleanup_xp_dontrcv] = new_osdb_int64(curEntry->xp_dontrcv, context);
    columns[VT_cleanup_xp_tls] = new_osdb_int64(curEntry->xp_tls, context);
    columns[VT_cleanup_xp_sslsec] = new_osdb_int64(curEntry->xp_sslsec, context);
    columns[VT_cleanup_xp_sslusec] = new_osdb_int64(curEntry->xp_sslusec, context);
    columns[VT_cleanup_xp_sslrefno] = new_osdb_int64(curEntry->xp_sslrefno, context);
    columns[VT_cleanup_xp_sslproc] = new_osdb_int64(curEntry->xp_sslproc, context);
    columns[VT_cleanup_xp_ngrps] = new_osdb_int64(curEntry->xp_ngrps, context);
    columns[VT_cleanup_xp_uid] = new_osdb_int64(curEntry->xp_uid, context);
//    columns[VT_cleanup_xp_gidp] =  TODO: Handle other types
    columns[VT_cleanup_xp_doneddp] = new_osdb_int64(curEntry->xp_doneddp, context);

    return 0;
}
void
vtab_svcxprt_list_lock(void)
{
    sx_slock(&cleanup_lock);
}

void
vtab_svcxprt_list_unlock(void)
{
    sx_sunlock(&cleanup_lock);
}

void
vtab_svcxprt_list_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct svcxprt_list *prc = LIST_FIRST(&cleanup);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_cleanup_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_cleanup_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("svcxprt_list digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_svcxprt_list_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_cleanup_PID];
    *pRowid = pid_value->int64_value;
    printf("svcxprt_list_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_svcxprt_list_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_svcxprt_list_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_svcxprt_list_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("svcxprt_list digest mismatch: UPDATE failed\n");
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
static sqlite3_module svcxprt_listvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ svcxprt_listvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ svcxprt_listvtabRowid,
    /* xUpdate     */ svcxprt_listvtabUpdate,
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
sqlite3_svcxprt_listvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &svcxprt_listvtabModule,
        pAux);
}
