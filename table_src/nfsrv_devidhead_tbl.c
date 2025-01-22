#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_nfsrv_devidhead_nfsdev_list = 0,
    VT_nfsrv_devidhead_nfsdev_dvp = 1,
    VT_nfsrv_devidhead_nfsdev_nmp = 2,
    VT_nfsrv_devidhead_nfsdev_deviceid = 3,
    VT_nfsrv_devidhead_nfsdev_hostnamelen = 4,
    VT_nfsrv_devidhead_nfsdev_fileaddrlen = 5,
    VT_nfsrv_devidhead_nfsdev_flexaddrlen = 6,
    VT_nfsrv_devidhead_nfsdev_mdsisset = 7,
    VT_nfsrv_devidhead_nfsdev_fileaddr = 8,
    VT_nfsrv_devidhead_nfsdev_flexaddr = 9,
    VT_nfsrv_devidhead_nfsdev_host = 10,
    VT_nfsrv_devidhead_nfsdev_mdsfsid = 11,
    VT_nfsrv_devidhead_nfsdev_nextdir = 12,
    VT_nfsrv_devidhead_nfsdev_nospc = 13,
    VT_nfsrv_devidhead_nfsdev_dsdir = 14,
    VT_nfsrv_devidhead_NUM_COLUMNS
};

static int
copy_columns(struct nfsrv_devidhead *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_nfsrv_devidhead_nfsdev_list] =  TODO: Handle other types
//    columns[VT_nfsrv_devidhead_nfsdev_dvp] =  TODO: Handle other types
//    columns[VT_nfsrv_devidhead_nfsdev_nmp] =  TODO: Handle other types
//    columns[VT_nfsrv_devidhead_nfsdev_deviceid] =  TODO: Handle other types
    columns[VT_nfsrv_devidhead_nfsdev_hostnamelen] = new_osdb_int64(curEntry->nfsdev_hostnamelen, context);
    columns[VT_nfsrv_devidhead_nfsdev_fileaddrlen] = new_osdb_int64(curEntry->nfsdev_fileaddrlen, context);
    columns[VT_nfsrv_devidhead_nfsdev_flexaddrlen] = new_osdb_int64(curEntry->nfsdev_flexaddrlen, context);
    columns[VT_nfsrv_devidhead_nfsdev_mdsisset] = new_osdb_int64(curEntry->nfsdev_mdsisset, context);
    columns[VT_nfsrv_devidhead_nfsdev_fileaddr] = new_osdb_text(curEntry->nfsdev_fileaddr, strlen(curEntry->nfsdev_fileaddr) + 1, context);
    columns[VT_nfsrv_devidhead_nfsdev_flexaddr] = new_osdb_text(curEntry->nfsdev_flexaddr, strlen(curEntry->nfsdev_flexaddr) + 1, context);
    columns[VT_nfsrv_devidhead_nfsdev_host] = new_osdb_text(curEntry->nfsdev_host, strlen(curEntry->nfsdev_host) + 1, context);
//    columns[VT_nfsrv_devidhead_nfsdev_mdsfsid] =  TODO: Handle other types
    columns[VT_nfsrv_devidhead_nfsdev_nextdir] = new_osdb_int64(curEntry->nfsdev_nextdir, context);
    columns[VT_nfsrv_devidhead_nfsdev_nospc] = new_osdb_int64(curEntry->nfsdev_nospc, context);
//    columns[VT_nfsrv_devidhead_nfsdev_dsdir] =  TODO: Handle other types

    return 0;
}
void
vtab_nfsdevicehead_lock(void)
{
    sx_slock(&nfsrv_devidhead_lock);
}

void
vtab_nfsdevicehead_unlock(void)
{
    sx_sunlock(&nfsrv_devidhead_lock);
}

void
vtab_nfsdevicehead_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct nfsdevicehead *prc = LIST_FIRST(&nfsrv_devidhead);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_nfsrv_devidhead_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_nfsrv_devidhead_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("nfsdevicehead digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_nfsdevicehead_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_nfsrv_devidhead_PID];
    *pRowid = pid_value->int64_value;
    printf("nfsdevicehead_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_nfsdevicehead_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_nfsdevicehead_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_nfsdevicehead_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("nfsdevicehead digest mismatch: UPDATE failed\n");
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
static sqlite3_module nfsdeviceheadvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ nfsdeviceheadvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ nfsdeviceheadvtabRowid,
    /* xUpdate     */ nfsdeviceheadvtabUpdate,
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
sqlite3_nfsdeviceheadvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &nfsdeviceheadvtabModule,
        pAux);
}
