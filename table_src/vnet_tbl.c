#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/vnet.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_vnet.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_vnet_head_vnet_le = 0,
    VT_vnet_head_vnet_magic_n = 1,
    VT_vnet_head_vnet_ifcnt = 2,
    VT_vnet_head_vnet_sockcnt = 3,
    VT_vnet_head_vnet_state = 4,
    VT_vnet_head_vnet_data_mem = 5,
    VT_vnet_head_vnet_data_base = 6,
    VT_vnet_head_vnet_shutdown = 7,
    VT_vnet_head_NUM_COLUMNS
};

static int
copy_columns(struct vnet *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vnet_head_vnet_le] =  /* Unsupported type */
    columns[VT_vnet_head_vnet_magic_n] = new_dbsc_int64(curEntry->vnet_magic_n, context);
    columns[VT_vnet_head_vnet_ifcnt] = new_dbsc_int64(curEntry->vnet_ifcnt, context);
    columns[VT_vnet_head_vnet_sockcnt] = new_dbsc_int64(curEntry->vnet_sockcnt, context);
    columns[VT_vnet_head_vnet_state] = new_dbsc_int64(curEntry->vnet_state, context);
    columns[VT_vnet_head_vnet_data_mem] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vnet_data_mem, context);
    columns[VT_vnet_head_vnet_data_base] = new_dbsc_int64(curEntry->vnet_data_base, context);
    columns[VT_vnet_head_vnet_shutdown] = new_dbsc_int64(curEntry->vnet_shutdown, context);

    return 0;
}
void
vtab_vnet_lock(void)
{
    sx_slock(&vnet_head_lock);
}

void
vtab_vnet_unlock(void)
{
    sx_sunlock(&vnet_head_lock);
}

void
vtab_vnet_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct vnet *prc = LIST_FIRST(&vnet_head);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_head_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_vnet_head_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("vnet digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vnetvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_vnet_head_p_pid];
    *pRowid = pid_value->int64_value;
    printf("vnet_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vnetvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
vnetvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_vnet_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("vnet digest mismatch: UPDATE failed\n");
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
static sqlite3_module vnetvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vnetvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vnetvtabRowid,
    /* xUpdate     */ vnetvtabUpdate,
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
sqlite3_vnetvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vnetvtabModule,
        pAux);
}
void vtab_vnet_serialize(sqlite3 *real_db, struct timespec when) {
    struct vnet *entry = LIST_FIRST(&vnet_head);

    const char *create_stmt =
        "CREATE TABLE all_vnets (vnet_magic_n INTEGER, vnet_ifcnt INTEGER, vnet_sockcnt INTEGER, vnet_state INTEGER, vnet_data_base INTEGER, vnet_shutdown INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_vnets VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->vnet_magic_n);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vnet_ifcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vnet_sockcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vnet_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vnet_data_base);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vnet_shutdown);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

