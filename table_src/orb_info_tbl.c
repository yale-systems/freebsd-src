#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/orb_info.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_orb_info.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_orbs_sc = 0,
    VT_orbs_fwdev = 1,
    VT_orbs_login = 2,
    VT_orbs_ccb = 3,
    VT_orbs_atio = 4,
    VT_orbs_state = 5,
    VT_orbs_refcount = 6,
    VT_orbs_orb_hi = 7,
    VT_orbs_orb_lo = 8,
    VT_orbs_data_hi = 9,
    VT_orbs_data_lo = 10,
    VT_orbs_orb4 = 11,
    VT_orbs_link = 12,
    VT_orbs_orb = 13,
    VT_orbs_page_table = 14,
    VT_orbs_cur_pte = 15,
    VT_orbs_last_pte = 16,
    VT_orbs_last_block_read = 17,
    VT_orbs_status = 18,
    VT_orbs_NUM_COLUMNS
};

static int
copy_columns(struct orb_info *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_orbs_sc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sc, context);
    columns[VT_orbs_fwdev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->fwdev, context);
    columns[VT_orbs_login] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->login, context);
    columns[VT_orbs_ccb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ccb, context);
    columns[VT_orbs_atio] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->atio, context);
    columns[VT_orbs_state] = new_dbsc_int64(curEntry->state, context);
    columns[VT_orbs_refcount] = new_dbsc_int64(curEntry->refcount, context);
    columns[VT_orbs_orb_hi] = new_dbsc_int64(curEntry->orb_hi, context);
    columns[VT_orbs_orb_lo] = new_dbsc_int64(curEntry->orb_lo, context);
    columns[VT_orbs_data_hi] = new_dbsc_int64(curEntry->data_hi, context);
    columns[VT_orbs_data_lo] = new_dbsc_int64(curEntry->data_lo, context);
//    columns[VT_orbs_orb4] =  /* Unsupported type */
//    columns[VT_orbs_link] =  /* Unsupported type */
//    columns[VT_orbs_orb] =  /* Unsupported type */
    columns[VT_orbs_page_table] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->page_table, context);
    columns[VT_orbs_cur_pte] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->cur_pte, context);
    columns[VT_orbs_last_pte] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->last_pte, context);
    columns[VT_orbs_last_block_read] = new_dbsc_int64(curEntry->last_block_read, context);
//    columns[VT_orbs_status] =  /* Unsupported type */

    return 0;
}
void
vtab_orb_info_lock(void)
{
    sx_slock(&orbs_lock);
}

void
vtab_orb_info_unlock(void)
{
    sx_sunlock(&orbs_lock);
}

void
vtab_orb_info_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct orb_info *prc = LIST_FIRST(&orbs);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_orbs_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_orbs_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("orb_info digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
orb_infovtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_orbs_p_pid];
    *pRowid = pid_value->int64_value;
    printf("orb_info_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
orb_infovtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
orb_infovtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_orb_info_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("orb_info digest mismatch: UPDATE failed\n");
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
static sqlite3_module orb_infovtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ orb_infovtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ orb_infovtabRowid,
    /* xUpdate     */ orb_infovtabUpdate,
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
sqlite3_orb_infovtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &orb_infovtabModule,
        pAux);
}
void vtab_orb_info_serialize(sqlite3 *real_db, struct timespec when) {
    struct orb_info *entry = LIST_FIRST(&orbs);

    const char *create_stmt =
        "CREATE TABLE all_orb_infos (state INTEGER, refcount INTEGER, orb_hi INTEGER, orb_lo INTEGER, data_hi INTEGER, data_lo INTEGER, last_block_read INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_orb_infos VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->refcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->orb_hi);
           sqlite3_bind_int64(stmt, bindIndex++, entry->orb_lo);
           sqlite3_bind_int64(stmt, bindIndex++, entry->data_hi);
           sqlite3_bind_int64(stmt, bindIndex++, entry->data_lo);
           sqlite3_bind_int64(stmt, bindIndex++, entry->last_block_read);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

