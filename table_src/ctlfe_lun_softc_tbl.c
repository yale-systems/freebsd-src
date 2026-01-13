#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ctlfe_lun_softc.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ctlfe_lun_softc.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_lun_softc_list_parent_softc = 0,
    VT_lun_softc_list_periph = 1,
    VT_lun_softc_list_flags = 2,
    VT_lun_softc_list_ctios_sent = 3,
    VT_lun_softc_list_refcount = 4,
    VT_lun_softc_list_atios_alloced = 5,
    VT_lun_softc_list_inots_alloced = 6,
    VT_lun_softc_list_refdrain_task = 7,
    VT_lun_softc_list_work_queue = 8,
    VT_lun_softc_list_atio_list = 9,
    VT_lun_softc_list_inot_list = 10,
    VT_lun_softc_list_links = 11,
    VT_lun_softc_list_NUM_COLUMNS
};

static int
copy_columns(struct ctlfe_lun_softc *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_lun_softc_list_parent_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->parent_softc, context);
    columns[VT_lun_softc_list_periph] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->periph, context);
    columns[VT_lun_softc_list_flags] = new_dbsc_int64((int64_t)(curEntry->flags), context); // TODO: need better enum representation 
    columns[VT_lun_softc_list_ctios_sent] = new_dbsc_int64(curEntry->ctios_sent, context);
    columns[VT_lun_softc_list_refcount] = new_dbsc_int64(curEntry->refcount, context);
    columns[VT_lun_softc_list_atios_alloced] = new_dbsc_int64(curEntry->atios_alloced, context);
    columns[VT_lun_softc_list_inots_alloced] = new_dbsc_int64(curEntry->inots_alloced, context);
//    columns[VT_lun_softc_list_refdrain_task] =  /* Unsupported type */
//    columns[VT_lun_softc_list_work_queue] =  /* Unsupported type */
//    columns[VT_lun_softc_list_atio_list] =  /* Unsupported type */
//    columns[VT_lun_softc_list_inot_list] =  /* Unsupported type */
//    columns[VT_lun_softc_list_links] =  /* Unsupported type */

    return 0;
}
void
vtab_ctlfe_lun_softc_lock(void)
{
    sx_slock(&lun_softc_list_lock);
}

void
vtab_ctlfe_lun_softc_unlock(void)
{
    sx_sunlock(&lun_softc_list_lock);
}

void
vtab_ctlfe_lun_softc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ctlfe_lun_softc *prc = LIST_FIRST(&lun_softc_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_lun_softc_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_lun_softc_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ctlfe_lun_softc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ctlfe_lun_softcvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_lun_softc_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ctlfe_lun_softc_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ctlfe_lun_softcvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ctlfe_lun_softcvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ctlfe_lun_softc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ctlfe_lun_softc digest mismatch: UPDATE failed\n");
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
static sqlite3_module ctlfe_lun_softcvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ctlfe_lun_softcvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ctlfe_lun_softcvtabRowid,
    /* xUpdate     */ ctlfe_lun_softcvtabUpdate,
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
sqlite3_ctlfe_lun_softcvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ctlfe_lun_softcvtabModule,
        pAux);
}
void vtab_ctlfe_lun_softc_serialize(sqlite3 *real_db, struct timespec when) {
    struct ctlfe_lun_softc *entry = LIST_FIRST(&lun_softc_list);

    const char *create_stmt =
        "CREATE TABLE all_ctlfe_lun_softcs (flags INTEGER, ctios_sent INTEGER, refcount INTEGER, atios_alloced INTEGER, inots_alloced INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ctlfe_lun_softcs VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ctios_sent);
           sqlite3_bind_int64(stmt, bindIndex++, entry->refcount);
           sqlite3_bind_int64(stmt, bindIndex++, entry->atios_alloced);
           sqlite3_bind_int64(stmt, bindIndex++, entry->inots_alloced);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

