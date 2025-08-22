#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/bcma_intr.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_bcma_intr.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_intrs_i_bank = 0,
    VT_intrs_i_sel = 1,
    VT_intrs_i_busline = 2,
    VT_intrs_i_mapped = 3,
    VT_intrs_i_rid = 4,
    VT_intrs_i_irq = 5,
    VT_intrs_i_link = 6,
    VT_intrs_NUM_COLUMNS
};

static int
copy_columns(struct bcma_intr *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_intrs_i_bank] = new_dbsc_int64(curEntry->i_bank, context);
    columns[VT_intrs_i_sel] = new_dbsc_int64(curEntry->i_sel, context);
    columns[VT_intrs_i_busline] = new_dbsc_int64(curEntry->i_busline, context);
    columns[VT_intrs_i_mapped] = new_dbsc_int64(curEntry->i_mapped, context);
    columns[VT_intrs_i_rid] = new_dbsc_int64(curEntry->i_rid, context);
    columns[VT_intrs_i_irq] = new_dbsc_int64(curEntry->i_irq, context);
//    columns[VT_intrs_i_link] =  /* Unsupported type */

    return 0;
}
void
vtab_bcma_intr_lock(void)
{
    sx_slock(&intrs_lock);
}

void
vtab_bcma_intr_unlock(void)
{
    sx_sunlock(&intrs_lock);
}

void
vtab_bcma_intr_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct bcma_intr *prc = LIST_FIRST(&intrs);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_intrs_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_intrs_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("bcma_intr digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
bcma_intrvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_intrs_p_pid];
    *pRowid = pid_value->int64_value;
    printf("bcma_intr_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
bcma_intrvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
bcma_intrvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_bcma_intr_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("bcma_intr digest mismatch: UPDATE failed\n");
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
static sqlite3_module bcma_intrvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ bcma_intrvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ bcma_intrvtabRowid,
    /* xUpdate     */ bcma_intrvtabUpdate,
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
sqlite3_bcma_intrvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &bcma_intrvtabModule,
        pAux);
}
void vtab_bcma_intr_serialize(sqlite3 *real_db, struct timespec when) {
    struct bcma_intr *entry = LIST_FIRST(&intrs);

    const char *create_stmt =
        "CREATE TABLE all_bcma_intrs (i_bank INTEGER, i_sel INTEGER, i_busline INTEGER, i_mapped INTEGER, i_rid INTEGER, i_irq INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_bcma_intrs VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->i_bank);
           sqlite3_bind_int64(stmt, bindIndex++, entry->i_sel);
           sqlite3_bind_int64(stmt, bindIndex++, entry->i_busline);
           sqlite3_bind_int64(stmt, bindIndex++, entry->i_mapped);
           sqlite3_bind_int64(stmt, bindIndex++, entry->i_rid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->i_irq);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

