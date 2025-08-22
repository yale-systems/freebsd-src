#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/fw_xfer.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_fw_xfer.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_q_sc = 0,
    VT_q_fc = 1,
    VT_q_q = 2,
    VT_q_tv = 3,
    VT_q_resp = 4,
    VT_q_flag = 5,
    VT_q_tl = 6,
    VT_q_hand = 7,
    VT_q_send = 8,
    VT_q_recv = 9,
    VT_q_mbuf = 10,
    VT_q_link = 11,
    VT_q_tlabel = 12,
    VT_q_malloc = 13,
    VT_q_NUM_COLUMNS
};

static int
copy_columns(struct fw_xfer *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_q_sc] = new_dbsc_text(curEntry->sc, strlen(curEntry->sc) + 1, context);
    columns[VT_q_fc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->fc, context);
    columns[VT_q_q] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->q, context);
//    columns[VT_q_tv] =  /* Unsupported type */
    columns[VT_q_resp] = new_dbsc_int64(curEntry->resp, context);
    columns[VT_q_flag] = new_dbsc_int64(curEntry->flag, context);
    columns[VT_q_tl] = new_dbsc_int64(curEntry->tl, context);
    columns[VT_q_hand] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->hand, context);
//    columns[VT_q_send] =  /* Unsupported type */
//    columns[VT_q_recv] =  /* Unsupported type */
    columns[VT_q_mbuf] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->mbuf, context);
//    columns[VT_q_link] =  /* Unsupported type */
//    columns[VT_q_tlabel] =  /* Unsupported type */
    columns[VT_q_malloc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->malloc, context);

    return 0;
}
void
vtab_fw_xfer_lock(void)
{
    sx_slock(&q_lock);
}

void
vtab_fw_xfer_unlock(void)
{
    sx_sunlock(&q_lock);
}

void
vtab_fw_xfer_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct fw_xfer *prc = LIST_FIRST(&q);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_q_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_q_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("fw_xfer digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
fw_xfervtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_q_p_pid];
    *pRowid = pid_value->int64_value;
    printf("fw_xfer_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
fw_xfervtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
fw_xfervtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_fw_xfer_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("fw_xfer digest mismatch: UPDATE failed\n");
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
static sqlite3_module fw_xfervtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ fw_xfervtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ fw_xfervtabRowid,
    /* xUpdate     */ fw_xfervtabUpdate,
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
sqlite3_fw_xfervtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &fw_xfervtabModule,
        pAux);
}
void vtab_fw_xfer_serialize(sqlite3 *real_db, struct timespec when) {
    struct fw_xfer *entry = LIST_FIRST(&q);

    const char *create_stmt =
        "CREATE TABLE all_fw_xfers (sc TEXT, resp INTEGER, flag INTEGER, tl INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_fw_xfers VALUES (?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->sc, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->resp);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tl);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

