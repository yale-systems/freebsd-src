#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/scb.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_scb.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_free_scbs_hscb = 0,
    VT_free_scbs_links = 1,
    VT_free_scbs_links2 = 2,
    VT_free_scbs_timedout_links = 3,
    VT_free_scbs_col_scb = 4,
    VT_free_scbs_io_ctx = 5,
    VT_free_scbs_ahd_softc = 6,
    VT_free_scbs_flags = 7,
    VT_free_scbs_dmamap = 8,
    VT_free_scbs_platform_data = 9,
    VT_free_scbs_hscb_map = 10,
    VT_free_scbs_sg_map = 11,
    VT_free_scbs_sense_map = 12,
    VT_free_scbs_sg_list = 13,
    VT_free_scbs_sense_data = 14,
    VT_free_scbs_sg_list_busaddr = 15,
    VT_free_scbs_sense_busaddr = 16,
    VT_free_scbs_sg_count = 17,
    VT_free_scbs_crc_retry_count = 18,
    VT_free_scbs_io_timer = 19,
    VT_free_scbs_NUM_COLUMNS
};

static int
copy_columns(struct scb *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_free_scbs_hscb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->hscb, context);
//    columns[VT_free_scbs_links] =  /* Unsupported type */
//    columns[VT_free_scbs_links2] =  /* Unsupported type */
//    columns[VT_free_scbs_timedout_links] =  /* Unsupported type */
    columns[VT_free_scbs_col_scb] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->col_scb, context);
    columns[VT_free_scbs_io_ctx] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->io_ctx, context);
    columns[VT_free_scbs_ahd_softc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ahd_softc, context);
    columns[VT_free_scbs_flags] = new_dbsc_int64((int64_t)(curEntry->flags), context); // TODO: need better enum representation 
    columns[VT_free_scbs_dmamap] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->dmamap, context);
    columns[VT_free_scbs_platform_data] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->platform_data, context);
    columns[VT_free_scbs_hscb_map] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->hscb_map, context);
    columns[VT_free_scbs_sg_map] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sg_map, context);
    columns[VT_free_scbs_sense_map] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sense_map, context);
    columns[VT_free_scbs_sg_list] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sg_list, context);
    columns[VT_free_scbs_sense_data] = new_dbsc_text(curEntry->sense_data, strlen(curEntry->sense_data) + 1, context);
    columns[VT_free_scbs_sg_list_busaddr] = new_dbsc_int64(curEntry->sg_list_busaddr, context);
    columns[VT_free_scbs_sense_busaddr] = new_dbsc_int64(curEntry->sense_busaddr, context);
    columns[VT_free_scbs_sg_count] = new_dbsc_int64(curEntry->sg_count, context);
    columns[VT_free_scbs_crc_retry_count] = new_dbsc_int64(curEntry->crc_retry_count, context);
//    columns[VT_free_scbs_io_timer] =  /* Unsupported type */

    return 0;
}
void
vtab_scb_lock(void)
{
    sx_slock(&free_scbs_lock);
}

void
vtab_scb_unlock(void)
{
    sx_sunlock(&free_scbs_lock);
}

void
vtab_scb_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct scb *prc = LIST_FIRST(&free_scbs);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_free_scbs_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_free_scbs_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("scb digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
scbvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_free_scbs_p_pid];
    *pRowid = pid_value->int64_value;
    printf("scb_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
scbvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
scbvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_scb_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("scb digest mismatch: UPDATE failed\n");
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
static sqlite3_module scbvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ scbvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ scbvtabRowid,
    /* xUpdate     */ scbvtabUpdate,
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
sqlite3_scbvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &scbvtabModule,
        pAux);
}
void vtab_scb_serialize(sqlite3 *real_db, struct timespec when) {
    struct scb *entry = LIST_FIRST(&free_scbs);

    const char *create_stmt =
        "CREATE TABLE all_scbs (flags INTEGER, sense_data TEXT, sg_list_busaddr INTEGER, sense_busaddr INTEGER, sg_count INTEGER, crc_retry_count INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_scbs VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_text(stmt, bindIndex++, entry->sense_data, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sg_list_busaddr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sense_busaddr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sg_count);
           sqlite3_bind_int64(stmt, bindIndex++, entry->crc_retry_count);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

