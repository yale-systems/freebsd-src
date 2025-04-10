#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cfg_redir.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cfg_redir.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_redir_chain__next = 0,
    VT_redir_chain_mode = 1,
    VT_redir_chain_proto = 2,
    VT_redir_chain_laddr = 3,
    VT_redir_chain_paddr = 4,
    VT_redir_chain_raddr = 5,
    VT_redir_chain_lport = 6,
    VT_redir_chain_pport = 7,
    VT_redir_chain_rport = 8,
    VT_redir_chain_pport_cnt = 9,
    VT_redir_chain_rport_cnt = 10,
    VT_redir_chain_alink = 11,
    VT_redir_chain_spool_cnt = 12,
    VT_redir_chain_spool_chain = 13,
    VT_redir_chain_NUM_COLUMNS
};

static int
copy_columns(struct cfg_redir *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_redir_chain__next] =  /* Unsupported type */
    columns[VT_redir_chain_mode] = new_dbsc_int64(curEntry->mode, context);
    columns[VT_redir_chain_proto] = new_dbsc_int64(curEntry->proto, context);
//    columns[VT_redir_chain_laddr] =  /* Unsupported type */
//    columns[VT_redir_chain_paddr] =  /* Unsupported type */
//    columns[VT_redir_chain_raddr] =  /* Unsupported type */
    columns[VT_redir_chain_lport] = new_dbsc_int64(curEntry->lport, context);
    columns[VT_redir_chain_pport] = new_dbsc_int64(curEntry->pport, context);
    columns[VT_redir_chain_rport] = new_dbsc_int64(curEntry->rport, context);
    columns[VT_redir_chain_pport_cnt] = new_dbsc_int64(curEntry->pport_cnt, context);
    columns[VT_redir_chain_rport_cnt] = new_dbsc_int64(curEntry->rport_cnt, context);
    columns[VT_redir_chain_alink] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->alink, context);
    columns[VT_redir_chain_spool_cnt] = new_dbsc_int64(curEntry->spool_cnt, context);
//    columns[VT_redir_chain_spool_chain] =  /* Unsupported type */

    return 0;
}
void
vtab_cfg_redir_lock(void)
{
    sx_slock(&redir_chain_lock);
}

void
vtab_cfg_redir_unlock(void)
{
    sx_sunlock(&redir_chain_lock);
}

void
vtab_cfg_redir_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cfg_redir *prc = LIST_FIRST(&redir_chain);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_redir_chain_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_redir_chain_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cfg_redir digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cfg_redirvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_redir_chain_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cfg_redir_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cfg_redirvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cfg_redirvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cfg_redir_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cfg_redir digest mismatch: UPDATE failed\n");
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
static sqlite3_module cfg_redirvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cfg_redirvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cfg_redirvtabRowid,
    /* xUpdate     */ cfg_redirvtabUpdate,
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
sqlite3_cfg_redirvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cfg_redirvtabModule,
        pAux);
}
void vtab_cfg_redir_serialize(sqlite3 *real_db, struct timespec when) {
    struct cfg_redir *entry = LIST_FIRST(&redir_chain);

    const char *create_stmt =
        "CREATE TABLE all_cfg_redirs (mode INTEGER, proto INTEGER, lport INTEGER, pport INTEGER, rport INTEGER, pport_cnt INTEGER, rport_cnt INTEGER, spool_cnt INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cfg_redirs VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->mode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->proto);
           sqlite3_bind_int64(stmt, bindIndex++, entry->lport);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pport);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rport);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pport_cnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rport_cnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->spool_cnt);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

