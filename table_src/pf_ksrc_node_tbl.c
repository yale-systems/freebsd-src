#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/pf_ksrc_node.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_pf_ksrc_node.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_nodes_entry = 0,
    VT_nodes_addr = 1,
    VT_nodes_raddr = 2,
    VT_nodes_match_rules = 3,
    VT_nodes_rule = 4,
    VT_nodes_rkif = 5,
    VT_nodes_bytes = 6,
    VT_nodes_packets = 7,
    VT_nodes_states = 8,
    VT_nodes_conn = 9,
    VT_nodes_conn_rate = 10,
    VT_nodes_creation = 11,
    VT_nodes_expire = 12,
    VT_nodes_af = 13,
    VT_nodes_ruletype = 14,
    VT_nodes_lock = 15,
    VT_nodes_NUM_COLUMNS
};

static int
copy_columns(struct pf_ksrc_node *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_nodes_entry] =  /* Unsupported type */
//    columns[VT_nodes_addr] =  /* Unsupported type */
//    columns[VT_nodes_raddr] =  /* Unsupported type */
//    columns[VT_nodes_match_rules] =  /* Unsupported type */
//    columns[VT_nodes_rule] =  /* Unsupported type */
    columns[VT_nodes_rkif] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rkif, context);
//    columns[VT_nodes_bytes] =  /* Unsupported type */
//    columns[VT_nodes_packets] =  /* Unsupported type */
    columns[VT_nodes_states] = new_dbsc_int64(curEntry->states, context);
    columns[VT_nodes_conn] = new_dbsc_int64(curEntry->conn, context);
//    columns[VT_nodes_conn_rate] =  /* Unsupported type */
    columns[VT_nodes_creation] = new_dbsc_int64(curEntry->creation, context);
    columns[VT_nodes_expire] = new_dbsc_int64(curEntry->expire, context);
    columns[VT_nodes_af] = new_dbsc_int64(curEntry->af, context);
    columns[VT_nodes_ruletype] = new_dbsc_int64(curEntry->ruletype, context);
    columns[VT_nodes_lock] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lock, context);

    return 0;
}
void
vtab_pf_ksrc_node_lock(void)
{
    sx_slock(&nodes_lock);
}

void
vtab_pf_ksrc_node_unlock(void)
{
    sx_sunlock(&nodes_lock);
}

void
vtab_pf_ksrc_node_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pf_ksrc_node *prc = LIST_FIRST(&nodes);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_nodes_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_nodes_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pf_ksrc_node digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
pf_ksrc_nodevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_nodes_p_pid];
    *pRowid = pid_value->int64_value;
    printf("pf_ksrc_node_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
pf_ksrc_nodevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
pf_ksrc_nodevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pf_ksrc_node_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pf_ksrc_node digest mismatch: UPDATE failed\n");
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
static sqlite3_module pf_ksrc_nodevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pf_ksrc_nodevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pf_ksrc_nodevtabRowid,
    /* xUpdate     */ pf_ksrc_nodevtabUpdate,
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
sqlite3_pf_ksrc_nodevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pf_ksrc_nodevtabModule,
        pAux);
}
void vtab_pf_ksrc_node_serialize(sqlite3 *real_db, struct timespec when) {
    struct pf_ksrc_node *entry = LIST_FIRST(&nodes);

    const char *create_stmt =
        "CREATE TABLE all_pf_ksrc_nodes (states INTEGER, conn INTEGER, creation INTEGER, expire INTEGER, af INTEGER, ruletype INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_pf_ksrc_nodes VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->states);
           sqlite3_bind_int64(stmt, bindIndex++, entry->conn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->creation);
           sqlite3_bind_int64(stmt, bindIndex++, entry->expire);
           sqlite3_bind_int64(stmt, bindIndex++, entry->af);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ruletype);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

