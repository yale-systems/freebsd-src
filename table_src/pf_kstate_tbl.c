#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/pf_kstate.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_pf_kstate.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_states_id = 0,
    VT_states_creatorid = 1,
    VT_states_direction = 2,
    VT_states_pad = 3,
    VT_states_state_flags = 4,
    VT_states_timeout = 5,
    VT_states_sync_state = 6,
    VT_states_sync_updates = 7,
    VT_states_refs = 8,
    VT_states_lock = 9,
    VT_states_sync_list = 10,
    VT_states_key_list = 11,
    VT_states_entry = 12,
    VT_states_src = 13,
    VT_states_dst = 14,
    VT_states_match_rules = 15,
    VT_states_rule = 16,
    VT_states_anchor = 17,
    VT_states_nat_rule = 18,
    VT_states_rt_addr = 19,
    VT_states_key = 20,
    VT_states_kif = 21,
    VT_states_orig_kif = 22,
    VT_states_rt_kif = 23,
    VT_states_src_node = 24,
    VT_states_nat_src_node = 25,
    VT_states_packets = 26,
    VT_states_bytes = 27,
    VT_states_creation = 28,
    VT_states_expire = 29,
    VT_states_pfsync_time = 30,
    VT_states_act = 31,
    VT_states_tag = 32,
    VT_states_rt = 33,
    VT_states_if_index_in = 34,
    VT_states_if_index_out = 35,
    VT_states_NUM_COLUMNS
};

static int
copy_columns(struct pf_kstate *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_states_id] = new_dbsc_int64(curEntry->id, context);
    columns[VT_states_creatorid] = new_dbsc_int64(curEntry->creatorid, context);
    columns[VT_states_direction] = new_dbsc_int64(curEntry->direction, context);
//    columns[VT_states_pad] =  /* Unsupported type */
    columns[VT_states_state_flags] = new_dbsc_int64(curEntry->state_flags, context);
    columns[VT_states_timeout] = new_dbsc_int64(curEntry->timeout, context);
    columns[VT_states_sync_state] = new_dbsc_int64(curEntry->sync_state, context);
    columns[VT_states_sync_updates] = new_dbsc_int64(curEntry->sync_updates, context);
    columns[VT_states_refs] = new_dbsc_int64(curEntry->refs, context);
    columns[VT_states_lock] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lock, context);
//    columns[VT_states_sync_list] =  /* Unsupported type */
//    columns[VT_states_key_list] =  /* Unsupported type */
//    columns[VT_states_entry] =  /* Unsupported type */
//    columns[VT_states_src] =  /* Unsupported type */
//    columns[VT_states_dst] =  /* Unsupported type */
//    columns[VT_states_match_rules] =  /* Unsupported type */
//    columns[VT_states_rule] =  /* Unsupported type */
//    columns[VT_states_anchor] =  /* Unsupported type */
//    columns[VT_states_nat_rule] =  /* Unsupported type */
//    columns[VT_states_rt_addr] =  /* Unsupported type */
//    columns[VT_states_key] =  /* Unsupported type */
    columns[VT_states_kif] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->kif, context);
    columns[VT_states_orig_kif] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->orig_kif, context);
    columns[VT_states_rt_kif] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->rt_kif, context);
    columns[VT_states_src_node] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->src_node, context);
    columns[VT_states_nat_src_node] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->nat_src_node, context);
//    columns[VT_states_packets] =  /* Unsupported type */
//    columns[VT_states_bytes] =  /* Unsupported type */
    columns[VT_states_creation] = new_dbsc_int64(curEntry->creation, context);
    columns[VT_states_expire] = new_dbsc_int64(curEntry->expire, context);
    columns[VT_states_pfsync_time] = new_dbsc_int64(curEntry->pfsync_time, context);
//    columns[VT_states_act] =  /* Unsupported type */
    columns[VT_states_tag] = new_dbsc_int64(curEntry->tag, context);
    columns[VT_states_rt] = new_dbsc_int64(curEntry->rt, context);
    columns[VT_states_if_index_in] = new_dbsc_int64(curEntry->if_index_in, context);
    columns[VT_states_if_index_out] = new_dbsc_int64(curEntry->if_index_out, context);

    return 0;
}
void
vtab_pf_kstate_lock(void)
{
    sx_slock(&states_lock);
}

void
vtab_pf_kstate_unlock(void)
{
    sx_sunlock(&states_lock);
}

void
vtab_pf_kstate_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pf_kstate *prc = LIST_FIRST(&states);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_states_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_states_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pf_kstate digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
pf_kstatevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_states_p_pid];
    *pRowid = pid_value->int64_value;
    printf("pf_kstate_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
pf_kstatevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
pf_kstatevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pf_kstate_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pf_kstate digest mismatch: UPDATE failed\n");
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
static sqlite3_module pf_kstatevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pf_kstatevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pf_kstatevtabRowid,
    /* xUpdate     */ pf_kstatevtabUpdate,
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
sqlite3_pf_kstatevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pf_kstatevtabModule,
        pAux);
}
void vtab_pf_kstate_serialize(sqlite3 *real_db, struct timespec when) {
    struct pf_kstate *entry = LIST_FIRST(&states);

    const char *create_stmt =
        "CREATE TABLE all_pf_kstates (id INTEGER, creatorid INTEGER, direction INTEGER, state_flags INTEGER, timeout INTEGER, sync_state INTEGER, sync_updates INTEGER, refs INTEGER, creation INTEGER, expire INTEGER, pfsync_time INTEGER, tag INTEGER, rt INTEGER, if_index_in INTEGER, if_index_out INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_pf_kstates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->id);
           sqlite3_bind_int64(stmt, bindIndex++, entry->creatorid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->direction);
           sqlite3_bind_int64(stmt, bindIndex++, entry->state_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sync_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sync_updates);
           sqlite3_bind_int64(stmt, bindIndex++, entry->refs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->creation);
           sqlite3_bind_int64(stmt, bindIndex++, entry->expire);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pfsync_time);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->if_index_in);
           sqlite3_bind_int64(stmt, bindIndex++, entry->if_index_out);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

