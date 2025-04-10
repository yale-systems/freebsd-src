#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/pf_krule.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_pf_krule.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_vnet_entry_pf_unlinked_rules_src = 0,
    VT_vnet_entry_pf_unlinked_rules_dst = 1,
    VT_vnet_entry_pf_unlinked_rules_skip = 2,
    VT_vnet_entry_pf_unlinked_rules_label = 3,
    VT_vnet_entry_pf_unlinked_rules_ridentifier = 4,
    VT_vnet_entry_pf_unlinked_rules_ifname = 5,
    VT_vnet_entry_pf_unlinked_rules_qname = 6,
    VT_vnet_entry_pf_unlinked_rules_pqname = 7,
    VT_vnet_entry_pf_unlinked_rules_tagname = 8,
    VT_vnet_entry_pf_unlinked_rules_match_tagname = 9,
    VT_vnet_entry_pf_unlinked_rules_overload_tblname = 10,
    VT_vnet_entry_pf_unlinked_rules_entries = 11,
    VT_vnet_entry_pf_unlinked_rules_rpool = 12,
    VT_vnet_entry_pf_unlinked_rules_evaluations = 13,
    VT_vnet_entry_pf_unlinked_rules_packets = 14,
    VT_vnet_entry_pf_unlinked_rules_bytes = 15,
    VT_vnet_entry_pf_unlinked_rules_timestamp = 16,
    VT_vnet_entry_pf_unlinked_rules_kif = 17,
    VT_vnet_entry_pf_unlinked_rules_anchor = 18,
    VT_vnet_entry_pf_unlinked_rules_overload_tbl = 19,
    VT_vnet_entry_pf_unlinked_rules_os_fingerprint = 20,
    VT_vnet_entry_pf_unlinked_rules_rtableid = 21,
    VT_vnet_entry_pf_unlinked_rules_timeout = 22,
    VT_vnet_entry_pf_unlinked_rules_max_states = 23,
    VT_vnet_entry_pf_unlinked_rules_max_src_nodes = 24,
    VT_vnet_entry_pf_unlinked_rules_max_src_states = 25,
    VT_vnet_entry_pf_unlinked_rules_max_src_conn = 26,
    VT_vnet_entry_pf_unlinked_rules_max_src_conn_rate = 27,
    VT_vnet_entry_pf_unlinked_rules_qid = 28,
    VT_vnet_entry_pf_unlinked_rules_pqid = 29,
    VT_vnet_entry_pf_unlinked_rules_dnpipe = 30,
    VT_vnet_entry_pf_unlinked_rules_dnrpipe = 31,
    VT_vnet_entry_pf_unlinked_rules_free_flags = 32,
    VT_vnet_entry_pf_unlinked_rules_nr = 33,
    VT_vnet_entry_pf_unlinked_rules_prob = 34,
    VT_vnet_entry_pf_unlinked_rules_cuid = 35,
    VT_vnet_entry_pf_unlinked_rules_cpid = 36,
    VT_vnet_entry_pf_unlinked_rules_states_cur = 37,
    VT_vnet_entry_pf_unlinked_rules_states_tot = 38,
    VT_vnet_entry_pf_unlinked_rules_src_nodes = 39,
    VT_vnet_entry_pf_unlinked_rules_return_icmp = 40,
    VT_vnet_entry_pf_unlinked_rules_return_icmp6 = 41,
    VT_vnet_entry_pf_unlinked_rules_max_mss = 42,
    VT_vnet_entry_pf_unlinked_rules_tag = 43,
    VT_vnet_entry_pf_unlinked_rules_match_tag = 44,
    VT_vnet_entry_pf_unlinked_rules_scrub_flags = 45,
    VT_vnet_entry_pf_unlinked_rules_uid = 46,
    VT_vnet_entry_pf_unlinked_rules_gid = 47,
    VT_vnet_entry_pf_unlinked_rules_rule_flag = 48,
    VT_vnet_entry_pf_unlinked_rules_rule_ref = 49,
    VT_vnet_entry_pf_unlinked_rules_action = 50,
    VT_vnet_entry_pf_unlinked_rules_direction = 51,
    VT_vnet_entry_pf_unlinked_rules_log = 52,
    VT_vnet_entry_pf_unlinked_rules_logif = 53,
    VT_vnet_entry_pf_unlinked_rules_quick = 54,
    VT_vnet_entry_pf_unlinked_rules_ifnot = 55,
    VT_vnet_entry_pf_unlinked_rules_match_tag_not = 56,
    VT_vnet_entry_pf_unlinked_rules_natpass = 57,
    VT_vnet_entry_pf_unlinked_rules_keep_state = 58,
    VT_vnet_entry_pf_unlinked_rules_af = 59,
    VT_vnet_entry_pf_unlinked_rules_proto = 60,
    VT_vnet_entry_pf_unlinked_rules_type = 61,
    VT_vnet_entry_pf_unlinked_rules_code = 62,
    VT_vnet_entry_pf_unlinked_rules_flags = 63,
    VT_vnet_entry_pf_unlinked_rules_flagset = 64,
    VT_vnet_entry_pf_unlinked_rules_min_ttl = 65,
    VT_vnet_entry_pf_unlinked_rules_allow_opts = 66,
    VT_vnet_entry_pf_unlinked_rules_rt = 67,
    VT_vnet_entry_pf_unlinked_rules_return_ttl = 68,
    VT_vnet_entry_pf_unlinked_rules_tos = 69,
    VT_vnet_entry_pf_unlinked_rules_set_tos = 70,
    VT_vnet_entry_pf_unlinked_rules_anchor_relative = 71,
    VT_vnet_entry_pf_unlinked_rules_anchor_wildcard = 72,
    VT_vnet_entry_pf_unlinked_rules_flush = 73,
    VT_vnet_entry_pf_unlinked_rules_prio = 74,
    VT_vnet_entry_pf_unlinked_rules_set_prio = 75,
    VT_vnet_entry_pf_unlinked_rules_divert = 76,
    VT_vnet_entry_pf_unlinked_rules_md5sum = 77,
    VT_vnet_entry_pf_unlinked_rules_entry_global = 78,
    VT_vnet_entry_pf_unlinked_rules_NUM_COLUMNS
};

static int
copy_columns(struct pf_krule *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vnet_entry_pf_unlinked_rules_src] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_dst] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_skip] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_label] =  /* Unsupported type */
    columns[VT_vnet_entry_pf_unlinked_rules_ridentifier] = new_dbsc_int64(curEntry->ridentifier, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_ifname] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_qname] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_pqname] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_tagname] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_match_tagname] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_overload_tblname] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_entries] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_rpool] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_evaluations] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_packets] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_bytes] =  /* Unsupported type */
    columns[VT_vnet_entry_pf_unlinked_rules_timestamp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->timestamp, context);
    columns[VT_vnet_entry_pf_unlinked_rules_kif] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->kif, context);
    columns[VT_vnet_entry_pf_unlinked_rules_anchor] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->anchor, context);
    columns[VT_vnet_entry_pf_unlinked_rules_overload_tbl] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->overload_tbl, context);
    columns[VT_vnet_entry_pf_unlinked_rules_os_fingerprint] = new_dbsc_int64(curEntry->os_fingerprint, context);
    columns[VT_vnet_entry_pf_unlinked_rules_rtableid] = new_dbsc_int64(curEntry->rtableid, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_timeout] =  /* Unsupported type */
    columns[VT_vnet_entry_pf_unlinked_rules_max_states] = new_dbsc_int64(curEntry->max_states, context);
    columns[VT_vnet_entry_pf_unlinked_rules_max_src_nodes] = new_dbsc_int64(curEntry->max_src_nodes, context);
    columns[VT_vnet_entry_pf_unlinked_rules_max_src_states] = new_dbsc_int64(curEntry->max_src_states, context);
    columns[VT_vnet_entry_pf_unlinked_rules_max_src_conn] = new_dbsc_int64(curEntry->max_src_conn, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_max_src_conn_rate] =  /* Unsupported type */
    columns[VT_vnet_entry_pf_unlinked_rules_qid] = new_dbsc_int64(curEntry->qid, context);
    columns[VT_vnet_entry_pf_unlinked_rules_pqid] = new_dbsc_int64(curEntry->pqid, context);
    columns[VT_vnet_entry_pf_unlinked_rules_dnpipe] = new_dbsc_int64(curEntry->dnpipe, context);
    columns[VT_vnet_entry_pf_unlinked_rules_dnrpipe] = new_dbsc_int64(curEntry->dnrpipe, context);
    columns[VT_vnet_entry_pf_unlinked_rules_free_flags] = new_dbsc_int64(curEntry->free_flags, context);
    columns[VT_vnet_entry_pf_unlinked_rules_nr] = new_dbsc_int64(curEntry->nr, context);
    columns[VT_vnet_entry_pf_unlinked_rules_prob] = new_dbsc_int64(curEntry->prob, context);
    columns[VT_vnet_entry_pf_unlinked_rules_cuid] = new_dbsc_int64(curEntry->cuid, context);
    columns[VT_vnet_entry_pf_unlinked_rules_cpid] = new_dbsc_int64(curEntry->cpid, context);
    columns[VT_vnet_entry_pf_unlinked_rules_states_cur] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->states_cur, context);
    columns[VT_vnet_entry_pf_unlinked_rules_states_tot] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->states_tot, context);
    columns[VT_vnet_entry_pf_unlinked_rules_src_nodes] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->src_nodes, context);
    columns[VT_vnet_entry_pf_unlinked_rules_return_icmp] = new_dbsc_int64(curEntry->return_icmp, context);
    columns[VT_vnet_entry_pf_unlinked_rules_return_icmp6] = new_dbsc_int64(curEntry->return_icmp6, context);
    columns[VT_vnet_entry_pf_unlinked_rules_max_mss] = new_dbsc_int64(curEntry->max_mss, context);
    columns[VT_vnet_entry_pf_unlinked_rules_tag] = new_dbsc_int64(curEntry->tag, context);
    columns[VT_vnet_entry_pf_unlinked_rules_match_tag] = new_dbsc_int64(curEntry->match_tag, context);
    columns[VT_vnet_entry_pf_unlinked_rules_scrub_flags] = new_dbsc_int64(curEntry->scrub_flags, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_uid] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_gid] =  /* Unsupported type */
    columns[VT_vnet_entry_pf_unlinked_rules_rule_flag] = new_dbsc_int64(curEntry->rule_flag, context);
    columns[VT_vnet_entry_pf_unlinked_rules_rule_ref] = new_dbsc_int64(curEntry->rule_ref, context);
    columns[VT_vnet_entry_pf_unlinked_rules_action] = new_dbsc_int64(curEntry->action, context);
    columns[VT_vnet_entry_pf_unlinked_rules_direction] = new_dbsc_int64(curEntry->direction, context);
    columns[VT_vnet_entry_pf_unlinked_rules_log] = new_dbsc_int64(curEntry->log, context);
    columns[VT_vnet_entry_pf_unlinked_rules_logif] = new_dbsc_int64(curEntry->logif, context);
    columns[VT_vnet_entry_pf_unlinked_rules_quick] = new_dbsc_int64(curEntry->quick, context);
    columns[VT_vnet_entry_pf_unlinked_rules_ifnot] = new_dbsc_int64(curEntry->ifnot, context);
    columns[VT_vnet_entry_pf_unlinked_rules_match_tag_not] = new_dbsc_int64(curEntry->match_tag_not, context);
    columns[VT_vnet_entry_pf_unlinked_rules_natpass] = new_dbsc_int64(curEntry->natpass, context);
    columns[VT_vnet_entry_pf_unlinked_rules_keep_state] = new_dbsc_int64(curEntry->keep_state, context);
    columns[VT_vnet_entry_pf_unlinked_rules_af] = new_dbsc_int64(curEntry->af, context);
    columns[VT_vnet_entry_pf_unlinked_rules_proto] = new_dbsc_int64(curEntry->proto, context);
    columns[VT_vnet_entry_pf_unlinked_rules_type] = new_dbsc_int64(curEntry->type, context);
    columns[VT_vnet_entry_pf_unlinked_rules_code] = new_dbsc_int64(curEntry->code, context);
    columns[VT_vnet_entry_pf_unlinked_rules_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_vnet_entry_pf_unlinked_rules_flagset] = new_dbsc_int64(curEntry->flagset, context);
    columns[VT_vnet_entry_pf_unlinked_rules_min_ttl] = new_dbsc_int64(curEntry->min_ttl, context);
    columns[VT_vnet_entry_pf_unlinked_rules_allow_opts] = new_dbsc_int64(curEntry->allow_opts, context);
    columns[VT_vnet_entry_pf_unlinked_rules_rt] = new_dbsc_int64(curEntry->rt, context);
    columns[VT_vnet_entry_pf_unlinked_rules_return_ttl] = new_dbsc_int64(curEntry->return_ttl, context);
    columns[VT_vnet_entry_pf_unlinked_rules_tos] = new_dbsc_int64(curEntry->tos, context);
    columns[VT_vnet_entry_pf_unlinked_rules_set_tos] = new_dbsc_int64(curEntry->set_tos, context);
    columns[VT_vnet_entry_pf_unlinked_rules_anchor_relative] = new_dbsc_int64(curEntry->anchor_relative, context);
    columns[VT_vnet_entry_pf_unlinked_rules_anchor_wildcard] = new_dbsc_int64(curEntry->anchor_wildcard, context);
    columns[VT_vnet_entry_pf_unlinked_rules_flush] = new_dbsc_int64(curEntry->flush, context);
    columns[VT_vnet_entry_pf_unlinked_rules_prio] = new_dbsc_int64(curEntry->prio, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_set_prio] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_divert] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_md5sum] =  /* Unsupported type */
//    columns[VT_vnet_entry_pf_unlinked_rules_entry_global] =  /* Unsupported type */

    return 0;
}
void
vtab_pf_krule_lock(void)
{
    sx_slock(&vnet_entry_pf_unlinked_rules_lock);
}

void
vtab_pf_krule_unlock(void)
{
    sx_sunlock(&vnet_entry_pf_unlinked_rules_lock);
}

void
vtab_pf_krule_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pf_krule *prc = LIST_FIRST(&vnet_entry_pf_unlinked_rules);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_pf_unlinked_rules_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_vnet_entry_pf_unlinked_rules_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pf_krule digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
pf_krulevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_vnet_entry_pf_unlinked_rules_p_pid];
    *pRowid = pid_value->int64_value;
    printf("pf_krule_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
pf_krulevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
pf_krulevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pf_krule_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pf_krule digest mismatch: UPDATE failed\n");
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
static sqlite3_module pf_krulevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pf_krulevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pf_krulevtabRowid,
    /* xUpdate     */ pf_krulevtabUpdate,
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
sqlite3_pf_krulevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pf_krulevtabModule,
        pAux);
}
void vtab_pf_krule_serialize(sqlite3 *real_db, struct timespec when) {
    struct pf_krule *entry = LIST_FIRST(&vnet_entry_pf_unlinked_rules);

    const char *create_stmt =
        "CREATE TABLE all_pf_krules (ridentifier INTEGER, os_fingerprint INTEGER, rtableid INTEGER, max_states INTEGER, max_src_nodes INTEGER, max_src_states INTEGER, max_src_conn INTEGER, qid INTEGER, pqid INTEGER, dnpipe INTEGER, dnrpipe INTEGER, free_flags INTEGER, nr INTEGER, prob INTEGER, cuid INTEGER, cpid INTEGER, return_icmp INTEGER, return_icmp6 INTEGER, max_mss INTEGER, tag INTEGER, match_tag INTEGER, scrub_flags INTEGER, rule_flag INTEGER, rule_ref INTEGER, action INTEGER, direction INTEGER, log INTEGER, logif INTEGER, quick INTEGER, ifnot INTEGER, match_tag_not INTEGER, natpass INTEGER, keep_state INTEGER, af INTEGER, proto INTEGER, type INTEGER, code INTEGER, flags INTEGER, flagset INTEGER, min_ttl INTEGER, allow_opts INTEGER, rt INTEGER, return_ttl INTEGER, tos INTEGER, set_tos INTEGER, anchor_relative INTEGER, anchor_wildcard INTEGER, flush INTEGER, prio INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_pf_krules VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->ridentifier);
           sqlite3_bind_int64(stmt, bindIndex++, entry->os_fingerprint);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rtableid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_states);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_src_nodes);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_src_states);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_src_conn);
           sqlite3_bind_int64(stmt, bindIndex++, entry->qid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pqid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->dnpipe);
           sqlite3_bind_int64(stmt, bindIndex++, entry->dnrpipe);
           sqlite3_bind_int64(stmt, bindIndex++, entry->free_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->nr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->prob);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cuid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cpid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->return_icmp);
           sqlite3_bind_int64(stmt, bindIndex++, entry->return_icmp6);
           sqlite3_bind_int64(stmt, bindIndex++, entry->max_mss);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->match_tag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->scrub_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rule_flag);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rule_ref);
           sqlite3_bind_int64(stmt, bindIndex++, entry->action);
           sqlite3_bind_int64(stmt, bindIndex++, entry->direction);
           sqlite3_bind_int64(stmt, bindIndex++, entry->log);
           sqlite3_bind_int64(stmt, bindIndex++, entry->logif);
           sqlite3_bind_int64(stmt, bindIndex++, entry->quick);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ifnot);
           sqlite3_bind_int64(stmt, bindIndex++, entry->match_tag_not);
           sqlite3_bind_int64(stmt, bindIndex++, entry->natpass);
           sqlite3_bind_int64(stmt, bindIndex++, entry->keep_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->af);
           sqlite3_bind_int64(stmt, bindIndex++, entry->proto);
           sqlite3_bind_int64(stmt, bindIndex++, entry->type);
           sqlite3_bind_int64(stmt, bindIndex++, entry->code);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flagset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->min_ttl);
           sqlite3_bind_int64(stmt, bindIndex++, entry->allow_opts);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->return_ttl);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tos);
           sqlite3_bind_int64(stmt, bindIndex++, entry->set_tos);
           sqlite3_bind_int64(stmt, bindIndex++, entry->anchor_relative);
           sqlite3_bind_int64(stmt, bindIndex++, entry->anchor_wildcard);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flush);
           sqlite3_bind_int64(stmt, bindIndex++, entry->prio);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

