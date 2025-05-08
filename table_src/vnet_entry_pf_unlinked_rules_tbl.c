#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

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
copy_columns(struct vnet_entry_pf_unlinked_rules *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_vnet_entry_pf_unlinked_rules_src] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_dst] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_skip] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_label] =  TODO: Handle other types
    columns[VT_vnet_entry_pf_unlinked_rules_ridentifier] = new_osdb_int64(curEntry->ridentifier, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_ifname] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_qname] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_pqname] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_tagname] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_match_tagname] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_overload_tblname] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_entries] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_rpool] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_evaluations] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_packets] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_bytes] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_timestamp] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_kif] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_anchor] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_overload_tbl] =  TODO: Handle other types
    columns[VT_vnet_entry_pf_unlinked_rules_os_fingerprint] = new_osdb_int64(curEntry->os_fingerprint, context);
    columns[VT_vnet_entry_pf_unlinked_rules_rtableid] = new_osdb_int64(curEntry->rtableid, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_timeout] =  TODO: Handle other types
    columns[VT_vnet_entry_pf_unlinked_rules_max_states] = new_osdb_int64(curEntry->max_states, context);
    columns[VT_vnet_entry_pf_unlinked_rules_max_src_nodes] = new_osdb_int64(curEntry->max_src_nodes, context);
    columns[VT_vnet_entry_pf_unlinked_rules_max_src_states] = new_osdb_int64(curEntry->max_src_states, context);
    columns[VT_vnet_entry_pf_unlinked_rules_max_src_conn] = new_osdb_int64(curEntry->max_src_conn, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_max_src_conn_rate] =  TODO: Handle other types
    columns[VT_vnet_entry_pf_unlinked_rules_qid] = new_osdb_int64(curEntry->qid, context);
    columns[VT_vnet_entry_pf_unlinked_rules_pqid] = new_osdb_int64(curEntry->pqid, context);
    columns[VT_vnet_entry_pf_unlinked_rules_dnpipe] = new_osdb_int64(curEntry->dnpipe, context);
    columns[VT_vnet_entry_pf_unlinked_rules_dnrpipe] = new_osdb_int64(curEntry->dnrpipe, context);
    columns[VT_vnet_entry_pf_unlinked_rules_free_flags] = new_osdb_int64(curEntry->free_flags, context);
    columns[VT_vnet_entry_pf_unlinked_rules_nr] = new_osdb_int64(curEntry->nr, context);
    columns[VT_vnet_entry_pf_unlinked_rules_prob] = new_osdb_int64(curEntry->prob, context);
    columns[VT_vnet_entry_pf_unlinked_rules_cuid] = new_osdb_int64(curEntry->cuid, context);
    columns[VT_vnet_entry_pf_unlinked_rules_cpid] = new_osdb_int64(curEntry->cpid, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_states_cur] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_states_tot] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_src_nodes] =  TODO: Handle other types
    columns[VT_vnet_entry_pf_unlinked_rules_return_icmp] = new_osdb_int64(curEntry->return_icmp, context);
    columns[VT_vnet_entry_pf_unlinked_rules_return_icmp6] = new_osdb_int64(curEntry->return_icmp6, context);
    columns[VT_vnet_entry_pf_unlinked_rules_max_mss] = new_osdb_int64(curEntry->max_mss, context);
    columns[VT_vnet_entry_pf_unlinked_rules_tag] = new_osdb_int64(curEntry->tag, context);
    columns[VT_vnet_entry_pf_unlinked_rules_match_tag] = new_osdb_int64(curEntry->match_tag, context);
    columns[VT_vnet_entry_pf_unlinked_rules_scrub_flags] = new_osdb_int64(curEntry->scrub_flags, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_uid] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_gid] =  TODO: Handle other types
    columns[VT_vnet_entry_pf_unlinked_rules_rule_flag] = new_osdb_int64(curEntry->rule_flag, context);
    columns[VT_vnet_entry_pf_unlinked_rules_rule_ref] = new_osdb_int64(curEntry->rule_ref, context);
    columns[VT_vnet_entry_pf_unlinked_rules_action] = new_osdb_int64(curEntry->action, context);
    columns[VT_vnet_entry_pf_unlinked_rules_direction] = new_osdb_int64(curEntry->direction, context);
    columns[VT_vnet_entry_pf_unlinked_rules_log] = new_osdb_int64(curEntry->log, context);
    columns[VT_vnet_entry_pf_unlinked_rules_logif] = new_osdb_int64(curEntry->logif, context);
    columns[VT_vnet_entry_pf_unlinked_rules_quick] = new_osdb_int64(curEntry->quick, context);
    columns[VT_vnet_entry_pf_unlinked_rules_ifnot] = new_osdb_int64(curEntry->ifnot, context);
    columns[VT_vnet_entry_pf_unlinked_rules_match_tag_not] = new_osdb_int64(curEntry->match_tag_not, context);
    columns[VT_vnet_entry_pf_unlinked_rules_natpass] = new_osdb_int64(curEntry->natpass, context);
    columns[VT_vnet_entry_pf_unlinked_rules_keep_state] = new_osdb_int64(curEntry->keep_state, context);
    columns[VT_vnet_entry_pf_unlinked_rules_af] = new_osdb_int64(curEntry->af, context);
    columns[VT_vnet_entry_pf_unlinked_rules_proto] = new_osdb_int64(curEntry->proto, context);
    columns[VT_vnet_entry_pf_unlinked_rules_type] = new_osdb_int64(curEntry->type, context);
    columns[VT_vnet_entry_pf_unlinked_rules_code] = new_osdb_int64(curEntry->code, context);
    columns[VT_vnet_entry_pf_unlinked_rules_flags] = new_osdb_int64(curEntry->flags, context);
    columns[VT_vnet_entry_pf_unlinked_rules_flagset] = new_osdb_int64(curEntry->flagset, context);
    columns[VT_vnet_entry_pf_unlinked_rules_min_ttl] = new_osdb_int64(curEntry->min_ttl, context);
    columns[VT_vnet_entry_pf_unlinked_rules_allow_opts] = new_osdb_int64(curEntry->allow_opts, context);
    columns[VT_vnet_entry_pf_unlinked_rules_rt] = new_osdb_int64(curEntry->rt, context);
    columns[VT_vnet_entry_pf_unlinked_rules_return_ttl] = new_osdb_int64(curEntry->return_ttl, context);
    columns[VT_vnet_entry_pf_unlinked_rules_tos] = new_osdb_int64(curEntry->tos, context);
    columns[VT_vnet_entry_pf_unlinked_rules_set_tos] = new_osdb_int64(curEntry->set_tos, context);
    columns[VT_vnet_entry_pf_unlinked_rules_anchor_relative] = new_osdb_int64(curEntry->anchor_relative, context);
    columns[VT_vnet_entry_pf_unlinked_rules_anchor_wildcard] = new_osdb_int64(curEntry->anchor_wildcard, context);
    columns[VT_vnet_entry_pf_unlinked_rules_flush] = new_osdb_int64(curEntry->flush, context);
    columns[VT_vnet_entry_pf_unlinked_rules_prio] = new_osdb_int64(curEntry->prio, context);
//    columns[VT_vnet_entry_pf_unlinked_rules_set_prio] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_divert] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_md5sum] =  TODO: Handle other types
//    columns[VT_vnet_entry_pf_unlinked_rules_entry_global] =  TODO: Handle other types

    return 0;
}
void
vtab_pf_krulequeue_lock(void)
{
    sx_slock(&vnet_entry_pf_unlinked_rules_lock);
}

void
vtab_pf_krulequeue_unlock(void)
{
    sx_sunlock(&vnet_entry_pf_unlinked_rules_lock);
}

void
vtab_pf_krulequeue_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct pf_krulequeue *prc = LIST_FIRST(&vnet_entry_pf_unlinked_rules);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_vnet_entry_pf_unlinked_rules_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_vnet_entry_pf_unlinked_rules_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("pf_krulequeue digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_pf_krulequeue_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_vnet_entry_pf_unlinked_rules_PID];
    *pRowid = pid_value->int64_value;
    printf("pf_krulequeue_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_pf_krulequeue_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_pf_krulequeue_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_pf_krulequeue_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("pf_krulequeue digest mismatch: UPDATE failed\n");
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
static sqlite3_module pf_krulequeuevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ pf_krulequeuevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ pf_krulequeuevtabRowid,
    /* xUpdate     */ pf_krulequeuevtabUpdate,
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
sqlite3_pf_krulequeuevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &pf_krulequeuevtabModule,
        pAux);
}
