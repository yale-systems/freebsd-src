#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_domains_dom_next = 0,
    VT_domains_dom_family = 1,
    VT_domains_dom_nprotosw = 2,
    VT_domains_dom_name = 3,
    VT_domains_dom_flags = 4,
    VT_domains_dom_probe = 5,
    VT_domains_dom_externalize = 6,
    VT_domains_dom_rtattach = 7,
    VT_domains_dom_rtdetach = 8,
    VT_domains_dom_ifattach = 9,
    VT_domains_dom_ifdetach = 10,
    VT_domains_dom_ifmtu = 11,
    VT_domains_dom_protosw = 12,
    VT_domains_NUM_COLUMNS
};

static int
copy_columns(struct domains *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_domains_dom_next] =  TODO: Handle other types
    columns[VT_domains_dom_family] = new_osdb_int64(curEntry->dom_family, context);
    columns[VT_domains_dom_nprotosw] = new_osdb_int64(curEntry->dom_nprotosw, context);
    columns[VT_domains_dom_name] = new_osdb_text(curEntry->dom_name, strlen(curEntry->dom_name) + 1, context);
    columns[VT_domains_dom_flags] = new_osdb_int64(curEntry->dom_flags, context);
//    columns[VT_domains_dom_probe] =  TODO: Handle other types
//    columns[VT_domains_dom_externalize] =  TODO: Handle other types
//    columns[VT_domains_dom_rtattach] =  TODO: Handle other types
//    columns[VT_domains_dom_rtdetach] =  TODO: Handle other types
//    columns[VT_domains_dom_ifattach] =  TODO: Handle other types
//    columns[VT_domains_dom_ifdetach] =  TODO: Handle other types
//    columns[VT_domains_dom_ifmtu] =  TODO: Handle other types
//    columns[VT_domains_dom_protosw] =  TODO: Handle other types

    return 0;
}
void
vtab_domainhead_lock(void)
{
    sx_slock(&domains_lock);
}

void
vtab_domainhead_unlock(void)
{
    sx_sunlock(&domains_lock);
}

void
vtab_domainhead_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct domainhead *prc = LIST_FIRST(&domains);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_domains_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_domains_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("domainhead digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab_domainhead_rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_domains_PID];
    *pRowid = pid_value->int64_value;
    printf("domainhead_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab_domainhead_bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab_domainhead_update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_domainhead_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("domainhead digest mismatch: UPDATE failed\n");
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
static sqlite3_module domainheadvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ domainheadvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ domainheadvtabRowid,
    /* xUpdate     */ domainheadvtabUpdate,
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
sqlite3_domainheadvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &domainheadvtabModule,
        pAux);
}
