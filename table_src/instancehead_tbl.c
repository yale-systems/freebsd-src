#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_instancehead_instancelist = 0,
    VT_instancehead_packetAliasMode = 1,
    VT_instancehead_aliasAddress = 2,
    VT_instancehead_targetAddress = 3,
    VT_instancehead_linkSplayOut = 4,
    VT_instancehead_linkSplayIn = 5,
    VT_instancehead_pptpList = 6,
    VT_instancehead_checkExpire = 7,
    VT_instancehead_icmpLinkCount = 8,
    VT_instancehead_udpLinkCount = 9,
    VT_instancehead_tcpLinkCount = 10,
    VT_instancehead_pptpLinkCount = 11,
    VT_instancehead_protoLinkCount = 12,
    VT_instancehead_fragmentIdLinkCount = 13,
    VT_instancehead_fragmentPtrLinkCount = 14,
    VT_instancehead_sockCount = 15,
    VT_instancehead_logDesc = 16,
    VT_instancehead_skinnyPort = 17,
    VT_instancehead_proxyList = 18,
    VT_instancehead_true_addr = 19,
    VT_instancehead_true_port = 20,
    VT_instancehead_aliasPortLower = 21,
    VT_instancehead_aliasPortLength = 22,
    VT_instancehead_sctpLinkCount = 23,
    VT_instancehead_sctpNatTimer = 24,
    VT_instancehead_sctpNatTableSize = 25,
    VT_instancehead_sctpTableLocal = 26,
    VT_instancehead_sctpTableGlobal = 27,
    VT_instancehead_mutex = 28,
    VT_instancehead_NUM_COLUMNS
};

static int
copy_columns(struct instancehead *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_instancehead_instancelist] =  TODO: Handle other types
    columns[VT_instancehead_packetAliasMode] = new_osdb_int64(curEntry->packetAliasMode, context);
//    columns[VT_instancehead_aliasAddress] =  TODO: Handle other types
//    columns[VT_instancehead_targetAddress] =  TODO: Handle other types
//    columns[VT_instancehead_linkSplayOut] =  TODO: Handle other types
//    columns[VT_instancehead_linkSplayIn] =  TODO: Handle other types
//    columns[VT_instancehead_pptpList] =  TODO: Handle other types
//    columns[VT_instancehead_checkExpire] =  TODO: Handle other types
    columns[VT_instancehead_icmpLinkCount] = new_osdb_int64(curEntry->icmpLinkCount, context);
    columns[VT_instancehead_udpLinkCount] = new_osdb_int64(curEntry->udpLinkCount, context);
    columns[VT_instancehead_tcpLinkCount] = new_osdb_int64(curEntry->tcpLinkCount, context);
    columns[VT_instancehead_pptpLinkCount] = new_osdb_int64(curEntry->pptpLinkCount, context);
    columns[VT_instancehead_protoLinkCount] = new_osdb_int64(curEntry->protoLinkCount, context);
    columns[VT_instancehead_fragmentIdLinkCount] = new_osdb_int64(curEntry->fragmentIdLinkCount, context);
    columns[VT_instancehead_fragmentPtrLinkCount] = new_osdb_int64(curEntry->fragmentPtrLinkCount, context);
    columns[VT_instancehead_sockCount] = new_osdb_int64(curEntry->sockCount, context);
    columns[VT_instancehead_logDesc] = new_osdb_text(curEntry->logDesc, strlen(curEntry->logDesc) + 1, context);
    columns[VT_instancehead_skinnyPort] = new_osdb_int64(curEntry->skinnyPort, context);
//    columns[VT_instancehead_proxyList] =  TODO: Handle other types
//    columns[VT_instancehead_true_addr] =  TODO: Handle other types
    columns[VT_instancehead_true_port] = new_osdb_int64(curEntry->true_port, context);
    columns[VT_instancehead_aliasPortLower] = new_osdb_int64(curEntry->aliasPortLower, context);
    columns[VT_instancehead_aliasPortLength] = new_osdb_int64(curEntry->aliasPortLength, context);
    columns[VT_instancehead_sctpLinkCount] = new_osdb_int64(curEntry->sctpLinkCount, context);
//    columns[VT_instancehead_sctpNatTimer] =  TODO: Handle other types
    columns[VT_instancehead_sctpNatTableSize] = new_osdb_int64(curEntry->sctpNatTableSize, context);
//    columns[VT_instancehead_sctpTableLocal] =  TODO: Handle other types
//    columns[VT_instancehead_sctpTableGlobal] =  TODO: Handle other types
//    columns[VT_instancehead_mutex] =  TODO: Handle other types

    return 0;
}
void
vtab__lock(void)
{
    sx_slock(&instancehead_lock);
}

void
vtab__unlock(void)
{
    sx_sunlock(&instancehead_lock);
}

void
vtab__snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct  *prc = LIST_FIRST(&instancehead);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_instancehead_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_instancehead_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf(" digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vtab__rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_instancehead_PID];
    *pRowid = pid_value->int64_value;
    printf("_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vtab__bestindex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
vtab__update(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab__snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf(" digest mismatch: UPDATE failed\n");
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
static sqlite3_module vtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vtabRowid,
    /* xUpdate     */ vtabUpdate,
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
sqlite3_vtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vtabModule,
        pAux);
}
