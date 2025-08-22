#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/ipmi_request.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_ipmi_request.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_ipmi_pending_requests_highpri_ir_link = 0,
    VT_ipmi_pending_requests_highpri_ir_owner = 1,
    VT_ipmi_pending_requests_highpri_ir_request = 2,
    VT_ipmi_pending_requests_highpri_ir_requestlen = 3,
    VT_ipmi_pending_requests_highpri_ir_reply = 4,
    VT_ipmi_pending_requests_highpri_ir_replybuflen = 5,
    VT_ipmi_pending_requests_highpri_ir_replylen = 6,
    VT_ipmi_pending_requests_highpri_ir_error = 7,
    VT_ipmi_pending_requests_highpri_ir_msgid = 8,
    VT_ipmi_pending_requests_highpri_ir_addr = 9,
    VT_ipmi_pending_requests_highpri_ir_command = 10,
    VT_ipmi_pending_requests_highpri_ir_compcode = 11,
    VT_ipmi_pending_requests_highpri_ir_ipmb = 12,
    VT_ipmi_pending_requests_highpri_ir_ipmb_addr = 13,
    VT_ipmi_pending_requests_highpri_ir_ipmb_command = 14,
    VT_ipmi_pending_requests_highpri_NUM_COLUMNS
};

static int
copy_columns(struct ipmi_request *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_ipmi_pending_requests_highpri_ir_link] =  /* Unsupported type */
    columns[VT_ipmi_pending_requests_highpri_ir_owner] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ir_owner, context);
    columns[VT_ipmi_pending_requests_highpri_ir_request] = new_dbsc_text(curEntry->ir_request, strlen(curEntry->ir_request) + 1, context);
    columns[VT_ipmi_pending_requests_highpri_ir_requestlen] = new_dbsc_int64(curEntry->ir_requestlen, context);
    columns[VT_ipmi_pending_requests_highpri_ir_reply] = new_dbsc_text(curEntry->ir_reply, strlen(curEntry->ir_reply) + 1, context);
    columns[VT_ipmi_pending_requests_highpri_ir_replybuflen] = new_dbsc_int64(curEntry->ir_replybuflen, context);
    columns[VT_ipmi_pending_requests_highpri_ir_replylen] = new_dbsc_int64(curEntry->ir_replylen, context);
    columns[VT_ipmi_pending_requests_highpri_ir_error] = new_dbsc_int64(curEntry->ir_error, context);
    columns[VT_ipmi_pending_requests_highpri_ir_msgid] = new_dbsc_int64(curEntry->ir_msgid, context);
    columns[VT_ipmi_pending_requests_highpri_ir_addr] = new_dbsc_int64(curEntry->ir_addr, context);
    columns[VT_ipmi_pending_requests_highpri_ir_command] = new_dbsc_int64(curEntry->ir_command, context);
    columns[VT_ipmi_pending_requests_highpri_ir_compcode] = new_dbsc_int64(curEntry->ir_compcode, context);
    columns[VT_ipmi_pending_requests_highpri_ir_ipmb] = new_dbsc_int64(curEntry->ir_ipmb, context);
    columns[VT_ipmi_pending_requests_highpri_ir_ipmb_addr] = new_dbsc_int64(curEntry->ir_ipmb_addr, context);
    columns[VT_ipmi_pending_requests_highpri_ir_ipmb_command] = new_dbsc_int64(curEntry->ir_ipmb_command, context);

    return 0;
}
void
vtab_ipmi_request_lock(void)
{
    sx_slock(&ipmi_pending_requests_highpri_lock);
}

void
vtab_ipmi_request_unlock(void)
{
    sx_sunlock(&ipmi_pending_requests_highpri_lock);
}

void
vtab_ipmi_request_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct ipmi_request *prc = LIST_FIRST(&ipmi_pending_requests_highpri);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_ipmi_pending_requests_highpri_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_ipmi_pending_requests_highpri_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("ipmi_request digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
ipmi_requestvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_ipmi_pending_requests_highpri_p_pid];
    *pRowid = pid_value->int64_value;
    printf("ipmi_request_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
ipmi_requestvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
ipmi_requestvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_ipmi_request_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("ipmi_request digest mismatch: UPDATE failed\n");
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
static sqlite3_module ipmi_requestvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ ipmi_requestvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ ipmi_requestvtabRowid,
    /* xUpdate     */ ipmi_requestvtabUpdate,
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
sqlite3_ipmi_requestvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &ipmi_requestvtabModule,
        pAux);
}
void vtab_ipmi_request_serialize(sqlite3 *real_db, struct timespec when) {
    struct ipmi_request *entry = LIST_FIRST(&ipmi_pending_requests_highpri);

    const char *create_stmt =
        "CREATE TABLE all_ipmi_requests (ir_request TEXT, ir_requestlen INTEGER, ir_reply TEXT, ir_replybuflen INTEGER, ir_replylen INTEGER, ir_error INTEGER, ir_msgid INTEGER, ir_addr INTEGER, ir_command INTEGER, ir_compcode INTEGER, ir_ipmb INTEGER, ir_ipmb_addr INTEGER, ir_ipmb_command INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_ipmi_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->ir_request, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_requestlen);
           sqlite3_bind_text(stmt, bindIndex++, entry->ir_reply, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_replybuflen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_replylen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_error);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_msgid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_addr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_command);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_compcode);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_ipmb);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_ipmb_addr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ir_ipmb_command);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

