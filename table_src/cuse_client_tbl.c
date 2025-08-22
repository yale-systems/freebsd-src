#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/cuse_client.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_cuse_client.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_hcli_entry = 0,
    VT_hcli_entry_ref = 1,
    VT_hcli_cmds = 2,
    VT_hcli_server = 3,
    VT_hcli_server_dev = 4,
    VT_hcli_read_base = 5,
    VT_hcli_write_base = 6,
    VT_hcli_read_length = 7,
    VT_hcli_write_length = 8,
    VT_hcli_read_buffer = 9,
    VT_hcli_write_buffer = 10,
    VT_hcli_ioctl_buffer = 11,
    VT_hcli_fflags = 12,
    VT_hcli_cflags = 13,
    VT_hcli_NUM_COLUMNS
};

static int
copy_columns(struct cuse_client *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_hcli_entry] =  /* Unsupported type */
//    columns[VT_hcli_entry_ref] =  /* Unsupported type */
//    columns[VT_hcli_cmds] =  /* Unsupported type */
    columns[VT_hcli_server] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->server, context);
    columns[VT_hcli_server_dev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->server_dev, context);
    columns[VT_hcli_read_base] = new_dbsc_int64(curEntry->read_base, context);
    columns[VT_hcli_write_base] = new_dbsc_int64(curEntry->write_base, context);
    columns[VT_hcli_read_length] = new_dbsc_int64(curEntry->read_length, context);
    columns[VT_hcli_write_length] = new_dbsc_int64(curEntry->write_length, context);
//    columns[VT_hcli_read_buffer] =  /* Unsupported type */
//    columns[VT_hcli_write_buffer] =  /* Unsupported type */
//    columns[VT_hcli_ioctl_buffer] =  /* Unsupported type */
    columns[VT_hcli_fflags] = new_dbsc_int64(curEntry->fflags, context);
    columns[VT_hcli_cflags] = new_dbsc_int64(curEntry->cflags, context);

    return 0;
}
void
vtab_cuse_client_lock(void)
{
    sx_slock(&hcli_lock);
}

void
vtab_cuse_client_unlock(void)
{
    sx_sunlock(&hcli_lock);
}

void
vtab_cuse_client_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct cuse_client *prc = LIST_FIRST(&hcli);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_hcli_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_hcli_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("cuse_client digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
cuse_clientvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_hcli_p_pid];
    *pRowid = pid_value->int64_value;
    printf("cuse_client_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
cuse_clientvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
cuse_clientvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_cuse_client_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("cuse_client digest mismatch: UPDATE failed\n");
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
static sqlite3_module cuse_clientvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ cuse_clientvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ cuse_clientvtabRowid,
    /* xUpdate     */ cuse_clientvtabUpdate,
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
sqlite3_cuse_clientvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &cuse_clientvtabModule,
        pAux);
}
void vtab_cuse_client_serialize(sqlite3 *real_db, struct timespec when) {
    struct cuse_client *entry = LIST_FIRST(&hcli);

    const char *create_stmt =
        "CREATE TABLE all_cuse_clients (read_base INTEGER, write_base INTEGER, read_length INTEGER, write_length INTEGER, fflags INTEGER, cflags INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_cuse_clients VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->read_base);
           sqlite3_bind_int64(stmt, bindIndex++, entry->write_base);
           sqlite3_bind_int64(stmt, bindIndex++, entry->read_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->write_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->fflags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cflags);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

