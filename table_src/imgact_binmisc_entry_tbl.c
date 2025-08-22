#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/imgact_binmisc_entry.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_imgact_binmisc_entry.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_interpreter_list_link = 0,
    VT_interpreter_list_ibe_name = 1,
    VT_interpreter_list_ibe_magic = 2,
    VT_interpreter_list_ibe_mask = 3,
    VT_interpreter_list_ibe_interpreter = 4,
    VT_interpreter_list_ibe_interpreter_vnode = 5,
    VT_interpreter_list_ibe_interp_offset = 6,
    VT_interpreter_list_ibe_interp_argcnt = 7,
    VT_interpreter_list_ibe_interp_length = 8,
    VT_interpreter_list_ibe_argv0_cnt = 9,
    VT_interpreter_list_ibe_flags = 10,
    VT_interpreter_list_ibe_moffset = 11,
    VT_interpreter_list_ibe_msize = 12,
    VT_interpreter_list_NUM_COLUMNS
};

static int
copy_columns(struct imgact_binmisc_entry *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_interpreter_list_link] =  /* Unsupported type */
    columns[VT_interpreter_list_ibe_name] = new_dbsc_text(curEntry->ibe_name, strlen(curEntry->ibe_name) + 1, context);
    columns[VT_interpreter_list_ibe_magic] = new_dbsc_text(curEntry->ibe_magic, strlen(curEntry->ibe_magic) + 1, context);
    columns[VT_interpreter_list_ibe_mask] = new_dbsc_text(curEntry->ibe_mask, strlen(curEntry->ibe_mask) + 1, context);
    columns[VT_interpreter_list_ibe_interpreter] = new_dbsc_text(curEntry->ibe_interpreter, strlen(curEntry->ibe_interpreter) + 1, context);
    columns[VT_interpreter_list_ibe_interpreter_vnode] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->ibe_interpreter_vnode, context);
    columns[VT_interpreter_list_ibe_interp_offset] = new_dbsc_int64(curEntry->ibe_interp_offset, context);
    columns[VT_interpreter_list_ibe_interp_argcnt] = new_dbsc_int64(curEntry->ibe_interp_argcnt, context);
    columns[VT_interpreter_list_ibe_interp_length] = new_dbsc_int64(curEntry->ibe_interp_length, context);
    columns[VT_interpreter_list_ibe_argv0_cnt] = new_dbsc_int64(curEntry->ibe_argv0_cnt, context);
    columns[VT_interpreter_list_ibe_flags] = new_dbsc_int64(curEntry->ibe_flags, context);
    columns[VT_interpreter_list_ibe_moffset] = new_dbsc_int64(curEntry->ibe_moffset, context);
    columns[VT_interpreter_list_ibe_msize] = new_dbsc_int64(curEntry->ibe_msize, context);

    return 0;
}
void
vtab_imgact_binmisc_entry_lock(void)
{
    sx_slock(&interpreter_list_lock);
}

void
vtab_imgact_binmisc_entry_unlock(void)
{
    sx_sunlock(&interpreter_list_lock);
}

void
vtab_imgact_binmisc_entry_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct imgact_binmisc_entry *prc = LIST_FIRST(&interpreter_list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_interpreter_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_interpreter_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("imgact_binmisc_entry digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
imgact_binmisc_entryvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_interpreter_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("imgact_binmisc_entry_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
imgact_binmisc_entryvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
imgact_binmisc_entryvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_imgact_binmisc_entry_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("imgact_binmisc_entry digest mismatch: UPDATE failed\n");
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
static sqlite3_module imgact_binmisc_entryvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ imgact_binmisc_entryvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ imgact_binmisc_entryvtabRowid,
    /* xUpdate     */ imgact_binmisc_entryvtabUpdate,
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
sqlite3_imgact_binmisc_entryvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &imgact_binmisc_entryvtabModule,
        pAux);
}
void vtab_imgact_binmisc_entry_serialize(sqlite3 *real_db, struct timespec when) {
    struct imgact_binmisc_entry *entry = LIST_FIRST(&interpreter_list);

    const char *create_stmt =
        "CREATE TABLE all_imgact_binmisc_entrys (ibe_name TEXT, ibe_magic TEXT, ibe_mask TEXT, ibe_interpreter TEXT, ibe_interp_offset INTEGER, ibe_interp_argcnt INTEGER, ibe_interp_length INTEGER, ibe_argv0_cnt INTEGER, ibe_flags INTEGER, ibe_moffset INTEGER, ibe_msize INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_imgact_binmisc_entrys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_text(stmt, bindIndex++, entry->ibe_name, -1, SQLITE_TRANSIENT);
           sqlite3_bind_text(stmt, bindIndex++, entry->ibe_magic, -1, SQLITE_TRANSIENT);
           sqlite3_bind_text(stmt, bindIndex++, entry->ibe_mask, -1, SQLITE_TRANSIENT);
           sqlite3_bind_text(stmt, bindIndex++, entry->ibe_interpreter, -1, SQLITE_TRANSIENT);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ibe_interp_offset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ibe_interp_argcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ibe_interp_length);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ibe_argv0_cnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ibe_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ibe_moffset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ibe_msize);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

