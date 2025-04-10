#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/g_eli_key.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_g_eli_key.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_sc_ekeys_queue_gek_key = 0,
    VT_sc_ekeys_queue_gek_magic = 1,
    VT_sc_ekeys_queue_gek_keyno = 2,
    VT_sc_ekeys_queue_gek_count = 3,
    VT_sc_ekeys_queue_gek_next = 4,
    VT_sc_ekeys_queue_gek_link = 5,
    VT_sc_ekeys_queue_NUM_COLUMNS
};

static int
copy_columns(struct g_eli_key *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_sc_ekeys_queue_gek_key] =  /* Unsupported type */
    columns[VT_sc_ekeys_queue_gek_magic] = new_dbsc_int64(curEntry->gek_magic, context);
    columns[VT_sc_ekeys_queue_gek_keyno] = new_dbsc_int64(curEntry->gek_keyno, context);
    columns[VT_sc_ekeys_queue_gek_count] = new_dbsc_int64(curEntry->gek_count, context);
//    columns[VT_sc_ekeys_queue_gek_next] =  /* Unsupported type */
//    columns[VT_sc_ekeys_queue_gek_link] =  /* Unsupported type */

    return 0;
}
void
vtab_g_eli_key_lock(void)
{
    sx_slock(&sc_ekeys_queue_lock);
}

void
vtab_g_eli_key_unlock(void)
{
    sx_sunlock(&sc_ekeys_queue_lock);
}

void
vtab_g_eli_key_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct g_eli_key *prc = LIST_FIRST(&sc_ekeys_queue);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_sc_ekeys_queue_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_sc_ekeys_queue_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("g_eli_key digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
g_eli_keyvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_sc_ekeys_queue_p_pid];
    *pRowid = pid_value->int64_value;
    printf("g_eli_key_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
g_eli_keyvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
g_eli_keyvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_g_eli_key_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("g_eli_key digest mismatch: UPDATE failed\n");
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
static sqlite3_module g_eli_keyvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ g_eli_keyvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ g_eli_keyvtabRowid,
    /* xUpdate     */ g_eli_keyvtabUpdate,
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
sqlite3_g_eli_keyvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &g_eli_keyvtabModule,
        pAux);
}
void vtab_g_eli_key_serialize(sqlite3 *real_db, struct timespec when) {
    struct g_eli_key *entry = LIST_FIRST(&sc_ekeys_queue);

    const char *create_stmt =
        "CREATE TABLE all_g_eli_keys (gek_magic INTEGER, gek_keyno INTEGER, gek_count INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_g_eli_keys VALUES (?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->gek_magic);
           sqlite3_bind_int64(stmt, bindIndex++, entry->gek_keyno);
           sqlite3_bind_int64(stmt, bindIndex++, entry->gek_count);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

