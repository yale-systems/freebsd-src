#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/secasvar.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_secasvar.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_savtree_alive_spi = 0,
    VT_savtree_alive_flags = 1,
    VT_savtree_alive_seq = 2,
    VT_savtree_alive_pid = 3,
    VT_savtree_alive_ivlen = 4,
    VT_savtree_alive_sah = 5,
    VT_savtree_alive_key_auth = 6,
    VT_savtree_alive_key_enc = 7,
    VT_savtree_alive_replay = 8,
    VT_savtree_alive_natt = 9,
    VT_savtree_alive_lock = 10,
    VT_savtree_alive_tdb_xform = 11,
    VT_savtree_alive_tdb_encalgxform = 12,
    VT_savtree_alive_tdb_authalgxform = 13,
    VT_savtree_alive_tdb_compalgxform = 14,
    VT_savtree_alive_tdb_cryptoid = 15,
    VT_savtree_alive_alg_auth = 16,
    VT_savtree_alive_alg_enc = 17,
    VT_savtree_alive_alg_comp = 18,
    VT_savtree_alive_state = 19,
    VT_savtree_alive_lft_c = 20,
    VT_savtree_alive_lft_h = 21,
    VT_savtree_alive_lft_s = 22,
    VT_savtree_alive_created = 23,
    VT_savtree_alive_firstused = 24,
    VT_savtree_alive_chain = 25,
    VT_savtree_alive_spihash = 26,
    VT_savtree_alive_drainq = 27,
    VT_savtree_alive_cntr = 28,
    VT_savtree_alive_refcnt = 29,
    VT_savtree_alive_NUM_COLUMNS
};

static int
copy_columns(struct secasvar *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_savtree_alive_spi] = new_dbsc_int64(curEntry->spi, context);
    columns[VT_savtree_alive_flags] = new_dbsc_int64(curEntry->flags, context);
    columns[VT_savtree_alive_seq] = new_dbsc_int64(curEntry->seq, context);
    columns[VT_savtree_alive_pid] = new_dbsc_int64(curEntry->pid, context);
    columns[VT_savtree_alive_ivlen] = new_dbsc_int64(curEntry->ivlen, context);
    columns[VT_savtree_alive_sah] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sah, context);
    columns[VT_savtree_alive_key_auth] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->key_auth, context);
    columns[VT_savtree_alive_key_enc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->key_enc, context);
    columns[VT_savtree_alive_replay] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->replay, context);
    columns[VT_savtree_alive_natt] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->natt, context);
    columns[VT_savtree_alive_lock] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lock, context);
    columns[VT_savtree_alive_tdb_xform] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tdb_xform, context);
    columns[VT_savtree_alive_tdb_encalgxform] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tdb_encalgxform, context);
    columns[VT_savtree_alive_tdb_authalgxform] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tdb_authalgxform, context);
    columns[VT_savtree_alive_tdb_compalgxform] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tdb_compalgxform, context);
    columns[VT_savtree_alive_tdb_cryptoid] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tdb_cryptoid, context);
    columns[VT_savtree_alive_alg_auth] = new_dbsc_int64(curEntry->alg_auth, context);
    columns[VT_savtree_alive_alg_enc] = new_dbsc_int64(curEntry->alg_enc, context);
    columns[VT_savtree_alive_alg_comp] = new_dbsc_int64(curEntry->alg_comp, context);
    columns[VT_savtree_alive_state] = new_dbsc_int64(curEntry->state, context);
    columns[VT_savtree_alive_lft_c] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lft_c, context);
    columns[VT_savtree_alive_lft_h] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lft_h, context);
    columns[VT_savtree_alive_lft_s] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->lft_s, context);
    columns[VT_savtree_alive_created] = new_dbsc_int64(curEntry->created, context);
    columns[VT_savtree_alive_firstused] = new_dbsc_int64(curEntry->firstused, context);
//    columns[VT_savtree_alive_chain] =  /* Unsupported type */
//    columns[VT_savtree_alive_spihash] =  /* Unsupported type */
//    columns[VT_savtree_alive_drainq] =  /* Unsupported type */
    columns[VT_savtree_alive_cntr] = new_dbsc_int64(curEntry->cntr, context);
    columns[VT_savtree_alive_refcnt] = new_dbsc_int64(curEntry->refcnt, context);

    return 0;
}
void
vtab_secasvar_lock(void)
{
    sx_slock(&savtree_alive_lock);
}

void
vtab_secasvar_unlock(void)
{
    sx_sunlock(&savtree_alive_lock);
}

void
vtab_secasvar_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct secasvar *prc = LIST_FIRST(&savtree_alive);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_savtree_alive_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_savtree_alive_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("secasvar digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
secasvarvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_savtree_alive_p_pid];
    *pRowid = pid_value->int64_value;
    printf("secasvar_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
secasvarvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
secasvarvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_secasvar_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("secasvar digest mismatch: UPDATE failed\n");
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
static sqlite3_module secasvarvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ secasvarvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ secasvarvtabRowid,
    /* xUpdate     */ secasvarvtabUpdate,
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
sqlite3_secasvarvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &secasvarvtabModule,
        pAux);
}
void vtab_secasvar_serialize(sqlite3 *real_db, struct timespec when) {
    struct secasvar *entry = LIST_FIRST(&savtree_alive);

    const char *create_stmt =
        "CREATE TABLE all_secasvars (spi INTEGER, flags INTEGER, seq INTEGER, pid INTEGER, ivlen INTEGER, alg_auth INTEGER, alg_enc INTEGER, alg_comp INTEGER, state INTEGER, created INTEGER, firstused INTEGER, cntr INTEGER, refcnt INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_secasvars VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->spi);
           sqlite3_bind_int64(stmt, bindIndex++, entry->flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->seq);
           sqlite3_bind_int64(stmt, bindIndex++, entry->pid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->ivlen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->alg_auth);
           sqlite3_bind_int64(stmt, bindIndex++, entry->alg_enc);
           sqlite3_bind_int64(stmt, bindIndex++, entry->alg_comp);
           sqlite3_bind_int64(stmt, bindIndex++, entry->state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->created);
           sqlite3_bind_int64(stmt, bindIndex++, entry->firstused);
           sqlite3_bind_int64(stmt, bindIndex++, entry->cntr);
           sqlite3_bind_int64(stmt, bindIndex++, entry->refcnt);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

