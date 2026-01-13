#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/carp_softc.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_carp_softc.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_cif_vrs_sc_carpdev = 0,
    VT_cif_vrs_sc_ifas = 1,
    VT_cif_vrs_sc_version = 2,
    VT_cif_vrs_sc_addr = 3,
    VT_cif_vrs_sc_ad_tmo = 4,
    VT_cif_vrs_sc_md_tmo = 5,
    VT_cif_vrs_sc_md6_tmo = 6,
    VT_cif_vrs_sc_mtx = 7,
    VT_cif_vrs_sc_vhid = 8,
    VT_cif_vrs_ = 9,
    VT_cif_vrs_sc_naddrs = 10,
    VT_cif_vrs_sc_naddrs6 = 11,
    VT_cif_vrs_sc_ifasiz = 12,
    VT_cif_vrs_sc_state = 13,
    VT_cif_vrs_sc_suppress = 14,
    VT_cif_vrs_sc_sendad_errors = 15,
    VT_cif_vrs_sc_sendad_success = 16,
    VT_cif_vrs_sc_list = 17,
    VT_cif_vrs_sc_next = 18,
    VT_cif_vrs_NUM_COLUMNS
};

static int
copy_columns(struct carp_softc *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_cif_vrs_sc_carpdev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sc_carpdev, context);
    columns[VT_cif_vrs_sc_ifas] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->sc_ifas, context);
    columns[VT_cif_vrs_sc_version] = new_dbsc_int64((int64_t)(curEntry->sc_version), context); // TODO: need better enum representation 
//    columns[VT_cif_vrs_sc_addr] =  /* Unsupported type */
//    columns[VT_cif_vrs_sc_ad_tmo] =  /* Unsupported type */
//    columns[VT_cif_vrs_sc_md_tmo] =  /* Unsupported type */
//    columns[VT_cif_vrs_sc_md6_tmo] =  /* Unsupported type */
//    columns[VT_cif_vrs_sc_mtx] =  /* Unsupported type */
    columns[VT_cif_vrs_sc_vhid] = new_dbsc_int64(curEntry->sc_vhid, context);
//    columns[VT_cif_vrs_] =  /* Unsupported type */
    columns[VT_cif_vrs_sc_naddrs] = new_dbsc_int64(curEntry->sc_naddrs, context);
    columns[VT_cif_vrs_sc_naddrs6] = new_dbsc_int64(curEntry->sc_naddrs6, context);
    columns[VT_cif_vrs_sc_ifasiz] = new_dbsc_int64(curEntry->sc_ifasiz, context);
    columns[VT_cif_vrs_sc_state] = new_dbsc_int64((int64_t)(curEntry->sc_state), context); // TODO: need better enum representation 
    columns[VT_cif_vrs_sc_suppress] = new_dbsc_int64(curEntry->sc_suppress, context);
    columns[VT_cif_vrs_sc_sendad_errors] = new_dbsc_int64(curEntry->sc_sendad_errors, context);
    columns[VT_cif_vrs_sc_sendad_success] = new_dbsc_int64(curEntry->sc_sendad_success, context);
//    columns[VT_cif_vrs_sc_list] =  /* Unsupported type */
//    columns[VT_cif_vrs_sc_next] =  /* Unsupported type */

    return 0;
}
void
vtab_carp_softc_lock(void)
{
    sx_slock(&cif_vrs_lock);
}

void
vtab_carp_softc_unlock(void)
{
    sx_sunlock(&cif_vrs_lock);
}

void
vtab_carp_softc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct carp_softc *prc = LIST_FIRST(&cif_vrs);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_cif_vrs_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_cif_vrs_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("carp_softc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
carp_softcvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_cif_vrs_p_pid];
    *pRowid = pid_value->int64_value;
    printf("carp_softc_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
carp_softcvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
carp_softcvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_carp_softc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("carp_softc digest mismatch: UPDATE failed\n");
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
static sqlite3_module carp_softcvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ carp_softcvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ carp_softcvtabRowid,
    /* xUpdate     */ carp_softcvtabUpdate,
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
sqlite3_carp_softcvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &carp_softcvtabModule,
        pAux);
}
void vtab_carp_softc_serialize(sqlite3 *real_db, struct timespec when) {
    struct carp_softc *entry = LIST_FIRST(&cif_vrs);

    const char *create_stmt =
        "CREATE TABLE all_carp_softcs (sc_version INTEGER, sc_vhid INTEGER, sc_naddrs INTEGER, sc_naddrs6 INTEGER, sc_ifasiz INTEGER, sc_state INTEGER, sc_suppress INTEGER, sc_sendad_errors INTEGER, sc_sendad_success INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_carp_softcs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_version);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_vhid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_naddrs);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_naddrs6);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_ifasiz);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_state);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_suppress);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_sendad_errors);
           sqlite3_bind_int64(stmt, bindIndex++, entry->sc_sendad_success);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

