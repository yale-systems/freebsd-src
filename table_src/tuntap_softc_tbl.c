#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/tuntap_softc.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_tuntap_softc.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_tunhead_tun_list = 0,
    VT_tunhead_tun_alias = 1,
    VT_tunhead_tun_dev = 2,
    VT_tunhead_tun_flags = 3,
    VT_tunhead_tun_pid = 4,
    VT_tunhead_tun_ifp = 5,
    VT_tunhead_tun_sigio = 6,
    VT_tunhead_tun_drv = 7,
    VT_tunhead_tun_rsel = 8,
    VT_tunhead_tun_mtx = 9,
    VT_tunhead_tun_cv = 10,
    VT_tunhead_tun_ether = 11,
    VT_tunhead_tun_busy = 12,
    VT_tunhead_tun_vhdrlen = 13,
    VT_tunhead_tun_lro = 14,
    VT_tunhead_tun_lro_ready = 15,
    VT_tunhead_NUM_COLUMNS
};

static int
copy_columns(struct tuntap_softc *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

//    columns[VT_tunhead_tun_list] =  /* Unsupported type */
    columns[VT_tunhead_tun_alias] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tun_alias, context);
    columns[VT_tunhead_tun_dev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tun_dev, context);
    columns[VT_tunhead_tun_flags] = new_dbsc_int64(curEntry->tun_flags, context);
    columns[VT_tunhead_tun_pid] = new_dbsc_int64(curEntry->tun_pid, context);
    columns[VT_tunhead_tun_ifp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tun_ifp, context);
    columns[VT_tunhead_tun_sigio] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tun_sigio, context);
    columns[VT_tunhead_tun_drv] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->tun_drv, context);
//    columns[VT_tunhead_tun_rsel] =  /* Unsupported type */
//    columns[VT_tunhead_tun_mtx] =  /* Unsupported type */
//    columns[VT_tunhead_tun_cv] =  /* Unsupported type */
//    columns[VT_tunhead_tun_ether] =  /* Unsupported type */
    columns[VT_tunhead_tun_busy] = new_dbsc_int64(curEntry->tun_busy, context);
    columns[VT_tunhead_tun_vhdrlen] = new_dbsc_int64(curEntry->tun_vhdrlen, context);
//    columns[VT_tunhead_tun_lro] =  /* Unsupported type */
    columns[VT_tunhead_tun_lro_ready] = new_dbsc_int64(curEntry->tun_lro_ready, context);

    return 0;
}
void
vtab_tuntap_softc_lock(void)
{
    sx_slock(&tunhead_lock);
}

void
vtab_tuntap_softc_unlock(void)
{
    sx_sunlock(&tunhead_lock);
}

void
vtab_tuntap_softc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct tuntap_softc *prc = LIST_FIRST(&tunhead);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_tunhead_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_tunhead_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("tuntap_softc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
tuntap_softcvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_tunhead_p_pid];
    *pRowid = pid_value->int64_value;
    printf("tuntap_softc_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
tuntap_softcvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
tuntap_softcvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_tuntap_softc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("tuntap_softc digest mismatch: UPDATE failed\n");
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
static sqlite3_module tuntap_softcvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ tuntap_softcvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ tuntap_softcvtabRowid,
    /* xUpdate     */ tuntap_softcvtabUpdate,
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
sqlite3_tuntap_softcvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &tuntap_softcvtabModule,
        pAux);
}
void vtab_tuntap_softc_serialize(sqlite3 *real_db, struct timespec when) {
    struct tuntap_softc *entry = LIST_FIRST(&tunhead);

    const char *create_stmt =
        "CREATE TABLE all_tuntap_softcs (tun_flags INTEGER, tun_pid INTEGER, tun_busy INTEGER, tun_vhdrlen INTEGER, tun_lro_ready INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_tuntap_softcs VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->tun_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tun_pid);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tun_busy);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tun_vhdrlen);
           sqlite3_bind_int64(stmt, bindIndex++, entry->tun_lro_ready);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

