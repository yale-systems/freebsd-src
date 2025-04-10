#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/mii_softc.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_mii_softc.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_mii_phys_mii_dev = 0,
    VT_mii_phys_mii_list = 1,
    VT_mii_phys_mii_mpd_oui = 2,
    VT_mii_phys_mii_mpd_model = 3,
    VT_mii_phys_mii_mpd_rev = 4,
    VT_mii_phys_mii_capmask = 5,
    VT_mii_phys_mii_phy = 6,
    VT_mii_phys_mii_offset = 7,
    VT_mii_phys_mii_inst = 8,
    VT_mii_phys_mii_funcs = 9,
    VT_mii_phys_mii_pdata = 10,
    VT_mii_phys_mii_flags = 11,
    VT_mii_phys_mii_capabilities = 12,
    VT_mii_phys_mii_extcapabilities = 13,
    VT_mii_phys_mii_ticks = 14,
    VT_mii_phys_mii_anegticks = 15,
    VT_mii_phys_mii_media_active = 16,
    VT_mii_phys_mii_media_status = 17,
    VT_mii_phys_mii_maxspeed = 18,
    VT_mii_phys_NUM_COLUMNS
};

static int
copy_columns(struct mii_softc *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_mii_phys_mii_dev] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->mii_dev, context);
//    columns[VT_mii_phys_mii_list] =  /* Unsupported type */
    columns[VT_mii_phys_mii_mpd_oui] = new_dbsc_int64(curEntry->mii_mpd_oui, context);
    columns[VT_mii_phys_mii_mpd_model] = new_dbsc_int64(curEntry->mii_mpd_model, context);
    columns[VT_mii_phys_mii_mpd_rev] = new_dbsc_int64(curEntry->mii_mpd_rev, context);
    columns[VT_mii_phys_mii_capmask] = new_dbsc_int64(curEntry->mii_capmask, context);
    columns[VT_mii_phys_mii_phy] = new_dbsc_int64(curEntry->mii_phy, context);
    columns[VT_mii_phys_mii_offset] = new_dbsc_int64(curEntry->mii_offset, context);
    columns[VT_mii_phys_mii_inst] = new_dbsc_int64(curEntry->mii_inst, context);
    columns[VT_mii_phys_mii_funcs] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->mii_funcs, context);
    columns[VT_mii_phys_mii_pdata] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->mii_pdata, context);
    columns[VT_mii_phys_mii_flags] = new_dbsc_int64(curEntry->mii_flags, context);
    columns[VT_mii_phys_mii_capabilities] = new_dbsc_int64(curEntry->mii_capabilities, context);
    columns[VT_mii_phys_mii_extcapabilities] = new_dbsc_int64(curEntry->mii_extcapabilities, context);
    columns[VT_mii_phys_mii_ticks] = new_dbsc_int64(curEntry->mii_ticks, context);
    columns[VT_mii_phys_mii_anegticks] = new_dbsc_int64(curEntry->mii_anegticks, context);
    columns[VT_mii_phys_mii_media_active] = new_dbsc_int64(curEntry->mii_media_active, context);
    columns[VT_mii_phys_mii_media_status] = new_dbsc_int64(curEntry->mii_media_status, context);
    columns[VT_mii_phys_mii_maxspeed] = new_dbsc_int64(curEntry->mii_maxspeed, context);

    return 0;
}
void
vtab_mii_softc_lock(void)
{
    sx_slock(&mii_phys_lock);
}

void
vtab_mii_softc_unlock(void)
{
    sx_sunlock(&mii_phys_lock);
}

void
vtab_mii_softc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct mii_softc *prc = LIST_FIRST(&mii_phys);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_mii_phys_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_mii_phys_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("mii_softc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
mii_softcvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_mii_phys_p_pid];
    *pRowid = pid_value->int64_value;
    printf("mii_softc_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
mii_softcvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
mii_softcvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_mii_softc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("mii_softc digest mismatch: UPDATE failed\n");
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
static sqlite3_module mii_softcvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ mii_softcvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ mii_softcvtabRowid,
    /* xUpdate     */ mii_softcvtabUpdate,
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
sqlite3_mii_softcvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &mii_softcvtabModule,
        pAux);
}
void vtab_mii_softc_serialize(sqlite3 *real_db, struct timespec when) {
    struct mii_softc *entry = LIST_FIRST(&mii_phys);

    const char *create_stmt =
        "CREATE TABLE all_mii_softcs (mii_mpd_oui INTEGER, mii_mpd_model INTEGER, mii_mpd_rev INTEGER, mii_capmask INTEGER, mii_phy INTEGER, mii_offset INTEGER, mii_inst INTEGER, mii_flags INTEGER, mii_capabilities INTEGER, mii_extcapabilities INTEGER, mii_ticks INTEGER, mii_anegticks INTEGER, mii_media_active INTEGER, mii_media_status INTEGER, mii_maxspeed INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_mii_softcs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_mpd_oui);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_mpd_model);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_mpd_rev);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_capmask);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_phy);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_offset);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_inst);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_capabilities);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_extcapabilities);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_ticks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_anegticks);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_media_active);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_media_status);
           sqlite3_bind_int64(stmt, bindIndex++, entry->mii_maxspeed);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

