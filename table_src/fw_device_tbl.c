#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/fw_device.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_fw_device.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_devices_dst = 0,
    VT_devices_eui = 1,
    VT_devices_speed = 2,
    VT_devices_maxrec = 3,
    VT_devices_nport = 4,
    VT_devices_power = 5,
    VT_devices_rommax = 6,
    VT_devices_csrrom = 7,
    VT_devices_rcnt = 8,
    VT_devices_fc = 9,
    VT_devices_status = 10,
    VT_devices_link = 11,
    VT_devices_NUM_COLUMNS
};

static int
copy_columns(struct fw_device *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_devices_dst] = new_dbsc_int64(curEntry->dst, context);
//    columns[VT_devices_eui] =  /* Unsupported type */
    columns[VT_devices_speed] = new_dbsc_int64(curEntry->speed, context);
    columns[VT_devices_maxrec] = new_dbsc_int64(curEntry->maxrec, context);
    columns[VT_devices_nport] = new_dbsc_int64(curEntry->nport, context);
    columns[VT_devices_power] = new_dbsc_int64(curEntry->power, context);
    columns[VT_devices_rommax] = new_dbsc_int64(curEntry->rommax, context);
//    columns[VT_devices_csrrom] =  /* Unsupported type */
    columns[VT_devices_rcnt] = new_dbsc_int64(curEntry->rcnt, context);
    columns[VT_devices_fc] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->fc, context);
    columns[VT_devices_status] = new_dbsc_int64(curEntry->status, context);
//    columns[VT_devices_link] =  /* Unsupported type */

    return 0;
}
void
vtab_fw_device_lock(void)
{
    sx_slock(&devices_lock);
}

void
vtab_fw_device_unlock(void)
{
    sx_sunlock(&devices_lock);
}

void
vtab_fw_device_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct fw_device *prc = LIST_FIRST(&devices);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_devices_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_devices_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("fw_device digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
fw_devicevtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_devices_p_pid];
    *pRowid = pid_value->int64_value;
    printf("fw_device_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
fw_devicevtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
fw_devicevtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_fw_device_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("fw_device digest mismatch: UPDATE failed\n");
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
static sqlite3_module fw_devicevtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ fw_devicevtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ fw_devicevtabRowid,
    /* xUpdate     */ fw_devicevtabUpdate,
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
sqlite3_fw_devicevtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &fw_devicevtabModule,
        pAux);
}
void vtab_fw_device_serialize(sqlite3 *real_db, struct timespec when) {
    struct fw_device *entry = LIST_FIRST(&devices);

    const char *create_stmt =
        "CREATE TABLE all_fw_devices (dst INTEGER, speed INTEGER, maxrec INTEGER, nport INTEGER, power INTEGER, rommax INTEGER, rcnt INTEGER, status INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_fw_devices VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->dst);
           sqlite3_bind_int64(stmt, bindIndex++, entry->speed);
           sqlite3_bind_int64(stmt, bindIndex++, entry->maxrec);
           sqlite3_bind_int64(stmt, bindIndex++, entry->nport);
           sqlite3_bind_int64(stmt, bindIndex++, entry->power);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rommax);
           sqlite3_bind_int64(stmt, bindIndex++, entry->rcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->status);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

