#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/vxlan_softc.h>
#include <sys/signal.h>
#include <sys/tty.h>

#include <dbsc/value.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"
#include "vtab_vxlan_softc.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_list_vxl_ifp = 0,
    VT_list_vxl_reqcap = 1,
    VT_list_vxl_fibnum = 2,
    VT_list_vxl_sock = 3,
    VT_list_vxl_vni = 4,
    VT_list_vxl_src_addr = 5,
    VT_list_vxl_dst_addr = 6,
    VT_list_vxl_flags = 7,
    VT_list_vxl_port_hash_key = 8,
    VT_list_vxl_min_port = 9,
    VT_list_vxl_max_port = 10,
    VT_list_vxl_ttl = 11,
    VT_list_vxl_ftable_cnt = 12,
    VT_list_vxl_ftable_max = 13,
    VT_list_vxl_ftable_timeout = 14,
    VT_list_vxl_ftable_hash_key = 15,
    VT_list_vxl_ftable = 16,
    VT_list_vxl_default_fe = 17,
    VT_list_vxl_im4o = 18,
    VT_list_vxl_im6o = 19,
    VT_list_vxl_lock = 20,
    VT_list_vxl_refcnt = 21,
    VT_list_vxl_unit = 22,
    VT_list_vxl_vso_mc_index = 23,
    VT_list_vxl_stats = 24,
    VT_list_vxl_sysctl_node = 25,
    VT_list_vxl_sysctl_ctx = 26,
    VT_list_vxl_callout = 27,
    VT_list_vxl_hwaddr = 28,
    VT_list_vxl_mc_ifindex = 29,
    VT_list_vxl_mc_ifp = 30,
    VT_list_vxl_media = 31,
    VT_list_vxl_mc_ifname = 32,
    VT_list_vxl_entry = 33,
    VT_list_vxl_ifdetach_list = 34,
    VT_list_err_time = 35,
    VT_list_err_pps = 36,
    VT_list_NUM_COLUMNS
};

static int
copy_columns(struct vxlan_softc *curEntry, struct dbsc_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_list_vxl_ifp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vxl_ifp, context);
    columns[VT_list_vxl_reqcap] = new_dbsc_int64(curEntry->vxl_reqcap, context);
    columns[VT_list_vxl_fibnum] = new_dbsc_int64(curEntry->vxl_fibnum, context);
    columns[VT_list_vxl_sock] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vxl_sock, context);
    columns[VT_list_vxl_vni] = new_dbsc_int64(curEntry->vxl_vni, context);
//    columns[VT_list_vxl_src_addr] =  /* Unsupported type */
//    columns[VT_list_vxl_dst_addr] =  /* Unsupported type */
    columns[VT_list_vxl_flags] = new_dbsc_int64(curEntry->vxl_flags, context);
    columns[VT_list_vxl_port_hash_key] = new_dbsc_int64(curEntry->vxl_port_hash_key, context);
    columns[VT_list_vxl_min_port] = new_dbsc_int64(curEntry->vxl_min_port, context);
    columns[VT_list_vxl_max_port] = new_dbsc_int64(curEntry->vxl_max_port, context);
    columns[VT_list_vxl_ttl] = new_dbsc_int64(curEntry->vxl_ttl, context);
    columns[VT_list_vxl_ftable_cnt] = new_dbsc_int64(curEntry->vxl_ftable_cnt, context);
    columns[VT_list_vxl_ftable_max] = new_dbsc_int64(curEntry->vxl_ftable_max, context);
    columns[VT_list_vxl_ftable_timeout] = new_dbsc_int64(curEntry->vxl_ftable_timeout, context);
    columns[VT_list_vxl_ftable_hash_key] = new_dbsc_int64(curEntry->vxl_ftable_hash_key, context);
    columns[VT_list_vxl_ftable] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vxl_ftable, context);
//    columns[VT_list_vxl_default_fe] =  /* Unsupported type */
    columns[VT_list_vxl_im4o] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vxl_im4o, context);
    columns[VT_list_vxl_im6o] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vxl_im6o, context);
//    columns[VT_list_vxl_lock] =  /* Unsupported type */
    columns[VT_list_vxl_refcnt] = new_dbsc_int64(curEntry->vxl_refcnt, context);
    columns[VT_list_vxl_unit] = new_dbsc_int64(curEntry->vxl_unit, context);
    columns[VT_list_vxl_vso_mc_index] = new_dbsc_int64(curEntry->vxl_vso_mc_index, context);
//    columns[VT_list_vxl_stats] =  /* Unsupported type */
    columns[VT_list_vxl_sysctl_node] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vxl_sysctl_node, context);
//    columns[VT_list_vxl_sysctl_ctx] =  /* Unsupported type */
//    columns[VT_list_vxl_callout] =  /* Unsupported type */
//    columns[VT_list_vxl_hwaddr] =  /* Unsupported type */
    columns[VT_list_vxl_mc_ifindex] = new_dbsc_int64(curEntry->vxl_mc_ifindex, context);
    columns[VT_list_vxl_mc_ifp] = new_dbsc_int64((int64_t)(uintptr_t)curEntry->vxl_mc_ifp, context);
//    columns[VT_list_vxl_media] =  /* Unsupported type */
//    columns[VT_list_vxl_mc_ifname] =  /* Unsupported type */
//    columns[VT_list_vxl_entry] =  /* Unsupported type */
//    columns[VT_list_vxl_ifdetach_list] =  /* Unsupported type */
//    columns[VT_list_err_time] =  /* Unsupported type */
    columns[VT_list_err_pps] = new_dbsc_int64(curEntry->err_pps, context);

    return 0;
}
void
vtab_vxlan_softc_lock(void)
{
    sx_slock(&list_lock);
}

void
vtab_vxlan_softc_unlock(void)
{
    sx_sunlock(&list_lock);
}

void
vtab_vxlan_softc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct vxlan_softc *prc = LIST_FIRST(&list);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_list_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        struct dbsc_value **columns = new_osdb_columns(VT_list_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("vxlan_softc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
vxlan_softcvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    common_cursor *pCur = (common_cursor *)cur;
    struct dbsc_value *pid_value = pCur->row->columns[VT_list_p_pid];
    *pRowid = pid_value->int64_value;
    printf("vxlan_softc_rowid was called, returning %lld\n", *pRowid);
    return SQLITE_OK;
}

static int
vxlan_softcvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

extern int kern_cpuset_setaffinity(struct thread *td, cpulevel_t level, cpuwhich_t which, id_t id, cpuset_t *mask);
extern int cpuset_setproc(pid_t pid, struct cpuset *set, cpuset_t *mask, struct domainset *domain, bool rebase);

static int
vxlan_softcvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_vxlan_softc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("vxlan_softc digest mismatch: UPDATE failed\n");
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
static sqlite3_module vxlan_softcvtabModule = {
    /* iVersion    */ 0,
    /* xCreate     */ commonCreate,
    /* xConnect    */ commonConnect,
    /* xBestIndex  */ vxlan_softcvtabBestIndex,
    /* xDisconnect */ commonDisconnect,
    /* xDestroy    */ commonDisconnect,
    /* xOpen       */ commonOpen,
    /* xClose      */ commonClose,
    /* xFilter     */ commonFilter,
    /* xNext       */ commonNext,
    /* xEof        */ commonEof,
    /* xColumn     */ commonColumn,
    /* xRowid      */ vxlan_softcvtabRowid,
    /* xUpdate     */ vxlan_softcvtabUpdate,
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
sqlite3_vxlan_softcvtab_init(sqlite3 *db, char **pzErrMsg,
    const sqlite3_api_routines *pApi, void *pAux)
{
    SQLITE_EXTENSION_INIT2(pApi);
    return sqlite3_create_module(db,
        vtable_type_to_name(((osdb_vtab *)pAux)->type), &vxlan_softcvtabModule,
        pAux);
}
void vtab_vxlan_softc_serialize(sqlite3 *real_db, struct timespec when) {
    struct vxlan_softc *entry = LIST_FIRST(&list);

    const char *create_stmt =
        "CREATE TABLE all_vxlan_softcs (vxl_reqcap INTEGER, vxl_fibnum INTEGER, vxl_vni INTEGER, vxl_flags INTEGER, vxl_port_hash_key INTEGER, vxl_min_port INTEGER, vxl_max_port INTEGER, vxl_ttl INTEGER, vxl_ftable_cnt INTEGER, vxl_ftable_max INTEGER, vxl_ftable_timeout INTEGER, vxl_ftable_hash_key INTEGER, vxl_refcnt INTEGER, vxl_unit INTEGER, vxl_vso_mc_index INTEGER, vxl_mc_ifindex INTEGER, err_pps INTEGER)";
    char *errMsg = NULL;
    sqlite3_exec(real_db, create_stmt, NULL, NULL, &errMsg);

    const char *insert_stmt = "INSERT INTO all_vxlan_softcs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(real_db, insert_stmt, -1, &stmt, NULL);

    while (entry) {
        int bindIndex = 1;
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_reqcap);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_fibnum);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_vni);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_flags);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_port_hash_key);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_min_port);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_max_port);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_ttl);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_ftable_cnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_ftable_max);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_ftable_timeout);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_ftable_hash_key);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_refcnt);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_unit);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_vso_mc_index);
           sqlite3_bind_int64(stmt, bindIndex++, entry->vxl_mc_ifindex);
           sqlite3_bind_int64(stmt, bindIndex++, entry->err_pps);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
        entry = LIST_NEXT(entry,  p_list);
    }

    sqlite3_finalize(stmt);
}

