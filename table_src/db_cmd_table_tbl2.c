#include <sys/types.h>

#include "osdb.h"
#include "osdb_mod.h"
#include "sqlite3ext.h"
#include "vtab_common.h"

SQLITE_EXTENSION_INIT1

enum col {
    VT_db_cmd_table_name = 0,
    VT_db_cmd_table_fcn = 1,
    VT_db_cmd_table_flag = 2,
    VT_db_cmd_table_more = 3,
    VT_db_cmd_table_next = 4,
    VT_db_cmd_table_mac_priv = 5,
    VT_db_cmd_table_NUM_COLUMNS
};

static int
copy_columns(struct db_cmd_table *curEntry, osdb_value **columns, struct timespec *when, MD5_CTX *context) {

    columns[VT_db_cmd_table_name] = new_osdb_text(curEntry->name, strlen(curEntry->name) + 1, context);
//    columns[VT_db_cmd_table_fcn] =  TODO: Handle other types
    columns[VT_db_cmd_table_flag] = new_osdb_int64(curEntry->flag, context);
//    columns[VT_db_cmd_table_more] =  TODO: Handle other types
//    columns[VT_db_cmd_table_next] =  TODO: Handle other types
//    columns[VT_db_cmd_table_mac_priv] =  TODO: Handle other types

    return 0;
}
void
vtab_proc_lock(void)
{
    sx_slock(&db_cmd_table_lock);
}

void
vtab_proc_unlock(void)
{
    sx_sunlock(&db_cmd_table_lock);
}

void
vtab_proc_snapshot(sqlite3_vtab *pVtab, struct timespec when)
{
    struct db_command_table *prc = LIST_FIRST(&db_cmd_table);

    osdb_snap *snap = malloc(sizeof(struct osdb_snap), M_SQLITE, M_WAITOK);
    snap->when = when;
    snap->snap_table = new_osdb_table(VT_db_cmd_table_NUM_COLUMNS);
    MD5Init(&snap->context);

    while (prc) {
        osdb_value **columns = new_osdb_columns(VT_db_cmd_table_NUM_COLUMNS);
        if (!columns) {
            return;
        }
        copy_columns(prc, columns, &snap->when, &snap->context);
        osdb_table_push(snap->snap_table, columns);
        prc = LIST_NEXT(prc, p_list);
    }

    MD5Final(snap->digest, &snap->context);
#ifdef DEBUG
    printf("proc digest: ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhx", snap->digest[i]);
    }
    printf("\n");
#endif
    osdb_snapshot_rotate((struct osdb_vtab *)pVtab, snap);
}

static int
procvtabRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
#if 1
    common_cursor *pCur = (common_cursor *)cur;
    osdb_value *pid_value = pCur->row->columns[VT_PROC_PID];
    *pRowid = pid_value->int64_value;
    printf("%s was called returning %lld pRowid\n", __func__, *pRowid);
#else
    printf("%s not implemented\n", __func__);
#endif
    return SQLITE_OK;
}

static int
procvtabBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo)
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

static int
procvtabUpdate(sqlite3_vtab *pVTab, int argc, sqlite3_value **argv, sqlite_int64 *pRowid)
{
    struct timespec when;
    nanotime(&when);
    vtab_proc_snapshot(pVTab, when);
    if (osdb_snapshot_compare((struct osdb_vtab *)pVTab) <= 0) {
#ifdef DEBUG
        printf("proc Digest mismatch UPDATE failed\n");
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
