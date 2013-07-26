/*
 * $Id: convert_init.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
 *
 * (C) 2013-2014 see FreeWAF Development Team
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GNU Make; see the file LICENSE.GPLv2.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#include "convert_private.h"

const apr_dbd_driver_t  *driver     = NULL;     /* sqlite3' driver */
apr_dbd_t               *default_db = NULL;     /* handle of database DEFAULT_DB */
apr_dbd_t               *tmp_db     = NULL;     /* handle of database TEMP_DB */
struct bitmap           nbitmap;                /* manage rules' id */

apr_pool_t *pconv;      /* 规则转换模块使用到的内存池 */
apr_pool_t *ptrans;     /* 临时内存池 */

unsigned long kw_id_flag = 0;

/* 规则转换模块初始化 */
/* 初始化临时数据库，并创建其中的表 */
#if APU_HAVE_SQLITE3
static int convert_temp_db_create(void)
{
    int                     rv, nrow;
    char                    *state;
    apr_pool_t              *ptemp;
    apr_dbd_transaction_t   *trans = NULL;

    rv = apr_pool_create(&ptemp, ptrans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_open(driver, pconv, TEMP_DB, &tmp_db);
    if (rv > 0) {
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    /* 创建表sec_policy */
    state = apr_psprintf(ptemp, "CREATE TABLE %s ( " \
                         "sec_policy VARCHAR NOT NULL, " \
                         "sub_policy VARCHAR NOT NULL, " \
                         "keyword VARCHAR, " \
                         "action INTEGER, " \
                         "log INTEGER, " \
                         "status INTEGER)",  \
                         SEC_POLICY_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    /* 创建表keyword_id */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (keyword_id INTEGER NOT NULL, "\
                         "sec_policy VARCHAR NOT NULL, "\
                         "sec_subpolicy INTEGER NOT NULL, "\
                         " type INTEGER)",
                         KEYWORD_ID_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    /* 创建表keyword */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (keyword_id INTEGER NOT NULL, "\
                         "number INTEGER NOT NULL, "\
                         "value VARCHAR NOT NULL)",
                         KEYWORD_TAB);
    apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    /* 创建表new */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (keyword_id INTEGER NOT NULL, "\
                         "new_id INTEGER NOT NULL)", NEW_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    /* 创建用于扩展弱密码的表 */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (sec_policy VARCHAR NOT NULL, "\
                         "sec_subpolicy INTEGER NOT NULL, url VARCHAR NOT NULL, "\
                         "passwdname VARCHAR NOT NULL, url_type INTEGER NOT NULL, "\
                         "url_passwd_id INTEGER NOT NULL)", WEAK_PASSWD_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    /* 创建黑白名单表 */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (lst INTEGER NOT NULL, "\
                         "type INTEGER NOT NULL, keyword VARCHAR NOT NULL)",
                        BLACK_WHITE);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        apr_pool_destroy(ptemp);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    apr_pool_destroy(ptemp);
    if (rv > 0) {
        return CONV_FAIL;
    } else {
        return CONV_OK;
    }
}
#elif APU_HAVE_MYSQL
static void drop_tables(apr_pool_t *ptemp)
{
    int                     rv, nrow;
    char                    *state;
    apr_dbd_transaction_t   *trans = NULL;

    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);

    /* 删除表sec_policy */
    state = apr_psprintf(ptemp, "drop table %s", SEC_POLICY_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
    }

    /* 删除表keyword_id */
    state = apr_psprintf(ptemp, "drop table %s", KEYWORD_ID_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
    }

    /* 删除表keyword */
    state = apr_psprintf(ptemp, "drop table %s", KEYWORD_TAB);
    apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
    }

    /* 删除表new */
    state = apr_psprintf(ptemp, "drop table %s", NEW_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
    }

    /* 删除用于扩展弱密码的表 */
    state = apr_psprintf(ptemp, "drop table %s", WEAK_PASSWD_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
    }

    /* 删除黑白名单表 */
    state = apr_psprintf(ptemp, "drop table %s", BLACK_WHITE);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
    }

    apr_dbd_transaction_end(driver, ptemp, trans);
}

static int create_tables(apr_pool_t *ptemp)
{
    int                     rv, nrow;
    char                    *state;
    apr_dbd_transaction_t   *trans = NULL;

    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    /* 创建表sec_policy */
    state = apr_psprintf(ptemp, "CREATE TABLE %s ( " \
                         "sec_policy VARCHAR(256) NOT NULL, " \
                         "sub_policy VARCHAR(32) NOT NULL, " \
                         "keyword VARCHAR(32), " \
                         "action INTEGER, " \
                         "log INTEGER, " \
                         "status INTEGER) ENGINE=MEMORY",  \
                         SEC_POLICY_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);

        return CONV_FAIL;
    }

    /* 创建表keyword_id */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (keyword_id INTEGER NOT NULL, "\
                         "sec_policy VARCHAR(256) NOT NULL, "\
                         "sec_subpolicy INTEGER NOT NULL, "\
                         " type INTEGER) ENGINE=MEMORY",
                         KEYWORD_ID_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    /* 创建表keyword */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (keyword_id INTEGER NOT NULL, "\
                         "number INTEGER NOT NULL, "\
                         "value VARCHAR(256) NOT NULL) ENGINE=MEMORY",
                         KEYWORD_TAB);
    apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    /* 创建表new */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (keyword_id INTEGER NOT NULL, "\
                         "new_id INTEGER NOT NULL) ENGINE=MEMORY", NEW_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    /* 创建用于扩展弱密码的表 */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (sec_policy VARCHAR(256) NOT NULL, "\
                         "sec_subpolicy INTEGER NOT NULL, url VARCHAR(256) NOT NULL, "\
                         "passwdname VARCHAR(256) NOT NULL, url_type INTEGER NOT NULL, "\
                         "url_passwd_id INTEGER NOT NULL) ENGINE=MEMORY", WEAK_PASSWD_TAB);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    /* 创建黑白名单表 */
    state = apr_psprintf(ptemp, "CREATE TABLE %s (lst INTEGER NOT NULL, "\
                         "type INTEGER NOT NULL, keyword VARCHAR(256) NOT NULL) ENGINE=MEMORY",
                         BLACK_WHITE);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        return CONV_FAIL;
    } else {
        return CONV_OK;
    }
}

static int convert_temp_db_create(void)
{
    int                     rv;
    apr_pool_t              *ptemp;

    rv = apr_pool_create(&ptemp, ptrans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    drop_tables(ptemp);

    rv = create_tables(ptemp);
    apr_pool_destroy(ptemp);
    return rv;
}
#endif

/* 规则转换模块初始化 */
int convert_init(apr_pool_t *p, apr_pool_t *pconf)
{
    int rv;
#if APU_HAVE_MYSQL
    char *db_param;
    const char *error;
#endif

    if ((p == NULL) || (pconf == NULL)) {
        return CONV_FAIL;
    }

    /* 规则转换模块使用单独的持久内存池 */
    rv = apr_pool_create(&pconv, p);
    if (rv > 0) {
        return CONV_FAIL;
    }

    apr_pool_tag(pconv, "pconv");
    /* 中间数据使用临时内存池 */
    ptrans = p;
    apr_dbd_init(pconv);

    /* 获取数据库驱动 */
    rv = apr_dbd_get_driver(pconv, SQL_TYPE, &driver);
    if (rv > 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to load %s driver!", SQL_TYPE);
        return CONV_FAIL;
    }

    /* 打开内置安全策略库 */
#if APU_HAVE_SQLITE3
    rv = apr_dbd_open(driver, pconv, DEFAULT_DB, &default_db);
    if (rv > 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to open default database!");
        return CONV_FAIL;
    }
#elif APU_HAVE_MYSQL
    error = NULL;
    db_param = apr_psprintf(pconv, "host=%s;user=%s;pass=%s;dbname=%s", 
        DB_HOST, DB_USER, DB_PASS, DEFAULT_DB);
    rv = apr_dbd_open_ex(driver, pconv, db_param, &default_db, &error);
    if (rv > 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to connect database--%s", error);
        return CONV_FAIL;
    }

    tmp_db = default_db;
#endif
    /* 初始化临时数据库 */
    rv = convert_temp_db_create();
    if (rv != CONV_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "WAF_CONVERT: failure to open temporary database!");
        return CONV_FAIL;
    }

    subpolicy_init(pconv);

    /* 设置黑白名单初始值 */
    rv = convert_access_default_set();
    if (rv != CONV_OK) {
        return rv;
    }

    /* 初始化位图 */
    nbitmap = bm_alloc(MAX_POLICY);
    bm_setbit(&nbitmap, 0);     /* 不使用0作为ID */

    return CONV_OK;
}
