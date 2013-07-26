/*
 * $Id: convert_sql_injection.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

static char *sql_flag = "sql-keyword";

static char * sql_rule = "SecRule TX:SQLI_SELECT_STATEMENT \"@contains %s\""
                         " \"phase:2,id:'%s',t:none,pass,nolog,"\
                         "setvar:tx.sqli_select_statement_count=+1,"\
                         "setvar:tx.sql_injection_score=+1\"";


static int sql_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp);

/* SQL注入防护相关子操作 */
static int sql_keyword_add(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv, nrow, new_id;
    unsigned long           kw_id;
    char                    *state, **kw;
    const char              *sec_name, *keyword;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_transaction_t   *trans = NULL;

    if ((k == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    /* 关键字数目不是一个则出错 */
    rv = k->keyword->nelts;
    if (rv != 1) {
        return CONV_FAIL;
    }

    kw = apr_array_pop(k->keyword);
    /* 查询内置安全策略库中是否已经存在此关键字 */
    rv = keyword_check(*kw, sql_flag, ptemp);
    if (rv != CONV_OK) {
        return rv;
    }

    /* 查询安全子策略下是否存在此关键字 */
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
    state = apr_psprintf(ptemp, "SELECT keyword_id FROM %s WHERE value = '%s' AND"\
                         " keyword_id IN (SELECT keyword_id FROM %s WHERE sec_policy"\
                         " = '%s' AND sec_subpolicy = %d)",
                         KEYWORD_TAB, keyword, KEYWORD_ID_TAB, sec_name, k->sec_subpolicy);

    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return DECLINED;
    } else if (rv > 0) {        /* 已经存在相同的关键字 */
        return CONV_CONFLICT;
    }

    kw_id = kw_id_flag++;
    new_id = bm_firstunset(&nbitmap);
    bm_setbit(&nbitmap, new_id);

    /* 插入指定的关键字 */
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, '%s', %d, %d)",
                         KEYWORD_ID_TAB, kw_id_flag, sec_name, k->sec_subpolicy, k->type);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d, '%s')",
                         KEYWORD_TAB, kw_id_flag, KEYWORD_FIRST, keyword);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d)",
                         NEW_TAB, kw_id_flag, new_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        return CONV_FAIL;
    }

    return CONV_OK;
}

/* 删除指定的单个关键字 */
static int sql_keyword_del(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv = 0;
    int                     new, nrow;
    char                    *state;
    const char              **kw, *kw_id, *new_id, *sec_name, *keyword;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;
    apr_dbd_transaction_t   *trans = NULL;

    if ((k == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    if (k->flag == FLAG_ALL) {
        return sql_subpolicy_del(k->sec_policy, ptemp);
    }

    /* 关键字数目不是一个则出错 */
    rv = k->keyword->nelts;
    if (rv != 1) {
        return CONV_FAIL;
    }

    kw = apr_array_pop(k->keyword);

    /* 查询安全子策略下是否存在此关键字 */
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
    state = apr_psprintf(ptemp, "SELECT keyword_id FROM %s WHERE value = '%s' AND"\
                         " keyword_id IN (SELECT keyword_id FROM %s WHERE sec_policy"\
                         " = '%s' AND sec_subpolicy = %d)",
                         KEYWORD_TAB, keyword, KEYWORD_ID_TAB, sec_name, k->sec_subpolicy);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {           /* 不存在此关键字 */
        return CONV_NOTEXIST;
    }

#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
    if (rv > 0) {
        return CONV_FAIL;
    }

    kw_id = apr_dbd_get_entry(driver, row, 0);
    if (kw_id == NULL) {
        return CONV_FAIL;
    }

    /* 获取增加关键字时分配的新规则的ID */
    state = apr_psprintf(ptemp, "SELECT new_id FROM %s where keyword_id = '%s'",
                         NEW_TAB, kw_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    }

#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }

    new_id = apr_dbd_get_entry(driver, row, 0);
    if (new_id == NULL) {
        return CONV_FAIL;
    }

    new = atoi(new_id);

    /* 删除数据库中的信息 */
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s where keyword_id = '%s'",
                         NEW_TAB, kw_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s where keyword_id = '%s'",
                         KEYWORD_TAB, kw_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s where keyword_id = '%s'",
                         KEYWORD_ID_TAB, kw_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    bm_clrbit(&nbitmap, new);
    return CONV_OK;
}

static void add_sql_rule(const char *name, apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 i, rv;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    char                *rule, **new, *state;
    const char          *sec_name, *keyword, *rule_id, *entry;
    apr_pool_t          *tpool;
    apr_dbd_results_t   *sql_res = NULL;
    apr_dbd_row_t       *sql_row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT %s.new_id, %s.value FROM %s, %s where "\
                         "%s.keyword_id = %s.keyword_id and %s.keyword_id in (SELECT "\
                         "keyword_id from %s WHERE sec_policy = '%s' and sec_subpolicy = %d)",
                         NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB,
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, SQL_INJECTION);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &sql_res, state, 1);
    if (rv > 0) {
        return;
    }
    rv = apr_dbd_num_tuples(driver, sql_res);
    if (rv == -1) {
        return;
    } else if (rv == 0){
        return ;
    }

    tpool = (*result)->pool;
#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, sql_res, &sql_row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, sql_res, &sql_row, i);
#endif
        if (rv == -1) {
            return;
        }

        /* 关键字若存在于内置安全策略库则不进行添加 */
        entry = apr_dbd_get_entry(driver, sql_row, 1);
        rv = keyword_check(entry, sql_flag, ptemp);
        if (rv == CONV_EXIST) {
            continue;
        } else if (rv == CONV_FAIL) {
            return;
        }

        /* 生成新添加的规则 */
        rule_id = apr_dbd_get_entry(driver, sql_row, 0);
        keyword = escape_keyword(entry, ptemp);
        rule = apr_psprintf(ptemp, sql_rule, keyword, rule_id);
        new = (char **)apr_array_push(*result);
        *new = apr_pstrdup(tpool, rule);
    }
}

static int sql_subpolicy_query(const char *name, apr_dbd_row_t *row,
                               apr_array_header_t **result, apr_pool_t *ptemp)
{
    int rv;

    rv = new_keyword_query(name, SQL_INJECTION, row, 0, result, ptemp);
    if (rv != CONV_OK) {
        return rv;
    }

    add_sql_rule(name, result, ptemp);
    return CONV_OK;
}

static int sql_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp)
{
    return sub_with_new_del(sec_policy, SQL_INJECTION, ptemp);
}

static int sql_subpolicy_list(const char *sec_policy, apr_array_header_t **result,
                              apr_pool_t *ptemp)
{
    return new_keyword_list(sec_policy, SQL_INJECTION, 0, sql_flag, ASCII, result, ptemp);
}

subpolicy_t sql_subpolicy = {
    SQL_INJECTION,
    sql_keyword_add,
    sql_keyword_del,
    sql_subpolicy_query,
    sql_subpolicy_del,
    sql_subpolicy_list
};
