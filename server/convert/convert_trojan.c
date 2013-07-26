/*
 * $Id: convert_trojan.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

static char *trojan_flag = "trojan-keyword";

static char *trojan_rule = "SecRule RESPONSE_BODY \"%s\" \"phase:4,t:none,block,"\
                           "msg:'Backdoor access',id:'%s',tag:'Trojan Attack',severity:'2'\"";

static int trojan_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp);

static int trojan_keyword_add(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv, nrow, new_id;
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

    kw_id_flag++;
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

static int trojan_keyword_del(keyword_t *k, apr_pool_t *ptemp)
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
        return trojan_subpolicy_del(k->sec_policy, ptemp);
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

static int trojan_subpolicy_query(const char *name, apr_dbd_row_t *row,
        apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 i, rv;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    char                *rule, **new, *state;
    const char          *sec_name, *keyword, *rule_id, *entry;
    apr_pool_t          *tpool;
    apr_dbd_results_t   *trojan_res = NULL;
    apr_dbd_row_t       *trojan_row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT %s.new_id, %s.value FROM %s, %s where "\
                         "%s.keyword_id = %s.keyword_id and %s.keyword_id in (SELECT "\
                         "keyword_id from %s WHERE sec_policy = '%s' and sec_subpolicy = %d)",
                         NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB,
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, TROJAN);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &trojan_res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, trojan_res);
    if (rv == -1) {
        return CONV_FAIL;
    }

    tpool = (*result)->pool;

#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, trojan_res, &trojan_row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, trojan_res, &trojan_row, i);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        /* 生成新添加的规则 */
        entry = apr_dbd_get_entry(driver, trojan_row, 1);
        keyword = escape_keyword(entry, ptemp);
        rule_id = apr_dbd_get_entry(driver, trojan_row, 0);
        rule = apr_psprintf(ptemp, trojan_rule, keyword, rule_id);
        new = (char **)apr_array_push(*result);
        *new = apr_pstrdup(tpool, rule);
    }

    combined_rule(row, NULL, NULL, result, ptemp);
    return CONV_OK;
}

static int trojan_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp)
{

    return sub_with_new_del(sec_policy, TROJAN, ptemp);
}

static int trojan_subpolicy_list(const char *sec_policy,
                                        apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i;
#if APU_HAVE_MYSQL
    int                     num;
#endif
    char                **new, *state;
    const char          *sec_name, *entry;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;
    apr_pool_t          *ptab;
    keyword_t           *keyword, **new_keyword;

    if ( (result == NULL) || (*result == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    ptab = (*result)->pool;
    sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);

    state = apr_psprintf(ptemp, "select check_value from %s where flag = '%s'",
                         BASIC_TAB, trojan_flag);
    rv = apr_dbd_select(driver, ptemp, default_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {                 /* 查询失败 */
        return CONV_FAIL;
    } else if (rv == 0) {           /* 不存在内置库 */
        return CONV_OK;
    }

#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }

    entry = apr_dbd_get_entry(driver, row, 0);
    if (entry == NULL) {
        return CONV_FAIL;
    }

    keyword = apr_pcalloc(ptab, sizeof(keyword_t));

    keyword->keyword = apr_array_make(ptab, 1, sizeof(char *));
    keyword->flag = INNER_KEYWORD;
    new = (char **)apr_array_push(keyword->keyword);
    *new = apr_pstrdup(ptab, entry);

    new_keyword = (keyword_t **)apr_array_push(* result);
    *new_keyword = keyword;

    state = apr_psprintf(ptemp, "select value from %s where keyword_id in (select keyword_id"\
                         " from %s where sec_policy = '%s' and sec_subpolicy = %d)",
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, TROJAN);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {      /* 临时库中不存在关键字 */
        return CONV_OK;
    }

#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, i);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, row, 0);
        if (entry == NULL) {
            return CONV_FAIL;
        }

        keyword = apr_pcalloc(ptab, sizeof(keyword_t));

        keyword->keyword = apr_array_make(ptab, 1, sizeof(char *));
        keyword->flag = OUTER_KEYWORD;
        new = (char **)apr_array_push(keyword->keyword);
        *new = apr_pstrdup(ptab, entry);

        new_keyword = (keyword_t **)apr_array_push(* result);
        *new_keyword = keyword;
    }

    return OK;
}

/* 请求方法处理驱动结构 */
subpolicy_t trojan_subpolicy = {
    TROJAN,
    trojan_keyword_add,
    trojan_keyword_del,
    trojan_subpolicy_query,
    trojan_subpolicy_del,
    trojan_subpolicy_list
};

