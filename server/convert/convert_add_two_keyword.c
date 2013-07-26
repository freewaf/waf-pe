/*
 * $Id: convert_add_two_keyword.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

int add_two_keyword(keyword_t *k, apr_pool_t *ptemp)
{
    int                     nkeyword, rv, new_id, nrow;
    char                    *old, *new, *state;
    const char              *sec_name, *old_str, *new_str;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_transaction_t   *trans = NULL;

    if ((k == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    /* 关键字数目不是两个则出错 */
    nkeyword = k->keyword->nelts;
    if (nkeyword != 2) {
        return CONV_FAIL;
    }

    /* 取出关键字 */
    new = ((char **)k->keyword->elts)[0];
    old = ((char **)k->keyword->elts)[1];

    /* 转换为利于存储的安全格式 */
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    new_str = apr_dbd_escape(driver, ptemp, new, tmp_db);
    old_str = apr_dbd_escape(driver, ptemp, old, tmp_db);

    /* 查询关键字是否存在 */
    state = apr_psprintf(ptemp, "select keyword_id from %s where value = '%s' and number = %d"\
                         " and keyword_id in (select keyword_id from %s where sec_policy = '%s'"\
                         " and sec_subpolicy = %d)",KEYWORD_TAB, old_str, KEYWORD_SECOND,
                         KEYWORD_ID_TAB, sec_name, k->sec_subpolicy);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv > 0) {        /* 已经存在相同的关键字 */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: keyword \"%s\" "\
                     "already exist!", old_str);
        return CONV_CONFLICT;
    }

    /* 申请新的规则ID */
    kw_id_flag++;
    new_id = bm_firstunset(&nbitmap);
    bm_setbit(&nbitmap, new_id);

    /* 插入对应关键字 */
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
                         KEYWORD_TAB, kw_id_flag, KEYWORD_FIRST, new_str);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d, '%s')",
                         KEYWORD_TAB, kw_id_flag, KEYWORD_SECOND, old_str);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d)", NEW_TAB, kw_id_flag, new_id);
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

int delete_two_keyword(keyword_t *k, apr_pool_t *ptemp, int flag)
{
    int                     rv = 0;
    int                     new, nrow;
    char                    *state;
    const char              **kw, *kw_id, *new_id, *sec_name, *keyword;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;
    apr_dbd_transaction_t   *trans = NULL;

    if ((k == NULL) || (ptemp == NULL) || (flag < 0)) {
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
    state = apr_psprintf(ptemp, "select keyword_id from %s where value = '%s' and number = %d"\
                         " and keyword_id in (select keyword_id from %s where sec_policy = '%s'"\
                         " and sec_subpolicy = %d)",KEYWORD_TAB, keyword, KEYWORD_SECOND,
                         KEYWORD_ID_TAB, sec_name, k->sec_subpolicy);

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

int query_info_leakage(const char *name, int type, char *orig_rule,
                       apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i, num;
    char                **new, *state, *rule;
    const char          *sec_name, *entry, *kw_id, *old_str, *new_str, *new_id;
    apr_dbd_results_t   *res = NULL, *sub_res = NULL;
    apr_dbd_row_t       *row = NULL, *sub_row = NULL;
    apr_pool_t          *tpool;

    if ((name == NULL) || (type < SQL_INJECTION) || (type >= MAX_SUBPOLICY)
            || (result == NULL) || (*result == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    tpool = (*result)->pool;
    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "select distinct keyword_id from %s where sec_policy = '%s'"\
                         " and sec_subpolicy = %d", KEYWORD_ID_TAB, sec_name, type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {
        return CONV_OK;
    } else {
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

            kw_id = apr_dbd_get_entry(driver, row, 0);
            state = apr_psprintf(ptemp, "select value from %s where keyword_id = %s order"\
                                 " by number", KEYWORD_TAB, kw_id);
            rv = apr_dbd_select(driver, ptemp, tmp_db, &sub_res, state, 1);
            if (rv > 0) {
                return CONV_FAIL;
            }

            rv = apr_dbd_num_tuples(driver, sub_res);
            if (rv != 2) {              /* 关键字必须两个都出现 */
                return CONV_FAIL;
            }

            /* 第一个关键字 */
#if APU_HAVE_SQLITE3
            rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, -1);
#elif APU_HAVE_MYSQL
            rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, 1);
#endif
            if (rv == -1) {
                return CONV_FAIL;
            }
            entry = apr_dbd_get_entry(driver, sub_row, 0);
            new_str = escape(entry, ptemp);
            if (new_str == NULL) {
                return CONV_FAIL;
            }

            /* 第二个关键字 */
#if APU_HAVE_SQLITE3
            rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, -1);
#elif APU_HAVE_MYSQL
            rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, 2);
#endif
            if (rv == -1) {
                return CONV_FAIL;
            }
            entry = apr_dbd_get_entry(driver, sub_row, 0);
            old_str = escape(entry, ptemp);
            if (old_str == NULL) {
                return CONV_FAIL;
            }

            /* 新规则id */
            state = apr_psprintf(ptemp, "select new_id from %s where keyword_id = %s",
                                 NEW_TAB, kw_id);
            rv = apr_dbd_select(driver, ptemp, tmp_db, &sub_res, state, 1);
            if (rv > 0) {
                return CONV_FAIL;
            }

            rv = apr_dbd_num_tuples(driver, sub_res);
            if (rv != 1) {              /* 必须存在新规则id */
                return CONV_FAIL;
            }

            /* 获得规则id */
#if APU_HAVE_SQLITE3
            rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, -1);
#elif APU_HAVE_MYSQL
            rv = apr_dbd_get_row(driver, ptemp, sub_res, &sub_row, 1);
#endif
            if (rv == -1) {
                return CONV_FAIL;
            }
            new_id = apr_dbd_get_entry(driver, sub_row, 0);

            /* 生成规则 */
            rule = apr_psprintf(ptemp, orig_rule, old_str, new_str, new_id);

            new = (char **)apr_array_push(*result);
            *new = apr_pstrdup(tpool, rule);
        }
    }

    return CONV_OK;
}

static int get_keyword(const char *kw_id, keyword_t *keyword, apr_pool_t *ptemp)
{
    int                 rv;
    char                **new, *state;
    const char          *entry;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;
    apr_pool_t          *ptab;

    ptab = keyword->pool;
    state = apr_psprintf(ptemp, "select value from %s where keyword_id = %s order"\
                         " by number", KEYWORD_TAB, kw_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv != 2) {              /* 关键字必须两个都出现 */
        return CONV_FAIL;
    }

    /* 第一个关键字 */
#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }

    entry = apr_dbd_get_entry(driver, row, 0);
    keyword->keyword = apr_array_make(ptab, 1, sizeof(char *));
    keyword->flag = OUTER_KEYWORD;
    keyword->type = 0;
    new = (char **)apr_array_push(keyword->keyword);
    *new = apr_pstrdup(ptab, entry);

    /* 第二个关键字 */
#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 2);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }

    entry = apr_dbd_get_entry(driver, row, 0);
    new = (char **)apr_array_push(keyword->keyword);
    *new = apr_pstrdup(ptab, entry);

    return CONV_OK;
}

int list_two_keyword(const char *sec_policy, int sec_subpolicy,
                                  apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    char                *state;
    const char          *sec_name, *kw_id, *type;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;
    keyword_t           *keyword, **new_keyword;
    apr_pool_t          *ptab;

    if ((sec_policy == NULL) || (sec_subpolicy < 0) || (result == NULL)
            || (*result == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "select keyword_id, type from %s where sec_policy = '%s'"\
                         " and sec_subpolicy = %d", KEYWORD_ID_TAB, sec_name, sec_subpolicy);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {
        return CONV_OK;
    } else {
        ptab = (*result)->pool;
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

            kw_id = apr_dbd_get_entry(driver, row, 0);
            keyword = apr_pcalloc(ptab, sizeof(keyword_t));
            keyword->pool = ptab;

            /* 获取关键字 */
            rv = get_keyword(kw_id, keyword, ptemp);
            if (rv != CONV_OK) {
                return rv;
            }

            /* 获取type */
            type = apr_dbd_get_entry(driver, row, 1);
            keyword->type = atoi(type);

            new_keyword = (keyword_t **)apr_array_push(* result);
            *new_keyword = keyword;
        }
    }
    return CONV_OK;
}
    
