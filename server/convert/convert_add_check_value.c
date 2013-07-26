/*
 * $Id: convert_add_check_value.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

/* 增加需要将关键字添加到对应规则中的检查值的关键字 */
int new_keyword_add(keyword_t *k, const char *flag, apr_pool_t *ptemp)
{
    int                     rv, nrows;
    char                    *state, **kw;
    const char              *sec_name, *keyword;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_transaction_t   *trans = NULL;

    if ((k == NULL ) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    if (k->keyword->nelts != 1) {
        return CONV_FAIL;
    }

    /* 提取关键字 */
    kw = apr_array_pop(k->keyword);
    /* 判断关键字是否已经存在于内置库中 */
    rv = keyword_check(*kw, flag, ptemp);
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: keyword \"%s\" "\
                     "already exist!", keyword);
        return CONV_CONFLICT;
    }

    kw_id_flag++;
    /* 插入指定的关键字 */
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        kw_id_flag--;
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, '%s', %d, %d)",
                         KEYWORD_ID_TAB, kw_id_flag, sec_name, k->sec_subpolicy, k->type);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);
    if (rv > 0) {
        kw_id_flag--;
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d, '%s')",
                         KEYWORD_TAB, kw_id_flag, KEYWORD_FIRST, keyword);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);
    if (rv > 0) {
        kw_id_flag--;
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        kw_id_flag--;
        return CONV_FAIL;
    }

    return CONV_OK;
}

/* 获取某一类关键字的ID */
static int get_keyword_id(keyword_t *k, apr_array_header_t **keyword_id, apr_pool_t *ptemp)
{
    int                     i, rv;
#if APU_HAVE_MYSQL
    int                     num;
#endif
    char                    *state, **new;
    const char              *sec_name, *entry;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;
    apr_pool_t              *ptab;

    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "select keyword_id from %s where sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %d",
                         KEYWORD_ID_TAB, sec_name, k->sec_subpolicy, k->type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv < 0) {
        return CONV_FAIL;
    } else if (rv == 0) {
        return CONV_OK;
    }

    ptab = (*keyword_id)->pool;
#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, res, &row, i);
#endif
        if (rv) {
            return CONV_FAIL;
        }

        /* 获得需要加入的关键字 */
        entry = apr_dbd_get_entry(driver, row, 0);
        new = (char **)apr_array_push(*keyword_id);
        *new = apr_pstrdup(ptab, entry);
    }

    return CONV_OK;
}

/* 删除所有需要添加到规则检查值中关键字 */
static int new_keyword_all_del(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv, i, nrows;
    char                    *state;
    const char              **kw_id;
    apr_dbd_transaction_t   *trans = NULL;
    apr_array_header_t      *keyword_id;

    keyword_id = apr_array_make(ptemp, 1, sizeof(char *));
    rv = get_keyword_id(k, &keyword_id, ptemp);
    if (rv != CONV_OK) {
        return rv;
    }

    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    for (i = keyword_id->nelts; i > 0; i--) {
        kw_id = apr_array_pop(keyword_id);
        state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id = %s",
                             KEYWORD_TAB, *kw_id);
        rv = apr_dbd_query(driver, tmp_db, &nrows, state);
        if (rv > 0) {
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id = %s",
                             KEYWORD_ID_TAB, *kw_id);
        rv = apr_dbd_query(driver, tmp_db, &nrows, state);
        if (rv > 0) {
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        return CONV_FAIL;
    } else {
        return CONV_OK;
    }
}

/* 删除需要添加到规则检查值中的某一个关键字 */
static int new_keyword_single_del(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv, nrows;
    char                    *state, **kw;
    const char              *kw_id, *sec_name, *keyword;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;
    apr_dbd_transaction_t   *trans = NULL;

    kw = apr_array_pop(k->keyword);
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
    state = apr_psprintf(ptemp, "select keyword_id from %s where value = '%s' and keyword_id"\
                         " in (SELECT keyword_id FROM %s where sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %d)", KEYWORD_TAB, keyword,
                         KEYWORD_ID_TAB, sec_name, k->sec_subpolicy, k->type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {    /* 不存在关键字，则返回成功 */
        return CONV_NOTEXIST;
    }

#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }

    kw_id = apr_dbd_get_entry(driver, row, 0);
    if (kw_id == NULL) {
        return CONV_FAIL;
    }

    /* 删除数据库中内容 */
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s where keyword_id = %s",
                         KEYWORD_TAB, kw_id);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s where keyword_id = %s",
                         KEYWORD_ID_TAB, kw_id);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);
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

/* 删除需要添加到规则检查值中的关键字 */
int new_keyword_del(keyword_t *k, apr_pool_t *ptemp)
{
    if ((k == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    if (k->flag == FLAG_ALL) {
        return new_keyword_all_del(k, ptemp);
    }

    return new_keyword_single_del(k, ptemp);
}

/* 删除无需添加新规则的关键字 */
int sub_without_new_del(const char *sec_policy, int sub_policy, apr_pool_t *ptemp)
{
    int                     rv, nrows;
    char                    *state;
    const char              *sec_name;
    apr_dbd_transaction_t   *trans = NULL;

    if ((sec_policy == NULL) || (sub_policy < SQL_INJECTION)
            || (sub_policy >= MAX_SUBPOLICY) || (ptemp == NULL)) {

    }

    sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);

    /* 删除数据库中的信息 */
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id in (SELECT keyword_id"\
                         " FROM %s where sec_policy = '%s' and sec_subpolicy = %d)",
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, sub_policy);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s where sec_policy = '%s' and sec_subpolicy = %d",
                         KEYWORD_ID_TAB, sec_name, sub_policy);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);
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

/* 删除需添加新规则ID的关键字 */
int sub_with_new_del(const char *sec_policy, int sub_policy, apr_pool_t *ptemp)
{
    int                     rv, i, nrow, new;
#if APU_HAVE_MYSQL
    int                     num;
#endif
    char                    *state;
    const char              *new_id, *sec_name;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;
    apr_dbd_transaction_t   *trans = NULL;
    apr_array_header_t      *id_arr;

    if ((sec_policy == NULL) || (sub_policy < SQL_INJECTION)
            || (sub_policy >= MAX_SUBPOLICY ) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "SELECT DISTINCT new_id FROM %s WHERE keyword_id in (SELECT"\
                         " keyword_id FROM %s where sec_policy = '%s' and sec_subpolicy = %d)",
                         NEW_TAB, KEYWORD_ID_TAB, sec_name, sub_policy);
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
        id_arr = apr_array_make(ptemp, 1, sizeof(int));
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

            new_id = apr_dbd_get_entry(driver, row, 0);
            new = atoi(new_id);
            *(int *)apr_array_push(id_arr) = new;
        }
    }

    /* 删除数据库中的信息 */
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id in (SELECT keyword_id"\
                         " FROM %s where sec_policy = '%s' and sec_subpolicy = %d)",
                         NEW_TAB, KEYWORD_ID_TAB, sec_name, sub_policy);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id in (SELECT keyword_id"\
                         " FROM %s where sec_policy = '%s' and sec_subpolicy = %d)",
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, sub_policy);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }


    state = apr_psprintf(ptemp, "DELETE FROM %s where sec_policy = '%s' and sec_subpolicy = %d",
                         KEYWORD_ID_TAB, sec_name, sub_policy);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    for (i = 0; i < id_arr->nelts; i++) {
        new = ((int *)id_arr->elts)[i];
        bm_clrbit(&nbitmap, new);
    }

    return CONV_OK;
}

/* 构建需要增加检查值的规则 */
int new_keyword_query(const char *name, int sec_subpolicy, apr_dbd_row_t *row, int type,
                           apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i;
#if APU_HAVE_MYSQL
    int                     num;
#endif
    const char          *sec_name, *variable, *entry;
    char                *state, *keyword;
    apr_dbd_results_t   *nres = NULL;
    apr_dbd_row_t       *nrow = NULL;

    if ((name == NULL) || (sec_subpolicy < SQL_INJECTION) || (sec_subpolicy >= MAX_SUBPOLICY)
            || (row == NULL) || (type < 0) || (result == NULL)
            || (*result == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT value FROM %s WHERE keyword_id in (select %s from"\
                         " keyword_id where sec_policy = '%s' and sec_subpolicy = %d "\
                         "and type = %d)", KEYWORD_TAB,
                         KEYWORD_ID_TAB, sec_name, sec_subpolicy, type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &nres, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, nres);

    keyword = NULL;
    variable = apr_dbd_get_entry(driver, row, B_CHK_VAL);
    if (rv < 0) {
        return CONV_FAIL;
    } else if (rv == 0) {
        combined_rule(row, variable, NULL, result, ptemp);
    } else {
#if APU_HAVE_SQLITE3
        for (i = rv; i > 0; i--) {
            rv = apr_dbd_get_row(driver, ptemp, nres, &nrow, -1);
#elif APU_HAVE_MYSQL
        num = rv;
        for (i = 1; i <= num; i++) {
            rv = apr_dbd_get_row(driver, ptemp, nres, &nrow, i);
#endif
            if (rv) {
                return CONV_FAIL;
            }

            /* 获得需要加入的关键字 */
            entry = apr_dbd_get_entry(driver, nrow, 0);
            keyword = escape_keyword(entry, ptemp);
            if (variable) {
                rv = strlen(variable) + strlen(keyword);
            } else {
                rv = strlen(keyword);
            }

            if (rv > KEYWORD_LEN) {
                combined_rule(row, variable, NULL, result, ptemp);
                variable = NULL;
            }
            if (sec_subpolicy == REQUEST_METHOD || sec_subpolicy == FILE_UPLOAD ||
                    sec_subpolicy == FILE_DOWNLOAD) {
                variable = apr_pstrcat(ptemp, keyword, " ", variable, " ", NULL);
            } else {
                variable = apr_pstrcat(ptemp, "\\\'",  keyword, "\\\' ", variable, " ", NULL);
            }
        }
    }

    if (variable) {
        combined_rule(row, variable, NULL, result, ptemp);
    }
    return CONV_OK;
}

/* 查询内置库中的关键字 */
static int inner_keyword_list(const char *mod_flag, int type, int conv_flag,
                       apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv;
    char                **new, *state, *p, *q, *kw_buf;
    const char          *entry, *modified;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;
    apr_pool_t          *ptab;
    keyword_t           *keyword, **new_keyword;

    ptab = (*result)->pool;
    modified = apr_dbd_escape(driver, ptemp, mod_flag, tmp_db);

    state = apr_psprintf(ptemp, "select check_value from %s where flag = '%s'",
                         BASIC_TAB, modified);
    rv = apr_dbd_select(driver, ptemp, default_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {                 /* 查询失败 */
        return CONV_FAIL;
    } else if (rv == 0) {           /* 不存在内置库 */
        return CONV_OK;
    } else if (rv != 1) {           /* 内置库规则不是一条 */
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

    entry = apr_dbd_get_entry(driver, row, 0);
    if (entry == NULL) {
        return CONV_FAIL;
    }

    p = (char *)entry;
    while (*p != '\0') {
        while (*p == ' ') {
            p++;;
        }

        if ((*p == '\\') && (*(p + 1) = '\'')) {       /* 字符串以\'分割 */
            p = p + 2;
            while (1) {
                q = strchr(p, '\\');
                if (q == NULL) {
                    break;
                } else if (*(q + 1) == '\'') {
                    *q = '\0';
                    break;
                }
            }
            q = q + 2;

        } else {                                    /* 字符串以空格分隔 */
            q = strchr(p, ' ');
            if (q != NULL) {
                *q = '\0';
            }
        }
        keyword = apr_pcalloc(ptab, sizeof(keyword_t));
        keyword->keyword = apr_array_make(ptab, 1, sizeof(char *));
        keyword->flag = INNER_KEYWORD;
        keyword->type = type;
        new = (char **)apr_array_push(keyword->keyword);
        if (conv_flag) {
            kw_buf = encode_output(p, ptemp);
            *new = apr_pstrdup(ptab, kw_buf);
        } else {
            *new = apr_pstrdup(ptab, p);
        } 
        
        new_keyword = (keyword_t **)apr_array_push(* result);
        *new_keyword = keyword;

        if (q == NULL) {
            break;
        }

        p = q + 1;
        while (*p == ' ') {     /* 去除后边的空白 */
            p++;
        }
    }
    return CONV_OK;
}

/* 查询需要添加规则关键字的规则中的关键字，包括内置和临时关键字 */
int new_keyword_list(const char *sec_policy, int sec_subpolicy, int type, const char *mod_flag,
                     int conv_flag, apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i, num;
    char                **new, *state, *kw_buf;
    const char          *sec_name, *entry;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;
    apr_pool_t          *ptab;
    keyword_t           *keyword, **new_keyword;

    if ((sec_policy == NULL) || (sec_subpolicy < SQL_INJECTION) || (sec_subpolicy >= MAX_SUBPOLICY)
            || (type < 0) || (result == NULL) || (*result == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    /* 查询是否启用该安全策略下的安全子策略 */
    sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "select * from %s where sec_policy = '%s' and sub_policy = '%s'",
                        SEC_POLICY_TAB, sec_name, policy_type[sec_subpolicy]);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {      /* 不存在此安全子策略 */
        return CONV_OK;
    }

    /* 查询内置安全策略库 */
    if (mod_flag != NULL) {
        rv = inner_keyword_list(mod_flag, type, conv_flag, result, ptemp);
        if (rv != CONV_OK) {
            return rv;
        }
    }

    /* 查询新增加的关键字 */
    ptab = (*result)->pool;
    state = apr_psprintf(ptemp, "select value from %s where keyword_id"\
                         " in (select keyword_id from %s where sec_policy"\
                         " = '%s' and sec_subpolicy = %d and type = %d)",
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, sec_subpolicy, type);
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
        keyword->type = type;
        new = (char **)apr_array_push(keyword->keyword);

        if (conv_flag) {
            kw_buf = encode_output((char *)entry, ptemp);
            *new = apr_pstrdup(ptab, kw_buf);
        } else {
            *new = apr_pstrdup(ptab, entry);
        }       

        new_keyword = (keyword_t **)apr_array_push(* result);
        *new_keyword = keyword;
    }

    return OK;
}
    
