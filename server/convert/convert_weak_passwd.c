/*
 * $Id: convert_weak_passwd.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

static unsigned long url_pwd_id = 0;
static char *plain_flag = "weak-password-keyword-pm";
static char *regular_flag = "weak-password-keyword-rx";

/* 检查表WEAK_PASSWD_TAB中是否已经存在指定的url-passwdname对，存在则返回其ID，否则返回NULL */
static int check_url(const char *sec_name, const char *url, const char *pwdname, int type,
                      const char **url_id, apr_pool_t *ptemp)
{
    int                 rv;
    char                *state;
    const char          *entry, *pwdname_buf;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    /* 查询URL是否存在 */
    state = apr_psprintf(ptemp, "SELECT url_passwd_id, passwdname FROM %s WHERE"\
                         " sec_policy = '%s' and sec_subpolicy = %d and url = '%s' and"\
                         " url_type = %d", WEAK_PASSWD_TAB, sec_name, WEAK_PASSWORD, url, type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {        /* 不存在对应的url */
        return CONV_OK;
    } else if (rv != 1) {       /* 一个url只能对应一个passwdname */
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
    *url_id = entry;
    entry = apr_dbd_get_entry(driver, row, 1);
    pwdname_buf = apr_dbd_escape(driver, ptemp, entry, tmp_db);
    rv = strcmp(pwdname_buf, pwdname);
    if (rv == 0) {              /* 存在相同的url-passwdname对 */
        return CONV_EXIST;
    } else {                    /* 存在相同的url，但passwdname不同 */
        return CONV_CONFLICT;
    }
}

/* 添加url-passwd对到表WEAK_PASSWD_TAB中去，并返回对应的url_id */
static int add_url(const char *sec_name, const char *url, const char *pwdname, int type,
                   const char **url_id, apr_pool_t *ptemp)
{
    int     rv, nrow;
    char    *state;

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES ('%s', %d, '%s', '%s', %d, %ld)",
                         WEAK_PASSWD_TAB, sec_name, WEAK_PASSWORD, url, pwdname,
                         type, ++url_pwd_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        url_pwd_id--;
        return CONV_FAIL;
    }

    *url_id = apr_ltoa(ptemp, url_pwd_id);
    return CONV_OK;
}

/* 检查关键字 */
static int check_keyword(const char *sec_name, const char *keyword, const char *url_id,
                         int kw_type, apr_pool_t *ptemp)
{
    int                 rv;
    char                *state;
    apr_dbd_results_t   *res = NULL;

    /**
    * 检查配置库
    * 1、对于正则只检查配置库
    * 2、对于字符串还需要检查内置库
    */
    state = apr_psprintf(ptemp, "select * from %s where value = '%s' and number = %d and"\
                         " keyword_id in (select keyword_id from %s where sec_policy = '%s'"\
                         " and sec_subpolicy = %d and type = %s)", KEYWORD_TAB, keyword,
                         kw_type, KEYWORD_ID_TAB, sec_name, WEAK_PASSWORD, url_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv > 0) {        /* 已经存在相同的关键字 */
        return CONV_CONFLICT;
    }

    if (kw_type != PLAIN) {
        return CONV_OK;
    }

    /* 检查内置库 */
    return keyword_check(keyword, plain_flag, ptemp);
}

static int add_keyword(const char *sec_name, const char *keyword, const char *url_id,
                       int kw_type, apr_pool_t *ptemp)
{
    int                     rv, nrow;
    char                    *state;
    apr_dbd_transaction_t   *trans = NULL;

    kw_id_flag++;
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        kw_id_flag--;
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, '%s', %d, %s)",
                         KEYWORD_ID_TAB, kw_id_flag, sec_name, WEAK_PASSWORD, url_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        kw_id_flag--;
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d, '%s')",
                         KEYWORD_TAB, kw_id_flag, kw_type, keyword);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
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

static int modify_regular(const char *sec_name, const char *keyword, const char *url_id,
                          int kw_type, apr_pool_t *ptemp)
{
    int                 rv, nrow;
    char                *state;
    const char          *kw_id;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    /* 判断是否存在正则 */
    state = apr_psprintf(ptemp, "SELECT keyword_id FROM %s WHERE sec_policy = '%s' and"\
                         " sec_subpolicy = %d AND type = %s AND keyword_id IN (SELECT"\
                         " keyword_id FROM %s WHERE number = %d OR number = %d)",
                         KEYWORD_ID_TAB, sec_name, WEAK_PASSWORD, url_id, KEYWORD_TAB,
                         REGEX, DEF_REGEX);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return DECLINED;
    } else if (rv == 0) {               /* 不存在正则，则需要添加 */
        return add_keyword(sec_name, keyword, url_id, kw_type, ptemp);
    } else {                            /* 已经存在正则，则只需要更新 */
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

        state = apr_psprintf(ptemp, "UPDATE %s SET value = '%s' ,number = %d WHERE"\
                             " keyword_id = %s", KEYWORD_TAB, keyword, kw_type, kw_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            return CONV_FAIL;
        } else {
            return CONV_OK;
        }
    }
}

static int weak_passwd_keyword_add(keyword_t *k, apr_pool_t *ptemp)
{
    int         rv, url_type, kw_type;
    char        **kw_arr, *kw_buf;
    const char  *sec_name, *keyword, *pwdname, *urlstring, *url_id;

    if (k == NULL || k->keyword->nelts > 3) {
        return CONV_FAIL;
    }

    if (k->sec_policy == NULL || *(k->sec_policy) == '\0') {
        return CONV_FAIL;
    }
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);

    if (k->keyword->nelts < 2) {
        return CONV_FAIL;
    }

    kw_arr = (char **)k->keyword->elts;
    kw_buf = kw_arr[0];
    if (*kw_buf == '\0') {
        return CONV_FAIL;
    }
    urlstring = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);

    kw_buf = kw_arr[1];
    if (*kw_buf == '\0') {
        return CONV_FAIL;
    }
    pwdname = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);

    if (k->type == PLAIN_URL || k->type == PLAIN_PLAIN ||k->type == PLAIN_REGEX) {
        url_type = PLAIN;
    } else {
        url_type = REGEX;
    }

    url_id = NULL;  
    rv = check_url(sec_name, urlstring, pwdname, url_type, &url_id, ptemp);
    if (rv == CONV_FAIL || rv == CONV_CONFLICT) {
        return rv;
    }

    /* 添加URL */
    if (url_id == NULL) {
        rv = add_url(sec_name, urlstring, pwdname, url_type, &url_id, ptemp);
        if (rv != CONV_OK) {
            return CONV_FAIL;
        }
    }

    /* 关键字数目不对则出错 */
    if (k->keyword->nelts == 2) {
        return CONV_OK;
    } else if (k->keyword->nelts != 3) {
        return CONV_FAIL;
    }

    kw_buf = kw_arr[2];
    if (*kw_buf == '\0') {
        return CONV_FAIL;
    }
    keyword = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);

    if (k->type == PLAIN_PLAIN || k->type == REGEX_PLAIN) {
        kw_type = PLAIN;
    } else {
        if (k->flag == WP_KEYWORD_DEFAULT) {
            kw_type = DEF_REGEX;
        } else {
            kw_type = REGEX;
        }
    }

    rv = check_keyword(sec_name, keyword, url_id, kw_type, ptemp);
    if (rv == CONV_CONFLICT) {        /* 存在指定关键字 */
        return CONV_CONFLICT;
    } else if (rv == CONV_FAIL) {
        return CONV_FAIL;
    }

    if (kw_type == PLAIN) {     /* 添加普通字符串 */
        rv = add_keyword(sec_name, keyword, url_id, kw_type, ptemp);
        if (rv != CONV_OK) {
            return CONV_FAIL;
        }
    } else {                    /* 修改正则 */
        return modify_regular(sec_name, keyword, url_id, kw_type, ptemp);
    }

    return CONV_OK;
}

/* 获取url_id列表 */
static int get_url_id_list(keyword_t *k, apr_array_header_t **url_id_arr, apr_pool_t *ptemp)
{
    int                 rv, i, type;
#if APU_HAVE_MYSQL
    int                     num;
#endif
    char                *state, **kw_arr, *kw_buf;
    const char          *sec_name, *pwdname, *urlstring, *entry, **new;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    if (k == NULL || k->sec_policy == NULL || *(k->sec_policy) == '\0') {
        return CONV_FAIL;
    }
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    urlstring = NULL;
    pwdname = NULL;
    if (k->flag != WP_NO_URL_ALL ) {       
        if (k->keyword->nelts < 1) {
            return CONV_FAIL;
        }
        kw_arr = (char **)k->keyword->elts;
        kw_buf = kw_arr[0];
        if (*kw_buf == '\0') {
            return CONV_FAIL;
        }
        urlstring = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);
        if (k->keyword->nelts > 1) {
            kw_buf = kw_arr[1];
            if (*kw_buf == '\0') {
                return CONV_FAIL;
            }
            pwdname = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);
        }
    }

    if (k->flag == WP_NO_URL_ALL) {
        state = apr_psprintf(ptemp, "SELECT url_passwd_id FROM %s WHERE sec_policy = '%s' "\
                             "and sec_subpolicy = %d", WEAK_PASSWD_TAB, sec_name, WEAK_PASSWORD);
    } else {
        if (k->type == PLAIN_URL || k->type == PLAIN_PLAIN ||k->type == PLAIN_REGEX) {
            type = PLAIN;
        } else {
            type = REGEX;
        }

        state = apr_psprintf(ptemp, "SELECT url_passwd_id FROM %s WHERE sec_policy = '%s' "\
                                 "and sec_subpolicy = %d and url = '%s' and url_type = %d",
                                 WEAK_PASSWD_TAB, sec_name, WEAK_PASSWORD, urlstring, type);
    }    
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {        /* 不存在对应的url */
        return CONV_NOTEXIST;
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
        new = (const char **)apr_array_push(*url_id_arr);
        *new = entry;
    }
    return CONV_OK;
}

/* 删除指定url下所有的关键字，将正则恢复为初始正则 */
static int del_all_weak(const char *sec_name, int flag, apr_array_header_t *url_id_arr, apr_pool_t *ptemp)
{
    int                     rv, i, nrow;
    char                    *state;
    const char              **url_id;
    apr_dbd_transaction_t   *trans = NULL;

    for (i = url_id_arr->nelts; i > 0; i--) {
        url_id = apr_array_pop(url_id_arr);

        rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
        if (rv > 0) {
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "delete from %s where keyword_id in (select keyword_id"\
                             " from %s where sec_policy = '%s' and sec_subpolicy = %d and"\
                             " type = %s)", KEYWORD_TAB, KEYWORD_ID_TAB, sec_name,
                             WEAK_PASSWORD, *url_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "delete from %s where sec_policy = '%s' and sec_subpolicy"\
                             " = %d and type = %s", KEYWORD_ID_TAB, sec_name,
                             WEAK_PASSWORD, *url_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }

        rv = apr_dbd_transaction_end(driver, ptemp, trans);
        if (rv > 0) {
            return CONV_FAIL;
        }
    }

    return CONV_OK;
}

static int get_keywrod_id(const char *sec_name, const char *url_id, const char *keyword,
                          int kw_type, const char **kw_id, apr_pool_t *ptemp)
{
    int                 rv;
    char                *state;
    const char          *entry;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    if (kw_type == PLAIN) {
    state = apr_psprintf(ptemp, "select keyword_id from %s where value = '%s' and number = %d"\
                         " and keyword_id in (select keyword_id from %s where sec_policy = '%s'"\
                         " and sec_subpolicy = %d and type = %s)", KEYWORD_TAB, keyword,
                         kw_type, KEYWORD_ID_TAB, sec_name, WEAK_PASSWORD, url_id);
    } else {
        state = apr_psprintf(ptemp, "select keyword_id from %s where keyword_id in (select"\
                            " keyword_id from %s where sec_policy = '%s' and sec_subpolicy = %d"\
                            " and type = %s) and number = %d or number = %d", KEYWORD_TAB, 
                            KEYWORD_ID_TAB, sec_name,WEAK_PASSWORD, url_id, DEF_REGEX, REGEX);
    }
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {        /* 不存在相同的关键字 */
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

    entry = apr_dbd_get_entry(driver, row, 0);
    *kw_id = entry;
    return CONV_OK;
}

static int del_one_keyword(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv, url_type, kw_type, nrow;
    char                    **kw_arr, *kw_buf, *state;
    const char              *sec_name, *keyword, *pwdname, *urlstring, *url_id, *kw_id;
    apr_dbd_transaction_t   *trans = NULL;

    if (k == NULL || (k->keyword->nelts < 2 && k->keyword->nelts > 3)) {
        return CONV_FAIL;
    }

    if (k->sec_policy == NULL || *(k->sec_policy) == '\0') {
        return CONV_FAIL;
    }
    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);

    kw_arr = (char **)k->keyword->elts;
    kw_buf = kw_arr[0];
    if (*kw_buf == '\0') {
        return CONV_FAIL;
    }
    urlstring = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);

    kw_buf = kw_arr[1];
    if (*kw_buf == '\0') {
        return CONV_FAIL;
    }
    pwdname = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);

    if (k->type == PLAIN_URL || k->type == PLAIN_PLAIN ||k->type == PLAIN_REGEX) {
        url_type = PLAIN;
    } else {
        url_type = REGEX;
    }

    /* 获取url_id */
    url_id = NULL;
    rv = check_url(sec_name, urlstring, pwdname, url_type, &url_id, ptemp);
    if (rv != CONV_EXIST) {
        return rv;
    }

    /* 获取keyword_id */
    keyword = NULL;
    if (k->keyword->nelts == 3) {
        kw_buf = kw_arr[2];
        if (*kw_buf == '\0') {
            return CONV_FAIL;
        }
        keyword = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);
    }

    if (k->type == PLAIN_PLAIN || k->type == REGEX_PLAIN) {
        kw_type = PLAIN;
    } else {
        kw_type = REGEX;
    }

    rv = get_keywrod_id(sec_name, url_id, keyword, kw_type, &kw_id, ptemp);
    if (rv != CONV_OK) {
        return rv;
    }

    /* 删除keyword */
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id = %s", KEYWORD_TAB, kw_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id = %s", KEYWORD_ID_TAB, kw_id);
    rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    if (rv > 0) {
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    return CONV_OK;
}

static int weak_passwd_keyword_del(keyword_t *k, apr_pool_t *ptemp)
{
    int                 rv, url_type, nrow;
    const char          *sec_name, *urlstring;
    char                *state, **kw_arr, *kw_buf;
    apr_array_header_t  *url_id_arr;

    if (k->flag == WP_KEYWORD) {        /* 删除单个关键字 */
        return del_one_keyword(k, ptemp);
    }

    url_id_arr = apr_array_make(ptemp, 1, sizeof(char *));
    rv = get_url_id_list(k, &url_id_arr, ptemp);
    if (rv != CONV_OK) {
        return rv;
    }

    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    rv = del_all_weak(sec_name, k->flag, url_id_arr, ptemp);
    if (rv != CONV_OK) {
        return rv;
    }

    if (k->type == PLAIN_URL || k->type == PLAIN_PLAIN ||k->type == PLAIN_REGEX) {
        url_type = PLAIN;
    } else {
        url_type = REGEX;
    }
    if (k->flag == WP_NO_URL_ALL) {
        state = apr_psprintf(ptemp, "delete from %s where sec_policy = '%s' and"\
                             " sec_subpolicy = %d", WEAK_PASSWD_TAB, sec_name, WEAK_PASSWORD);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    } else if (k->flag == WP_NO_URL) {
        kw_arr = (char **)k->keyword->elts;
        kw_buf = kw_arr[0]; 
        urlstring = apr_dbd_escape(driver, ptemp, kw_buf, tmp_db);
        state = apr_psprintf(ptemp, "delete from %s where sec_policy = '%s' and"\
                             " sec_subpolicy = %d and url_type = %d and url = '%s'",
                             WEAK_PASSWD_TAB, sec_name, WEAK_PASSWORD, url_type, urlstring);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
    } 

    if (rv > 0) {
        return CONV_FAIL;
    }
    return CONV_OK;
}

static void combined_weak_rule(apr_dbd_row_t *row, const char *pwdname, const char *check_val,
                             apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 i, flag;
    const char          *entry;
    char                *rule, **new;
    apr_pool_t          *tpool;

    flag = 0;
    rule = NULL;
    for (i = B_LIST_ID; i < TOTAL; i++) {
        entry = apr_dbd_get_entry(driver, row, i);
        switch(i) {
            case B_LIST_ID:             /* basis.list_id */
            case B_TYPE:             /* basis.type */
            case B_FLAG:             /* basis.flag */
            case E_LIST_ID:            /* extension.list_id */
                break;
            case B_KEYWORD:             /* basis.keyword */
                rule = apr_psprintf(ptemp, "%s", entry);
                break;
            case B_VAR:             /* basis.variable */
                if (!pwdname) {
                    rule = apr_pstrcat(ptemp, rule, " ", entry, NULL);
                } else {
                    rule = apr_pstrcat(ptemp, rule, " ARGS:", pwdname, NULL);
                }
                break;
            case B_OPER:             /* basis.operator */
                rule = apr_pstrcat(ptemp, rule, " \"", entry, NULL);
                break;
            case B_CHK_VAL:             /* basis.check_value */
                if (check_val) {
                    rule = apr_pstrcat(ptemp, rule, " ", check_val, "\"", NULL);
                } else {
                    rule = apr_pstrcat(ptemp, rule, " ", entry, "\"", NULL);
                }
                break;
            case B_CHAIN:             /* basis.chain */
                if (entry) {
                    rule = apr_pstrcat(ptemp, rule, " \"chain", NULL);
                    flag = 1;
                } else {
                    rule = apr_pstrcat(ptemp, rule, " \"", NULL);
                }
                break;
            case B_TRANS:             /* basis.trans_func */
            case B_ACT:             /* basis.action */
            case E_DISRUPT:            /* extension.disruptive */
            case E_LOG:            /* extension.log */
                if (entry) {
                    if (flag) {
                        rule = apr_pstrcat(ptemp, rule, ",", NULL);
                    }
                    rule = apr_pstrcat(ptemp, rule, entry, NULL);
                    flag = 1;
                }
                break;
            case E_PHASE:            /* extension.phase */
                if ( entry != NULL) {
                    if (flag) {
                        rule = apr_pstrcat(ptemp, rule, ",", NULL);
                    }
                    rule = apr_pstrcat(ptemp, rule, "phase:", entry, NULL);
                    flag = 1;
                }
                break;
            case E_ID:            /* extension.id */
                if (entry) {
                    if (flag) {
                        rule = apr_pstrcat(ptemp, rule, ",", NULL);
                    }
                    rule = apr_pstrcat(ptemp, rule, "id:'", entry, "'", NULL);
                    flag = 1;
                }
                break;
            case E_MSG:            /* extension.msg */
                if (entry) {
                    if (flag) {
                        rule = apr_pstrcat(ptemp, rule, ",", NULL);
                    }
                    rule = apr_pstrcat(ptemp, rule, "msg:'", entry, "'", NULL);
                }
                break;
            default:
                break;
        }
    }

    rule = apr_pstrcat(ptemp, rule, "\"", NULL);
    tpool = (* result)->pool;
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);

    return ;
}

static int combind_pm_rule(const char *sec_name, const char *pwdname, const char *url_id,
                            apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i, j;
#if APU_HAVE_MYSQL
    int                     num;
#endif
    char                *state, *keyword;
    const char          *entry, *ptype, *value;
    apr_dbd_results_t   *res = NULL, *kw_res = NULL;
    apr_dbd_row_t       *row = NULL, *kw_row = NULL;

    /* 先根据内置弱密码列表生成规则 */
    entry = apr_psprintf(ptemp, "%s", policy_type[WEAK_PASSWORD]);
    ptype = apr_dbd_escape(driver, ptemp, entry, tmp_db);
    state = apr_psprintf(ptemp, "select * from %s left join %s on %s.list_id = "\
                         "%s.list_id where type = '%s' and flag = '%s'",
                         BASIC_TAB, EXTEND_TAB, BASIC_TAB, EXTEND_TAB, ptype, plain_flag);
    rv = apr_dbd_select(driver, ptemp, default_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1 || rv == 0) {
        return CONV_FAIL;
    }

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

        combined_weak_rule(row, pwdname, NULL, result, ptemp);
    }

    /* 根据用户配置的弱密码生成规则 */
    state = apr_psprintf(ptemp, "select value from %s where number = %d and keyword_id in "\
                         "(select keyword_id from %s where sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %s)",
                         KEYWORD_TAB, PLAIN, KEYWORD_ID_TAB, sec_name, WEAK_PASSWORD, url_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &kw_res, state, 1);
    if (rv > 0) {
        return  CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, kw_res);
    if (rv == -1) {
        return CONV_FAIL ;
    } else if (rv == 0){
        return CONV_OK;
    }

    keyword = NULL;

#if APU_HAVE_SQLITE3
    for (j = rv; j > 0; j--) {
        rv = apr_dbd_get_row(driver, ptemp, kw_res, &kw_row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (j = 1; j <= num; j++) {
        rv = apr_dbd_get_row(driver, ptemp, kw_res, &kw_row, j);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        entry = apr_dbd_get_entry(driver, kw_row, 0);
        value = escape_keyword(entry, ptemp);
        if (keyword) {
            rv = strlen(value) + strlen(keyword);
        } else {
            rv = strlen(value);
        }

        if (rv > KEYWORD_LEN) {
            combined_weak_rule(row, pwdname, keyword, result, ptemp);
            keyword = NULL;
        }
        keyword = apr_pstrcat(ptemp, " ", value, " ", keyword, NULL);
    }

    if (keyword) {
        combined_weak_rule(row, pwdname, keyword, result, ptemp);
    }
    return CONV_OK;
}

static int combind_rx_rule(const char *sec_name, const char *pwdname, const char *url_id,
                            apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv;
    char                *state;
    const char          *entry, *ptype, *keyword;
    apr_dbd_results_t   *res = NULL, *kw_res = NULL;
    apr_dbd_row_t       *row = NULL, *kw_row = NULL;

    /* 查找内置规则 */
    entry = apr_psprintf(ptemp, "%s", policy_type[WEAK_PASSWORD]);
    ptype = apr_dbd_escape(driver, ptemp, entry, tmp_db);
    state = apr_psprintf(ptemp, "select * from %s left join %s on %s.list_id = "\
                         "%s.list_id where type = '%s' and flag = '%s'",
                         BASIC_TAB, EXTEND_TAB, BASIC_TAB, EXTEND_TAB, ptype, regular_flag);
    rv = apr_dbd_select(driver, ptemp, default_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1 || rv != 1) {
        return CONV_FAIL;
    }

#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
    if (rv) {
        return CONV_FAIL;
    }

    /* 查找正则(DEF_REGEX) */
    state = apr_psprintf(ptemp, "select value from %s where number = %d and keyword_id in "\
                         "(select keyword_id from %s where sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %s)",
                         KEYWORD_TAB, DEF_REGEX, KEYWORD_ID_TAB, sec_name, WEAK_PASSWORD, url_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &kw_res, state, 1);
    if (rv > 0) {
        return  CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, kw_res);
    if (rv == -1) {
        return CONV_FAIL ;
    } else if (rv != 0){        /* 根据缺省正则生成规则 */
        combined_weak_rule(row, pwdname, NULL, result, ptemp);
        return CONV_OK;
    }

    /* 查找正则(REGEX) */
    state = apr_psprintf(ptemp, "select value from %s where number = %d and keyword_id in "\
                         "(select keyword_id from %s where sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %s)",
                         KEYWORD_TAB, REGEX, KEYWORD_ID_TAB, sec_name, WEAK_PASSWORD, url_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &kw_res, state, 1);
    if (rv > 0) {
        return  CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, kw_res);
    if (rv == -1) {
        return CONV_FAIL ;
    } else if (rv == 0){        /* 根据缺省正则生成规则 */
        combined_weak_rule(row, pwdname, NULL, result, ptemp);
        return CONV_OK;
    }

    /* 根据指定正则生成规则 */
#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, kw_res, &kw_row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, kw_res, &kw_row, 1);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }

    entry = apr_dbd_get_entry(driver, kw_row, 0);
    keyword = escape_keyword(entry, ptemp);
    combined_weak_rule(row, pwdname, keyword, result, ptemp);
    return CONV_OK;
}

static int weak_passwd_subpolicy_query(const char *name, apr_dbd_row_t *row,
        apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i, url_type;
#if APU_HAVE_MYSQL
    int                     num;
#endif
    char                *state, *rule, **new;
    const char          *entry, *sec_name, *url, *pwdname, *url_id;
    apr_pool_t          *tpool;
    apr_dbd_results_t   *url_res = NULL;
    apr_dbd_row_t       *url_row = NULL;

    /** flag为plain，则不进行处理，到了flag为regex的时候再进行生成规则 */
    entry = apr_dbd_get_entry(driver, row, B_FLAG);
    if (!strcmp(entry, plain_flag)) {
        return CONV_OK;
    }

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    /* 获取url和passwdname */
    state = apr_psprintf(ptemp, "SELECT url, passwdname, url_type, url_passwd_id FROM %s"\
                         " WHERE sec_policy = '%s' AND sec_subpolicy = %d",
                         WEAK_PASSWD_TAB, sec_name, WEAK_PASSWORD);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &url_res, state, 1);
    if (rv > 0) {
        return  CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, url_res);
    if (rv == -1) {
        return CONV_FAIL ;
    } else if (rv == 0){
        return CONV_OK;
    }

    tpool = (*result)->pool;

    /* 生成Location */
#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, url_res, &url_row, -1);
#elif APU_HAVE_MYSQL
    num = rv;
    for (i = 1; i <= num; i++) {
        rv = apr_dbd_get_row(driver, ptemp, url_res, &url_row, i);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        url = apr_dbd_get_entry(driver, url_row, 0);
        pwdname = apr_dbd_get_entry(driver, url_row, 1);
        entry = apr_dbd_get_entry(driver, url_row, 2);
        url_type = atoi(entry);
        url_id = apr_dbd_get_entry(driver, url_row, 3);

        if (url_type == PLAIN) {
            rule = apr_psprintf(ptemp, "<Location %s>", url);
        } else {
            rule = apr_psprintf(ptemp, "<LocationMatch %s>", url);
        }
        new = (char **)apr_array_push(*result);
        *new = apr_pstrdup(tpool, rule);

        /* 生成pm规则 */
        rv = combind_pm_rule(sec_name, pwdname, url_id, result, ptemp);
        if (rv != CONV_OK) {
            return rv;
        }

        /* 生成rx规则 */
        rv = combind_rx_rule(sec_name, pwdname, url_id, result, ptemp);
        if (rv != CONV_OK) {
            return rv;
        }

        /* 生成</Location> */
        if (url_type == PLAIN) {
            rule = apr_psprintf(ptemp, "</Location>");
        } else {
            rule = apr_psprintf(ptemp, "</LocationMatch>");
        }
        new = (char **)apr_array_push(*result);
        *new = apr_pstrdup(tpool, rule);
    }

    return CONV_OK;
}

static int weak_passwd_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp)
{
    int                     rv, i, nrow;
#if APU_HAVE_MYSQL
    int                     num;
#endif
    char                    *state;
    const char              *sec_name, **new_id;
    const char              *url_id, **new;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;
    apr_array_header_t      *url_pwd;
    apr_dbd_transaction_t   *trans = NULL;

    /* 获取所有的url_pwd编号 */
    sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "SELECT url_passwd_id FROM %s WHERE sec_policy='%s' AND"\
                         " sec_subpolicy = %d", WEAK_PASSWD_TAB, sec_name, WEAK_PASSWORD);
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
        url_pwd = apr_array_make(ptemp, 1, sizeof(char *));
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

            url_id = apr_dbd_get_entry(driver, row, 0);
            new = (const char **)apr_array_push(url_pwd);
            *new = url_id;
        }
    }

    /* 进行删除操作 */
    for (i = url_pwd->nelts; i>0; i--) {
        rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
        if (rv > 0) {
            return CONV_FAIL;
        }

        new_id = apr_array_pop(url_pwd);
        state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id IN (SELECT keyword_id FROM"\
                             " %s WHERE sec_policy = '%s' AND sec_subpolicy = %d AND type = %s)",
                             KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, WEAK_PASSWORD, *new_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "DELETE FROM %s WHERE sec_policy = '%s' AND"\
                             " sec_subpolicy = %d AND type = %s",
                             KEYWORD_ID_TAB, sec_name, WEAK_PASSWORD, *new_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "DELETE FROM %s WHERE url_passwd_id = %s",
                             WEAK_PASSWD_TAB, *new_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }

        rv = apr_dbd_transaction_end(driver, ptemp, trans);
        if (rv > 0) {
            return CONV_FAIL;
        }
    }

    return CONV_OK;
}

static int weak_passwd_subpolicy_list(const char *sec_policy,
                                        apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv, i, j, nurl_type, nkw_type, type;
#if APU_HAVE_MYSQL
    int                 num_url, num_kw;
#endif
    char                *state, **new;
    const char          *sec_name;
    const char          *url, *passwdname, *url_type, *url_passwd_id;
    const char          *value, *kw_type;
    apr_dbd_results_t   *url_res = NULL, *kw_res = NULL;
    apr_dbd_row_t       *url_row = NULL, *kw_row = NULL;
    apr_pool_t          *ptab;
    keyword_t           *keyword, **new_keyword;

    /* 查询url和passwdname */
    sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "SELECT url, passwdname, url_type, url_passwd_id "\
                         "FROM %s WHERE sec_policy='%s' AND sec_subpolicy = %d",
                         WEAK_PASSWD_TAB, sec_name, WEAK_PASSWORD);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &url_res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, url_res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {
        return CONV_OK;
    }

    ptab = (*result)->pool;
#if APU_HAVE_SQLITE3
    for (i = rv; i > 0; i--) {
        rv = apr_dbd_get_row(driver, ptemp, url_res, &url_row, -1);
#elif APU_HAVE_MYSQL
    num_url = rv;
    for (i = 1; i <= num_url; i++) {
        rv = apr_dbd_get_row(driver, ptemp, url_res, &url_row, i);
#endif
        if (rv == -1) {
            return CONV_FAIL;
        }

        url = apr_dbd_get_entry(driver, url_row, 0);
        passwdname = apr_dbd_get_entry(driver, url_row, 1);
        url_type = apr_dbd_get_entry(driver, url_row, 2);
        url_passwd_id = apr_dbd_get_entry(driver, url_row, 3);
        nurl_type = atoi(url_type);

        /* 查询关键字 */
        state = apr_psprintf(ptemp, "SELECT value, number FROM %s WHERE keyword_id IN"\
                             " (SELECT keyword_id FROM %s WHERE sec_policy = '%s' AND"\
                             " sec_subpolicy = %d AND type = %s)", KEYWORD_TAB,
                             KEYWORD_ID_TAB, sec_name, WEAK_PASSWORD, url_passwd_id);
        rv = apr_dbd_select(driver, ptemp, tmp_db, &kw_res, state, 1);
        if (rv > 0) {
            return CONV_FAIL;
        }

        rv = apr_dbd_num_tuples(driver, kw_res);
        if (rv == -1) {
            return CONV_FAIL;
        }

        type = 0;
        if (rv == 0) { /* 不存在关键字时，只显示URL */
            type = (nurl_type == PLAIN) ? PLAIN_URL : REGEX_URL;
            keyword = apr_pcalloc(ptab, sizeof(keyword_t));
            keyword->keyword = apr_array_make(ptab, 1, sizeof(char *));
            keyword->flag = OUTER_KEYWORD;
            keyword->type = type;
            new = (char **)apr_array_push(keyword->keyword);
            *new = apr_pstrdup(ptab, url);
            new = (char **)apr_array_push(keyword->keyword);
            *new = apr_pstrdup(ptab, passwdname);

            new_keyword = (keyword_t **)apr_array_push(*result);
            *new_keyword = keyword; 
			continue;
        }

#if APU_HAVE_SQLITE3
        for (j = rv; j > 0; j--) {
            rv = apr_dbd_get_row(driver, ptemp, kw_res, &kw_row, -1);
#elif APU_HAVE_MYSQL
        num_kw = rv;
        for (j = 1; j <= num_kw; j++) {
            rv = apr_dbd_get_row(driver, ptemp, kw_res, &kw_row, j);
#endif
            if (rv == -1) {
                return CONV_FAIL;
            }

            value = apr_dbd_get_entry(driver, kw_row, 0);
            kw_type = apr_dbd_get_entry(driver, kw_row, 1);
            nkw_type = atoi(kw_type);
            if (nurl_type == PLAIN) {
                if (nkw_type == PLAIN) {
                    type = PLAIN_PLAIN;
                } else {
                    type = PLAIN_REGEX;
                }
            } else {
                if (nkw_type == PLAIN) {
                    type = REGEX_PLAIN;
                } else {
                    type = REGEX_REGEX;
                }
            }

            keyword = apr_pcalloc(ptab, sizeof(keyword_t));
            keyword->keyword = apr_array_make(ptab, 1, sizeof(char *));
            keyword->flag = OUTER_KEYWORD;
            keyword->type = type;
            new = (char **)apr_array_push(keyword->keyword);
            *new = apr_pstrdup(ptab, url);
            new = (char **)apr_array_push(keyword->keyword);
            *new = apr_pstrdup(ptab, passwdname);
            new = (char **)apr_array_push(keyword->keyword);
            *new = apr_pstrdup(ptab, value);

            new_keyword = (keyword_t **)apr_array_push(* result);
            *new_keyword = keyword;
        }
    }

    return CONV_OK;
}

/* 请求方法处理驱动结构 */
subpolicy_t weak_passwd_subpolicy = {
    WEAK_PASSWORD,
    weak_passwd_keyword_add,
    weak_passwd_keyword_del,
    weak_passwd_subpolicy_query,
    weak_passwd_subpolicy_del,
    weak_passwd_subpolicy_list
};

