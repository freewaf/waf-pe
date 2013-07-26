/*
 * $Id: convert_cookie.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

static char *attribution = "SecRule &RESPONSE_HEADERS:/Set-Cookie2?/ \"@ge 1\""\
                           " \" phase:3,id:'%s',t:none,pass,log,auditlog,appendCookie:'%s'\"";

static char *expire = "SecRule &RESPONSE_HEADERS:/Set-Cookie2?/ \"@ge 1\""\
                      " \"phase:3,id:'%s',t:none,pass,log,auditlog,appendExpireCookie:'%s'\"";

static char *verification[] = {"SecRule &RESPONSE_HEADERS:/Set-Cookie2?/ \"@ge 1\""\
                               " \"phase:3,id:'%s',t:none,pass,log,auditlog,%s:'%s'\"",

                            "SecRule REQUEST_COOKIES_BLOCK \"!@%s %s\""\
                            " \"phase:2,id:'%s',pass,log,auditlog,tag:'Cookie Attack'\""};

static char *verify_action[] = {"appendSignatureCookie",
                                "appendSignatureIpCookie",
                                "encryptCookie",
                                "encryptIpCookie"};

static char *verify_operator[] = {"verifyCookieSignature",
                                    "verifyCookieIpSignature",
                                    "decryptCookie",
                                    "decryptIpCookie"};

static int cookie_name_add(keyword_t *k, apr_dbd_results_t *res, apr_pool_t *ptemp)
{
    int                     rv, nrows;
    char                    *state, **kw;
    const char              *kw_id, *keyword, *new_id;
    apr_dbd_row_t           *row = NULL;

    new_id = NULL;
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

    kw = apr_array_pop(k->keyword);
    keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%s, %d, '%s')",
                         KEYWORD_TAB, kw_id, KEYWORD_FIRST, keyword);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);
    if (rv > 0) {
        return CONV_FAIL;
    }

    return CONV_OK;
}

static int cookie_add(keyword_t *k, apr_dbd_results_t *res, apr_pool_t *ptemp)
{
    int                     rv, nrows, i, new_id;
    char                    *state, **kw;
    const char              *sec_name, *keyword;
    apr_dbd_transaction_t   *trans = NULL;

    if ( k->type == COOKIE_NAME) {
        sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
        state = apr_psprintf(ptemp, "SELECT keyword_id FROM %s where sec_policy = '%s' and"\
                             " sec_subpolicy = %d and type = %d", KEYWORD_ID_TAB,
                             sec_name, k->sec_subpolicy, k->type);
        rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
        if (rv > 0) {
            return CONV_FAIL;
        }
        rv = apr_dbd_num_tuples(driver, res);
        if (rv == -1) {
            return rv;
        } else if (rv > 0) {                    /* 存在其他cookie_name */
            return cookie_name_add(k, res, ptemp);
        }
    }

    kw_id_flag++;
    new_id = bm_firstunset(&nbitmap);
    bm_setbit(&nbitmap, new_id);
    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        return CONV_FAIL;
    }

    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, '%s', %d, %d)",
                         KEYWORD_ID_TAB, kw_id_flag, sec_name, k->sec_subpolicy, k->type);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d)",
                         NEW_TAB, kw_id_flag, new_id);
    rv = apr_dbd_query(driver, tmp_db, &nrows, state);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        apr_dbd_transaction_end(driver, ptemp, trans);
        return CONV_FAIL;
    }

    for (i = k->keyword->nelts; i > 0; i--) {
        kw = apr_array_pop(k->keyword);
        keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
        state = apr_psprintf(ptemp, "INSERT INTO %s VALUES (%ld, %d, '%s')",
                             KEYWORD_TAB, kw_id_flag, i, keyword);
        rv = apr_dbd_query(driver, tmp_db, &nrows, state);
        if (rv > 0) {
            kw_id_flag--;
            bm_clrbit(&nbitmap, new_id);
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }
    }

    rv = apr_dbd_transaction_end(driver, ptemp, trans);
    if (rv > 0) {
        kw_id_flag--;
        bm_clrbit(&nbitmap, new_id);
        return CONV_FAIL;
    } else {
        return CONV_OK;
    }
}

static int cookie_modified(keyword_t *k, apr_dbd_results_t *res, apr_pool_t *ptemp)
{
    int                     rv, nrows, i;
    apr_dbd_row_t           *row = NULL;
    const char              *kw_id, *keyword;
    char                    *state, **kw;
    apr_dbd_transaction_t   *trans = NULL;

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

    rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
    if (rv > 0) {
        return CONV_FAIL;
    }

    for (i = k->keyword->nelts; i > 0; i--) {
        kw = apr_array_pop(k->keyword);
        keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
        state = apr_psprintf(ptemp, "UPDATE %s SET value = '%s' WHERE keyword_id = %s "\
                             "and number = %d", KEYWORD_TAB, keyword, kw_id, i);

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

static int cookie_keyword_add(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv;
    char                    *state, **kw;
    const char              *sec_name, *keyword;
    apr_dbd_results_t       *res = NULL;

    if ((k == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    /* 关键字数目判断 */
    if (k->type == VERIFICATION ) {
        if ( k->keyword->nelts != 2) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: wrong keyword number!");
            return CONV_FAIL;
        }
    } else if (k->keyword->nelts != 1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "WAF_CONVERT: too much keyword!");
        return CONV_FAIL;
    }

     if (k->type != COOKIE_NAME) {
        sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
        state = apr_psprintf(ptemp, "SELECT keyword_id FROM %s where sec_policy = '%s' and"\
                             " sec_subpolicy = %d and type = %d", KEYWORD_ID_TAB,
                             sec_name, k->sec_subpolicy, k->type);
        rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
        if (rv > 0) {
            return CONV_FAIL;
        }
        rv = apr_dbd_num_tuples(driver, res);
        if (rv == -1) {
            return rv;
        } else if (rv > 0) {
            return cookie_modified(k, res, ptemp);
        } else {
            return cookie_add(k, res, ptemp);
        }
    } else {
        sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
        kw = apr_array_pop(k->keyword);
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
            return rv;
        } else if (rv > 0) {
            return CONV_CONFLICT;
        } else {
            kw = apr_array_push(k->keyword);
            return cookie_add(k, res, ptemp);
        }
    }
}

static int cookie_keyword_del(keyword_t *k, apr_pool_t *ptemp)
{
    int                     rv, id, nrow;
    char                    *state;
    const char              **kw, *kw_id, *new_id, *sec_name, *keyword;
    apr_dbd_results_t       *res = NULL;
    apr_dbd_row_t           *row = NULL;
    apr_dbd_transaction_t   *trans = NULL;

    if ((k == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    sec_name = apr_dbd_escape(driver, ptemp, k->sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "SELECT keyword_id FROM %s WHERE sec_policy = '%s' AND"\
                         " sec_subpolicy = %d and type = %d", KEYWORD_ID_TAB, sec_name,
                         k->sec_subpolicy, k->type);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0) {           /* 不存在此类型关键字 */
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

    /* 查询关键字的数量 */
    state = apr_psprintf(ptemp, "SELECT value FROM %s where keyword_id = %s", KEYWORD_TAB, kw_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return rv;
    } else if ((k->type == COOKIE_NAME) && (rv > 1) && (k->flag != FLAG_ALL)) {
        kw = apr_array_pop(k->keyword);
        keyword = apr_dbd_escape(driver, ptemp, *kw, tmp_db);
        state = apr_psprintf(ptemp, "SELECT * FROM %s where value = '%s' and keyword_id = %s",
                             KEYWORD_TAB, keyword, kw_id);
        rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
        if (rv > 0) {
            return CONV_FAIL;
        }

        rv = apr_dbd_num_tuples(driver, res);
        if (rv == -1) {
            return CONV_FAIL;
        } else if (rv == 0) {
            return CONV_NOTEXIST;
        }
        
        state = apr_psprintf(ptemp, "DELETE FROM %s where value = '%s' and keyword_id = %s",
                             KEYWORD_TAB, keyword, kw_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            return CONV_FAIL;
        } else {
            return CONV_OK;
        }
    } else if (rv == 0) {
        return CONV_OK;
    } else {                                                /* 删除关键字且归还new_id */
        state = apr_psprintf(ptemp, "SELECT new_id FROM %s WHERE keyword_id = %s",
                             NEW_TAB, kw_id);
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
            new_id = apr_dbd_get_entry(driver, row, 0);
        }

        /* 删除数据库中的信息 */
        rv = apr_dbd_transaction_start(driver, ptemp, tmp_db, &trans);
        if (rv > 0) {
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id = %s",
                             NEW_TAB, kw_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "DELETE FROM %s WHERE keyword_id = %s",
                             KEYWORD_TAB, kw_id);
        rv = apr_dbd_query(driver, tmp_db, &nrow, state);
        if (rv > 0) {
            apr_dbd_transaction_end(driver, ptemp, trans);
            return CONV_FAIL;
        }

        state = apr_psprintf(ptemp, "DELETE FROM %s where keyword_id = %s",
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

        id = atoi(new_id);
        bm_clrbit(&nbitmap, id);
        return CONV_OK;
    }
}

static int add_attribution(const char *name, apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv;
    char                *rule, **new, *state;
    const char          *sec_name, *new_id, *entry;
    apr_pool_t          *tpool;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT %s.new_id, %s.value FROM %s, %s where %s.keyword_id "\
                         "= %s.keyword_id and %s.keyword_id in (SELECT keyword_id from %s WHERE"\
                         " sec_policy = '%s' and sec_subpolicy = %d and type = %d)",
                         NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB,
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, COOKIE, ATTRIBUTION);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0){
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

    /* 获取规则ID */
    new_id = apr_dbd_get_entry(driver, row, 0);
    entry = apr_dbd_get_entry(driver, row, 1);
    if (atoi(entry) == SECURE) {
        rule = apr_psprintf(ptemp, attribution, new_id, "Secure;");
    } else if (atoi(entry) == HTTPDONLY) {
        rule = apr_psprintf(ptemp, attribution, new_id, "HttpOnly;");
    } else {
        rule = apr_psprintf(ptemp, attribution, new_id, "Secure; HttpOnly;");
    }

    tpool = (*result)->pool;
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);
    return CONV_OK;
}

static int add_expire_time(const char *name, apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv;
    char                *rule, **new, *state;
    const char          *sec_name, *entry, *new_id;
    apr_pool_t          *tpool;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT %s.new_id, %s.value FROM %s, %s where %s.keyword_id "\
                         "= %s.keyword_id and %s.keyword_id in (SELECT keyword_id from %s WHERE"\
                         " sec_policy = '%s' and sec_subpolicy = %d and type = %d)",
                         NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB, NEW_TAB, KEYWORD_TAB,
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, COOKIE, EXPIRE_TIME);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0){
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

    /* 获取规则ID */
    new_id = apr_dbd_get_entry(driver, row, 0);
    entry = apr_dbd_get_entry(driver, row, 1);
    if (!strcmp(entry, "0")) {
        return CONV_OK;
    }
    
    rule = apr_psprintf(ptemp, expire, new_id, entry);

    tpool = (*result)->pool;
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);
    return CONV_OK;
}

static int get_verify_method(const char *name, char **action, char **operator,
                             char **verify_id, apr_pool_t *ptemp)
{
    int                 rv, kw1, kw2;
    char                *state;
    const char          *sec_name, *entry, *kw_id;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT new_id, keyword_id FROM %s where keyword_id in (SELECT"\
                         " keyword_id from %s WHERE sec_policy = '%s' and sec_subpolicy = %d"\
                         " and type = %d)",
                         NEW_TAB, KEYWORD_ID_TAB, sec_name, COOKIE, VERIFICATION);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0){
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

    /* 获取规则ID */
    entry = apr_dbd_get_entry(driver, row, 0);
    *verify_id = apr_psprintf(ptemp, "%s", entry);
    kw_id = apr_dbd_get_entry(driver, row, 1);

    /* 获取校验方式 */
    state = apr_psprintf(ptemp, "SELECT number, value from %s where keyword_id = %s ORDER BY number",
                         KEYWORD_TAB, kw_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0){
        return CONV_NOTEXIST;
    } else if (rv != 2) {
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

    entry = apr_dbd_get_entry(driver, row, 1);
    kw1 = atoi(entry);

#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 2);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }
    entry = apr_dbd_get_entry(driver, row, 1);
    kw2 = atoi(entry);

    if (kw1 == SIGNATURE) {
        if (kw2 == COOKIE_VERTFICATION) {
            *action = verify_action[0];
            *operator = verify_operator[0];
        } else {
            *action = verify_action[1];
            *operator = verify_operator[1];
        }
    } else if (kw1 == ENCRYPTION ) {
        if (kw2 == COOKIE_VERTFICATION) {
            *action = verify_action[2];
            *operator = verify_operator[2];
        } else {
            *action = verify_action[3];
            *operator = verify_operator[3];
        }
    }

    return CONV_OK;
}

static int get_cookie_name(const char *name, char **name_id,
                           char **cookie_name, apr_pool_t *ptemp)
{
    int                 i, rv;
#if APU_HAVE_MYSQL
    int                 num;
#endif
    char                *state, *kw_buf;
    const char          *sec_name, *entry, *keyword;
    const char          *kw_id;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    sec_name = apr_dbd_escape(driver, ptemp, name, tmp_db);
    state = apr_psprintf(ptemp, "SELECT new_id, keyword_id FROM %s where keyword_id in (SELECT"\
                     " keyword_id from %s WHERE sec_policy = '%s' and sec_subpolicy = %d"\
                     " and type = %d)", NEW_TAB, KEYWORD_ID_TAB, sec_name, COOKIE, COOKIE_NAME);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0){
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

    /* 获取规则ID */
    entry = apr_dbd_get_entry(driver, row, 0);
    *name_id = apr_psprintf(ptemp, "%s", entry);
    kw_id = apr_dbd_get_entry(driver, row, 1);

    state = apr_psprintf(ptemp, "SELECT value from %s where keyword_id = %s", KEYWORD_TAB, kw_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }
    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0){
        return CONV_NOTEXIST;
    }

    kw_buf = NULL;
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
        if (kw_buf == NULL) {
            kw_buf = apr_pstrcat(ptemp, entry, kw_buf, NULL);
        } else {
            kw_buf = apr_pstrcat(ptemp, entry, ",", kw_buf, NULL);
        }
    }

    if (strlen(kw_buf) > KEYWORD_LEN) {
        kw_buf[KEYWORD_LEN] = '\0';
    }
    *cookie_name = apr_psprintf(ptemp, "%s", kw_buf);
    return CONV_OK;
}

static int add_verify(const char *name, apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv;
    char                *rule, **new;
    char                *action, *operator, *verify_id, *name_id, *cookie_name;
    apr_pool_t          *tpool;

    action = NULL;
    operator = NULL;
    verify_id = NULL;
    rv = get_verify_method(name, &action, &operator, &verify_id, ptemp);
    if (rv == CONV_FAIL) {
        return CONV_FAIL;
    } else if (rv == CONV_NOTEXIST) {
        return CONV_OK;
    }

    name_id = NULL;
    cookie_name = NULL;
    rv = get_cookie_name(name, &name_id, &cookie_name, ptemp);
    if (rv == CONV_FAIL) {
        return CONV_FAIL;
    } else if (rv == CONV_NOTEXIST) {
        return CONV_OK;
    }

    tpool = (*result)->pool;
    /* 构造规则 */
    rule = apr_psprintf(ptemp, verification[0], name_id, action, cookie_name);
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);

    rule = apr_psprintf(ptemp, verification[1], operator, cookie_name, verify_id);
    new = (char **)apr_array_push(*result);
    *new = apr_pstrdup(tpool, rule);

    return CONV_OK;

}

static int cookie_subpolicy_query(const char *name, apr_dbd_row_t *row,
        apr_array_header_t **result, apr_pool_t *ptemp)
{
    int rv;

    rv = add_attribution(name, result, ptemp);
    if (rv != CONV_OK) {
        return CONV_FAIL;
    }

    rv = add_expire_time(name, result, ptemp);
    if (rv != CONV_OK) {
        return CONV_FAIL;
    }

    rv = add_verify(name, result, ptemp);
    if (rv != CONV_OK) {
        return CONV_FAIL;
    }

    return CONV_OK;
}

static int cookie_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp)
{
    return sub_with_new_del(sec_policy, COOKIE, ptemp);
}

static int cookie_subpolicy_list(const char *sec_policy,
                                        apr_array_header_t **result, apr_pool_t *ptemp)
{
    int                 rv;
    char                **new, *state;
    const char          *sec_name, *entry, *kw_id;
    keyword_t           *keyword, **new_keyword;
    apr_pool_t          *tpool;
    apr_dbd_results_t   *res = NULL;
    apr_dbd_row_t       *row = NULL;

    /* COOKIE_NAME */
    rv = new_keyword_list(sec_policy, COOKIE, COOKIE_NAME, NULL, ASCII, result, ptemp);
    if (rv != CONV_OK) {
        return rv;
    }

    /* EXPIRE_TIME */
    tpool = (*result)->pool;
    sec_name = apr_dbd_escape(driver, ptemp, sec_policy, tmp_db);
    state = apr_psprintf(ptemp, "select value from %s where keyword_id"\
                         " in (select keyword_id from %s where sec_policy"\
                         " = '%s' and sec_subpolicy = %d and type = %d)",
                         KEYWORD_TAB, KEYWORD_ID_TAB, sec_name, COOKIE, EXPIRE_TIME);   
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }    

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv != 0){
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
    } 

    keyword = apr_pcalloc(tpool, sizeof(keyword_t));
    
    keyword->keyword = apr_array_make(tpool, 1, sizeof(char *));
    keyword->flag = OUTER_KEYWORD;
    keyword->type = EXPIRE_TIME;
    new = (char **)apr_array_push(keyword->keyword);
    if (!entry) {
        *new = apr_pstrdup(tpool, "0");
    } else {
        *new = apr_pstrdup(tpool, entry);
    }
    
    
    new_keyword = (keyword_t **)apr_array_push(* result);
    *new_keyword = keyword;
    
    /* ATTRIBUTION */
    rv = new_keyword_list(sec_policy, COOKIE, ATTRIBUTION, NULL, ASCII, result, ptemp);
    if (rv != CONV_OK) {
        return rv;
    }

    /* VERIFICATION */
    res = NULL;
    state = apr_psprintf(ptemp, "SELECT keyword_id from %s WHERE sec_policy = '%s' and"\
                         " sec_subpolicy = %d and type = %d",
                         KEYWORD_ID_TAB, sec_name, COOKIE, VERIFICATION);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0){
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

    /* 获取校验方式 */
    state = apr_psprintf(ptemp, "SELECT number, value from %s where keyword_id = %s ORDER"\
                         " BY number", KEYWORD_TAB, kw_id);
    rv = apr_dbd_select(driver, ptemp, tmp_db, &res, state, 1);
    if (rv > 0) {
        return CONV_FAIL;
    }

    rv = apr_dbd_num_tuples(driver, res);
    if (rv == -1) {
        return CONV_FAIL;
    } else if (rv == 0){
        return CONV_NOTEXIST;
    } else if (rv != 2) {
        return CONV_FAIL;
    }
    
    keyword = apr_pcalloc(tpool, sizeof(keyword_t));
    keyword->keyword = apr_array_make(tpool, 1, sizeof(char *));
    keyword->flag = OUTER_KEYWORD;
    keyword->type = VERIFICATION;

#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 1);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }

    entry = apr_dbd_get_entry(driver, row, 1);
    new = (char **)apr_array_push(keyword->keyword);
    *new = apr_pstrdup(tpool, entry);

#if APU_HAVE_SQLITE3
    rv = apr_dbd_get_row(driver, ptemp, res, &row, -1);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_get_row(driver, ptemp, res, &row, 2);
#endif
    if (rv == -1) {
        return CONV_FAIL;
    }

    entry = apr_dbd_get_entry(driver, row, 1);
    new = (char **)apr_array_push(keyword->keyword);
    *new = apr_pstrdup(tpool, entry);

    new_keyword = (keyword_t **)apr_array_push(* result);
    *new_keyword = keyword;
    return CONV_OK;
}

/* 请求方法处理驱动结构 */
subpolicy_t cookie_subpolicy = {
    COOKIE,
    cookie_keyword_add,
    cookie_keyword_del,
    cookie_subpolicy_query,
    cookie_subpolicy_del,
    cookie_subpolicy_list
};
